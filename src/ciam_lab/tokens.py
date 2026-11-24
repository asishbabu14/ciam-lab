"""Mint and validate ID tokens and access tokens with Authlib."""

from __future__ import annotations

import time
from dataclasses import dataclass

from authlib.jose import jwt
from authlib.jose.errors import BadSignatureError, DecodeError
from authlib.oauth2.claims import JWTClaims
from authlib.oidc.core import CodeIDToken

from ciam_lab.keys import generate_rsa


class TokenValidationError(Exception):
    def __init__(self, code: str, message: str, checks: list[Check]):
        super().__init__(message)
        self.code = code
        self.message = message
        self.checks = checks

    def as_dict(self) -> dict:
        return {
            "error": self.code,
            "error_description": self.message,
            "checks": [check.as_dict() for check in self.checks],
            "fix": FIXES.get(self.code, ""),
        }


@dataclass
class Check:
    name: str
    ok: bool
    detail: str

    def as_dict(self) -> dict:
        return {"name": self.name, "ok": self.ok, "detail": self.detail}


FIXES = {
    "malformed": "Use a compact JWT with three segments: header, payload, and signature.",
    "bad_signature": "Trust only tokens whose signature matches the issuer JWKS.",
    "id_token_used_as_access_token": (
        "Send the access token to the API. Keep the ID token in the client. "
        "An ID token says who signed in. An access token is the API credential."
    ),
    "access_token_used_as_id_token": (
        "Validate the ID token when establishing the login session. "
        "Do not treat the access token as proof of authentication."
    ),
    "issuer_mismatch": "The iss claim must equal the issuer from the discovery document.",
    "audience_mismatch": (
        "Match aud to the component that is receiving the token. "
        "An ID token audience is the client id. An access token audience is the API."
    ),
    "expired": "Sign in again. The lab allows a few seconds of clock skew, then rejects the token.",
    "clock_skew": "Check the host clock. The lab leeway is small on purpose (default 10 seconds).",
    "nonce_mismatch": "Start a new login. The ID token nonce must match the nonce stored for this attempt.",
    "insufficient_scope": "Request the missing scope and have the user consent to it.",
    "state_mismatch": "Start a new login. The returned state must match the state stored before the redirect.",
}


def mint(payload: dict, private_key, kid: str) -> str:
    raw = jwt.encode({"alg": "RS256", "kid": kid, "typ": "JWT"}, payload, private_key)
    if isinstance(raw, bytes):
        return raw.decode("ascii")
    return raw


def issue_tokens(
    *,
    private_key,
    kid: str,
    issuer: str,
    subject: str,
    client_id: str,
    audience: str,
    nonce: str,
    scopes: list[str],
    name: str,
    email: str,
    amr: list[str],
    auth_time: int,
    lifetime: int = 300,
    lab_idp: str,
    extra_id_claims: dict | None = None,
    now: int | None = None,
) -> tuple[str, str]:
    issued = int(time.time()) if now is None else now
    shared = {
        "iss": issuer,
        "sub": subject,
        "iat": issued,
        "nbf": issued,
        "exp": issued + lifetime,
        "auth_time": auth_time,
        "amr": amr,
        "lab_idp": lab_idp,
    }
    id_payload = {
        **shared,
        "aud": client_id,
        "azp": client_id,
        "nonce": nonce,
        "name": name,
        "email": email,
        "email_verified": True,
        "token_use": "id",
    }
    if extra_id_claims:
        id_payload.update(extra_id_claims)
    access_payload = {
        **shared,
        "aud": audience,
        "scope": " ".join(scopes),
        "client_id": client_id,
        "token_use": "access",
    }
    return (
        mint(id_payload, private_key, kid),
        mint(access_payload, private_key, kid),
    )


class TokenValidator:
    """Validate signatures with JWKS, then issuer, audience, time, nonce, and token use.

    Signature verification and claim checks go through Authlib. The check list is
    the lab's readable trace of those same decisions.
    """

    def __init__(self, issuer: str, jwks: dict, leeway: int = 10):
        self.issuer = issuer
        self.jwks = jwks
        self.leeway = leeway

    def validate_id_token(
        self,
        token: str,
        *,
        audience: str,
        nonce: str | None,
        client_id: str | None = None,
        now: int | None = None,
    ) -> tuple[dict, list[Check]]:
        return self._validate(
            token,
            expected_use="id",
            audience=audience,
            nonce=nonce,
            client_id=client_id or audience,
            required_scope=None,
            now=now,
        )

    def validate_access_token(
        self,
        token: str,
        *,
        audience: str | None,
        required_scope: str | None = None,
        now: int | None = None,
    ) -> tuple[dict, list[Check]]:
        return self._validate(
            token,
            expected_use="access",
            audience=audience,
            nonce=None,
            client_id=None,
            required_scope=required_scope,
            now=now,
        )

    def _validate(
        self,
        token: str,
        *,
        expected_use: str,
        audience: str | None,
        nonce: str | None,
        client_id: str | None,
        required_scope: str | None,
        now: int | None,
    ) -> tuple[dict, list[Check]]:
        current = int(time.time()) if now is None else now
        checks: list[Check] = []
        if token.count(".") != 2:
            self._fail(
                "malformed",
                "The value is not a compact JWT.",
                checks,
                "structure",
                False,
                "expected three base64url segments",
            )

        claims_cls = CodeIDToken if expected_use == "id" else JWTClaims
        options: dict = {"iss": {"essential": True, "value": self.issuer}}
        if audience is not None:
            options["aud"] = {"essential": True, "value": audience}
        params = {"nonce": nonce, "client_id": client_id} if expected_use == "id" else {}
        try:
            claims_obj = jwt.decode(
                token,
                self.jwks,
                claims_cls=claims_cls,
                claims_options=options,
                claims_params=params,
            )
        except (BadSignatureError, DecodeError) as exc:
            self._fail(
                "bad_signature",
                "Signature verification failed. The token is not signed by this issuer's JWKS.",
                checks,
                "signature",
                False,
                exc.__class__.__name__,
            )
        checks.append(Check("signature", True, "RS256 signature matches the issuer JWKS"))

        token_use = claims_obj.get("token_use")
        if expected_use == "access" and token_use == "id":
            self._fail(
                "id_token_used_as_access_token",
                "This is an ID token. The API requires an access token. "
                "An ID token tells the client who signed in. An access token is what the API accepts.",
                checks,
                "token_use",
                False,
                "token_use is id",
            )
        if expected_use == "id" and token_use == "access":
            self._fail(
                "access_token_used_as_id_token",
                "This is an access token. The login callback must validate the ID token.",
                checks,
                "token_use",
                False,
                "token_use is access",
            )
        if token_use not in (None, expected_use):
            self._fail(
                "malformed",
                f"Unexpected token_use {token_use!r}.",
                checks,
                "token_use",
                False,
                f"got {token_use!r}",
            )
        if token_use is None:
            use_detail = "no token_use claim; audience is the remaining distinction"
        elif expected_use == "access":
            use_detail = "access token"
        else:
            use_detail = "ID token"
        checks.append(Check("token_use", True, use_detail))

        issuer = claims_obj.get("iss")
        if issuer != self.issuer:
            self._fail(
                "issuer_mismatch",
                f"Token issuer {issuer!r} does not match {self.issuer!r}.",
                checks,
                "issuer",
                False,
                f"got {issuer!r}",
            )
        checks.append(Check("issuer", True, str(issuer)))

        if audience is not None:
            aud = claims_obj.get("aud")
            aud_list = aud if isinstance(aud, list) else [aud]
            if audience not in aud_list:
                self._fail(
                    "audience_mismatch",
                    f"Token audience {aud!r} does not include {audience!r}.",
                    checks,
                    "audience",
                    False,
                    f"got {aud!r}, expected {audience}",
                )
            checks.append(Check("audience", True, str(audience)))
        else:
            checks.append(Check("audience", True, "not required at this endpoint"))

        self._check_time(claims_obj, current, checks)

        if expected_use == "id":
            if not nonce:
                self._fail(
                    "nonce_mismatch",
                    "This login has no stored nonce, so the ID token cannot be accepted.",
                    checks,
                    "nonce",
                    False,
                    "client nonce is missing",
                )
            if claims_obj.get("nonce") != nonce:
                self._fail(
                    "nonce_mismatch",
                    "ID token nonce does not match the nonce stored for this login.",
                    checks,
                    "nonce",
                    False,
                    "nonce differs from the authorization request",
                )
            checks.append(Check("nonce", True, "nonce matches the login request"))

        if required_scope:
            granted = str(claims_obj.get("scope") or "").split()
            if required_scope not in granted:
                shown = " ".join(granted) if granted else "(none)"
                self._fail(
                    "insufficient_scope",
                    f"Token is missing scope {required_scope}. Granted scopes: {shown}.",
                    checks,
                    "scope",
                    False,
                    f"missing {required_scope}",
                )
            checks.append(Check("scope", True, f"includes {required_scope}"))

        try:
            claims_obj.validate(now=current, leeway=self.leeway)
        except Exception as exc:
            claim = getattr(exc, "claim", "") or ""
            text = str(exc).lower()
            if "expired" in text or claim == "exp":
                code = "expired"
            elif claim in {"iat", "nbf"} or "future" in text or "not yet valid" in text:
                code = "clock_skew"
            elif claim == "aud" or "aud" in text:
                code = "audience_mismatch"
            elif claim == "iss":
                code = "issuer_mismatch"
            elif claim == "nonce":
                code = "nonce_mismatch"
            else:
                code = "malformed"
            self._fail(code, str(exc), checks, "authlib", False, exc.__class__.__name__)

        checks.append(Check("authlib", True, "Authlib claim validation passed"))
        return dict(claims_obj), checks

    def _check_time(self, claims, now: int, checks: list[Check]) -> None:
        exp = claims.get("exp")
        if not _is_time(exp) or exp <= now - self.leeway:
            self._fail(
                "expired",
                f"Token is expired (exp={exp}, now={now}, leeway={self.leeway}s).",
                checks,
                "expiry",
                False,
                "exp is outside the leeway window",
            )
        checks.append(Check("expiry", True, f"exp is inside the {self.leeway}s leeway"))

        iat = claims.get("iat")
        if _is_time(iat) and iat > now + self.leeway:
            self._fail(
                "clock_skew",
                f"Token iat is in the future beyond the {self.leeway}s leeway. Check the host clock.",
                checks,
                "issued_at",
                False,
                f"iat {iat} is too far ahead of {now}",
            )
        checks.append(Check("issued_at", True, "iat is within leeway"))

        nbf = claims.get("nbf")
        if _is_time(nbf) and nbf > now + self.leeway:
            self._fail(
                "clock_skew",
                f"Token is not valid yet (nbf={nbf}, now={now}, leeway={self.leeway}s).",
                checks,
                "not_before",
                False,
                "nbf is still in the future",
            )
        if nbf is not None:
            checks.append(Check("not_before", True, "nbf is within leeway"))

    @staticmethod
    def _fail(code, message, checks, name, ok, detail):
        checks.append(Check(name, ok, detail))
        raise TokenValidationError(code, message, checks)


def _is_time(value) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def test_keypair(kid: str = "unit-test"):
    return generate_rsa(kid)
