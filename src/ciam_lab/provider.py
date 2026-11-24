"""Local OpenID Connect providers.

The customer provider is labeled MOCK:local-idp. The enterprise provider is
labeled MOCK:enterprise-idp. Both are in-memory and only know synthetic users.
"""

from __future__ import annotations

import secrets
import time
from dataclasses import dataclass, field
from pathlib import Path

import httpx
from authlib.integrations.httpx_client import OAuth2Client
from authlib.oauth2.rfc7636.challenge import compare_s256_code_challenge
from fastapi import FastAPI, Form, Request
from fastapi.responses import JSONResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from webauthn import (
    generate_authentication_options,
    generate_registration_options,
    verify_authentication_response,
    verify_registration_response,
)
from webauthn.helpers import bytes_to_base64url, options_to_json_dict
from webauthn.helpers.exceptions import (
    InvalidAuthenticationResponse,
    InvalidRegistrationResponse,
)
from webauthn.helpers.structs import (
    AuthenticatorSelectionCriteria,
    PublicKeyCredentialDescriptor,
    ResidentKeyRequirement,
    UserVerificationRequirement,
)

from ciam_lab.catalog import (
    BROKER_CLIENT_ID,
    CUSTOMER_SCOPES,
    ENTERPRISE_SCOPES,
    SCOPE_COPY,
)
from ciam_lab.config import Settings
from ciam_lab.keys import generate_rsa
from ciam_lab.tokens import TokenValidationError, TokenValidator, issue_tokens

PACKAGE = Path(__file__).resolve().parent
TOKEN_TTL = 300
CODE_TTL = 180
CHALLENGE_TTL = 180


@dataclass
class Client:
    client_id: str
    name: str
    redirect_uris: list[str]


@dataclass
class ProviderConfig:
    label: str
    issuer: str
    kid: str
    cookie_name: str
    clients: dict[str, Client]
    users: dict[str, dict]
    scopes: list[str]
    audience: str
    leeway: int
    webauthn: bool
    consent: bool
    federation: bool
    rp_id: str
    origin: str
    hints: list[tuple[str, str]]
    post_logout_uris: list[str] = field(default_factory=list)
    enterprise_issuer: str | None = None
    broker_client_id: str = BROKER_CLIENT_ID


@dataclass
class AuthTransaction:
    request_id: str
    client_id: str
    redirect_uri: str
    scopes: list[str]
    state: str
    nonce: str
    code_challenge: str
    prompt: str
    created: float
    user_id: str | None = None
    amr: list[str] | None = None
    auth_time: int | None = None
    authenticated: bool = False
    consent_done: bool = False
    federated_sub: str | None = None
    federated_issuer: str | None = None


@dataclass
class AuthCode:
    user_id: str
    client_id: str
    redirect_uri: str
    scopes: list[str]
    nonce: str
    code_challenge: str
    amr: list[str]
    auth_time: int
    exp: float
    used: bool = False
    federated_sub: str | None = None
    federated_issuer: str | None = None


class ProviderState:
    def __init__(self, config: ProviderConfig):
        self.config = config
        self.private_key, self.jwks = generate_rsa(config.kid)
        self.seed_users = {email: dict(user) for email, user in config.users.items()}
        self.users = {email: dict(user) for email, user in self.seed_users.items()}
        self.transactions: dict[str, AuthTransaction] = {}
        self.codes: dict[str, AuthCode] = {}
        self.sessions: dict[str, dict] = {}
        self.consents: set[tuple[str, str, str]] = set()
        self.challenges: dict[str, dict] = {}
        self.credentials: dict[str, dict] = {}
        self.federation: dict[str, dict] = {}
        self.enterprise_jwks: dict | None = None

    def reset(self) -> None:
        self.users = {email: dict(user) for email, user in self.seed_users.items()}
        self.transactions.clear()
        self.codes.clear()
        self.sessions.clear()
        self.consents.clear()
        self.challenges.clear()
        self.credentials.clear()
        self.federation.clear()
        self.enterprise_jwks = None


class OIDCProvider:
    def __init__(self, config: ProviderConfig):
        self.config = config
        self.state = ProviderState(config)
        self.app = FastAPI(title=config.label, docs_url=None, redoc_url=None)
        self.templates = Jinja2Templates(directory=str(PACKAGE / "templates"))
        self.app.mount("/static", StaticFiles(directory=str(PACKAGE / "static")), name="static")
        self._routes()

    def _routes(self) -> None:
        app = self.app

        @app.get("/favicon.ico", include_in_schema=False)
        def favicon() -> Response:
            return Response(status_code=204)

        @app.get("/health")
        def health() -> dict:
            return {"status": "ok", "label": self.config.label}

        @app.get("/.well-known/openid-configuration")
        def discovery() -> dict:
            issuer = self.config.issuer
            return {
                "issuer": issuer,
                "authorization_endpoint": f"{issuer}/authorize",
                "token_endpoint": f"{issuer}/token",
                "userinfo_endpoint": f"{issuer}/userinfo",
                "jwks_uri": f"{issuer}/.well-known/jwks.json",
                "end_session_endpoint": f"{issuer}/logout",
                "response_types_supported": ["code"],
                "grant_types_supported": ["authorization_code"],
                "subject_types_supported": ["public"],
                "id_token_signing_alg_values_supported": ["RS256"],
                "code_challenge_methods_supported": ["S256"],
                "scopes_supported": self.config.scopes,
                "token_endpoint_auth_methods_supported": ["none"],
                "claims_supported": [
                    "sub",
                    "iss",
                    "aud",
                    "exp",
                    "iat",
                    "nonce",
                    "name",
                    "email",
                    "amr",
                ],
                "provider_label": self.config.label,
            }

        @app.get("/.well-known/jwks.json")
        @app.get("/jwks")
        def jwks() -> dict:
            return self.state.jwks

        @app.get("/authorize")
        def authorize(
            request: Request,
            response_type: str = "",
            client_id: str = "",
            redirect_uri: str = "",
            scope: str = "",
            state: str = "",
            nonce: str = "",
            code_challenge: str = "",
            code_challenge_method: str = "",
            prompt: str = "",
            connection: str = "",
        ):
            client = self.config.clients.get(client_id)
            if client is None:
                return _json_error("invalid_client", "Unknown client_id.")
            if redirect_uri not in client.redirect_uris:
                return _json_error(
                    "invalid_request",
                    "redirect_uri is not registered for this client.",
                )
            if response_type != "code":
                return self._redirect_error(
                    redirect_uri,
                    state,
                    "unsupported_response_type",
                    "Only response_type=code is supported.",
                )
            if code_challenge_method != "S256" or not code_challenge:
                return self._redirect_error(
                    redirect_uri,
                    state,
                    "invalid_request",
                    "PKCE with code_challenge_method=S256 is required.",
                )
            scopes = [part for part in scope.split() if part]
            if "openid" not in scopes:
                return self._redirect_error(
                    redirect_uri,
                    state,
                    "invalid_scope",
                    "The openid scope is required.",
                )
            unknown = [part for part in scopes if part not in self.config.scopes]
            if unknown:
                return self._redirect_error(
                    redirect_uri,
                    state,
                    "invalid_scope",
                    "Unsupported scope: " + " ".join(unknown),
                )
            if not state or not nonce:
                return self._redirect_error(
                    redirect_uri,
                    state,
                    "invalid_request",
                    "state and nonce are required.",
                )
            request_id = secrets.token_urlsafe(18)
            transaction = AuthTransaction(
                request_id=request_id,
                client_id=client_id,
                redirect_uri=redirect_uri,
                scopes=scopes,
                state=state,
                nonce=nonce,
                code_challenge=code_challenge,
                prompt=prompt,
                created=time.time(),
            )
            self.state.transactions[request_id] = transaction
            if connection == "enterprise":
                if not self.config.federation:
                    return self._redirect_error(
                        redirect_uri,
                        state,
                        "invalid_request",
                        "This provider has no enterprise connection.",
                    )
                return self._begin_federation(transaction)
            session = self._session(request)
            if session:
                self._attach_session(transaction, session)
                return self._continue(transaction)
            return RedirectResponse(f"{self.config.issuer}/login?request_id={request_id}", status_code=302)

        @app.get("/login")
        def login_form(request: Request, request_id: str = "", error: str = ""):
            return self._login_page(request, request_id, error or None)

        @app.post("/login")
        def login_submit(
            request: Request,
            email: str = Form(""),
            password: str = Form(""),
            request_id: str = Form(""),
        ):
            user = self.state.users.get(email.strip())
            if not _password_ok(None if user is None else user.get("password"), password):
                return self._login_page(
                    request,
                    request_id,
                    "Unknown user or password.",
                    status_code=401,
                )
            assert user is not None
            auth_time = int(time.time())
            if not request_id:
                response = RedirectResponse(f"{self.config.issuer}/security", status_code=302)
                self._set_session(response, user["id"], ["pwd"], auth_time)
                return response
            transaction = self.state.transactions.get(request_id)
            if transaction is None:
                return _json_error("invalid_request", "Unknown or expired login request.")
            transaction.authenticated = True
            transaction.user_id = user["id"]
            transaction.amr = ["pwd"]
            transaction.auth_time = auth_time
            response = RedirectResponse(self._continue_target(transaction), status_code=302)
            self._set_session(response, user["id"], ["pwd"], auth_time)
            return response

        @app.get("/login/enterprise")
        def login_enterprise(request_id: str = ""):
            transaction = self.state.transactions.get(request_id)
            if transaction is None or not self.config.federation:
                return _json_error("invalid_request", "Enterprise sign-in needs an active request.")
            return self._begin_federation(transaction)

        @app.get("/federation/callback")
        def federation_callback(
            code: str = "",
            state: str = "",
            error: str = "",
            error_description: str = "",
        ):
            if error:
                return _json_error(error, error_description or "The enterprise provider returned an error.")
            fed = self.state.federation.pop(state, None)
            if fed is None:
                return _json_error("state_mismatch", "Enterprise callback state does not match this login.")
            transaction = self.state.transactions.get(fed["request_id"])
            if transaction is None:
                return _json_error("invalid_request", "The original sign-in request expired.")
            oauth = OAuth2Client(
                client_id=self.config.broker_client_id,
                redirect_uri=fed["redirect_uri"],
                token_endpoint_auth_method="none",
                code_challenge_method="S256",
            )
            try:
                token = oauth.fetch_token(
                    f"{self.config.enterprise_issuer}/token",
                    code=code,
                    grant_type="authorization_code",
                    code_verifier=fed["verifier"],
                    redirect_uri=fed["redirect_uri"],
                )
            except Exception as exc:
                return _json_error("federation_failed", f"Enterprise token exchange failed: {exc}")
            finally:
                oauth.close()
            try:
                claims, _checks = self._enterprise_validator().validate_id_token(
                    token["id_token"],
                    audience=self.config.broker_client_id,
                    nonce=fed["nonce"],
                    client_id=self.config.broker_client_id,
                )
            except TokenValidationError as exc:
                return JSONResponse(exc.as_dict(), status_code=400)
            user = self._link_federated_user(claims)
            auth_time = int(time.time())
            transaction.authenticated = True
            transaction.user_id = user["id"]
            transaction.amr = ["fed"]
            transaction.auth_time = auth_time
            transaction.federated_sub = str(claims.get("sub"))
            transaction.federated_issuer = str(claims.get("iss"))
            response = RedirectResponse(self._continue_target(transaction), status_code=302)
            self._set_session(
                response,
                user["id"],
                ["fed"],
                auth_time,
                {
                    "federated_sub": transaction.federated_sub,
                    "federated_issuer": transaction.federated_issuer,
                },
            )
            return response

        @app.get("/consent")
        def consent_form(request: Request, request_id: str = ""):
            transaction = self._ready_transaction(request_id)
            if isinstance(transaction, JSONResponse):
                return transaction
            return self._consent_page(request, transaction)

        @app.post("/consent")
        def consent_submit(request_id: str = Form(""), decision: str = Form("")):
            transaction = self._ready_transaction(request_id)
            if isinstance(transaction, JSONResponse):
                return transaction
            if decision != "allow":
                return self._redirect_error(
                    transaction.redirect_uri,
                    transaction.state,
                    "access_denied",
                    "The user denied the requested scopes.",
                )
            transaction.consent_done = True
            if transaction.user_id:
                self.state.consents.add(self._consent_key(transaction))
            return RedirectResponse(self._code_redirect(transaction), status_code=302)

        @app.post("/token")
        def token(
            grant_type: str = Form(""),
            code: str = Form(""),
            redirect_uri: str = Form(""),
            client_id: str = Form(""),
            code_verifier: str = Form(""),
        ):
            if grant_type != "authorization_code":
                return _json_error("unsupported_grant_type", "Only authorization_code is supported.")
            record = self.state.codes.get(code)
            if record is None:
                return _json_error("invalid_grant", "Unknown authorization code.")
            if record.used:
                return _json_error("invalid_grant", "Authorization code has already been used.")
            if record.exp < time.time():
                return _json_error("invalid_grant", "Authorization code is expired.")
            if record.client_id != client_id or record.redirect_uri != redirect_uri:
                return _json_error(
                    "invalid_grant",
                    "redirect_uri does not match the authorization request.",
                )
            if not code_verifier or not compare_s256_code_challenge(code_verifier, record.code_challenge):
                return _json_error(
                    "invalid_grant",
                    "PKCE verification failed. The code_verifier does not match the code_challenge.",
                )
            record.used = True
            user = self._user_by_id(record.user_id)
            if user is None:
                return _json_error("invalid_grant", "The user for this code no longer exists.")
            extra = {}
            if record.federated_sub:
                extra["federated_sub"] = record.federated_sub
                extra["federated_issuer"] = record.federated_issuer
            id_token, access_token = issue_tokens(
                private_key=self.state.private_key,
                kid=self.config.kid,
                issuer=self.config.issuer,
                subject=user["id"],
                client_id=record.client_id,
                audience=self.config.audience,
                nonce=record.nonce,
                scopes=record.scopes,
                name=user["name"],
                email=user["email"],
                amr=record.amr,
                auth_time=record.auth_time,
                lifetime=TOKEN_TTL,
                lab_idp=self.config.label,
                extra_id_claims=extra or None,
            )
            response = JSONResponse(
                {
                    "access_token": access_token,
                    "id_token": id_token,
                    "token_type": "Bearer",
                    "expires_in": TOKEN_TTL,
                    "scope": " ".join(record.scopes),
                }
            )
            response.headers["cache-control"] = "no-store"
            return response

        @app.get("/userinfo")
        def userinfo(request: Request):
            raw = _bearer(request)
            if not raw:
                return _json_error("invalid_token", "Missing bearer access token.", status=401)
            try:
                claims, _checks = TokenValidator(
                    self.config.issuer,
                    self.state.jwks,
                    self.config.leeway,
                ).validate_access_token(raw, audience=None)
            except TokenValidationError as exc:
                return JSONResponse(exc.as_dict(), status_code=401)
            user = self._user_by_id(str(claims.get("sub")))
            if user is None:
                return _json_error("invalid_token", "Unknown subject.", status=401)
            return {
                "sub": user["id"],
                "name": user["name"],
                "email": user["email"],
                "email_verified": True,
            }

        @app.get("/logout")
        def logout(request: Request, post_logout_redirect_uri: str = ""):
            sid = request.cookies.get(self.config.cookie_name)
            if sid:
                self.state.sessions.pop(sid, None)
            if post_logout_redirect_uri:
                if post_logout_redirect_uri not in self.config.post_logout_uris:
                    return _json_error(
                        "invalid_request",
                        "post_logout_redirect_uri is not registered.",
                    )
                target = post_logout_redirect_uri
            else:
                target = f"{self.config.issuer}/login"
            response = RedirectResponse(target, status_code=302)
            response.delete_cookie(self.config.cookie_name, path="/")
            return response

        @app.get("/security")
        def security(request: Request):
            session = self._session(request)
            if session is None:
                return RedirectResponse(f"{self.config.issuer}/login", status_code=302)
            user = self._user_by_id(session["user_id"])
            creds = [
                record["id_b64"][:16]
                for record in self.state.credentials.values()
                if record["user_id"] == session["user_id"]
            ]
            return self.templates.TemplateResponse(
                request,
                "idp_security.html",
                {
                    "title": "Passkeys",
                    "label": self.config.label,
                    "email": None if user is None else user["email"],
                    "credentials": creds,
                    "webauthn": self.config.webauthn,
                },
            )

        @app.post("/webauthn/register/options")
        def register_options(request: Request):
            if not self.config.webauthn:
                return _json_error("invalid_request", "This provider does not offer passkeys.")
            session = self._session(request)
            if session is None:
                return _json_error("login_required", "Sign in before registering a passkey.", status=401)
            user = self._user_by_id(session["user_id"])
            if user is None:
                return _json_error("login_required", "Unknown session user.", status=401)
            exclude = [
                PublicKeyCredentialDescriptor(id=record["id"])
                for record in self.state.credentials.values()
                if record["user_id"] == user["id"]
            ]
            options = generate_registration_options(
                rp_id=self.config.rp_id,
                rp_name=self.config.label,
                user_name=user["email"],
                user_display_name=user["name"],
                user_id=user["id"].encode("utf-8"),
                authenticator_selection=AuthenticatorSelectionCriteria(
                    resident_key=ResidentKeyRequirement.PREFERRED,
                    user_verification=UserVerificationRequirement.REQUIRED,
                ),
                exclude_credentials=exclude or None,
            )
            challenge_id = secrets.token_urlsafe(18)
            self.state.challenges[challenge_id] = {
                "challenge": options.challenge,
                "user_id": user["id"],
                "kind": "registration",
                "exp": time.time() + CHALLENGE_TTL,
            }
            return {"challenge_id": challenge_id, "publicKey": options_to_json_dict(options)}

        @app.post("/webauthn/register/verify")
        async def register_verify(request: Request):
            if not self.config.webauthn:
                return _json_error("invalid_request", "This provider does not offer passkeys.")
            body = await request.json()
            credential = body.get("credential") or {}
            response_body = credential.get("response") or {}
            if "authenticatorData" in response_body and "attestationObject" not in response_body:
                return _json_error(
                    "ceremony_mismatch",
                    "This is an authentication assertion (webauthn.get). "
                    "Registration needs an attestation from webauthn.create.",
                )
            challenge = self._take_challenge(str(body.get("challenge_id") or ""), "registration")
            if isinstance(challenge, JSONResponse):
                return challenge
            try:
                verified = verify_registration_response(
                    credential=credential,
                    expected_challenge=challenge["challenge"],
                    expected_rp_id=self.config.rp_id,
                    expected_origin=self.config.origin,
                    require_user_verification=True,
                )
            except InvalidRegistrationResponse as exc:
                return _webauthn_error(exc, "registration")
            encoded_id = bytes_to_base64url(verified.credential_id)
            self.state.credentials[encoded_id] = {
                "id": verified.credential_id,
                "id_b64": encoded_id,
                "public_key": verified.credential_public_key,
                "sign_count": verified.sign_count,
                "user_id": challenge["user_id"],
            }
            return {
                "ok": True,
                "credential_id": encoded_id,
                "sign_count": verified.sign_count,
                "fmt": "none",
            }

        @app.post("/webauthn/authenticate/options")
        async def authenticate_options(request: Request):
            if not self.config.webauthn:
                return _json_error("invalid_request", "This provider does not offer passkeys.")
            body = await request.json()
            email = str(body.get("email") or "").strip()
            user = self.state.users.get(email)
            if user is None:
                return _json_error("unknown_user", "Unknown user.", status=404)
            creds = [record for record in self.state.credentials.values() if record["user_id"] == user["id"]]
            if not creds:
                return _json_error(
                    "no_passkey",
                    "No passkey is registered for this user. "
                    "Registration and authentication are different ceremonies.",
                )
            options = generate_authentication_options(
                rp_id=self.config.rp_id,
                allow_credentials=[PublicKeyCredentialDescriptor(id=record["id"]) for record in creds],
                user_verification=UserVerificationRequirement.REQUIRED,
            )
            challenge_id = secrets.token_urlsafe(18)
            self.state.challenges[challenge_id] = {
                "challenge": options.challenge,
                "user_id": user["id"],
                "kind": "authentication",
                "exp": time.time() + CHALLENGE_TTL,
            }
            return {
                "challenge_id": challenge_id,
                "request_id": body.get("request_id") or "",
                "publicKey": options_to_json_dict(options),
            }

        @app.post("/webauthn/authenticate/verify")
        async def authenticate_verify(request: Request):
            if not self.config.webauthn:
                return _json_error("invalid_request", "This provider does not offer passkeys.")
            body = await request.json()
            credential = body.get("credential") or {}
            response_body = credential.get("response") or {}
            if "attestationObject" in response_body and "signature" not in response_body:
                return _json_error(
                    "ceremony_mismatch",
                    "This is a registration attestation (webauthn.create). "
                    "Authentication needs an assertion from webauthn.get.",
                )
            challenge = self._take_challenge(str(body.get("challenge_id") or ""), "authentication")
            if isinstance(challenge, JSONResponse):
                return challenge
            encoded_id = str(credential.get("id") or "")
            record = self.state.credentials.get(encoded_id)
            if record is None or record["user_id"] != challenge["user_id"]:
                return _json_error(
                    "unknown_credential",
                    "No passkey is registered with that credential id. "
                    "Register a passkey before authentication. The two ceremonies are not interchangeable.",
                )
            try:
                verified = verify_authentication_response(
                    credential=credential,
                    expected_challenge=challenge["challenge"],
                    expected_rp_id=self.config.rp_id,
                    expected_origin=self.config.origin,
                    credential_public_key=record["public_key"],
                    credential_current_sign_count=record["sign_count"],
                    require_user_verification=True,
                )
            except InvalidAuthenticationResponse as exc:
                return _webauthn_error(exc, "authentication")
            record["sign_count"] = verified.new_sign_count
            user = self._user_by_id(record["user_id"])
            if user is None:
                return _json_error("unknown_user", "Unknown user.", status=404)
            auth_time = int(time.time())
            request_id = str(body.get("request_id") or "")
            transaction = self.state.transactions.get(request_id) if request_id else None
            if transaction is not None:
                transaction.authenticated = True
                transaction.user_id = user["id"]
                transaction.amr = ["webauthn"]
                transaction.auth_time = auth_time
                next_url = self._continue_target(transaction)
            else:
                next_url = f"{self.config.issuer}/security"
            response = JSONResponse(
                {
                    "ok": True,
                    "next_url": next_url,
                    "amr": ["webauthn"],
                    "sign_count": verified.new_sign_count,
                }
            )
            self._set_session(response, user["id"], ["webauthn"], auth_time)
            return response

    def _login_page(self, request: Request, request_id: str, error: str | None, status_code: int = 200):
        return self.templates.TemplateResponse(
            request,
            "idp_login.html",
            {
                "title": "Sign in",
                "label": self.config.label,
                "request_id": request_id,
                "error": error,
                "show_passkey": self.config.webauthn,
                "show_enterprise": self.config.federation and bool(request_id),
                "hints": self.config.hints,
            },
            status_code=status_code,
        )

    def _consent_page(self, request: Request, transaction: AuthTransaction):
        user = self._user_by_id(transaction.user_id or "")
        client = self.config.clients[transaction.client_id]
        scopes = [{"name": scope, "description": SCOPE_COPY.get(scope, scope)} for scope in transaction.scopes]
        return self.templates.TemplateResponse(
            request,
            "idp_consent.html",
            {
                "title": "Consent",
                "label": self.config.label,
                "request_id": transaction.request_id,
                "client_name": client.name,
                "email": None if user is None else user["email"],
                "scopes": scopes,
            },
        )

    def _ready_transaction(self, request_id: str) -> AuthTransaction | JSONResponse:
        transaction = self.state.transactions.get(request_id)
        if transaction is None or not transaction.authenticated or not transaction.user_id:
            return _json_error("invalid_request", "Sign in before granting consent.")
        return transaction

    def _attach_session(self, transaction: AuthTransaction, session: dict) -> None:
        transaction.authenticated = True
        transaction.user_id = session["user_id"]
        transaction.amr = list(session.get("amr") or ["pwd"])
        transaction.auth_time = int(session.get("auth_time") or time.time())
        transaction.federated_sub = session.get("federated_sub")
        transaction.federated_issuer = session.get("federated_issuer")

    def _needs_consent(self, transaction: AuthTransaction) -> bool:
        if not self.config.consent or transaction.consent_done:
            return False
        if transaction.prompt == "consent":
            return True
        if transaction.user_id is None:
            return True
        return self._consent_key(transaction) not in self.state.consents

    def _consent_key(self, transaction: AuthTransaction) -> tuple[str, str, str]:
        return (transaction.user_id or "", transaction.client_id, " ".join(transaction.scopes))

    def _continue_target(self, transaction: AuthTransaction) -> str:
        if self._needs_consent(transaction):
            return f"{self.config.issuer}/consent?request_id={transaction.request_id}"
        return self._code_redirect(transaction)

    def _continue(self, transaction: AuthTransaction) -> RedirectResponse:
        return RedirectResponse(self._continue_target(transaction), status_code=302)

    def _code_redirect(self, transaction: AuthTransaction) -> str:
        code = secrets.token_urlsafe(32)
        self.state.codes[code] = AuthCode(
            user_id=transaction.user_id or "",
            client_id=transaction.client_id,
            redirect_uri=transaction.redirect_uri,
            scopes=list(transaction.scopes),
            nonce=transaction.nonce,
            code_challenge=transaction.code_challenge,
            amr=list(transaction.amr or ["pwd"]),
            auth_time=int(transaction.auth_time or time.time()),
            exp=time.time() + CODE_TTL,
            federated_sub=transaction.federated_sub,
            federated_issuer=transaction.federated_issuer,
        )
        from urllib.parse import urlencode

        return transaction.redirect_uri + "?" + urlencode({"code": code, "state": transaction.state})

    def _redirect_error(self, redirect_uri: str, state: str, error: str, description: str):
        from urllib.parse import urlencode

        query = urlencode({"error": error, "error_description": description, "state": state})
        return RedirectResponse(f"{redirect_uri}?{query}", status_code=302)

    def _begin_federation(self, transaction: AuthTransaction) -> RedirectResponse:
        verifier = secrets.token_urlsafe(48)
        nonce = secrets.token_urlsafe(18)
        redirect_uri = f"{self.config.issuer}/federation/callback"
        oauth = OAuth2Client(
            client_id=self.config.broker_client_id,
            redirect_uri=redirect_uri,
            token_endpoint_auth_method="none",
            code_challenge_method="S256",
            scope="openid profile email",
        )
        try:
            url, upstream_state = oauth.create_authorization_url(
                f"{self.config.enterprise_issuer}/authorize",
                redirect_uri=redirect_uri,
                code_verifier=verifier,
                nonce=nonce,
                scope="openid profile email",
            )
        finally:
            oauth.close()
        self.state.federation[upstream_state] = {
            "request_id": transaction.request_id,
            "verifier": verifier,
            "nonce": nonce,
            "redirect_uri": redirect_uri,
        }
        return RedirectResponse(url, status_code=302)

    def _enterprise_validator(self) -> TokenValidator:
        if self.state.enterprise_jwks is None:
            response = httpx.get(
                f"{self.config.enterprise_issuer}/.well-known/jwks.json",
                timeout=5,
            )
            response.raise_for_status()
            self.state.enterprise_jwks = response.json()
        return TokenValidator(
            issuer=self.config.enterprise_issuer or "",
            jwks=self.state.enterprise_jwks,
            leeway=self.config.leeway,
        )

    def _link_federated_user(self, claims: dict) -> dict:
        email = str(claims.get("email") or "")
        user = self.state.users.get(email)
        if user is None:
            user = {
                "id": "fed_" + str(claims.get("sub")),
                "email": email,
                "name": claims.get("name") or email,
                "password": None,
            }
            self.state.users[email] = user
        return user

    def _session(self, request: Request) -> dict | None:
        sid = request.cookies.get(self.config.cookie_name)
        if not sid:
            return None
        return self.state.sessions.get(sid)

    def _set_session(self, response, user_id: str, amr: list[str], auth_time: int, extra: dict | None = None):
        sid = secrets.token_urlsafe(24)
        record = {"user_id": user_id, "amr": amr, "auth_time": auth_time}
        if extra:
            record.update(extra)
        self.state.sessions[sid] = record
        response.set_cookie(self.config.cookie_name, sid, httponly=True, samesite="lax", path="/")

    def _user_by_id(self, user_id: str) -> dict | None:
        for user in self.state.users.values():
            if user["id"] == user_id:
                return user
        return None

    def _take_challenge(self, challenge_id: str, kind: str) -> dict | JSONResponse:
        challenge = self.state.challenges.pop(challenge_id, None)
        if challenge is None or challenge["kind"] != kind or challenge["exp"] < time.time():
            return _json_error("challenge_mismatch", "The WebAuthn challenge is missing or expired.")
        return challenge


def customer_provider(settings: Settings) -> OIDCProvider:
    client = Client(
        client_id=settings.client_id,
        name=settings.app_name,
        redirect_uris=[settings.redirect_uri],
    )
    from ciam_lab.catalog import CUSTOMER_USERS, users_by_email

    config = ProviderConfig(
        label="MOCK:local-idp",
        issuer=settings.customer_issuer,
        kid="mock-local-1",
        cookie_name="local_idp_session",
        clients={client.client_id: client},
        users=users_by_email(CUSTOMER_USERS),
        scopes=list(CUSTOMER_SCOPES),
        audience=settings.audience,
        leeway=settings.leeway_seconds,
        webauthn=True,
        consent=True,
        federation=True,
        rp_id=settings.rp_id,
        origin=settings.customer_issuer,
        hints=[
            ("alice@example.com", "correct-horse"),
            ("bob@example.com", "river-stone"),
        ],
        post_logout_uris=[settings.post_logout_redirect_uri],
        enterprise_issuer=settings.enterprise_issuer,
        broker_client_id=BROKER_CLIENT_ID,
    )
    return OIDCProvider(config)


def enterprise_provider(settings: Settings) -> OIDCProvider:
    client = Client(
        client_id=BROKER_CLIENT_ID,
        name="MOCK:local-idp broker",
        redirect_uris=[settings.customer_issuer + "/federation/callback"],
    )
    from ciam_lab.catalog import ENTERPRISE_USERS, users_by_email

    config = ProviderConfig(
        label="MOCK:enterprise-idp",
        issuer=settings.enterprise_issuer,
        kid="mock-enterprise-1",
        cookie_name="enterprise_idp_session",
        clients={client.client_id: client},
        users=users_by_email(ENTERPRISE_USERS),
        scopes=list(ENTERPRISE_SCOPES),
        audience=settings.customer_issuer,
        leeway=settings.leeway_seconds,
        webauthn=False,
        consent=False,
        federation=False,
        rp_id=settings.rp_id,
        origin=settings.enterprise_issuer,
        hints=[("sam@enterprise.example", "warehouse-key")],
        post_logout_uris=[],
    )
    return OIDCProvider(config)


def _password_ok(stored, given: str) -> bool:
    if not isinstance(stored, str) or not isinstance(given, str):
        return False
    if len(stored) != len(given):
        return False
    return secrets.compare_digest(stored, given)


def _bearer(request: Request) -> str | None:
    header = request.headers.get("authorization", "")
    if not header.lower().startswith("bearer "):
        return None
    token = header.split(" ", 1)[1].strip()
    return token or None


def _json_error(error: str, description: str, status: int = 400) -> JSONResponse:
    return JSONResponse({"error": error, "error_description": description}, status_code=status)


def _webauthn_error(exc: Exception, ceremony: str) -> JSONResponse:
    text = str(exc)
    lowered = text.lower()
    if "origin" in lowered:
        code = "origin_mismatch"
    elif "sign count" in lowered:
        code = "sign_count"
    elif "challenge" in lowered:
        code = "challenge_mismatch"
    else:
        code = f"{ceremony}_failed"
    return _json_error(code, text)
