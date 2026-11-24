"""Fieldnote Supply, the customer-facing storefront and resource server."""

from __future__ import annotations

import secrets
from pathlib import Path
from urllib.parse import urlencode

import httpx
from authlib.integrations.httpx_client import OAuth2Client
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from ciam_lab.catalog import DEFAULT_SCOPE, fresh_orders
from ciam_lab.config import Settings
from ciam_lab.tokens import TokenValidationError, TokenValidator

PACKAGE = Path(__file__).resolve().parent


class AppState:
    def __init__(self, settings: Settings):
        self.settings = settings
        self.sessions: dict[str, dict] = {}
        self.orders = fresh_orders()
        self.metadata: dict | None = None
        self.jwks: dict | None = None
        self.next_order = 3000

    def reset(self) -> None:
        self.sessions.clear()
        self.orders = fresh_orders()
        self.metadata = None
        self.jwks = None
        self.next_order = 3000

    def discovery(self) -> dict:
        if self.metadata is None:
            url = self.settings.customer_issuer.rstrip("/") + "/.well-known/openid-configuration"
            response = httpx.get(url, timeout=5)
            response.raise_for_status()
            self.metadata = response.json()
        return self.metadata

    def validator(self) -> TokenValidator:
        meta = self.discovery()
        if self.jwks is None:
            response = httpx.get(meta["jwks_uri"], timeout=5)
            response.raise_for_status()
            self.jwks = response.json()
        return TokenValidator(meta["issuer"], self.jwks, self.settings.leeway_seconds)


class Storefront:
    def __init__(self, settings: Settings):
        self.settings = settings
        self.state = AppState(settings)
        self.app = FastAPI(title=settings.app_name, docs_url=None, redoc_url=None)
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
            return {
                "status": "ok",
                "service": "fieldnote-supply",
                "idp_mode": self.settings.idp_mode,
            }

        @app.get("/")
        def home(request: Request):
            return self.templates.TemplateResponse(
                request,
                "home.html",
                {"title": self.settings.app_name, "label": "", "mode": self.settings.idp_mode},
            )

        @app.get("/login")
        def login(request: Request, scope: str | None = None, prompt: str = "consent"):
            return self._start(scope or DEFAULT_SCOPE, prompt, {})

        @app.get("/login/enterprise")
        def login_enterprise(request: Request, scope: str | None = None, prompt: str = "consent"):
            if self.settings.idp_mode == "auth0" and not self.settings.auth0_enterprise_connection:
                return self._error(
                    request,
                    "missing_enterprise_connection",
                    "Set AUTH0_ENTERPRISE_CONNECTION to the enterprise connection name, "
                    "or use local mode for the built-in MOCK:enterprise-idp. See docs/auth0-setup.md.",
                )
            connection = (
                self.settings.auth0_enterprise_connection if self.settings.idp_mode == "auth0" else "enterprise"
            )
            return self._start(scope or DEFAULT_SCOPE, prompt, {"connection": connection})

        @app.get("/callback")
        def callback(
            request: Request,
            code: str = "",
            state: str = "",
            error: str = "",
            error_description: str = "",
        ):
            if error:
                return self._error(request, error, error_description or "The identity provider returned an error.")
            pending = self._pending(request)
            if pending is None:
                return self._error(request, "state_mismatch", "No login is in progress for this browser.")
            if state != pending["state"]:
                return self._error(
                    request,
                    "state_mismatch",
                    "The state returned to the redirect URI does not match the state stored for this login.",
                )
            meta = self.state.discovery()
            oauth = OAuth2Client(
                client_id=self.settings.client_id,
                client_secret=self.settings.client_secret,
                redirect_uri=self.settings.redirect_uri,
                token_endpoint_auth_method=("client_secret_post" if self.settings.client_secret else "none"),
                code_challenge_method="S256",
            )
            try:
                token = oauth.fetch_token(
                    meta["token_endpoint"],
                    code=code,
                    grant_type="authorization_code",
                    code_verifier=pending["code_verifier"],
                    redirect_uri=self.settings.redirect_uri,
                )
            except Exception as exc:
                return self._error(request, "token_exchange_failed", f"Token endpoint rejected the code: {exc}")
            finally:
                oauth.close()
            validator = self.state.validator()
            try:
                id_claims, id_checks = validator.validate_id_token(
                    token["id_token"],
                    audience=self.settings.client_id,
                    nonce=pending["nonce"],
                    client_id=self.settings.client_id,
                )
                access_claims, access_checks = validator.validate_access_token(
                    token["access_token"],
                    audience=self.settings.audience,
                )
            except TokenValidationError as exc:
                return self._error(request, exc.code, exc.message)
            sid = request.cookies.get("ciam_session")
            self.state.sessions[sid] = {
                "kind": "user",
                "sub": id_claims["sub"],
                "email": id_claims.get("email"),
                "name": id_claims.get("name"),
                "amr": id_claims.get("amr") or [],
                "scope": access_claims.get("scope") or pending["scope"],
                "nonce": pending["nonce"],
                "id_token": token["id_token"],
                "access_token": token["access_token"],
                "id_claims": id_claims,
                "access_claims": access_claims,
                "id_checks": [check.as_dict() for check in id_checks],
                "access_checks": [check.as_dict() for check in access_checks],
            }
            return RedirectResponse(self.settings.app_base + "/account", status_code=302)

        @app.get("/logout")
        def logout(request: Request):
            sid = request.cookies.get("ciam_session")
            if sid:
                self.state.sessions.pop(sid, None)
            try:
                end_session = self.state.discovery()["end_session_endpoint"]
                query = urlencode(
                    {
                        "post_logout_redirect_uri": self.settings.post_logout_redirect_uri,
                        "client_id": self.settings.client_id,
                    }
                )
                target = f"{end_session}?{query}"
            except Exception:
                target = self.settings.app_base + "/"
            response = RedirectResponse(target, status_code=302)
            response.delete_cookie("ciam_session", path="/")
            return response

        @app.get("/account")
        def account(request: Request):
            try:
                record = self._revalidate(request)
            except TokenValidationError as exc:
                return self._error(request, exc.code, exc.message)
            if record is None:
                return RedirectResponse(self.settings.app_base + "/", status_code=302)
            security = ""
            if self.settings.local_mode:
                security = self.settings.customer_issuer + "/security"
            return self.templates.TemplateResponse(
                request,
                "account.html",
                {
                    "title": "Your account",
                    "label": "",
                    "user": record,
                    "orders": self.state.orders.get(record["sub"], []),
                    "security_url": security,
                },
            )

        @app.get("/session")
        def session(request: Request):
            try:
                record = self._revalidate(request)
            except TokenValidationError as exc:
                return JSONResponse(exc.as_dict(), status_code=401)
            if record is None:
                return JSONResponse({"authenticated": False}, status_code=401)
            return {
                "authenticated": True,
                "user": {
                    "sub": record["sub"],
                    "email": record["email"],
                    "name": record["name"],
                },
                "amr": record["amr"],
                "scope": record["scope"],
                "id_token": record["id_token"],
                "access_token": record["access_token"],
                "id_token_claims": record["id_claims"],
                "access_token_claims": record["access_claims"],
                "id_checks": record["id_checks"],
                "access_checks": record["access_checks"],
            }

        @app.get("/api/orders")
        def list_orders(request: Request):
            try:
                claims, _checks = self._bearer(request, "orders:read")
            except TokenValidationError as exc:
                status = 403 if exc.code == "insufficient_scope" else 401
                return JSONResponse(exc.as_dict(), status_code=status)
            return {"sub": claims["sub"], "orders": self.state.orders.get(claims["sub"], [])}

        @app.post("/api/orders")
        async def create_order(request: Request):
            try:
                claims, _checks = self._bearer(request, "orders:write")
            except TokenValidationError as exc:
                status = 403 if exc.code == "insufficient_scope" else 401
                return JSONResponse(exc.as_dict(), status_code=status)
            body = await request.json()
            item = str(body.get("item") or "").strip()
            total = str(body.get("total") or "").strip()
            if not item or not total or len(item) > 80 or len(total) > 16:
                return JSONResponse(
                    {"error": "invalid_request", "error_description": "item and total are required."},
                    status_code=400,
                )
            order = {"id": str(self.state.next_order), "item": item, "total": total}
            self.state.next_order += 1
            self.state.orders.setdefault(str(claims["sub"]), []).append(order)
            return order

    def _start(self, scope: str, prompt: str, extra: dict) -> RedirectResponse:
        meta = self.state.discovery()
        verifier = secrets.token_urlsafe(48)
        nonce = secrets.token_urlsafe(18)
        oauth = OAuth2Client(
            client_id=self.settings.client_id,
            client_secret=self.settings.client_secret,
            redirect_uri=self.settings.redirect_uri,
            token_endpoint_auth_method="client_secret_post" if self.settings.client_secret else "none",
            code_challenge_method="S256",
            scope=scope,
        )
        try:
            url, state = oauth.create_authorization_url(
                meta["authorization_endpoint"],
                redirect_uri=self.settings.redirect_uri,
                code_verifier=verifier,
                nonce=nonce,
                scope=scope,
                prompt=prompt,
                **extra,
            )
        finally:
            oauth.close()
        sid = secrets.token_urlsafe(24)
        self.state.sessions[sid] = {
            "kind": "pending",
            "state": state,
            "nonce": nonce,
            "code_verifier": verifier,
            "scope": scope,
        }
        response = RedirectResponse(url, status_code=302)
        response.set_cookie("ciam_session", sid, httponly=True, samesite="lax", path="/")
        return response

    def _pending(self, request: Request) -> dict | None:
        sid = request.cookies.get("ciam_session")
        record = self.state.sessions.get(sid) if sid else None
        if not record or record.get("kind") != "pending":
            return None
        return record

    def _user_record(self, request: Request) -> dict | None:
        sid = request.cookies.get("ciam_session")
        record = self.state.sessions.get(sid) if sid else None
        if not record or record.get("kind") != "user":
            return None
        return record

    def _revalidate(self, request: Request) -> dict | None:
        record = self._user_record(request)
        if record is None:
            return None
        validator = self.state.validator()
        id_claims, id_checks = validator.validate_id_token(
            record["id_token"],
            audience=self.settings.client_id,
            nonce=record.get("nonce"),
            client_id=self.settings.client_id,
        )
        access_claims, access_checks = validator.validate_access_token(
            record["access_token"],
            audience=self.settings.audience,
        )
        record["id_claims"] = id_claims
        record["access_claims"] = access_claims
        record["id_checks"] = [check.as_dict() for check in id_checks]
        record["access_checks"] = [check.as_dict() for check in access_checks]
        return record

    def _bearer(self, request: Request, scope: str):
        header = request.headers.get("authorization", "")
        if not header.lower().startswith("bearer "):
            raise TokenValidationError(
                "malformed",
                "Missing Authorization: Bearer access token.",
                [],
            )
        token = header.split(" ", 1)[1].strip()
        if not token:
            raise TokenValidationError("malformed", "The bearer token is empty.", [])
        return self.state.validator().validate_access_token(
            token,
            audience=self.settings.audience,
            required_scope=scope,
        )

    def _error(self, request: Request, code: str, message: str):
        return self.templates.TemplateResponse(
            request,
            "error.html",
            {"title": "Sign-in error", "label": "", "code": code, "message": message},
            status_code=400,
        )


def create_storefront(settings: Settings) -> Storefront:
    return Storefront(settings)
