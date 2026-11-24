"""Runtime settings for local mode and Auth0 mode."""

from __future__ import annotations

import os
from dataclasses import dataclass

from ciam_lab.catalog import API_AUDIENCE, APP_CLIENT_ID, APP_NAME

AUTH0_ENV_VARS = (
    "AUTH0_DOMAIN",
    "AUTH0_CLIENT_ID",
    "AUTH0_CLIENT_SECRET",
    "AUTH0_AUDIENCE",
)


class Auth0ConfigError(Exception):
    pass


@dataclass
class Settings:
    idp_mode: str
    bind_host: str
    public_host: str
    app_port: int
    customer_port: int
    enterprise_port: int
    session_secret: str
    leeway_seconds: int
    client_id: str
    client_secret: str | None
    audience: str
    auth0_domain: str | None = None
    auth0_enterprise_connection: str | None = None
    app_name: str = APP_NAME

    @property
    def app_base(self) -> str:
        return f"http://{self.public_host}:{self.app_port}"

    @property
    def customer_issuer(self) -> str:
        if self.idp_mode == "auth0":
            return auth0_issuer(self.auth0_domain or "")
        return f"http://{self.public_host}:{self.customer_port}"

    @property
    def enterprise_issuer(self) -> str:
        return f"http://{self.public_host}:{self.enterprise_port}"

    @property
    def redirect_uri(self) -> str:
        return self.app_base + "/callback"

    @property
    def post_logout_redirect_uri(self) -> str:
        return self.app_base + "/"

    @property
    def rp_id(self) -> str:
        return self.public_host

    @property
    def local_mode(self) -> bool:
        return self.idp_mode == "local"


def auth0_issuer(domain: str) -> str:
    cleaned = domain.strip().rstrip("/")
    if cleaned.startswith("https://"):
        return cleaned + "/"
    return f"https://{cleaned}/"


def settings_from_env(env: dict[str, str] | None = None) -> Settings:
    source = os.environ if env is None else env
    mode = source.get("IDP_MODE", "local").strip().lower()
    if mode not in {"local", "auth0"}:
        raise Auth0ConfigError("IDP_MODE must be local or auth0.")

    auth0_domain = _blank(source.get("AUTH0_DOMAIN"))
    auth0_client_id = _blank(source.get("AUTH0_CLIENT_ID"))
    auth0_client_secret = _blank(source.get("AUTH0_CLIENT_SECRET"))
    auth0_audience = _blank(source.get("AUTH0_AUDIENCE"))
    enterprise_connection = _blank(source.get("AUTH0_ENTERPRISE_CONNECTION"))

    if mode == "auth0":
        missing = [name for name in AUTH0_ENV_VARS if not _blank(source.get(name))]
        if missing:
            joined = ", ".join(missing)
            raise Auth0ConfigError(
                f"Auth0 mode needs {joined}. Follow docs/auth0-setup.md. Do not commit the values."
            )
        client_id = auth0_client_id or ""
        client_secret = auth0_client_secret
        audience = auth0_audience or ""
    else:
        client_id = APP_CLIENT_ID
        client_secret = None
        audience = source.get("API_AUDIENCE", API_AUDIENCE)

    return Settings(
        idp_mode=mode,
        bind_host=source.get("BIND_HOST", "127.0.0.1"),
        public_host=source.get("PUBLIC_HOST", "127.0.0.1"),
        app_port=int(source.get("APP_PORT", "8000")),
        customer_port=int(source.get("IDP_PORT", "9000")),
        enterprise_port=int(source.get("ENTERPRISE_PORT", "9001")),
        session_secret=source.get("SESSION_SECRET", "dev-only-session-secret"),
        leeway_seconds=int(source.get("TOKEN_LEEWAY_SECONDS", "10")),
        client_id=client_id,
        client_secret=client_secret,
        audience=audience,
        auth0_domain=auth0_domain,
        auth0_enterprise_connection=enterprise_connection,
    )


def demo_settings() -> Settings:
    """Local ports for `make demo`. Ignores IDP_MODE so the demo stays offline."""
    return Settings(
        idp_mode="local",
        bind_host=os.environ.get("BIND_HOST", "127.0.0.1"),
        public_host=os.environ.get("PUBLIC_HOST", "127.0.0.1"),
        app_port=int(os.environ.get("APP_PORT", "8000")),
        customer_port=int(os.environ.get("IDP_PORT", "9000")),
        enterprise_port=int(os.environ.get("ENTERPRISE_PORT", "9001")),
        session_secret="demo-only-session-secret",
        leeway_seconds=int(os.environ.get("TOKEN_LEEWAY_SECONDS", "10")),
        client_id=APP_CLIENT_ID,
        client_secret=None,
        audience=os.environ.get("API_AUDIENCE", API_AUDIENCE),
    )


def _blank(value: str | None) -> str | None:
    if value is None:
        return None
    stripped = value.strip()
    return stripped or None
