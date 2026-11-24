"""Readable local walkthrough: login, tokens, a passkey, federation, and one failure."""

from __future__ import annotations

import os
import sys
import time

import httpx

from ciam_lab.config import demo_settings
from ciam_lab.runtime import port_is_free, start_lab, stop_lab
from ciam_lab.soft_authenticator import SoftAuthenticator
from ciam_lab.walk import Walker

PACE = float(os.environ.get("DEMO_PACE_SECONDS", "0.72"))


def emit(text: str = "", hold: float = 1.0) -> None:
    print(text, flush=True)
    if PACE > 0 and hold > 0:
        time.sleep(PACE * hold)


def run() -> int:
    settings = demo_settings()
    for port, name in (
        (settings.app_port, "storefront"),
        (settings.customer_port, "customer identity provider"),
        (settings.enterprise_port, "enterprise identity provider"),
    ):
        if not port_is_free(settings.bind_host, port):
            emit(f"{name} port {port} is already in use. Stop that process and run make demo again.")
            return 1

    lab = start_lab(settings)
    try:
        with httpx.Client(timeout=10) as client:
            walker = Walker(client, lab)
            _script(walker)
    except Exception as exc:
        emit("")
        emit(f"demo failed: {exc}")
        return 1
    finally:
        stop_lab(lab)
    return 0


def _script(walker: Walker) -> None:
    settings = walker.settings
    emit("ciam-lab demo")
    emit("personal lab, synthetic users, local mocks only", hold=1.4)
    emit("")
    emit("[1] discovery", hold=1.3)
    customer = httpx.get(settings.customer_issuer + "/.well-known/openid-configuration", timeout=5).json()
    enterprise = httpx.get(settings.enterprise_issuer + "/.well-known/openid-configuration", timeout=5).json()
    emit(f"    storefront      {settings.app_base}")
    emit(f"    customer idp    {customer['issuer']}   {customer['provider_label']}")
    emit(f"    enterprise idp  {enterprise['issuer']}   {enterprise['provider_label']}")
    emit("    signing         RS256 via each provider JWKS", hold=1.5)
    emit("")
    emit("[2] authorization code + PKCE", hold=1.3)
    emit("    user            alice@example.com (synthetic)")
    session = walker.login_password("alice@example.com", "correct-horse")
    emit("    pkce            S256 code_challenge, verifier checked at the token endpoint")
    emit("    state           matched the value stored before the redirect")
    emit("    consent         allow openid profile email orders:read orders:write")
    _print_token("id token", session["id_token_claims"], ("iss", "aud", "sub", "nonce", "amr", "exp"))
    for check in session["id_checks"]:
        if check["name"] in {"signature", "issuer", "audience", "expiry", "nonce"}:
            emit(f"    check           {check['name']}: ok")
    _print_token("access token", session["access_token_claims"], ("aud", "scope", "token_use", "sub"))
    orders = walker.api("GET", "/api/orders", token=session["access_token"])
    emit(f"    GET /api/orders {orders.status_code}")
    for order in orders.json()["orders"]:
        emit(f"                    {order['id']}  {order['item']}  {order['total']}")
    emit("")
    emit("[3] passkey registration and sign-in", hold=1.3)
    authenticator = SoftAuthenticator()
    registered = walker.register_passkey(authenticator)
    emit("    ceremony        webauthn.create with the soft authenticator")
    emit(f"    attestation     fmt none, sign count {registered['sign_count']}")
    emit("    stored          public key and credential id on MOCK:local-idp")
    walker.logout()
    emit("    signed out")
    passkey = walker.login_passkey(authenticator, "alice@example.com")
    emit("    ceremony        webauthn.get, signature verified, sign count increased")
    emit(f"    amr             {' '.join(passkey['amr'])}")
    emit("    result          OIDC tokens issued after the passkey login", hold=1.4)
    emit("")
    emit("[4] enterprise federation", hold=1.3)
    walker.logout()
    federated = walker.login_enterprise("sam@enterprise.example", "warehouse-key")
    emit("    connection      enterprise-oidc")
    emit("    upstream        MOCK:enterprise-idp")
    emit("    user            sam@enterprise.example (synthetic employee)")
    emit(f"    customer sub    {federated['user']['sub']}")
    emit(f"    federated sub   {federated['id_token_claims'].get('federated_sub')}")
    emit(f"    amr             {' '.join(federated['amr'])}")
    staff = walker.api("GET", "/api/orders", token=federated["access_token"])
    item = staff.json()["orders"][0]
    emit(f"    GET /api/orders {staff.status_code}  {item['item']}", hold=1.4)
    emit("")
    emit("[5] deliberate failure, then the fix", hold=1.3)
    emit("    mistake         call GET /api/orders with the ID token")
    failed = walker.api("GET", "/api/orders", token=federated["id_token"])
    body = failed.json()
    emit(f"    result          HTTP {failed.status_code}  {body['error']}")
    _wrap("    why             ", body["error_description"])
    _wrap("    fix             ", body["fix"])
    healed = walker.api("GET", "/api/orders", token=federated["access_token"])
    emit(f"    retry           HTTP {healed.status_code} with the access token", hold=1.6)
    emit("")
    emit("demo complete")
    if failed.status_code != 401 or healed.status_code != 200:
        raise RuntimeError("the deliberate failure did not behave as expected")


def _print_token(title: str, claims: dict, fields: tuple[str, ...]) -> None:
    emit(f"    {title}")
    for name in fields:
        value = claims.get(name)
        if isinstance(value, list):
            value = " ".join(str(part) for part in value)
        emit(f"                    {name}={value}")


def _wrap(prefix: str, text: str, width: int = 78) -> None:
    words = text.split()
    if not words:
        emit(prefix.rstrip())
        return
    line = prefix + words[0]
    spacer = " " * len(prefix)
    for word in words[1:]:
        candidate = f"{line} {word}"
        if len(candidate) > width:
            emit(line)
            line = spacer + word
        else:
            line = candidate
    emit(line)


def main() -> None:
    sys.exit(run())


if __name__ == "__main__":
    main()
