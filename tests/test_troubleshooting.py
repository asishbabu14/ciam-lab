"""Failure cases named by docs/troubleshooting.md."""

import pytest

from ciam_lab.soft_authenticator import SoftAuthenticator
from ciam_lab.walk import WalkError


def test_state_mismatch(walker):
    with pytest.raises(WalkError, match="state_mismatch"):
        walker.login_password(
            "alice@example.com",
            "correct-horse",
            session_patch={"state": "tampered-state"},
        )


def test_nonce_mismatch(walker):
    with pytest.raises(WalkError, match="nonce_mismatch"):
        walker.login_password(
            "alice@example.com",
            "correct-horse",
            session_patch={"nonce": "tampered-nonce"},
        )


def test_id_token_is_rejected_by_the_api(walker):
    session = walker.login_password("alice@example.com", "correct-horse")
    response = walker.api("GET", "/api/orders", token=session["id_token"])
    assert response.status_code == 401
    body = response.json()
    assert body["error"] == "id_token_used_as_access_token"
    fixed = walker.api("GET", "/api/orders", token=session["access_token"])
    assert fixed.status_code == 200


def test_userinfo_rejects_an_id_token(walker):
    session = walker.login_password("alice@example.com", "correct-horse")
    response = walker.client.get(
        walker.customer + "/userinfo",
        headers={"authorization": f"Bearer {session['id_token']}"},
    )
    assert response.status_code == 401
    assert response.json()["error"] == "id_token_used_as_access_token"


def test_passkey_registration_rejects_the_wrong_origin(walker):
    authenticator = SoftAuthenticator()
    walker.login_password("alice@example.com", "correct-horse")
    with pytest.raises(WalkError, match="origin"):
        walker.register_passkey(authenticator, origin="http://evil.example")


def test_passkey_authentication_rejects_an_unknown_credential(walker):
    authenticator = SoftAuthenticator()
    walker.login_password("alice@example.com", "correct-horse")
    walker.register_passkey(authenticator)
    walker.logout()
    start = walker.client.get(walker.app + "/login")
    current = walker.client.get(walker._location(start))
    if current.status_code in (302, 303):
        current = walker.client.get(walker._location(current))
    from webauthn.helpers import base64url_to_bytes

    from ciam_lab.walk import _field

    request_id = _field(current.text, "request_id")
    options = walker.client.post(
        walker.customer + "/webauthn/authenticate/options",
        json={"email": "alice@example.com", "request_id": request_id},
    )
    body = options.json()
    credential = authenticator.authenticate(
        challenge=base64url_to_bytes(body["publicKey"]["challenge"]),
        rp_id=walker.settings.rp_id,
        origin=walker.customer,
    )
    credential["id"] = "not-a-registered-credential"
    credential["rawId"] = "not-a-registered-credential"
    verified = walker.client.post(
        walker.customer + "/webauthn/authenticate/verify",
        json={"challenge_id": body["challenge_id"], "credential": credential, "request_id": request_id},
    )
    assert verified.status_code == 400
    assert verified.json()["error"] == "unknown_credential"


def test_passkey_ceremony_mixup(walker):
    registration = walker.client.post(
        walker.customer + "/webauthn/authenticate/verify",
        json={"challenge_id": "unused", "credential": {"response": {"attestationObject": "abc"}}},
    )
    assert registration.status_code == 400
    assert registration.json()["error"] == "ceremony_mismatch"
    authentication = walker.client.post(
        walker.customer + "/webauthn/register/verify",
        json={"challenge_id": "unused", "credential": {"response": {"authenticatorData": "abc"}}},
    )
    assert authentication.status_code == 400
    assert authentication.json()["error"] == "ceremony_mismatch"
