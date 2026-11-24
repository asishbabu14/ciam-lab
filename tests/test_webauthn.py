import pytest

from ciam_lab.soft_authenticator import SoftAuthenticator
from ciam_lab.walk import WalkError


def test_passkey_registration_and_oidc_login(walker):
    authenticator = SoftAuthenticator()
    walker.login_password("alice@example.com", "correct-horse")
    registered = walker.register_passkey(authenticator)
    assert registered["ok"] is True
    assert registered["fmt"] == "none"
    walker.logout()
    session = walker.login_passkey(authenticator, "alice@example.com")
    assert session["amr"] == ["webauthn"]
    assert session["user"]["email"] == "alice@example.com"
    orders = walker.api("GET", "/api/orders", token=session["access_token"])
    assert orders.status_code == 200


def test_sign_count_must_increase(walker):
    authenticator = SoftAuthenticator()
    walker.login_password("alice@example.com", "correct-horse")
    walker.register_passkey(authenticator)
    walker.logout()
    walker.login_passkey(authenticator, "alice@example.com")
    authenticator.sign_count = 0
    walker.logout()
    with pytest.raises(WalkError, match="sign count"):
        walker.login_passkey(authenticator, "alice@example.com")
