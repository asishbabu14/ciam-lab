import time

import pytest

from ciam_lab.keys import generate_rsa
from ciam_lab.tokens import TokenValidationError, TokenValidator, mint

ISS = "http://mock.local"
AUD = "https://api.fieldnote.lab"
CLIENT = "ciam-lab"


@pytest.fixture
def validator():
    key, jwks = generate_rsa("unit-test")
    return key, TokenValidator(ISS, jwks, leeway=10)


def _access(key, **overrides):
    now = overrides.pop("now", int(time.time()))
    payload = {
        "iss": ISS,
        "sub": "user_alice",
        "aud": AUD,
        "iat": now,
        "nbf": now,
        "exp": now + 300,
        "scope": "openid orders:read",
        "token_use": "access",
        "client_id": CLIENT,
        "auth_time": now,
        "amr": ["pwd"],
    }
    payload.update(overrides)
    return mint(payload, key, "unit-test")


def _identity(key, **overrides):
    now = overrides.pop("now", int(time.time()))
    payload = {
        "iss": ISS,
        "sub": "user_alice",
        "aud": CLIENT,
        "azp": CLIENT,
        "iat": now,
        "nbf": now,
        "exp": now + 300,
        "nonce": "nonce-ok",
        "token_use": "id",
        "name": "Alice Nguyen",
        "email": "alice@example.com",
        "email_verified": True,
        "auth_time": now,
        "amr": ["pwd"],
    }
    payload.update(overrides)
    return mint(payload, key, "unit-test")


def test_access_token_happy_path(validator):
    key, checker = validator
    claims, checks = checker.validate_access_token(_access(key), audience=AUD, required_scope="orders:read")
    assert claims["sub"] == "user_alice"
    assert any(check.name == "authlib" and check.ok for check in checks)


def test_id_token_nonce_must_match(validator):
    key, checker = validator
    token = _identity(key)
    claims, _checks = checker.validate_id_token(token, audience=CLIENT, nonce="nonce-ok")
    assert claims["email"] == "alice@example.com"
    with pytest.raises(TokenValidationError) as caught:
        checker.validate_id_token(token, audience=CLIENT, nonce="other-nonce")
    assert caught.value.code == "nonce_mismatch"


def test_bad_signature(validator):
    key, checker = validator
    token = _access(key)
    broken = token[:-4] + ("aaaa" if not token.endswith("aaaa") else "bbbb")
    with pytest.raises(TokenValidationError) as caught:
        checker.validate_access_token(broken, audience=AUD)
    assert caught.value.code == "bad_signature"


def test_issuer_mismatch(validator):
    key, _checker = validator
    other = TokenValidator("http://other.example", _checker.jwks, leeway=10)
    with pytest.raises(TokenValidationError) as caught:
        other.validate_access_token(_access(key), audience=AUD)
    assert caught.value.code == "issuer_mismatch"


def test_audience_mismatch(validator):
    key, checker = validator
    with pytest.raises(TokenValidationError) as caught:
        checker.validate_access_token(_access(key), audience="https://wrong.example")
    assert caught.value.code == "audience_mismatch"


def test_expired_token(validator):
    key, checker = validator
    now = 1_700_000_000
    token = _access(key, now=now - 120, exp=now - 30, iat=now - 120, nbf=now - 120)
    with pytest.raises(TokenValidationError) as caught:
        checker.validate_access_token(token, audience=AUD, now=now)
    assert caught.value.code == "expired"


def test_clock_skew_within_leeway(validator):
    key, checker = validator
    now = 1_700_000_000
    token = _access(key, now=now, iat=now - 5, nbf=now - 5, exp=now - 5)
    claims, _checks = checker.validate_access_token(token, audience=AUD, now=now)
    assert claims["sub"] == "user_alice"


def test_clock_skew_beyond_leeway(validator):
    key, checker = validator
    now = 1_700_000_000
    token = _access(key, now=now, iat=now + 60, nbf=now - 1, exp=now + 300)
    with pytest.raises(TokenValidationError) as caught:
        checker.validate_access_token(token, audience=AUD, now=now)
    assert caught.value.code == "clock_skew"


def test_id_token_rejected_as_access_token(validator):
    key, checker = validator
    with pytest.raises(TokenValidationError) as caught:
        checker.validate_access_token(_identity(key), audience=AUD)
    assert caught.value.code == "id_token_used_as_access_token"
    assert caught.value.as_dict()["fix"]
