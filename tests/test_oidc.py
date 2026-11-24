from authlib.oauth2.rfc7636 import create_s256_code_challenge


def test_discovery_names_the_mock(walker):
    response = walker.client.get(walker.customer + "/.well-known/openid-configuration")
    body = response.json()
    assert response.status_code == 200
    assert body["provider_label"] == "MOCK:local-idp"
    assert body["issuer"] == walker.customer
    assert body["code_challenge_methods_supported"] == ["S256"]
    assert "orders:read" in body["scopes_supported"]
    jwks = walker.client.get(body["jwks_uri"])
    assert jwks.json()["keys"][0]["alg"] == "RS256"


def test_password_login_pkce_and_userinfo(walker):
    session = walker.login_password("alice@example.com", "correct-horse")
    assert session["user"]["email"] == "alice@example.com"
    assert session["amr"] == ["pwd"]
    assert "orders:read" in session["scope"]
    assert session["id_token_claims"]["aud"] == "ciam-lab"
    assert session["access_token_claims"]["aud"] == "https://api.fieldnote.lab"
    assert session["access_token_claims"]["token_use"] == "access"
    assert any(check["name"] == "signature" and check["ok"] for check in session["id_checks"])
    info = walker.client.get(
        walker.customer + "/userinfo",
        headers={"authorization": f"Bearer {session['access_token']}"},
    )
    assert info.status_code == 200
    assert info.json()["sub"] == "user_alice"


def test_logout_clears_the_session(walker):
    walker.login_password("alice@example.com", "correct-horse")
    walker.logout()
    response = walker.client.get(walker.app + "/session")
    assert response.status_code == 401
    assert response.json()["authenticated"] is False


def test_wrong_password_is_rejected(walker):
    response = walker.client.post(
        walker.customer + "/login",
        data={"email": "alice@example.com", "password": "not-the-password"},
    )
    assert response.status_code == 401
    assert "Unknown user or password" in response.text


def test_pkce_failure_then_success_then_replay(walker):
    issued = walker.fetch_code("alice@example.com", "correct-horse")
    bad = _token(walker, issued, "b" * 50)
    assert bad.status_code == 400
    assert "PKCE" in bad.json()["error_description"]
    good = _token(walker, issued, issued["verifier"])
    assert good.status_code == 200
    assert good.json()["token_type"] == "Bearer"
    replay = _token(walker, issued, issued["verifier"])
    assert replay.status_code == 400
    assert "already been used" in replay.json()["error_description"]


def test_redirect_uri_mismatch_on_authorize(walker):
    challenge = create_s256_code_challenge("a" * 50)
    response = walker.client.get(
        walker.customer + "/authorize",
        params={
            "response_type": "code",
            "client_id": "ciam-lab",
            "redirect_uri": "http://evil.example/callback",
            "scope": "openid",
            "state": "state-1",
            "nonce": "nonce-1",
            "code_challenge": challenge,
            "code_challenge_method": "S256",
        },
    )
    assert response.status_code == 400
    assert response.json()["error"] == "invalid_request"
    assert "redirect_uri" in response.json()["error_description"]


def test_redirect_uri_mismatch_on_token(walker):
    issued = walker.fetch_code("bob@example.com", "river-stone")
    response = _token(walker, issued, issued["verifier"], redirect_uri="http://127.0.0.1:9/callback")
    assert response.status_code == 400
    assert "redirect_uri" in response.json()["error_description"]


def _token(walker, issued: dict, verifier: str, redirect_uri: str | None = None):
    return walker.client.post(
        walker.customer + "/token",
        data={
            "grant_type": "authorization_code",
            "code": issued["code"],
            "redirect_uri": redirect_uri or issued["redirect_uri"],
            "client_id": "ciam-lab",
            "code_verifier": verifier,
        },
    )
