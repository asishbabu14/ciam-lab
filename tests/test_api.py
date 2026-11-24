def test_orders_api_and_write_scope(walker):
    session = walker.login_password("alice@example.com", "correct-horse")
    created = walker.api(
        "POST",
        "/api/orders",
        token=session["access_token"],
        json_body={"item": "Ink refill", "total": "6.00"},
    )
    assert created.status_code == 200
    listed = walker.api("GET", "/api/orders", token=session["access_token"])
    items = [order["item"] for order in listed.json()["orders"]]
    assert "Ink refill" in items
    assert "Field journal" in items


def test_missing_scope_is_forbidden(walker):
    session = walker.login_password(
        "bob@example.com",
        "river-stone",
        scope="openid profile email",
    )
    response = walker.api("GET", "/api/orders", token=session["access_token"])
    assert response.status_code == 403
    assert response.json()["error"] == "insufficient_scope"


def test_api_without_a_token(walker):
    response = walker.api("GET", "/api/orders")
    assert response.status_code == 401
    assert response.json()["error"] == "malformed"


def test_denied_consent_returns_access_denied(walker):
    page = walker.deny_consent("bob@example.com", "river-stone")
    assert page.status_code == 400
    assert 'data-error="access_denied"' in page.text
