def test_enterprise_federation_issues_customer_tokens(walker):
    session = walker.login_enterprise("sam@enterprise.example", "warehouse-key")
    assert session["user"]["email"] == "sam@enterprise.example"
    assert session["user"]["sub"] == "user_sam"
    assert session["amr"] == ["fed"]
    assert session["id_token_claims"]["federated_sub"] == "emp_sam"
    assert session["id_token_claims"]["federated_issuer"] == walker.enterprise
    assert session["id_token_claims"]["lab_idp"] == "MOCK:local-idp"
    orders = walker.api("GET", "/api/orders", token=session["access_token"])
    assert orders.status_code == 200
    assert orders.json()["orders"][0]["item"] == "Staff field notebook"


def test_enterprise_password_is_not_a_customer_password(walker):
    response = walker.client.post(
        walker.customer + "/login",
        data={"email": "sam@enterprise.example", "password": "warehouse-key"},
    )
    assert response.status_code == 401
