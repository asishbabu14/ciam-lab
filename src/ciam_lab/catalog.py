"""Synthetic people, orders, and scope copy for the lab.

Nothing here is a real customer. Passwords exist only so the mock identity
provider can demonstrate a login form.
"""

from __future__ import annotations

import copy

CUSTOMER_SCOPES = ["openid", "profile", "email", "orders:read", "orders:write"]
ENTERPRISE_SCOPES = ["openid", "profile", "email"]

SCOPE_COPY = {
    "openid": "Sign you in and issue an ID token to the storefront.",
    "profile": "Read your display name.",
    "email": "Read your email address.",
    "orders:read": "Read orders on your Fieldnote Supply account.",
    "orders:write": "Add an order to your Fieldnote Supply account.",
}

DEFAULT_SCOPE = "openid profile email orders:read orders:write"
API_AUDIENCE = "https://api.fieldnote.lab"
APP_CLIENT_ID = "ciam-lab"
BROKER_CLIENT_ID = "local-idp-broker"
APP_NAME = "Fieldnote Supply"

CUSTOMER_USERS = [
    {
        "id": "user_alice",
        "email": "alice@example.com",
        "name": "Alice Nguyen",
        "password": "correct-horse",
    },
    {
        "id": "user_bob",
        "email": "bob@example.com",
        "name": "Bob Patel",
        "password": "river-stone",
    },
    {
        "id": "user_sam",
        "email": "sam@enterprise.example",
        "name": "Sam Okonkwo",
        "password": None,
    },
]

ENTERPRISE_USERS = [
    {
        "id": "emp_sam",
        "email": "sam@enterprise.example",
        "name": "Sam Okonkwo",
        "password": "warehouse-key",
    },
]

ORDERS = {
    "user_alice": [
        {"id": "1001", "item": "Field journal", "total": "18.00"},
        {"id": "1002", "item": "Cedar pencil set", "total": "12.00"},
    ],
    "user_bob": [
        {"id": "1003", "item": "Linen tote", "total": "24.00"},
    ],
    "user_sam": [
        {"id": "2001", "item": "Staff field notebook", "total": "9.00"},
    ],
}


def users_by_email(records: list[dict]) -> dict[str, dict]:
    return {record["email"]: copy.deepcopy(record) for record in records}


def fresh_orders() -> dict[str, list[dict]]:
    return copy.deepcopy(ORDERS)
