"""RSA signing keys for the mock identity providers."""

from __future__ import annotations

from authlib.jose import JsonWebKey


def generate_rsa(kid: str):
    """Return a private JsonWebKey and a public JWKS document."""
    key = JsonWebKey.generate_key(
        "RSA",
        2048,
        {"kid": kid, "use": "sig", "alg": "RS256"},
        is_private=True,
    )
    public = key.as_dict(is_private=False)
    public["kid"] = kid
    public["use"] = "sig"
    public["alg"] = "RS256"
    return key, {"keys": [public]}
