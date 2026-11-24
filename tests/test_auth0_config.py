import pytest

from ciam_lab.config import Auth0ConfigError, settings_from_env


def test_local_mode_does_not_need_auth0_values():
    settings = settings_from_env({"IDP_MODE": "local"})
    assert settings.local_mode is True
    assert settings.client_id == "ciam-lab"
    assert settings.client_secret is None
    assert settings.customer_issuer.startswith("http://127.0.0.1:")


def test_auth0_mode_requires_the_documented_variables():
    with pytest.raises(Auth0ConfigError, match="AUTH0_DOMAIN"):
        settings_from_env({"IDP_MODE": "auth0"})


def test_auth0_mode_builds_the_issuer_from_the_domain():
    settings = settings_from_env(
        {
            "IDP_MODE": "auth0",
            "AUTH0_DOMAIN": "lab.example.auth0.com",
            "AUTH0_CLIENT_ID": "example-client",
            "AUTH0_CLIENT_SECRET": "example-client-secret",
            "AUTH0_AUDIENCE": "https://api.fieldnote.lab",
            "AUTH0_ENTERPRISE_CONNECTION": "example-enterprise",
        }
    )
    assert settings.customer_issuer == "https://lab.example.auth0.com/"
    assert settings.client_id == "example-client"
    assert settings.audience == "https://api.fieldnote.lab"
    assert settings.auth0_enterprise_connection == "example-enterprise"
    assert settings.local_mode is False
