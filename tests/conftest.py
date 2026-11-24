import socket

import httpx
import pytest

from ciam_lab.catalog import API_AUDIENCE, APP_CLIENT_ID
from ciam_lab.config import Settings
from ciam_lab.runtime import start_lab, stop_lab
from ciam_lab.walk import Walker


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


@pytest.fixture(scope="session")
def lab():
    settings = Settings(
        idp_mode="local",
        bind_host="127.0.0.1",
        public_host="127.0.0.1",
        app_port=_free_port(),
        customer_port=_free_port(),
        enterprise_port=_free_port(),
        session_secret="test-only-session-secret",
        leeway_seconds=10,
        client_id=APP_CLIENT_ID,
        client_secret=None,
        audience=API_AUDIENCE,
    )
    started = start_lab(settings)
    yield started
    stop_lab(started)


@pytest.fixture
def walker(lab):
    lab.reset()
    with httpx.Client(timeout=10) as client:
        yield Walker(client, lab)
