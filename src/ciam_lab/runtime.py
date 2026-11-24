"""Start and stop the storefront and the local identity providers."""

from __future__ import annotations

import socket
import threading
import time
from dataclasses import dataclass, field

import httpx
import uvicorn

from ciam_lab.app import Storefront, create_storefront
from ciam_lab.config import Settings
from ciam_lab.provider import OIDCProvider, customer_provider, enterprise_provider


class _QuietServer(uvicorn.Server):
    def install_signal_handlers(self) -> None:
        return


@dataclass
class RunningServer:
    server: _QuietServer
    thread: threading.Thread
    port: int


@dataclass
class Lab:
    settings: Settings
    customer: OIDCProvider
    enterprise: OIDCProvider
    store: Storefront
    servers: list[RunningServer] = field(default_factory=list)

    def reset(self) -> None:
        self.customer.state.reset()
        self.enterprise.state.reset()
        self.store.state.reset()


def start_lab(settings: Settings) -> Lab:
    enterprise = enterprise_provider(settings)
    customer = customer_provider(settings)
    store = create_storefront(settings)
    lab = Lab(settings=settings, customer=customer, enterprise=enterprise, store=store)
    if settings.local_mode:
        lab.servers.append(_spawn(enterprise.app, settings.bind_host, settings.enterprise_port))
        lab.servers.append(_spawn(customer.app, settings.bind_host, settings.customer_port))
        _wait(f"{settings.enterprise_issuer}/health")
        _wait(f"{settings.customer_issuer}/health")
    lab.servers.append(_spawn(store.app, settings.bind_host, settings.app_port))
    _wait(f"{settings.app_base}/health")
    return lab


def stop_lab(lab: Lab) -> None:
    for running in lab.servers:
        running.server.should_exit = True
    for running in lab.servers:
        running.thread.join(timeout=5)


def port_is_free(host: str, port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        try:
            sock.bind((host, port))
        except OSError:
            return False
    return True


def _spawn(app, host: str, port: int) -> RunningServer:
    config = uvicorn.Config(app, host=host, port=port, log_level="error", access_log=False)
    server = _QuietServer(config)
    thread = threading.Thread(target=server.run, name=f"ciam-{port}", daemon=True)
    thread.start()
    return RunningServer(server=server, thread=thread, port=port)


def _wait(url: str) -> None:
    deadline = time.time() + 10
    last_error = "server did not become ready"
    while time.time() < deadline:
        try:
            response = httpx.get(url, timeout=0.4)
            if response.status_code == 200:
                return
            last_error = f"HTTP {response.status_code}"
        except Exception as exc:
            last_error = str(exc)
        time.sleep(0.05)
    raise RuntimeError(f"{url} did not become ready: {last_error}")
