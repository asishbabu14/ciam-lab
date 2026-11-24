"""HTTP walkthroughs shared by tests and `make demo`."""

from __future__ import annotations

import re
from urllib.parse import parse_qs, urljoin, urlparse

from webauthn.helpers import base64url_to_bytes

from ciam_lab.runtime import Lab
from ciam_lab.soft_authenticator import SoftAuthenticator


class WalkError(Exception):
    def __init__(self, message: str, response=None):
        if response is not None:
            body = response.text[:600].replace("\n", " ")
            message = f"{message} (HTTP {response.status_code} {response.url} {body})"
        super().__init__(message)
        self.response = response


class Walker:
    def __init__(self, client, lab: Lab):
        self.client = client
        self.lab = lab
        self.settings = lab.settings

    @property
    def app(self) -> str:
        return self.settings.app_base

    @property
    def customer(self) -> str:
        return self.settings.customer_issuer

    @property
    def enterprise(self) -> str:
        return self.settings.enterprise_issuer

    def login_password(
        self,
        email: str,
        password: str,
        scope: str | None = None,
        prompt: str = "consent",
        session_patch: dict | None = None,
    ) -> dict:
        start = self.client.get(self._app_url("/login", scope=scope, prompt=prompt))
        self._expect(start, 302)
        if session_patch:
            self._only_app_session().update(session_patch)
        current = self.client.get(self._location(start))
        if current.status_code in (302, 303):
            current = self.client.get(self._location(current))
        if not _is(current, "login"):
            raise WalkError("expected the customer identity provider login form", current)
        posted = self._post_login(self.customer, current, email, password)
        current = self.client.get(self._location(posted))
        current = self.submit_consent(current)
        finished = self.follow(current)
        if finished.status_code != 200 or "/account" not in str(finished.url):
            raise WalkError("password login did not reach the account page", finished)
        return self.session()

    def deny_consent(self, email: str, password: str):
        start = self.client.get(self._app_url("/login"))
        self._expect(start, 302)
        current = self.client.get(self._location(start))
        if current.status_code in (302, 303):
            current = self.client.get(self._location(current))
        posted = self._post_login(self.customer, current, email, password)
        current = self.client.get(self._location(posted))
        denied = self.submit_consent(current, decision="deny")
        return self.follow(denied)

    def fetch_code(self, email: str, password: str, scope: str | None = None) -> dict:
        start = self.client.get(self._app_url("/login", scope=scope))
        self._expect(start, 302)
        current = self.client.get(self._location(start))
        if current.status_code in (302, 303):
            current = self.client.get(self._location(current))
        posted = self._post_login(self.customer, current, email, password)
        current = self.client.get(self._location(posted))
        granted = self.submit_consent(current)
        self._expect(granted, 302)
        location = self._location(granted)
        parsed = urlparse(location)
        query = parse_qs(parsed.query)
        if "code" not in query:
            raise WalkError(f"consent did not return an authorization code: {location}")
        pending = self._only_app_session()
        return {
            "code": query["code"][0],
            "state": query.get("state", [""])[0],
            "verifier": pending["code_verifier"],
            "redirect_uri": self.settings.redirect_uri,
        }

    def register_passkey(self, authenticator: SoftAuthenticator, origin: str | None = None) -> dict:
        options = self.client.post(self.customer + "/webauthn/register/options")
        self._expect(options, 200)
        body = options.json()
        credential = authenticator.register(
            challenge=base64url_to_bytes(body["publicKey"]["challenge"]),
            rp_id=self.settings.rp_id,
            origin=origin or self.customer,
        )
        verified = self.client.post(
            self.customer + "/webauthn/register/verify",
            json={"challenge_id": body["challenge_id"], "credential": credential},
        )
        if verified.status_code != 200:
            raise WalkError("passkey registration was rejected", verified)
        return verified.json()

    def login_passkey(self, authenticator: SoftAuthenticator, email: str, origin: str | None = None) -> dict:
        start = self.client.get(self._app_url("/login"))
        self._expect(start, 302)
        current = self.client.get(self._location(start))
        if current.status_code in (302, 303):
            current = self.client.get(self._location(current))
        if not _is(current, "login"):
            raise WalkError("expected a login form before the passkey ceremony", current)
        request_id = _field(current.text, "request_id")
        options = self.client.post(
            self.customer + "/webauthn/authenticate/options",
            json={"email": email, "request_id": request_id},
        )
        self._expect(options, 200)
        body = options.json()
        credential = authenticator.authenticate(
            challenge=base64url_to_bytes(body["publicKey"]["challenge"]),
            rp_id=self.settings.rp_id,
            origin=origin or self.customer,
        )
        verified = self.client.post(
            self.customer + "/webauthn/authenticate/verify",
            json={
                "challenge_id": body["challenge_id"],
                "credential": credential,
                "request_id": request_id,
            },
        )
        self._expect(verified, 200)
        current = self.client.get(verified.json()["next_url"])
        current = self.submit_consent(current)
        finished = self.follow(current)
        if finished.status_code != 200 or "/account" not in str(finished.url):
            raise WalkError("passkey login did not reach the account page", finished)
        return self.session()

    def login_enterprise(self, email: str, password: str) -> dict:
        start = self.client.get(self._app_url("/login/enterprise"))
        self._expect(start, 302)
        authorize = self.client.get(self._location(start))
        self._expect(authorize, 302)
        current = self.client.get(self._location(authorize))
        if current.status_code in (302, 303):
            current = self.client.get(self._location(current))
        if not _is(current, "login") or "MOCK:enterprise-idp" not in current.text:
            raise WalkError("expected the enterprise identity provider login form", current)
        posted = self._post_login(self.enterprise, current, email, password)
        current = self.client.get(self._location(posted))
        current = self.submit_consent(current)
        finished = self.follow(current)
        if finished.status_code != 200 or "/account" not in str(finished.url):
            raise WalkError("enterprise login did not reach the account page", finished)
        return self.session()

    def logout(self):
        response = self.client.get(self.app + "/logout")
        return self.follow(response)

    def session(self) -> dict:
        response = self.client.get(self.app + "/session")
        if response.status_code != 200:
            raise WalkError("session was not established", response)
        return response.json()

    def api(self, method: str, path: str, token: str | None = None, json_body: dict | None = None):
        headers = {}
        if token is not None:
            headers["authorization"] = f"Bearer {token}"
        return self.client.request(method, self.app + path, headers=headers, json=json_body)

    def submit_consent(self, response, decision: str = "allow"):
        current = response
        if current.status_code in (302, 303):
            current = self.client.get(self._location(current))
        if current.status_code in (302, 303):
            return current
        if not _is(current, "consent"):
            return current
        posted = self.client.post(
            self.customer + "/consent",
            data={"request_id": _field(current.text, "request_id"), "decision": decision},
        )
        self._expect(posted, 302)
        return posted

    def follow(self, response, limit: int = 6):
        current = response
        for _ in range(limit):
            if current.status_code not in (301, 302, 303, 307, 308):
                return current
            current = self.client.get(self._location(current))
        return current

    def _post_login(self, issuer: str, page, email: str, password: str):
        posted = self.client.post(
            issuer + "/login",
            data={
                "email": email,
                "password": password,
                "request_id": _field(page.text, "request_id"),
            },
        )
        self._expect(posted, 302)
        return posted

    def _app_url(self, path: str, **params: str | None) -> str:
        clean = {key: value for key, value in params.items() if value is not None}
        if not clean:
            return self.app + path
        from urllib.parse import urlencode

        return self.app + path + "?" + urlencode(clean)

    def _location(self, response) -> str:
        return urljoin(str(response.url), response.headers["location"])

    def _expect(self, response, status: int) -> None:
        if response.status_code != status:
            raise WalkError(f"expected HTTP {status}", response)

    def _only_app_session(self) -> dict:
        sessions = self.lab.store.state.sessions
        if len(sessions) != 1:
            raise WalkError(f"expected one storefront session, found {len(sessions)}")
        return next(iter(sessions.values()))


def _is(response, page: str) -> bool:
    return response.status_code == 200 and f'data-page="{page}"' in response.text


def _field(html: str, name: str) -> str:
    match = re.search(rf'name="{name}" value="([^"]*)"', html)
    if not match:
        raise WalkError(f"page is missing {name}")
    return match.group(1)
