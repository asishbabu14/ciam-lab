"""Virtual WebAuthn authenticator for tests and `make demo`.

This is a software stand-in for a passkey. It generates a P-256 key and signs
registration and authentication ceremonies so py_webauthn can verify them.
It does not talk to a real authenticator.
"""

from __future__ import annotations

import hashlib
import json
import secrets

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ec import ECDSA
from cryptography.hazmat.primitives.hashes import SHA256
from webauthn.helpers import bytes_to_base64url
from webauthn.helpers.encode_cbor import encode_cbor


class SoftAuthenticator:
    def __init__(self) -> None:
        self._private = ec.generate_private_key(ec.SECP256R1())
        self.credential_id = secrets.token_bytes(32)
        self.sign_count = 0
        self.user_handle: bytes | None = None

    def register(self, *, challenge: bytes, rp_id: str, origin: str) -> dict:
        self.sign_count = 0
        auth_data = self._auth_data(rp_id, flags=0x45, include_credential=True)
        client_data = _client_data("webauthn.create", challenge, origin)
        attestation = encode_cbor({"fmt": "none", "attStmt": {}, "authData": auth_data})
        return _public_key_credential(
            self.credential_id,
            client_data_json=client_data,
            attestation_object=attestation,
        )

    def authenticate(
        self,
        *,
        challenge: bytes,
        rp_id: str,
        origin: str,
        user_handle: bytes | None = None,
    ) -> dict:
        self.sign_count += 1
        auth_data = self._auth_data(rp_id, flags=0x05, include_credential=False)
        client_data = _client_data("webauthn.get", challenge, origin)
        signature = self._private.sign(
            auth_data + hashlib.sha256(client_data).digest(),
            ECDSA(SHA256()),
        )
        handle = user_handle if user_handle is not None else self.user_handle
        return _public_key_credential(
            self.credential_id,
            client_data_json=client_data,
            authenticator_data=auth_data,
            signature=signature,
            user_handle=handle,
        )

    def _auth_data(self, rp_id: str, *, flags: int, include_credential: bool) -> bytes:
        rp_hash = hashlib.sha256(rp_id.encode("utf-8")).digest()
        sign_count = self.sign_count.to_bytes(4, "big")
        body = rp_hash + bytes([flags]) + sign_count
        if not include_credential:
            return body
        numbers = self._private.public_key().public_numbers()
        cose_key = encode_cbor(
            {
                1: 2,
                3: -7,
                -1: 1,
                -2: numbers.x.to_bytes(32, "big"),
                -3: numbers.y.to_bytes(32, "big"),
            }
        )
        return body + bytes(16) + len(self.credential_id).to_bytes(2, "big") + self.credential_id + cose_key


def _client_data(kind: str, challenge: bytes, origin: str) -> bytes:
    payload = {
        "type": kind,
        "challenge": bytes_to_base64url(challenge),
        "origin": origin,
        "crossOrigin": False,
    }
    return json.dumps(payload, separators=(",", ":")).encode("utf-8")


def _public_key_credential(
    credential_id: bytes,
    *,
    client_data_json: bytes,
    attestation_object: bytes | None = None,
    authenticator_data: bytes | None = None,
    signature: bytes | None = None,
    user_handle: bytes | None = None,
) -> dict:
    encoded_id = bytes_to_base64url(credential_id)
    response = {"clientDataJSON": bytes_to_base64url(client_data_json)}
    if attestation_object is not None:
        response["attestationObject"] = bytes_to_base64url(attestation_object)
    if authenticator_data is not None:
        response["authenticatorData"] = bytes_to_base64url(authenticator_data)
    if signature is not None:
        response["signature"] = bytes_to_base64url(signature)
    if user_handle is not None:
        response["userHandle"] = bytes_to_base64url(user_handle)
    return {
        "id": encoded_id,
        "rawId": encoded_id,
        "type": "public-key",
        "response": response,
    }
