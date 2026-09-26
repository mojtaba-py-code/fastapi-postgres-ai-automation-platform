"""A software authenticator: real WebAuthn registrations and assertions for tests.

It plays the browser and the authenticator at once. It writes the client data
JSON and the authenticator data, wraps a registration in a ``none``
attestation object, and signs assertions with a real key from
``cryptography`` (P-256, Ed25519 or RSA-2048) - so tests drive the platform's
own verification end to end. Every part can be overridden to produce the
malformed and hostile responses the platform must refuse.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
from dataclasses import dataclass, field
from typing import Any, Literal

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from nexusflow.domain.identity.webauthn import AssertionResponse, AttestationResponse
from tests.support.cbor import encode

ES256, EDDSA, RS256 = -7, -8, -257
ALGORITHMS = (ES256, EDDSA, RS256)
UP, UV, BE, BS, AT, ED = 0x01, 0x04, 0x08, 0x10, 0x40, 0x80

RP_ID = "nexusflow.test.example"  # the host of the test container's public_base_url
ORIGIN = f"https://{RP_ID}"

type Tamper = Literal["authenticator_data", "client_data", "signature"]


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64url_decode(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def client_data(
    kind: str, challenge: str, origin: str, members: dict[str, Any] | None = None
) -> bytes:
    """Client data JSON as a browser serialises it; ``members`` are added or replace."""
    data: dict[str, Any] = {
        "type": kind,
        "challenge": challenge,
        "origin": origin,
        "crossOrigin": False,
    }
    data.update(members or {})
    return json.dumps(data, separators=(",", ":")).encode()


def rp_id_hash(rp_id: str = RP_ID) -> bytes:
    return hashlib.sha256(rp_id.encode()).digest()


def authenticator_data(
    *,
    flags: int,
    sign_count: int = 0,
    attested: bytes = b"",
    extensions: bytes = b"",
    rp_hash: bytes | None = None,
) -> bytes:
    return (
        (rp_hash if rp_hash is not None else rp_id_hash())
        + bytes([flags])
        + sign_count.to_bytes(4, "big")
        + attested
        + extensions
    )


def attested_credential(credential_id: bytes, cose_key: bytes, aaguid: bytes = bytes(16)) -> bytes:
    return aaguid + len(credential_id).to_bytes(2, "big") + credential_id + cose_key


def attestation_response(credential: dict[str, Any]) -> AttestationResponse:
    """What the API layer hands the domain for a registration."""
    response = credential["response"]
    return AttestationResponse(
        raw_id=b64url_decode(credential["rawId"]),
        client_data_json=b64url_decode(response["clientDataJSON"]),
        attestation_object=b64url_decode(response["attestationObject"]),
    )


def assertion_response(credential: dict[str, Any]) -> AssertionResponse:
    """What the API layer hands the domain for a sign-in."""
    response = credential["response"]
    handle = response.get("userHandle")
    return AssertionResponse(
        raw_id=b64url_decode(credential["rawId"]),
        client_data_json=b64url_decode(response["clientDataJSON"]),
        authenticator_data=b64url_decode(response["authenticatorData"]),
        signature=b64url_decode(response["signature"]),
        user_handle=b64url_decode(handle) if handle else None,
    )


type PrivateKey = ec.EllipticCurvePrivateKey | Ed25519PrivateKey | rsa.RSAPrivateKey


def new_private_key(algorithm: int) -> PrivateKey:
    if algorithm == ES256:
        return ec.generate_private_key(ec.SECP256R1())
    if algorithm == EDDSA:
        return Ed25519PrivateKey.generate()
    if algorithm == RS256:
        return rsa.generate_private_key(public_exponent=65537, key_size=2048)
    raise ValueError(f"unsupported algorithm {algorithm}")


def sign(key: PrivateKey, data: bytes) -> bytes:
    if isinstance(key, ec.EllipticCurvePrivateKey):
        return key.sign(data, ec.ECDSA(hashes.SHA256()))
    if isinstance(key, Ed25519PrivateKey):
        return key.sign(data)
    return key.sign(data, padding.PKCS1v15(), hashes.SHA256())


def cose_key(key: PrivateKey, algorithm: int) -> dict[int, Any]:
    """The COSE form of ``key``'s public half, as an authenticator writes it."""
    if isinstance(key, ec.EllipticCurvePrivateKey):
        numbers = key.public_key().public_numbers()
        return {
            1: 2,
            3: algorithm,
            -1: 1,
            -2: numbers.x.to_bytes(32, "big"),
            -3: numbers.y.to_bytes(32, "big"),
        }
    if isinstance(key, Ed25519PrivateKey):
        raw = key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        return {1: 1, 3: algorithm, -1: 6, -2: raw}
    public = key.public_key().public_numbers()
    return {
        1: 3,
        3: algorithm,
        -1: public.n.to_bytes((public.n.bit_length() + 7) // 8, "big"),
        -2: public.e.to_bytes((public.e.bit_length() + 7) // 8, "big"),
    }


_UNSET: Any = object()


@dataclass
class SoftwareAuthenticator:
    """One passkey. ``sign_count`` is the last value it reported; it counts up
    on every assertion unless ``counting`` is off (as for many synced passkeys)."""

    algorithm: int = ES256
    origin: str = ORIGIN
    counting: bool = True
    sign_count: int = 0
    backup_eligible: bool = False
    backed_up: bool = False
    credential_id: bytes = field(default_factory=lambda: os.urandom(32))
    user_handle: bytes | None = None
    key: PrivateKey = field(init=False)

    def __post_init__(self) -> None:
        self.key = new_private_key(self.algorithm)

    def flags(self, *, attested: bool) -> int:
        flags = UP | UV
        if self.backup_eligible:
            flags |= BE
        if self.backed_up:
            flags |= BS
        if attested:
            flags |= AT
        return flags

    def cose_key(self) -> dict[int, Any]:
        return cose_key(self.key, self.algorithm)

    def _client_data(
        self,
        kind: str,
        options: dict[str, Any],
        challenge: str | None,
        origin: str | None,
        members: dict[str, Any] | None,
    ) -> bytes:
        return client_data(
            kind,
            options["challenge"] if challenge is None else challenge,
            self.origin if origin is None else origin,
            members,
        )

    # ---------------------------------------------------------- registration

    def attestation(
        self,
        options: dict[str, Any],
        *,
        kind: str = "webauthn.create",
        challenge: str | None = None,
        origin: str | None = None,
        client_members: dict[str, Any] | None = None,
        client_data_json: bytes | None = None,
        flags: int | None = None,
        rp_hash: bytes | None = None,
        fmt: Any = "none",
        att_stmt: Any = _UNSET,
        public_key: Any = _UNSET,
        credential_id: bytes | None = None,
        raw_id: bytes | None = None,
        extensions: bytes = b"",
        attestation_object: bytes | None = None,
        transports: list[str] | None = None,
    ) -> dict[str, Any]:
        """The JSON a browser posts after ``navigator.credentials.create(options)``."""
        self.user_handle = b64url_decode(options["user"]["id"])
        cdj = (
            client_data_json
            if client_data_json is not None
            else self._client_data(kind, options, challenge, origin, client_members)
        )
        embedded_id = credential_id if credential_id is not None else self.credential_id
        key = self.cose_key() if public_key is _UNSET else public_key
        encoded_key = key if isinstance(key, bytes) else encode(key)  # bytes: hostile, as is
        auth_data = authenticator_data(
            flags=self.flags(attested=True) if flags is None else flags,
            sign_count=self.sign_count,
            attested=attested_credential(embedded_id, encoded_key),
            extensions=extensions,
            rp_hash=rp_hash,
        )
        statement = {} if att_stmt is _UNSET else att_stmt
        attestation = (
            attestation_object
            if attestation_object is not None
            else encode({"fmt": fmt, "attStmt": statement, "authData": auth_data})
        )
        identifier = raw_id if raw_id is not None else self.credential_id
        return {
            "id": b64url(identifier),
            "rawId": b64url(identifier),
            "type": "public-key",
            "response": {
                "clientDataJSON": b64url(cdj),
                "attestationObject": b64url(attestation),
                "transports": ["internal", "hybrid"] if transports is None else transports,
            },
            "clientExtensionResults": {},
            "authenticatorAttachment": "platform",
        }

    # --------------------------------------------------------------- sign-in

    def assertion(
        self,
        options: dict[str, Any],
        *,
        kind: str = "webauthn.get",
        challenge: str | None = None,
        origin: str | None = None,
        client_members: dict[str, Any] | None = None,
        client_data_json: bytes | None = None,
        flags: int | None = None,
        rp_hash: bytes | None = None,
        sign_count: int | None = None,
        attested: bytes = b"",
        extensions: bytes = b"",
        raw_id: bytes | None = None,
        user_handle: Any = _UNSET,
        signing_key: PrivateKey | None = None,
        signature: bytes | None = None,
        tamper: Tamper | None = None,
    ) -> dict[str, Any]:
        """The JSON a browser posts after ``navigator.credentials.get(options)``."""
        if sign_count is None:
            if self.counting:
                self.sign_count += 1
            sign_count = self.sign_count
        cdj = (
            client_data_json
            if client_data_json is not None
            else self._client_data(kind, options, challenge, origin, client_members)
        )
        auth_data = authenticator_data(
            flags=self.flags(attested=False) if flags is None else flags,
            sign_count=sign_count,
            attested=attested,
            extensions=extensions,
            rp_hash=rp_hash,
        )
        sig = (
            signature
            if signature is not None
            else sign(signing_key or self.key, auth_data + hashlib.sha256(cdj).digest())
        )
        if tamper == "authenticator_data":
            auth_data = auth_data[:-1] + bytes([auth_data[-1] ^ 0x01])  # the counter's last bit
        elif tamper == "client_data":
            cdj = self._client_data(
                kind,
                options,
                challenge,
                origin,
                {**(client_members or {}), "other_keys_can_be_added_here": "added after signing"},
            )
        elif tamper == "signature":
            sig = sig[:-1] + bytes([sig[-1] ^ 0x01])
        handle = self.user_handle if user_handle is _UNSET else user_handle
        identifier = raw_id if raw_id is not None else self.credential_id
        return {
            "id": b64url(identifier),
            "rawId": b64url(identifier),
            "type": "public-key",
            "response": {
                "clientDataJSON": b64url(cdj),
                "authenticatorData": b64url(auth_data),
                "signature": b64url(sig),
                "userHandle": b64url(handle) if handle is not None else None,
            },
            "clientExtensionResults": {},
            "authenticatorAttachment": "platform",
        }
