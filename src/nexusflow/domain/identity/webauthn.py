"""Passkeys (WebAuthn Level 2) as a second factor: the domain's side.

A passkey is a key pair held by an authenticator - a phone, a laptop's secure
element, a security key or a password manager. At sign-in the authenticator
signs a fresh challenge together with the relying party ID and the origin the
browser saw, so a signature obtained through a look-alike site is useless
here. That is what makes a passkey phishing-resistant, unlike a TOTP code,
which a person can be tricked into typing anywhere.

Parsing and verifying what the browser sends - CBOR, COSE keys, client data,
authenticator data, signatures - happens behind :class:`WebAuthnVerifier`
(``infrastructure.security.webauthn``). This module holds the relying party,
the values that cross that boundary, the single-use challenge store and the
options handed to the browser.
"""

from __future__ import annotations

import base64
import hashlib
import re
from dataclasses import dataclass
from typing import Protocol

from nexusflow.core.errors import ErrorDetail, InvalidInputError
from nexusflow.core.jsonutil import JSONObject

# COSE algorithm identifiers accepted for a passkey, in order of preference.
ES256 = -7  # ECDSA with P-256 and SHA-256
EDDSA = -8  # Ed25519
RS256 = -257  # RSASSA-PKCS1-v1_5 with SHA-256
ALGORITHMS: tuple[int, ...] = (ES256, EDDSA, RS256)
ALGORITHM_NAMES = {ES256: "ES256", EDDSA: "EdDSA", RS256: "RS256"}

# Transports a browser may report; others are dropped (they are only hints).
TRANSPORTS = ("usb", "nfc", "ble", "smart-card", "hybrid", "internal")

CHALLENGE_BYTES = 32
USER_HANDLE_BYTES = 64  # WebAuthn section 14.6.1: 64 random bytes, never the account's ID
CHALLENGE_TTL_SECONDS = 300
MIN_CREDENTIAL_ID_BYTES = 16
MAX_CREDENTIAL_ID_BYTES = 1023
MAX_PASSKEYS_PER_USER = 10
MAX_PASSKEY_NAME = 64

_BASE64URL = re.compile(r"[A-Za-z0-9_-]*")

# Why a ceremony was refused: a fixed vocabulary, for the audit trail and for
# the person registering a passkey (never shown to someone signing in).
_REASON_TEXTS: tuple[tuple[str, str], ...] = (
    # the challenge, as the platform issued it
    ("challenge_missing", "No challenge is pending for this response: start again."),
    ("challenge_expired", "The challenge has expired: start again."),
    # the client data
    ("client_data_invalid", "The client data is not valid."),
    ("type_mismatch", "The client data belongs to a different ceremony."),
    ("challenge_mismatch", "The response does not answer the challenge that was issued."),
    ("origin_not_allowed", "The response comes from an origin that is not allowed."),
    ("cross_origin", "Passkeys cannot be used from a cross-origin frame."),
    ("token_binding_unsupported", "Token binding is not supported."),
    # the attestation object and the authenticator data
    ("attestation_invalid", "The attestation object is not valid."),
    ("attestation_format_unsupported", 'Only the attestation format "none" is accepted.'),
    ("authenticator_data_invalid", "The authenticator data is not valid."),
    ("rp_id_mismatch", "The passkey was made for a different relying party."),
    ("user_not_present", "The authenticator did not confirm the user's presence."),
    ("user_not_verified", "The authenticator did not verify the user."),
    ("credential_data_missing", "The authenticator data carries no new credential."),
    ("credential_data_unexpected", "The authenticator data carries an unexpected credential."),
    ("backup_flags_invalid", "The authenticator data's backup flags contradict each other."),
    ("credential_id_invalid", "The credential ID is not valid."),
    ("public_key_invalid", "The credential public key is not valid."),
    ("algorithm_not_allowed", "The credential's signature algorithm is not allowed."),
    ("signature_invalid", "The signature is not valid."),
    # the stored credential
    ("credential_unknown", "The passkey is not registered for this account."),
    ("user_handle_mismatch", "The passkey belongs to another account."),
    ("backup_eligibility_changed", "The passkey's backup eligibility has changed."),
    ("counter_regression", "The passkey's signature counter did not increase."),
)
REASONS: dict[str, str] = dict(_REASON_TEXTS)


def b64url(data: bytes) -> str:
    """Unpadded base64url, the encoding WebAuthn's JSON forms use for binary."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64url_decode(text: str) -> bytes:
    """Strict inverse of :func:`b64url`: its canonical output, and nothing else
    (no padding, no whitespace, no other alphabet, no stray trailing bits)."""
    if not _BASE64URL.fullmatch(text) or len(text) % 4 == 1:
        raise ValueError("not unpadded base64url")
    data = base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    if b64url(data) != text:
        raise ValueError("not canonical base64url")
    return data


def credential_fingerprint(credential_id: bytes) -> str:
    """A short, fixed-size stand-in for a credential ID (challenge state)."""
    return hashlib.sha256(credential_id).hexdigest()


@dataclass(frozen=True, slots=True)
class RelyingParty:
    """This deployment as a WebAuthn relying party."""

    id: str  # a domain: the public host, or a registrable suffix of it
    name: str
    origins: frozenset[str]  # exact origins a response may come from


class PasskeyRejectedError(InvalidInputError):
    """A registration or assertion failed verification.

    ``reason`` is a key of :data:`REASONS`. A person registering a passkey
    sees it; at sign-in only the audit trail does (the answer stays generic).
    """

    default_code = "passkey_rejected"
    default_message = "The passkey could not be verified."

    def __init__(self, reason: str) -> None:
        if reason not in REASONS:  # pragma: no cover - programming error
            raise ValueError(f"unknown passkey rejection reason {reason!r}")
        super().__init__(details=(ErrorDetail(message=REASONS[reason], code=reason),))
        self.reason = reason


@dataclass(frozen=True, slots=True)
class AttestationResponse:
    """A browser's answer to a registration (``navigator.credentials.create``)."""

    raw_id: bytes
    client_data_json: bytes
    attestation_object: bytes


@dataclass(frozen=True, slots=True)
class AssertionResponse:
    """A browser's answer to a sign-in (``navigator.credentials.get``)."""

    raw_id: bytes
    client_data_json: bytes
    authenticator_data: bytes
    signature: bytes
    user_handle: bytes | None


@dataclass(frozen=True, slots=True)
class NewCredential:
    """What a verified registration yields: nothing secret, only public data."""

    credential_id: bytes
    public_key: bytes  # SubjectPublicKeyInfo, DER
    algorithm: int
    sign_count: int
    backup_eligible: bool
    backed_up: bool


@dataclass(frozen=True, slots=True)
class VerifiedAssertion:
    sign_count: int
    backup_eligible: bool
    backed_up: bool


class WebAuthnVerifier(Protocol):
    """WebAuthn Level 2 sections 7.1 and 7.2, up to the checks that need the
    account's records (challenge bookkeeping, ownership, counters)."""

    def verify_registration(
        self, response: AttestationResponse, *, challenge: bytes, rp: RelyingParty
    ) -> NewCredential:
        """Raises :class:`PasskeyRejectedError`."""
        ...

    def verify_assertion(
        self,
        response: AssertionResponse,
        *,
        challenge: bytes,
        rp: RelyingParty,
        public_key: bytes,
        algorithm: int,
    ) -> VerifiedAssertion:
        """Raises :class:`PasskeyRejectedError`."""
        ...


class ChallengeStore(Protocol):
    """Server-side challenge state: expires on its own, and taking it deletes
    it, so each challenge is answered at most once."""

    async def put(self, key: str, state: JSONObject, *, ttl_seconds: int) -> None: ...

    async def take(self, key: str) -> JSONObject | None: ...


@dataclass(frozen=True, slots=True)
class PasskeySupport:
    """What the passkey flows need; ``relying_party`` is ``None`` when this
    deployment cannot offer passkeys (its public host is not a domain name)."""

    relying_party: RelyingParty | None
    verifier: WebAuthnVerifier
    challenges: ChallengeStore


@dataclass(frozen=True, slots=True)
class CredentialDescriptor:
    id: bytes
    transports: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class CreationOptions:
    """``PublicKeyCredentialCreationOptions`` for a new passkey."""

    rp: RelyingParty
    user_handle: bytes
    user_name: str
    user_display_name: str
    challenge: bytes
    algorithms: tuple[int, ...]
    exclude: tuple[CredentialDescriptor, ...]
    timeout_ms: int


@dataclass(frozen=True, slots=True)
class RequestOptions:
    """``PublicKeyCredentialRequestOptions`` for signing in with a passkey."""

    rp_id: str
    challenge: bytes
    allow: tuple[CredentialDescriptor, ...]
    timeout_ms: int
