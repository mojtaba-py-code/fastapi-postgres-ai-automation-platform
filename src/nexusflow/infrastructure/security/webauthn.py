"""WebAuthn Level 2 ceremony verification (sections 7.1 and 7.2), strictly.

No vetted WebAuthn library is available to this project, so this module is
deliberately small and refuses whatever a second factor does not need:

* client data: UTF-8 JSON of at most 4 KiB, without duplicate keys, with the
  expected ``type``, the issued challenge (canonical base64url, compared in
  constant time), an allowed origin, no cross-origin frame and no token
  binding. Other members are ignored, as the specification requires;
* attestation: the ``none`` format only, with an empty statement. The
  platform asks for no attestation and does not judge authenticator models,
  so a signed attestation would prove nothing it relies on;
* authenticator data: the relying party ID's hash, user presence *and* user
  verification, consistent backup flags, a credential at registration and
  none at sign-in, extension outputs (unasked for) that parse, and nothing
  after the declared parts;
* public keys: ES256 (P-256), EdDSA (Ed25519) or RS256 (RSA of 2048 to 4096
  bits with exponent 65537), the COSE key's type, algorithm and curve
  consistent, with exactly that key type's parameters, and a point on the
  curve;
* signatures: over the authenticator data followed by the SHA-256 of the
  client data, with the stored key: DER-encoded ECDSA in its canonical form,
  64-byte Ed25519, PKCS#1 v1.5 of the key's length.

What needs the account's records - a challenge's single use and expiry, who
owns a credential, its signature counter - is checked by the domain services.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import dataclass
from typing import Any

from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature,
    encode_dss_signature,
)

from nexusflow.core.jsonutil import max_nesting_depth
from nexusflow.domain.identity.webauthn import (
    ALGORITHMS,
    EDDSA,
    ES256,
    MAX_CREDENTIAL_ID_BYTES,
    MIN_CREDENTIAL_ID_BYTES,
    RS256,
    AssertionResponse,
    AttestationResponse,
    NewCredential,
    PasskeyRejectedError,
    RelyingParty,
    VerifiedAssertion,
    b64url,
)
from nexusflow.infrastructure.security.cbor import (
    CborError,
    CborKey,
    CborLimits,
    CborValue,
    decode,
    decode_prefix,
)

type PublicKey = ec.EllipticCurvePublicKey | Ed25519PublicKey | rsa.RSAPublicKey

MAX_CLIENT_DATA_BYTES = 4 * 1024
MAX_ATTESTATION_OBJECT_BYTES = 64 * 1024
MAX_AUTHENTICATOR_DATA_BYTES = 4 * 1024
MAX_SIGNATURE_BYTES = 512  # RSA-4096
_MAX_CLIENT_DATA_DEPTH = 4
_CBOR_LIMITS = CborLimits(max_size=MAX_ATTESTATION_OBJECT_BYTES, max_depth=4, max_items=256)

# Authenticator data: rpIdHash (32) | flags (1) | signCount (4) | [credential] | [extensions]
_FIXED_PART = 37
_AAGUID_BYTES = 16
_UP, _UV, _BE, _BS, _AT, _ED = 0x01, 0x04, 0x08, 0x10, 0x40, 0x80

# COSE (RFC 9052, RFC 9053, RFC 8230)
_KTY, _ALG = 1, 3
_OKP, _EC2, _RSA = 1, 2, 3
_CRV, _X, _Y = -1, -2, -3
_N, _E = -1, -2
_P256, _ED25519 = 1, 6
_KEY_LABELS = {
    ES256: frozenset({_KTY, _ALG, _CRV, _X, _Y}),
    EDDSA: frozenset({_KTY, _ALG, _CRV, _X}),
    RS256: frozenset({_KTY, _ALG, _N, _E}),
}
_RSA_EXPONENT = 65537
_RSA_MIN_BITS, _RSA_MAX_BITS = 2048, 4096


@dataclass(frozen=True, slots=True)
class _AuthenticatorData:
    rp_id_hash: bytes
    flags: int
    sign_count: int
    credential_id: bytes | None = None
    public_key: CborValue = None


class StrictWebAuthnVerifier:
    """The ``WebAuthnVerifier`` port. Every refusal is a
    :class:`PasskeyRejectedError` naming its reason."""

    def verify_registration(
        self, response: AttestationResponse, *, challenge: bytes, rp: RelyingParty
    ) -> NewCredential:
        _verify_client_data(response.client_data_json, "webauthn.create", challenge, rp)
        auth = _authenticator_data(_attested(response.attestation_object), registration=True)
        _verify_authenticator(auth, rp)
        if auth.credential_id is None:  # pragma: no cover - guaranteed by registration=True
            raise PasskeyRejectedError("credential_data_missing")
        if not hmac.compare_digest(auth.credential_id, response.raw_id):
            raise PasskeyRejectedError("credential_id_invalid")
        algorithm, key = _cose_public_key(auth.public_key)
        return NewCredential(
            credential_id=auth.credential_id,
            public_key=key.public_bytes(
                serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
            ),
            algorithm=algorithm,
            sign_count=auth.sign_count,
            backup_eligible=bool(auth.flags & _BE),
            backed_up=bool(auth.flags & _BS),
        )

    def verify_assertion(
        self,
        response: AssertionResponse,
        *,
        challenge: bytes,
        rp: RelyingParty,
        public_key: bytes,
        algorithm: int,
    ) -> VerifiedAssertion:
        _verify_client_data(response.client_data_json, "webauthn.get", challenge, rp)
        if len(response.authenticator_data) > MAX_AUTHENTICATOR_DATA_BYTES:
            raise PasskeyRejectedError("authenticator_data_invalid")
        auth = _authenticator_data(response.authenticator_data, registration=False)
        _verify_authenticator(auth, rp)
        key = _stored_public_key(public_key, algorithm)
        signed = response.authenticator_data + hashlib.sha256(response.client_data_json).digest()
        _verify_signature(key, response.signature, signed)
        return VerifiedAssertion(
            sign_count=auth.sign_count,
            backup_eligible=bool(auth.flags & _BE),
            backed_up=bool(auth.flags & _BS),
        )


# ------------------------------------------------------------------ client data


def _verify_client_data(raw: bytes, expected_type: str, challenge: bytes, rp: RelyingParty) -> None:
    data = _client_data(raw)
    kind = data.get("type")
    if not isinstance(kind, str):
        raise PasskeyRejectedError("client_data_invalid")
    if kind != expected_type:
        raise PasskeyRejectedError("type_mismatch")
    received = data.get("challenge")
    if not isinstance(received, str):
        raise PasskeyRejectedError("client_data_invalid")
    if not hmac.compare_digest(received.encode("utf-8"), b64url(challenge).encode("ascii")):
        raise PasskeyRejectedError("challenge_mismatch")
    origin = data.get("origin")
    if not isinstance(origin, str):
        raise PasskeyRejectedError("client_data_invalid")
    if origin not in rp.origins:
        raise PasskeyRejectedError("origin_not_allowed")
    cross_origin = data.get("crossOrigin", False)
    if not isinstance(cross_origin, bool):
        raise PasskeyRejectedError("client_data_invalid")
    if cross_origin or "topOrigin" in data:
        raise PasskeyRejectedError("cross_origin")
    binding = data.get("tokenBinding")
    if binding is not None:
        status = binding.get("status") if isinstance(binding, dict) else None
        if status == "present":
            raise PasskeyRejectedError("token_binding_unsupported")
        if status not in ("supported", "not-supported"):
            raise PasskeyRejectedError("client_data_invalid")


def _client_data(raw: bytes) -> dict[str, Any]:
    if (
        not raw
        or len(raw) > MAX_CLIENT_DATA_BYTES
        or max_nesting_depth(raw) > _MAX_CLIENT_DATA_DEPTH
    ):
        raise PasskeyRejectedError("client_data_invalid")
    try:
        data = json.loads(
            raw.decode("utf-8"), object_pairs_hook=_unique_members, parse_constant=_no_constants
        )
    except (UnicodeDecodeError, ValueError, RecursionError) as exc:
        raise PasskeyRejectedError("client_data_invalid") from exc
    if not isinstance(data, dict):
        raise PasskeyRejectedError("client_data_invalid")
    return data


def _unique_members(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    members: dict[str, Any] = {}
    for name, value in pairs:
        if name in members:
            raise ValueError("duplicate member in client data")
        members[name] = value
    return members


def _no_constants(name: str) -> Any:
    raise ValueError(f"{name} is not JSON")


# ------------------------------------------------- attestation, authenticator data


def _attested(raw: bytes) -> bytes:
    """The authenticator data of an attestation object in the ``none`` format."""
    if not raw or len(raw) > MAX_ATTESTATION_OBJECT_BYTES:
        raise PasskeyRejectedError("attestation_invalid")
    try:
        attestation = decode(raw, limits=_CBOR_LIMITS)
    except CborError as exc:
        raise PasskeyRejectedError("attestation_invalid") from exc
    if not isinstance(attestation, dict) or set(attestation) != {"fmt", "attStmt", "authData"}:
        raise PasskeyRejectedError("attestation_invalid")
    fmt, statement, auth_data = attestation["fmt"], attestation["attStmt"], attestation["authData"]
    if not (isinstance(fmt, str) and isinstance(statement, dict) and isinstance(auth_data, bytes)):
        raise PasskeyRejectedError("attestation_invalid")
    if fmt != "none" or statement:
        raise PasskeyRejectedError("attestation_format_unsupported")
    return auth_data


def _authenticator_data(raw: bytes, *, registration: bool) -> _AuthenticatorData:
    if len(raw) < _FIXED_PART:
        raise PasskeyRejectedError("authenticator_data_invalid")
    flags = raw[32]
    offset = _FIXED_PART
    credential_id: bytes | None = None
    public_key: CborValue = None
    if flags & _AT:
        if not registration:
            raise PasskeyRejectedError("credential_data_unexpected")
        credential_id, public_key, offset = _attested_credential(raw, offset)
    elif registration:
        raise PasskeyRejectedError("credential_data_missing")
    if flags & _ED:
        offset = _skip_extensions(raw, offset)
    if offset != len(raw):
        raise PasskeyRejectedError("authenticator_data_invalid")
    return _AuthenticatorData(
        rp_id_hash=raw[:32],
        flags=flags,
        sign_count=int.from_bytes(raw[33:37], "big"),
        credential_id=credential_id,
        public_key=public_key,
    )


def _attested_credential(raw: bytes, offset: int) -> tuple[bytes, CborValue, int]:
    """aaguid (16) | credentialIdLength (2) | credentialId | credentialPublicKey (COSE)."""
    length_at = offset + _AAGUID_BYTES
    if length_at + 2 > len(raw):
        raise PasskeyRejectedError("authenticator_data_invalid")
    length = int.from_bytes(raw[length_at : length_at + 2], "big")
    if not MIN_CREDENTIAL_ID_BYTES <= length <= MAX_CREDENTIAL_ID_BYTES:
        raise PasskeyRejectedError("credential_id_invalid")
    start = length_at + 2
    end = start + length
    if end >= len(raw):  # the public key must follow
        raise PasskeyRejectedError("authenticator_data_invalid")
    try:
        public_key, after = decode_prefix(raw, end, limits=_CBOR_LIMITS)
    except CborError as exc:
        raise PasskeyRejectedError("public_key_invalid") from exc
    return raw[start:end], public_key, after


def _skip_extensions(raw: bytes, offset: int) -> int:
    """Extension outputs: none were asked for, so they are parsed, then ignored."""
    try:
        extensions, after = decode_prefix(raw, offset, limits=_CBOR_LIMITS)
    except CborError as exc:
        raise PasskeyRejectedError("authenticator_data_invalid") from exc
    if not isinstance(extensions, dict) or not all(isinstance(k, str) for k in extensions):
        raise PasskeyRejectedError("authenticator_data_invalid")
    return after


def _verify_authenticator(auth: _AuthenticatorData, rp: RelyingParty) -> None:
    expected = hashlib.sha256(rp.id.encode("ascii")).digest()
    if not hmac.compare_digest(auth.rp_id_hash, expected):
        raise PasskeyRejectedError("rp_id_mismatch")
    if not auth.flags & _UP:
        raise PasskeyRejectedError("user_not_present")
    if not auth.flags & _UV:
        raise PasskeyRejectedError("user_not_verified")
    if auth.flags & _BS and not auth.flags & _BE:
        raise PasskeyRejectedError("backup_flags_invalid")


# --------------------------------------------------------------------- keys


def _cose_public_key(key: CborValue) -> tuple[int, PublicKey]:
    if not isinstance(key, dict):
        raise PasskeyRejectedError("public_key_invalid")
    algorithm = key.get(_ALG)
    if type(algorithm) is not int:
        raise PasskeyRejectedError("public_key_invalid")
    if algorithm not in ALGORITHMS:
        raise PasskeyRejectedError("algorithm_not_allowed")
    if set(key) != _KEY_LABELS[algorithm]:
        raise PasskeyRejectedError("public_key_invalid")
    try:
        if algorithm == ES256:
            return algorithm, _ec2_key(key)
        if algorithm == EDDSA:
            return algorithm, _okp_key(key)
        return algorithm, _rsa_key(key)
    except (ValueError, UnsupportedAlgorithm) as exc:  # e.g. a point off the curve
        raise PasskeyRejectedError("public_key_invalid") from exc


def _ec2_key(key: dict[CborKey, CborValue]) -> ec.EllipticCurvePublicKey:
    x, y = key[_X], key[_Y]
    if (
        not _is_int(key[_KTY], _EC2)
        or not _is_int(key[_CRV], _P256)
        or not isinstance(x, bytes)
        or not isinstance(y, bytes)
        or len(x) != 32
        or len(y) != 32
    ):
        raise PasskeyRejectedError("public_key_invalid")
    return ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), b"\x04" + x + y)


def _okp_key(key: dict[CborKey, CborValue]) -> Ed25519PublicKey:
    x = key[_X]
    if (
        not _is_int(key[_KTY], _OKP)
        or not _is_int(key[_CRV], _ED25519)
        or not isinstance(x, bytes)
        or len(x) != 32
    ):
        raise PasskeyRejectedError("public_key_invalid")
    return Ed25519PublicKey.from_public_bytes(x)


def _rsa_key(key: dict[CborKey, CborValue]) -> rsa.RSAPublicKey:
    if not _is_int(key[_KTY], _RSA):
        raise PasskeyRejectedError("public_key_invalid")
    modulus, exponent = _unsigned(key[_N]), _unsigned(key[_E])
    if (
        exponent != _RSA_EXPONENT
        or modulus % 2 == 0
        or not _RSA_MIN_BITS <= modulus.bit_length() <= _RSA_MAX_BITS
    ):
        raise PasskeyRejectedError("public_key_invalid")
    return rsa.RSAPublicNumbers(exponent, modulus).public_key()


def _unsigned(value: CborValue) -> int:
    """RFC 8230: a big-endian byte string without leading zero bytes."""
    if not isinstance(value, bytes) or not value or value[0] == 0:
        raise PasskeyRejectedError("public_key_invalid")
    return int.from_bytes(value, "big")


def _is_int(value: CborValue, expected: int) -> bool:
    return type(value) is int and value == expected  # never ``True == 1``


def _stored_public_key(spki: bytes, algorithm: int) -> PublicKey:
    """A stored key, loaded and checked against its recorded algorithm."""
    try:
        key = serialization.load_der_public_key(spki)
    except (ValueError, UnsupportedAlgorithm) as exc:
        raise PasskeyRejectedError("public_key_invalid") from exc
    match key:
        case ec.EllipticCurvePublicKey() if algorithm == ES256 and isinstance(
            key.curve, ec.SECP256R1
        ):
            return key
        case Ed25519PublicKey() if algorithm == EDDSA:
            return key
        case rsa.RSAPublicKey() if (
            algorithm == RS256 and _RSA_MIN_BITS <= key.key_size <= _RSA_MAX_BITS
        ):
            return key
    raise PasskeyRejectedError("public_key_invalid")


def _verify_signature(key: PublicKey, signature: bytes, signed: bytes) -> None:
    if not signature or len(signature) > MAX_SIGNATURE_BYTES:
        raise PasskeyRejectedError("signature_invalid")
    try:
        if isinstance(key, ec.EllipticCurvePublicKey):
            r, s = decode_dss_signature(signature)
            if encode_dss_signature(r, s) != signature:  # BER, padding, trailing bytes
                raise InvalidSignature
            key.verify(signature, signed, ec.ECDSA(hashes.SHA256()))
        elif isinstance(key, Ed25519PublicKey):
            if len(signature) != 64:
                raise InvalidSignature
            key.verify(signature, signed)
        else:
            if len(signature) != (key.key_size + 7) // 8:
                raise InvalidSignature
            key.verify(signature, signed, padding.PKCS1v15(), hashes.SHA256())
    except (InvalidSignature, ValueError) as exc:
        raise PasskeyRejectedError("signature_invalid") from exc
