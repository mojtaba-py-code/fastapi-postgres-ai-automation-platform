"""HMAC-SHA256 webhook signature scheme (used for inbound and outbound webhooks).

Header format (Stripe-style, supports secret rotation with multiple ``v1``)::

    X-NexusFlow-Signature: t=1726000000,v1=<hex>[,v1=<hex>]
    X-NexusFlow-Delivery:  <uuid>            (unique per delivery - replay nonce)

The signed message is ``f"{t}.{delivery_id}.".encode() + raw_body``. Binding the
timestamp and delivery id into the MAC means neither can be altered to bypass
the freshness window or the replay (nonce) store.
"""

from __future__ import annotations

import hashlib
import hmac
import re
from collections.abc import Sequence
from dataclasses import dataclass

from nexusflow.core.errors import AuthenticationError

SIGNATURE_HEADER = "X-NexusFlow-Signature"
DELIVERY_HEADER = "X-NexusFlow-Delivery"
REJECTION_CODE = "invalid_signature"
_MAX_HEADER_LENGTH = 1024
_MAX_SIGNATURES = 5
_HEX_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_DELIVERY_ID = re.compile(r"^[A-Za-z0-9._:-]{8,128}$")


@dataclass(frozen=True, slots=True)
class ParsedSignature:
    timestamp: int
    signatures: tuple[str, ...]


def _reject(reason: str) -> AuthenticationError:
    # One generic client-facing code and message; the specific reason is only
    # logged, so failed attempts cannot be used as an oracle.
    return AuthenticationError(
        "Webhook signature verification failed.", code=REJECTION_CODE, internal_detail=reason
    )


def compute_signature(secret: bytes, *, timestamp: int, delivery_id: str, body: bytes) -> str:
    message = f"{timestamp}.{delivery_id}.".encode() + body
    return hmac.new(secret, message, hashlib.sha256).hexdigest()


def build_signature_header(secret: bytes, *, timestamp: int, delivery_id: str, body: bytes) -> str:
    signature = compute_signature(secret, timestamp=timestamp, delivery_id=delivery_id, body=body)
    return f"t={timestamp},v1={signature}"


def parse_signature_header(header: str | None) -> ParsedSignature:
    if not header:
        raise _reject("signature_missing")
    if len(header) > _MAX_HEADER_LENGTH:
        raise _reject("signature_malformed")
    timestamp: int | None = None
    signatures: list[str] = []
    for part in header.split(","):
        key, sep, value = part.strip().partition("=")
        if not sep:
            raise _reject("signature_malformed")
        if key == "t":
            if timestamp is not None or not value.isdigit() or len(value) > 12:
                raise _reject("signature_malformed")
            timestamp = int(value)
        elif key == "v1":
            if not _HEX_SHA256.fullmatch(value):
                raise _reject("signature_malformed")
            signatures.append(value)
        # Unknown schemes are ignored for forward compatibility.
    if timestamp is None or not signatures or len(signatures) > _MAX_SIGNATURES:
        raise _reject("signature_malformed")
    return ParsedSignature(timestamp=timestamp, signatures=tuple(signatures))


def validate_delivery_id(delivery_id: str | None) -> str:
    if not delivery_id or not _DELIVERY_ID.fullmatch(delivery_id):
        raise _reject("delivery_id_invalid")
    return delivery_id


def verify_signature(
    *,
    secrets: Sequence[bytes],
    header: str | None,
    delivery_id: str | None,
    body: bytes,
    now_timestamp: int,
    tolerance_seconds: int,
) -> ParsedSignature:
    """Verify freshness and authenticity; raises ``AuthenticationError``.

    ``secrets`` may contain several active secrets during rotation. Every
    comparison is constant-time.
    """
    parsed = parse_signature_header(header)
    valid_delivery_id = validate_delivery_id(delivery_id)
    if abs(now_timestamp - parsed.timestamp) > tolerance_seconds:
        raise _reject("timestamp_out_of_tolerance")
    matched = False
    for secret in secrets:
        expected = compute_signature(
            secret, timestamp=parsed.timestamp, delivery_id=valid_delivery_id, body=body
        )
        for candidate in parsed.signatures:
            if hmac.compare_digest(expected, candidate):
                matched = True
    if not matched:
        raise _reject("signature_mismatch")
    return parsed
