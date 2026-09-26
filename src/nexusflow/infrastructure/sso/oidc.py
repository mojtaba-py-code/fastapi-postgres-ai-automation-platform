"""OpenID Connect relying party: discovery, signing keys, code exchange and
strict ID token verification.

Every request goes through :class:`SafeHttpClient` - identity providers are
configured by tenants, so their URLs get the same SSRF protection as any other
tenant URL (static policy, connect-time IP check of every DNS answer, size and
time limits). The token endpoint is never redirected to.

ID tokens (OpenID Connect Core, section 3.1.3.7):

* the header's ``alg`` must be in :data:`ID_TOKEN_ALGORITHMS` - never ``none``
  or an HMAC algorithm - and the signing key must be of the matching type
  (a JWK is never used with an algorithm its key type does not belong to);
* the key comes from the provider's ``jwks_uri`` (cached briefly; fetched
  again once for an unknown ``kid``); ``jku``/``jwk``/``x5u`` headers are
  ignored and ``crit`` is refused;
* ``iss`` equals the configured issuer, ``aud`` contains the client id, and
  with several audiences (or any ``azp``) ``azp`` equals the client id;
* ``exp``, ``iat`` and ``nbf`` are checked against the platform clock with a
  small leeway, and ``iat`` must be recent.
"""

from __future__ import annotations

import base64
import time
from collections import OrderedDict
from collections.abc import Mapping
from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.parse import quote, urlencode

import jwt

from nexusflow.core.errors import NexusFlowError, PolicyViolationError, TransientError
from nexusflow.core.jsonutil import JSONValue
from nexusflow.domain.identity.sso import (
    ID_TOKEN_ALGORITHMS,
    ISSUER_POLICY,
    IdTokenClaims,
    ProviderMetadata,
    SsoProtocolError,
    discovery_url,
)
from nexusflow.infrastructure.http.client import HttpResponse, SafeHttpClient

_JSON_TYPES = frozenset({"application/json", "application/jwk-set+json"})
_MAX_ID_TOKEN_LENGTH = 16 * 1024
_MAX_KEYS = 50
_MAX_TOKEN_RESPONSE_BYTES = 64 * 1024
# An ID token issued longer ago than this is refused, whatever its expiry says.
_MAX_ID_TOKEN_AGE = timedelta(minutes=10)
_KEY_TYPES: dict[str, tuple[str, str | None]] = {
    "RS256": ("RSA", None),
    "PS256": ("RSA", None),
    "ES256": ("EC", "P-256"),
    "EdDSA": ("OKP", "Ed25519"),
}
_SUPPORTED_CLIENT_AUTH = ("client_secret_basic", "client_secret_post")


class IdentityProviderUnavailableError(TransientError):
    default_code = "sso_unavailable"
    default_message = "The identity provider is not reachable. Try again later."


class _TtlCache[V]:
    """A small, bounded time-to-live cache (per process)."""

    def __init__(self, ttl_seconds: float, max_entries: int = 256) -> None:
        self._ttl = ttl_seconds
        self._max = max_entries
        self._items: OrderedDict[str, tuple[float, V]] = OrderedDict()

    def get(self, key: str) -> V | None:
        entry = self._items.get(key)
        if entry is None:
            return None
        stored_at, value = entry
        if time.monotonic() - stored_at >= self._ttl:
            del self._items[key]
            return None
        self._items.move_to_end(key)
        return value

    def put(self, key: str, value: V) -> None:
        if self._ttl <= 0:
            return
        self._items[key] = (time.monotonic(), value)
        self._items.move_to_end(key)
        while len(self._items) > self._max:
            self._items.popitem(last=False)


def _object(response: HttpResponse, what: str) -> dict[str, JSONValue]:
    try:
        document = response.json(max_depth=16)
    except NexusFlowError as exc:  # malformed or nested too deeply
        raise SsoProtocolError(f"{what}_not_json") from exc
    if not isinstance(document, dict):
        raise SsoProtocolError(f"{what}_not_object")
    return document


def _endpoint(document: Mapping[str, JSONValue], name: str) -> str:
    value = document.get(name)
    if not isinstance(value, str):
        raise SsoProtocolError("discovery_incomplete", internal_detail=f"missing {name}")
    try:
        return ISSUER_POLICY.validate(value).url
    except PolicyViolationError as exc:
        raise SsoProtocolError(
            "endpoint_not_allowed", internal_detail=f"{name}: {exc.code}"
        ) from exc


def _strings(value: JSONValue, *, limit: int = 20, max_length: int = 64) -> tuple[str, ...]:
    if not isinstance(value, list):
        return ()
    return tuple(
        item for item in value[:limit] if isinstance(item, str) and len(item) <= max_length
    )


class OidcClient:
    """Implements :class:`nexusflow.domain.identity.sso.OidcProvider`."""

    def __init__(
        self,
        http: SafeHttpClient,
        *,
        cache_seconds: float,
        leeway_seconds: int,
        max_response_bytes: int,
    ) -> None:
        self._http = http
        self._leeway = timedelta(seconds=leeway_seconds)
        self._max_bytes = max_response_bytes
        self._discovery: _TtlCache[ProviderMetadata] = _TtlCache(cache_seconds)
        self._jwks: _TtlCache[list[dict[str, Any]]] = _TtlCache(cache_seconds)

    # ------------------------------------------------------------ discovery

    async def metadata(self, issuer: str) -> ProviderMetadata:
        cached = self._discovery.get(issuer)
        if cached is not None:
            return cached
        response = await self._get(discovery_url(issuer))
        document = _object(response, "discovery")
        if document.get("issuer") != issuer:
            # The document must name exactly the configured issuer (OpenID
            # Connect Discovery 1.0, section 4.3): anything else is a different
            # provider, or a mix-up.
            raise SsoProtocolError("issuer_mismatch")
        methods = _strings(document.get("token_endpoint_auth_methods_supported"))
        metadata = ProviderMetadata(
            issuer=issuer,
            authorization_endpoint=_endpoint(document, "authorization_endpoint"),
            token_endpoint=_endpoint(document, "token_endpoint"),
            jwks_uri=_endpoint(document, "jwks_uri"),
            token_endpoint_auth_methods=methods or ("client_secret_basic",),
        )
        self._discovery.put(issuer, metadata)
        return metadata

    # ------------------------------------------------------------ code exchange

    async def exchange_code(
        self,
        metadata: ProviderMetadata,
        *,
        client_id: str,
        client_secret: str,
        code: str,
        redirect_uri: str,
        code_verifier: str,
    ) -> str:
        form = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": redirect_uri,
            "code_verifier": code_verifier,
        }
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/x-www-form-urlencoded",
        }
        method = next(
            (m for m in _SUPPORTED_CLIENT_AUTH if m in metadata.token_endpoint_auth_methods), None
        )
        if method == "client_secret_basic":
            # RFC 6749, section 2.3.1: both values form-encoded, then Basic.
            pair = f"{quote(client_id, safe='')}:{quote(client_secret, safe='')}"
            headers["Authorization"] = "Basic " + base64.b64encode(pair.encode()).decode("ascii")
        elif method == "client_secret_post":
            form["client_id"] = client_id
            form["client_secret"] = client_secret
        else:
            raise SsoProtocolError("unsupported_client_authentication")
        try:
            response = await self._http.request(
                "POST",
                metadata.token_endpoint,
                headers=headers,
                content=urlencode(form).encode("ascii"),
                follow_redirects=False,  # never carry the secret or the code elsewhere
                raise_for_status=False,
                max_bytes=_MAX_TOKEN_RESPONSE_BYTES,
            )
        except TransientError as exc:
            raise IdentityProviderUnavailableError(internal_detail=exc.code) from exc
        if response.status_code == 429 or response.status_code >= 500:
            raise IdentityProviderUnavailableError(internal_detail=f"HTTP {response.status_code}")
        if response.status_code != 200:
            raise SsoProtocolError(
                "code_exchange_refused", internal_detail=f"HTTP {response.status_code}"
            )
        if response.content_type not in _JSON_TYPES:
            raise SsoProtocolError("code_exchange_not_json")
        body = _object(response, "token_response")
        id_token = body.get("id_token")
        if not isinstance(id_token, str) or not id_token:
            raise SsoProtocolError("no_id_token")
        return id_token

    # ------------------------------------------------------------ ID tokens

    async def verify_id_token(
        self, id_token: str, metadata: ProviderMetadata, *, client_id: str, now: datetime
    ) -> IdTokenClaims:
        if len(id_token) > _MAX_ID_TOKEN_LENGTH:
            raise SsoProtocolError("id_token_too_large")
        try:
            header = jwt.get_unverified_header(id_token)
        except jwt.PyJWTError as exc:
            raise SsoProtocolError("id_token_malformed") from exc
        algorithm = header.get("alg")
        if not isinstance(algorithm, str) or algorithm not in ID_TOKEN_ALGORITHMS:
            raise SsoProtocolError("algorithm_not_allowed", internal_detail=f"alg={algorithm!r}")
        if "crit" in header:
            raise SsoProtocolError("unsupported_critical_header")
        kid = header.get("kid")
        if kid is not None and not isinstance(kid, str):
            raise SsoProtocolError("id_token_malformed", internal_detail="kid is not a string")
        key = await self._signing_key(metadata.jwks_uri, kid, algorithm)
        try:
            payload: dict[str, Any] = jwt.decode(
                id_token,
                key=key,
                algorithms=[algorithm],
                audience=client_id,
                issuer=metadata.issuer,
                options={
                    "require": ["iss", "aud", "sub", "exp", "iat"],
                    "verify_exp": False,  # checked below, against the platform clock
                    "verify_iat": False,
                    "verify_nbf": False,
                },
            )
        except jwt.InvalidAudienceError as exc:
            raise SsoProtocolError("audience_mismatch") from exc
        except jwt.InvalidIssuerError as exc:
            raise SsoProtocolError("issuer_mismatch") from exc
        except jwt.InvalidSignatureError as exc:
            raise SsoProtocolError("invalid_signature") from exc
        except jwt.PyJWTError as exc:
            raise SsoProtocolError("id_token_invalid", internal_detail=type(exc).__name__) from exc
        self._check_authorized_party(payload, client_id)
        self._check_times(payload, now)
        return _claims(payload)

    def _check_authorized_party(self, payload: Mapping[str, Any], client_id: str) -> None:
        audience = payload.get("aud")
        several = isinstance(audience, list) and len(audience) > 1
        azp = payload.get("azp")
        if (several or azp is not None) and azp != client_id:
            raise SsoProtocolError("authorized_party_mismatch")

    def _check_times(self, payload: Mapping[str, Any], now: datetime) -> None:
        def instant(name: str) -> datetime | None:
            raw = payload.get(name)
            if raw is None:
                return None
            if isinstance(raw, bool) or not isinstance(raw, (int, float)):
                raise SsoProtocolError("id_token_invalid", internal_detail=f"{name} not numeric")
            try:
                return datetime.fromtimestamp(float(raw), tz=UTC)
            except (OverflowError, OSError, ValueError) as exc:
                raise SsoProtocolError("id_token_invalid", internal_detail=name) from exc

        expires, issued, not_before = instant("exp"), instant("iat"), instant("nbf")
        if expires is None or issued is None:
            raise SsoProtocolError("id_token_invalid", internal_detail="exp/iat missing")
        if now >= expires + self._leeway:
            raise SsoProtocolError("id_token_expired")
        if issued > now + self._leeway or issued < now - _MAX_ID_TOKEN_AGE - self._leeway:
            raise SsoProtocolError("id_token_not_current", internal_detail="iat out of range")
        if not_before is not None and not_before > now + self._leeway:
            raise SsoProtocolError("id_token_not_yet_valid")

    # ------------------------------------------------------------ signing keys

    async def _signing_key(self, jwks_uri: str, kid: str | None, algorithm: str) -> Any:
        keys = self._jwks.get(jwks_uri)
        fetched = keys is None
        if keys is None:
            keys = await self._fetch_jwks(jwks_uri)
        candidates = _candidates(keys, kid, algorithm)
        if not candidates and kid is not None and not fetched:
            # Perhaps a rotated key: fetch the set again - once per token (the
            # callback's rate limit bounds how often that can happen).
            keys = await self._fetch_jwks(jwks_uri)
            candidates = _candidates(keys, kid, algorithm)
        if len(candidates) != 1:
            raise SsoProtocolError(
                "unknown_signing_key" if not candidates else "ambiguous_signing_key"
            )
        try:
            return jwt.PyJWK(candidates[0], algorithm=algorithm).key
        except jwt.PyJWTError as exc:
            raise SsoProtocolError("invalid_signing_key", internal_detail=str(exc)[:200]) from exc

    async def _fetch_jwks(self, jwks_uri: str) -> list[dict[str, Any]]:
        response = await self._get(jwks_uri)
        document = _object(response, "jwks")
        raw_keys = document.get("keys")
        if not isinstance(raw_keys, list):
            raise SsoProtocolError("jwks_invalid")
        keys = [key for key in raw_keys[:_MAX_KEYS] if isinstance(key, dict)]
        self._jwks.put(jwks_uri, keys)
        return keys

    async def _get(self, url: str) -> HttpResponse:
        try:
            response = await self._http.request(
                "GET",
                url,
                headers={"Accept": "application/json"},
                max_bytes=self._max_bytes,
                raise_for_status=False,
            )
        except TransientError as exc:
            raise IdentityProviderUnavailableError(internal_detail=exc.code) from exc
        if response.status_code == 429 or response.status_code >= 500:
            raise IdentityProviderUnavailableError(internal_detail=f"HTTP {response.status_code}")
        if response.status_code != 200:
            raise SsoProtocolError(
                "metadata_unavailable", internal_detail=f"HTTP {response.status_code}"
            )
        if response.content_type not in _JSON_TYPES:
            raise SsoProtocolError("metadata_not_json", internal_detail=str(response.content_type))
        return response


def _candidates(
    keys: list[dict[str, Any]], kid: str | None, algorithm: str
) -> list[dict[str, Any]]:
    """Signature keys that fit ``algorithm``: its key type (and curve), no other
    declared algorithm, not an encryption key - and the ``kid`` if one is named."""
    kty, crv = _KEY_TYPES[algorithm]
    found = []
    for key in keys:
        if key.get("kty") != kty or (crv is not None and key.get("crv") != crv):
            continue
        if key.get("alg") not in (None, algorithm):
            continue
        if key.get("use") not in (None, "sig"):
            continue
        operations = key.get("key_ops")
        if isinstance(operations, list) and "verify" not in operations:
            continue
        if kid is not None and key.get("kid") != kid:
            continue
        found.append(key)
    return found


def _text(payload: Mapping[str, Any], name: str, max_length: int) -> str | None:
    value = payload.get(name)
    if isinstance(value, str) and 0 < len(value) <= max_length:
        return value
    return None


def _claims(payload: Mapping[str, Any]) -> IdTokenClaims:
    subject = payload.get("sub")
    if not isinstance(subject, str) or not 0 < len(subject) <= 255:
        raise SsoProtocolError("id_token_invalid", internal_detail="sub")
    verified = payload.get("email_verified")
    if verified is None:
        # Microsoft Entra ID has no email_verified claim. Its optional xms_edov
        # says the address is in a domain the account's own tenant verified -
        # false for a guest whose home tenant set an address it does not own.
        verified = payload.get("xms_edov")
    # Some providers send the JSON string "true"; nothing else counts.
    email_verified = verified is True or (isinstance(verified, str) and verified.lower() == "true")
    amr = payload.get("amr")
    return IdTokenClaims(
        issuer=str(payload["iss"]),
        subject=subject,
        nonce=_text(payload, "nonce", 512),
        email=_text(payload, "email", 254),
        email_verified=email_verified,
        name=_text(payload, "name", 200),
        given_name=_text(payload, "given_name", 120),
        family_name=_text(payload, "family_name", 120),
        amr=_strings(amr, limit=20, max_length=32) if isinstance(amr, list) else (),
        hosted_domain=_text(payload, "hd", 253),
    )
