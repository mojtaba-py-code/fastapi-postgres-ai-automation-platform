"""EdDSA (Ed25519) JWTs with key rotation.

Security properties:

* Only ``EdDSA`` is accepted - ``alg=none``, HMAC/RSA confusion and algorithm
  downgrade are impossible because the verifier never consults the header's
  algorithm to select a key type.
* ``kid`` selects a verification key from a fixed keyring (no JWK/``jku`` URLs).
* A ``token_use`` claim separates access tokens from MFA challenge tokens so one
  can never be replayed as the other.
* Time claims are verified against the injected clock with a small leeway.
* Tokens larger than 4 KiB are rejected before any parsing.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any
from uuid import UUID

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from nexusflow.core.errors import AuthenticationError
from nexusflow.core.ids import parse_uuid, uuid7
from nexusflow.domain.identity.tokens import AccessTokenClaims, IssuedToken, MfaChallengeClaims

_ALGORITHM = "EdDSA"
_MAX_TOKEN_LENGTH = 4096
_ACCESS = "access"
_MFA = "mfa_challenge"


_MAX_PRIOR_FAILURES = 1000


def _invalid(code: str = "invalid_token") -> AuthenticationError:
    return AuthenticationError("The access token is invalid or expired.", code=code)


@dataclass(frozen=True, slots=True)
class JwtKeyRing:
    active_key_id: str
    private_key: Ed25519PrivateKey
    verification_keys: dict[str, Ed25519PublicKey]

    @classmethod
    def from_pem(
        cls, private_key_pem: str, key_id: str, previous_public_keys: dict[str, str]
    ) -> JwtKeyRing:
        pem = private_key_pem.replace("\\n", "\n").encode()
        private_key = serialization.load_pem_private_key(pem, password=None)
        if not isinstance(private_key, Ed25519PrivateKey):
            raise ValueError("JWT signing key must be an Ed25519 private key")
        keys: dict[str, Ed25519PublicKey] = {key_id: private_key.public_key()}
        for kid, public_pem in previous_public_keys.items():
            public_key = serialization.load_pem_public_key(public_pem.replace("\\n", "\n").encode())
            if not isinstance(public_key, Ed25519PublicKey):
                raise ValueError(f"verification key {kid!r} must be an Ed25519 public key")
            keys.setdefault(kid, public_key)
        return cls(active_key_id=key_id, private_key=private_key, verification_keys=keys)

    def public_jwks(self) -> list[dict[str, str]]:
        """Public keys in JWK form (for other services that verify tokens)."""
        jwks = []
        for kid, key in self.verification_keys.items():
            raw = key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
            jwks.append(
                {
                    "kty": "OKP",
                    "crv": "Ed25519",
                    "kid": kid,
                    "use": "sig",
                    "alg": _ALGORITHM,
                    "x": jwt.utils.base64url_encode(raw).decode(),
                }
            )
        return jwks


class JwtTokenCodec:
    def __init__(
        self,
        keyring: JwtKeyRing,
        *,
        issuer: str,
        audience: str,
        access_ttl_seconds: int,
        mfa_ttl_seconds: int,
        leeway_seconds: int = 30,
    ) -> None:
        self._keyring = keyring
        self._issuer = issuer
        self._audience = audience
        self._access_ttl = access_ttl_seconds
        self._mfa_ttl = mfa_ttl_seconds
        self._leeway = timedelta(seconds=leeway_seconds)

    # ----------------------------------------------------------------- access

    def issue_access_token(
        self,
        *,
        user_id: UUID,
        org_id: UUID | None,
        session_id: UUID,
        token_version: int,
        now: datetime,
    ) -> IssuedToken:
        claims: dict[str, Any] = {
            "sub": str(user_id),
            "sid": str(session_id),
            "ver": token_version,
        }
        if org_id is not None:
            claims["org"] = str(org_id)
        return self._encode(claims, token_use=_ACCESS, now=now, ttl=self._access_ttl)

    def decode_access_token(self, token: str, *, now: datetime) -> AccessTokenClaims:
        payload = self._decode(token, token_use=_ACCESS, now=now)
        user_id = _uuid_claim(payload, "sub")
        session_id = _uuid_claim(payload, "sid")
        org_raw = payload.get("org")
        org_id = _uuid_claim(payload, "org") if org_raw is not None else None
        version = payload.get("ver")
        if not isinstance(version, int) or isinstance(version, bool) or version < 0:
            raise _invalid()
        return AccessTokenClaims(
            user_id=user_id,
            org_id=org_id,
            session_id=session_id,
            token_version=version,
            token_id=str(payload["jti"]),
            issued_at=datetime.fromtimestamp(payload["iat"], tz=now.tzinfo),
            expires_at=datetime.fromtimestamp(payload["exp"], tz=now.tzinfo),
        )

    # -------------------------------------------------------------------- mfa

    def issue_mfa_challenge(
        self,
        *,
        user_id: UUID,
        org_id: UUID | None,
        now: datetime,
        prior_failures: int = 0,
        sso: bool = False,
    ) -> IssuedToken:
        claims: dict[str, Any] = {"sub": str(user_id)}
        if org_id is not None:
            claims["org"] = str(org_id)
        if prior_failures > 0:
            claims["pf"] = min(prior_failures, _MAX_PRIOR_FAILURES)
        if sso:
            if org_id is None:
                raise ValueError("a single sign-on challenge names its organization")
            claims["sso"] = True
        return self._encode(claims, token_use=_MFA, now=now, ttl=self._mfa_ttl)

    def decode_mfa_challenge(self, token: str, *, now: datetime) -> MfaChallengeClaims:
        payload = self._decode(token, token_use=_MFA, now=now)
        org_raw = payload.get("org")
        prior = payload.get("pf", 0)
        if not isinstance(prior, int) or isinstance(prior, bool) or not 0 <= prior <= 1000:
            raise _invalid()
        sso = payload.get("sso", False)
        if not isinstance(sso, bool) or (sso and org_raw is None):
            raise _invalid()
        return MfaChallengeClaims(
            user_id=_uuid_claim(payload, "sub"),
            org_id=_uuid_claim(payload, "org") if org_raw is not None else None,
            challenge_id=str(payload["jti"]),
            expires_at=datetime.fromtimestamp(payload["exp"], tz=now.tzinfo),
            prior_failures=prior,
            sso=sso,
        )

    # ---------------------------------------------------------------- helpers

    def _encode(
        self, claims: dict[str, Any], *, token_use: str, now: datetime, ttl: int
    ) -> IssuedToken:
        issued_at = int(now.timestamp())
        expires_at = issued_at + ttl
        payload = {
            **claims,
            "iss": self._issuer,
            "aud": self._audience,
            "iat": issued_at,
            "nbf": issued_at,
            "exp": expires_at,
            "jti": str(uuid7()),
            "token_use": token_use,
        }
        token = jwt.encode(
            payload,
            self._keyring.private_key,
            algorithm=_ALGORITHM,
            headers={"kid": self._keyring.active_key_id, "typ": "JWT"},
        )
        return IssuedToken(
            token=token,
            expires_at=datetime.fromtimestamp(expires_at, tz=now.tzinfo),
            expires_in=ttl,
        )

    def _decode(self, token: str, *, token_use: str, now: datetime) -> dict[str, Any]:
        if not token or len(token) > _MAX_TOKEN_LENGTH:
            raise _invalid()
        try:
            header = jwt.get_unverified_header(token)
        except jwt.PyJWTError as exc:
            raise _invalid() from exc
        kid = header.get("kid")
        if header.get("alg") != _ALGORITHM or not isinstance(kid, str):
            raise _invalid()
        key = self._keyring.verification_keys.get(kid)
        if key is None:
            raise _invalid()
        try:
            payload: dict[str, Any] = jwt.decode(
                token,
                key=key,
                algorithms=[_ALGORITHM],
                audience=self._audience,
                issuer=self._issuer,
                options={
                    "require": ["exp", "iat", "nbf", "iss", "aud", "sub", "jti"],
                    "verify_exp": False,
                    "verify_nbf": False,
                    "verify_iat": False,
                },
            )
        except jwt.PyJWTError as exc:
            raise _invalid() from exc
        if payload.get("token_use") != token_use:
            raise _invalid()
        self._verify_time(payload, now)
        return payload

    def _verify_time(self, payload: dict[str, Any], now: datetime) -> None:
        try:
            exp = datetime.fromtimestamp(float(payload["exp"]), tz=now.tzinfo)
            nbf = datetime.fromtimestamp(float(payload["nbf"]), tz=now.tzinfo)
            iat = datetime.fromtimestamp(float(payload["iat"]), tz=now.tzinfo)
        except (TypeError, ValueError, OverflowError) as exc:
            raise _invalid() from exc
        if now >= exp + self._leeway:
            raise _invalid("token_expired")
        if now + self._leeway < nbf or now + self._leeway < iat:
            raise _invalid()


def _uuid_claim(payload: dict[str, Any], name: str) -> UUID:
    raw = payload.get(name)
    value = parse_uuid(raw) if isinstance(raw, str) else None
    if value is None:
        raise _invalid()
    return value


def generate_ed25519_private_key_pem() -> str:
    """Helper for key provisioning scripts and tests."""
    key = Ed25519PrivateKey.generate()
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
