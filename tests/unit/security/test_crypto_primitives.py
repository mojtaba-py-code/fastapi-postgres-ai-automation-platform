from __future__ import annotations

import base64
import json
import os
from datetime import timedelta
from uuid import uuid4

import pytest

from nexusflow.core.clock import FrozenClock
from nexusflow.core.errors import AuthenticationError
from nexusflow.infrastructure.security.crypto import DecryptionError, EnvelopeCipher
from nexusflow.infrastructure.security.hashing import HmacTokenHasher, SecureTokenGenerator
from nexusflow.infrastructure.security.jwt_tokens import (
    JwtKeyRing,
    JwtTokenCodec,
    generate_ed25519_private_key_pem,
)
from nexusflow.infrastructure.security.passwords import Argon2idPasswordHasher
from nexusflow.infrastructure.security.totp import TotpService

pytestmark = pytest.mark.security


def _cipher(active: str = "k1", **keys: bytes) -> EnvelopeCipher:
    return EnvelopeCipher(keys or {"k1": os.urandom(32)}, active)


class TestEnvelopeCipher:
    def test_round_trip(self) -> None:
        cipher = _cipher()
        blob = cipher.encrypt("s3cr3t-value", context="org:1|integration:2")
        assert b"s3cr3t" not in blob
        assert cipher.decrypt(blob, context="org:1|integration:2") == "s3cr3t-value"

    def test_nonces_are_unique(self) -> None:
        cipher = _cipher()
        assert cipher.encrypt("x", context="c") != cipher.encrypt("x", context="c")

    def test_context_binding_prevents_ciphertext_swapping(self) -> None:
        cipher = _cipher()
        blob = cipher.encrypt("tenant-a-secret", context="org:A|integration:1")
        with pytest.raises(DecryptionError):
            cipher.decrypt(blob, context="org:B|integration:1")

    @pytest.mark.parametrize("position", [0, 5, 30, -1])
    def test_tampering_is_detected(self, position: int) -> None:
        cipher = _cipher()
        blob = bytearray(cipher.encrypt("value", context="c"))
        blob[position] ^= 0x01
        with pytest.raises(DecryptionError):
            cipher.decrypt(bytes(blob), context="c")

    def test_truncated_blob_rejected(self) -> None:
        cipher = _cipher()
        blob = cipher.encrypt("value", context="c")
        with pytest.raises(DecryptionError):
            cipher.decrypt(blob[:20], context="c")

    def test_key_rotation_and_rewrap(self) -> None:
        old_key, new_key = os.urandom(32), os.urandom(32)
        old = EnvelopeCipher({"k1": old_key}, "k1")
        blob = old.encrypt("rotate-me", context="ctx")
        rotated = EnvelopeCipher({"k1": old_key, "k2": new_key}, "k2")
        assert rotated.needs_rewrap(blob)
        rewrapped = rotated.rewrap(blob, context="ctx")
        assert rotated.key_id_of(rewrapped) == "k2"
        assert not rotated.needs_rewrap(rewrapped)
        # After re-wrapping, the old key can be retired.
        retired = EnvelopeCipher({"k2": new_key}, "k2")
        assert retired.decrypt(rewrapped, context="ctx") == "rotate-me"
        with pytest.raises(DecryptionError):
            retired.decrypt(blob, context="ctx")

    def test_rejects_short_keys(self) -> None:
        with pytest.raises(ValueError, match="32 bytes"):
            EnvelopeCipher({"k1": b"short"}, "k1")

    def test_from_config(self) -> None:
        keys = json.dumps({"kek-1": base64.b64encode(os.urandom(32)).decode()})
        cipher = EnvelopeCipher.from_config(keys, "kek-1")
        assert cipher.decrypt(cipher.encrypt("v", context="c"), context="c") == "v"


class TestHmacHasher:
    def test_hash_is_keyed_and_verifiable(self) -> None:
        a = HmacTokenHasher(os.urandom(32))
        b = HmacTokenHasher(os.urandom(32))
        token = SecureTokenGenerator().generate()
        assert a.verify(token, a.hash(token))
        assert a.hash(token) != b.hash(token)
        assert not a.verify(token + "x", a.hash(token))

    def test_rejects_weak_pepper(self) -> None:
        with pytest.raises(ValueError):
            HmacTokenHasher(b"too-short")

    def test_generator_enforces_entropy(self) -> None:
        with pytest.raises(ValueError):
            SecureTokenGenerator().generate(8)


class TestPasswordHasher:
    @pytest.fixture
    def hasher(self) -> Argon2idPasswordHasher:
        return Argon2idPasswordHasher(time_cost=1, memory_cost_kib=19_456, parallelism=1)

    async def test_hash_and_verify(self, hasher: Argon2idPasswordHasher) -> None:
        hashed = await hasher.hash("correct horse battery staple")
        assert hashed.startswith("$argon2id$")
        assert await hasher.verify(hashed, "correct horse battery staple")
        assert not await hasher.verify(hashed, "wrong password")

    async def test_garbage_hash_never_verifies(self, hasher: Argon2idPasswordHasher) -> None:
        assert not await hasher.verify("not-a-hash", "anything")
        assert hasher.needs_rehash("not-a-hash")

    async def test_parameter_upgrade_triggers_rehash(self, hasher: Argon2idPasswordHasher) -> None:
        hashed = await hasher.hash("pw-123456789012")
        stronger = Argon2idPasswordHasher(time_cost=2, memory_cost_kib=19_456, parallelism=1)
        assert stronger.needs_rehash(hashed)
        assert not hasher.needs_rehash(hashed)

    async def test_dummy_verify_runs(self, hasher: Argon2idPasswordHasher) -> None:
        await hasher.dummy_verify("whatever")


class TestJwt:
    @pytest.fixture
    def codec(self, jwt_private_key_pem: str) -> JwtTokenCodec:
        ring = JwtKeyRing.from_pem(jwt_private_key_pem, "k1", {})
        return JwtTokenCodec(
            ring, issuer="nf", audience="nf-api", access_ttl_seconds=600, mfa_ttl_seconds=300
        )

    def test_round_trip(self, codec: JwtTokenCodec, clock: FrozenClock) -> None:
        user, org, sid = uuid4(), uuid4(), uuid4()
        issued = codec.issue_access_token(
            user_id=user, org_id=org, session_id=sid, token_version=3, now=clock.now()
        )
        claims = codec.decode_access_token(issued.token, now=clock.now())
        assert (claims.user_id, claims.org_id, claims.session_id, claims.token_version) == (
            user,
            org,
            sid,
            3,
        )

    def test_expired_token_rejected(self, codec: JwtTokenCodec, clock: FrozenClock) -> None:
        issued = codec.issue_access_token(
            user_id=uuid4(), org_id=None, session_id=uuid4(), token_version=0, now=clock.now()
        )
        clock.advance(timedelta(seconds=600 + 31))
        with pytest.raises(AuthenticationError) as exc:
            codec.decode_access_token(issued.token, now=clock.now())
        assert exc.value.code == "token_expired"

    def test_mfa_challenge_cannot_be_used_as_access_token(
        self, codec: JwtTokenCodec, clock: FrozenClock
    ) -> None:
        challenge = codec.issue_mfa_challenge(user_id=uuid4(), org_id=None, now=clock.now())
        with pytest.raises(AuthenticationError):
            codec.decode_access_token(challenge.token, now=clock.now())

    def test_token_signed_by_unknown_key_rejected(
        self, codec: JwtTokenCodec, clock: FrozenClock
    ) -> None:
        other_ring = JwtKeyRing.from_pem(generate_ed25519_private_key_pem(), "k1", {})
        forger = JwtTokenCodec(
            other_ring, issuer="nf", audience="nf-api", access_ttl_seconds=600, mfa_ttl_seconds=300
        )
        forged = forger.issue_access_token(
            user_id=uuid4(), org_id=None, session_id=uuid4(), token_version=0, now=clock.now()
        ).token
        with pytest.raises(AuthenticationError):
            codec.decode_access_token(forged, now=clock.now())

    def test_alg_none_rejected(self, codec: JwtTokenCodec, clock: FrozenClock) -> None:
        header = base64.urlsafe_b64encode(b'{"alg":"none","kid":"k1"}').rstrip(b"=").decode()
        payload = (
            base64.urlsafe_b64encode(
                json.dumps({"sub": str(uuid4()), "token_use": "access"}).encode()
            )
            .rstrip(b"=")
            .decode()
        )
        with pytest.raises(AuthenticationError):
            codec.decode_access_token(f"{header}.{payload}.", now=clock.now())

    def test_hs256_confusion_rejected(self, codec: JwtTokenCodec, clock: FrozenClock) -> None:
        import jwt

        token = jwt.encode(
            {"sub": str(uuid4()), "token_use": "access"},
            "k" * 64,
            algorithm="HS256",
            headers={"kid": "k1"},
        )
        with pytest.raises(AuthenticationError):
            codec.decode_access_token(token, now=clock.now())

    def test_oversized_token_rejected(self, codec: JwtTokenCodec, clock: FrozenClock) -> None:
        with pytest.raises(AuthenticationError):
            codec.decode_access_token("a" * 5000, now=clock.now())

    def test_key_rotation_keeps_old_tokens_valid(self, clock: FrozenClock) -> None:
        old_pem = generate_ed25519_private_key_pem()
        old_codec = JwtTokenCodec(
            JwtKeyRing.from_pem(old_pem, "k1", {}),
            issuer="nf",
            audience="a",
            access_ttl_seconds=600,
            mfa_ttl_seconds=300,
        )
        token = old_codec.issue_access_token(
            user_id=uuid4(), org_id=None, session_id=uuid4(), token_version=0, now=clock.now()
        ).token
        old_public = old_codec._keyring.verification_keys["k1"]
        from cryptography.hazmat.primitives import serialization

        public_pem = old_public.public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode()
        new_codec = JwtTokenCodec(
            JwtKeyRing.from_pem(generate_ed25519_private_key_pem(), "k2", {"k1": public_pem}),
            issuer="nf",
            audience="a",
            access_ttl_seconds=600,
            mfa_ttl_seconds=300,
        )
        assert new_codec.decode_access_token(token, now=clock.now()).token_version == 0
        assert {k["kid"] for k in new_codec._keyring.public_jwks()} == {"k1", "k2"}


class TestTotp:
    def test_verify_and_replay_protection(self, clock: FrozenClock) -> None:
        import pyotp

        service = TotpService()
        secret = service.generate_secret()
        code = pyotp.TOTP(secret).at(clock.now())
        step = service.verify(secret, code, now=clock.now(), last_used_step=None)
        assert step is not None
        # The same code cannot be used twice.
        assert service.verify(secret, code, now=clock.now(), last_used_step=step) is None

    def test_rejects_malformed_codes(self, clock: FrozenClock) -> None:
        service = TotpService()
        secret = service.generate_secret()
        for bad in ("", "12345", "1234567", "abcdef", "12 34 5x"):
            assert service.verify(secret, bad, now=clock.now(), last_used_step=None) is None

    def test_rejects_codes_outside_window(self, clock: FrozenClock) -> None:
        import pyotp

        service = TotpService()
        secret = service.generate_secret()
        old_code = pyotp.TOTP(secret).at(clock.now() - timedelta(minutes=5))
        assert service.verify(secret, old_code, now=clock.now(), last_used_step=None) is None
