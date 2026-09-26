"""WebAuthn ceremony verification (``infrastructure.security.webauthn``).

Real responses from the software authenticator (tests/support/webauthn.py),
then one defect at a time: each must be refused, and for its own reason, so a
test cannot pass because something else broke first. The flows around the
verifier - challenges, ownership, counters, lockout - are tested end to end
through the API in tests/security/test_passkeys.py.
"""

from __future__ import annotations

import json
import os
from dataclasses import replace
from typing import Any

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from nexusflow.domain.identity.webauthn import (
    NewCredential,
    PasskeyRejectedError,
    RelyingParty,
    VerifiedAssertion,
)
from nexusflow.infrastructure.security.cbor import decode
from nexusflow.infrastructure.security.webauthn import StrictWebAuthnVerifier
from tests.support.cbor import encode
from tests.support.webauthn import (
    ALGORITHMS,
    AT,
    BS,
    ED,
    EDDSA,
    ES256,
    ORIGIN,
    RP_ID,
    RS256,
    UP,
    UV,
    SoftwareAuthenticator,
    assertion_response,
    attestation_response,
    authenticator_data,
    b64url,
    client_data,
    rp_id_hash,
)

pytestmark = pytest.mark.security

RP = RelyingParty(id=RP_ID, name="NexusFlow AI", origins=frozenset({ORIGIN}))
VERIFIER = StrictWebAuthnVerifier()


def _options(challenge: bytes) -> dict[str, Any]:
    return {"challenge": b64url(challenge), "user": {"id": b64url(os.urandom(64))}}


def _register(
    authenticator: SoftwareAuthenticator, issued: bytes, **overrides: Any
) -> NewCredential:
    credential = authenticator.attestation(_options(issued), **overrides)
    return VERIFIER.verify_registration(attestation_response(credential), challenge=issued, rp=RP)


def _refused_registration(
    reason: str, authenticator: SoftwareAuthenticator | None = None, **overrides: Any
) -> None:
    issued = overrides.pop("issued", None) or os.urandom(32)
    with pytest.raises(PasskeyRejectedError) as refused:
        _register(authenticator or SoftwareAuthenticator(), issued, **overrides)
    assert refused.value.reason == reason
    assert refused.value.code == "passkey_rejected"
    assert [detail.code for detail in refused.value.details] == [reason]


def _sign_in(
    authenticator: SoftwareAuthenticator,
    stored: NewCredential,
    issued: bytes,
    **overrides: Any,
) -> VerifiedAssertion:
    credential = authenticator.assertion({"challenge": b64url(issued)}, **overrides)
    return VERIFIER.verify_assertion(
        assertion_response(credential),
        challenge=issued,
        rp=RP,
        public_key=stored.public_key,
        algorithm=stored.algorithm,
    )


def _registered(algorithm: int = ES256) -> tuple[SoftwareAuthenticator, NewCredential]:
    authenticator = SoftwareAuthenticator(algorithm)
    return authenticator, _register(authenticator, os.urandom(32))


def _refused_sign_in(
    reason: str,
    authenticator: SoftwareAuthenticator,
    stored: NewCredential,
    **overrides: Any,
) -> None:
    with pytest.raises(PasskeyRejectedError) as refused:
        _sign_in(authenticator, stored, os.urandom(32), **overrides)
    assert refused.value.reason == reason


def _attestation_object(authenticator: SoftwareAuthenticator, **fields: Any) -> bytes:
    """An attestation object around a valid authenticator data, reshaped."""
    challenge = os.urandom(32)
    credential = authenticator.attestation(_options(challenge))
    valid = attestation_response(credential).attestation_object
    parts = decode(valid)
    assert isinstance(parts, dict)
    parts.update(fields)
    return encode({k: v for k, v in parts.items() if v is not None})


class TestRegistration:
    @pytest.mark.parametrize("algorithm", ALGORITHMS)
    def test_each_algorithm_registers_with_its_real_public_key(self, algorithm: int) -> None:
        authenticator = SoftwareAuthenticator(algorithm)
        stored = _register(authenticator, os.urandom(32))
        assert stored.algorithm == algorithm
        assert stored.credential_id == authenticator.credential_id
        assert stored.public_key == authenticator.key.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
        )
        assert (stored.sign_count, stored.backup_eligible, stored.backed_up) == (0, False, False)

    def test_the_backup_flags_are_recorded(self) -> None:
        synced = SoftwareAuthenticator(backup_eligible=True, backed_up=True)
        stored = _register(synced, os.urandom(32))
        assert (stored.backup_eligible, stored.backed_up) == (True, True)
        eligible = SoftwareAuthenticator(backup_eligible=True)
        assert _register(eligible, os.urandom(32)).backup_eligible

    def test_a_starting_counter_is_kept(self) -> None:
        stored = _register(SoftwareAuthenticator(sign_count=41), os.urandom(32))
        assert stored.sign_count == 41

    def test_unknown_client_data_members_are_ignored(self) -> None:
        _register(
            SoftwareAuthenticator(),
            os.urandom(32),
            client_members={
                "other_keys_can_be_added_here": "do not compare clientDataJSON against a template",
                "tokenBinding": {"status": "supported"},
            },
        )

    def test_extension_outputs_are_parsed_and_ignored(self) -> None:
        _register(
            SoftwareAuthenticator(),
            os.urandom(32),
            flags=UP | UV | AT | ED,
            extensions=encode({"credProtect": 2}),
        )


class TestRefusedClientData:
    def test_the_wrong_ceremony(self) -> None:
        _refused_registration("type_mismatch", kind="webauthn.get")

    def test_another_challenge(self) -> None:
        _refused_registration("challenge_mismatch", challenge=b64url(os.urandom(32)))

    @pytest.mark.parametrize("variant", ["padded", "standard_alphabet", "empty"])
    def test_a_non_canonical_or_empty_challenge(self, variant: str) -> None:
        issued = bytes([0xFB]) + os.urandom(31)  # "+" or "/" in standard base64
        encoded = {
            "padded": b64url(issued) + "=",
            "standard_alphabet": b64url(issued).replace("-", "+").replace("_", "/"),
            "empty": "",
        }[variant]
        _refused_registration("challenge_mismatch", issued=issued, challenge=encoded)

    @pytest.mark.parametrize(
        "origin",
        [
            "https://evil.example",
            f"{ORIGIN}/",
            f"http://{RP_ID}",
            f"https://www.{RP_ID}",
            f"{ORIGIN}:443",
            ORIGIN.upper(),
            "null",
        ],
    )
    def test_an_origin_that_is_not_allowed(self, origin: str) -> None:
        _refused_registration("origin_not_allowed", origin=origin)

    @pytest.mark.parametrize(
        "members",
        [{"crossOrigin": True}, {"topOrigin": "https://evil.example"}],
    )
    def test_a_cross_origin_frame(self, members: dict[str, Any]) -> None:
        _refused_registration("cross_origin", client_members=members)

    def test_token_binding_in_use(self) -> None:
        _refused_registration(
            "token_binding_unsupported",
            client_members={"tokenBinding": {"status": "present", "id": "AAAA"}},
        )

    @pytest.mark.parametrize(
        "members",
        [
            {"crossOrigin": "false"},
            {"crossOrigin": None},
            {"tokenBinding": "present"},
            {"tokenBinding": {"status": "unknown"}},
            {"type": 1},
            {"challenge": None},
            {"origin": ["https://nexusflow.test.example"]},
        ],
    )
    def test_members_of_the_wrong_type(self, members: dict[str, Any]) -> None:
        _refused_registration("client_data_invalid", client_members=members)

    @pytest.mark.parametrize(
        "raw",
        [
            pytest.param(b"", id="empty"),
            pytest.param(b"not json", id="not-json"),
            pytest.param(b"\xff\xfe{}", id="not-utf8"),
            pytest.param(b"[1, 2]", id="array"),
            pytest.param(b'"a string"', id="string"),
            pytest.param(b'{"type": "webauthn.create", "value": NaN}', id="nan"),
            pytest.param(b"\xef\xbb\xbf{}", id="byte-order-mark"),
            pytest.param(b'{"a":' * 5 + b"1" + b"}" * 5, id="too-deep"),
            pytest.param(b'{"pad": "' + b"x" * 4096 + b'"}', id="over-4-KiB"),
        ],
    )
    def test_client_data_that_is_not_one_small_json_object(self, raw: bytes) -> None:
        _refused_registration("client_data_invalid", client_data_json=raw)

    def test_duplicate_members(self) -> None:
        issued = os.urandom(32)
        raw = (
            '{"type":"webauthn.create","type":"webauthn.create",'
            f'"challenge":"{b64url(issued)}","origin":"{ORIGIN}"}}'
        ).encode()
        _refused_registration("client_data_invalid", issued=issued, client_data_json=raw)

    @pytest.mark.parametrize("missing", ["type", "challenge", "origin"])
    def test_a_missing_member(self, missing: str) -> None:
        issued = os.urandom(32)
        members = {"type": "webauthn.create", "challenge": b64url(issued), "origin": ORIGIN}
        del members[missing]
        raw = json.dumps(members).encode()
        _refused_registration("client_data_invalid", issued=issued, client_data_json=raw)


class TestRefusedAttestations:
    @pytest.mark.parametrize(
        ("fmt", "statement"),
        [
            ("packed", {"alg": -7, "sig": b"\x30\x06\x02\x01\x01\x02\x01\x01"}),  # self
            ("packed", {"alg": -7, "sig": b"s", "x5c": [b"certificate"]}),
            ("fido-u2f", {"sig": b"s", "x5c": [b"certificate"]}),
            ("tpm", {"ver": "2.0"}),
            ("android-key", {}),
            ("apple", {}),
            ("none", {"sig": b"s"}),  # "none" with a statement
        ],
    )
    def test_any_format_but_none(self, fmt: str, statement: dict[str, Any]) -> None:
        _refused_registration("attestation_format_unsupported", fmt=fmt, att_stmt=statement)

    @pytest.mark.parametrize(
        "fields",
        [
            {"authData": None},  # missing
            {"extra": 1},
            {"authData": "text, not bytes"},
            {"fmt": 1},
            {"attStmt": []},
            {"fmt": None},
        ],
    )
    def test_an_attestation_object_of_the_wrong_shape(self, fields: dict[str, Any]) -> None:
        authenticator = SoftwareAuthenticator()
        _refused_registration(
            "attestation_invalid",
            authenticator,
            attestation_object=_attestation_object(authenticator, **fields),
        )

    @pytest.mark.parametrize(
        "raw",
        [
            pytest.param(b"\x00", id="an-integer"),
            pytest.param(b"\xa0", id="an-empty-map"),
            pytest.param(encode(["fmt", "none"]), id="an-array"),
            pytest.param(
                encode({"fmt": "none", "attStmt": {}, "authData": b"\x00" * 37}) + b"\x00",
                id="trailing-bytes",
            ),
            pytest.param(b"\xbf\x63fmt\x64none\xff", id="indefinite-length"),
            pytest.param(b"\xa3\x63fmt\x64none\x63fmt\x64none\x68authData\x40", id="duplicate-key"),
            pytest.param(
                encode({"fmt": "none", "attStmt": {}, "authData": b"\x00" * (64 * 1024)}),
                id="over-64-KiB",
            ),
        ],
    )
    def test_an_attestation_object_that_is_not_strict_cbor(self, raw: bytes) -> None:
        _refused_registration("attestation_invalid", attestation_object=raw)


class TestRefusedAuthenticatorData:
    def test_another_relying_party(self) -> None:
        _refused_registration("rp_id_mismatch", rp_hash=rp_id_hash("evil.example"))

    def test_user_presence_is_required(self) -> None:
        _refused_registration("user_not_present", flags=UV | AT)

    def test_user_verification_is_required(self) -> None:
        _refused_registration("user_not_verified", flags=UP | AT)

    def test_a_registration_carries_a_credential(self) -> None:
        _refused_registration("credential_data_missing", flags=UP | UV)

    def test_backed_up_but_not_eligible(self) -> None:
        _refused_registration("backup_flags_invalid", flags=UP | UV | AT | BS)

    @pytest.mark.parametrize(
        ("flags", "extensions"),
        [
            (UP | UV | AT, b"\x00"),  # trailing bytes without the ED flag
            (UP | UV | AT | ED, b""),  # the ED flag without extensions
            (UP | UV | AT | ED, b"\xff"),
            (UP | UV | AT | ED, encode([1])),  # not a map
            (UP | UV | AT | ED, encode({1: 2})),  # not an identifier key
            (UP | UV | AT | ED, encode({"credProtect": 2}) + b"\x00"),
        ],
    )
    def test_anything_but_well_formed_extensions_after_the_credential(
        self, flags: int, extensions: bytes
    ) -> None:
        _refused_registration("authenticator_data_invalid", flags=flags, extensions=extensions)

    def test_authenticator_data_too_short(self) -> None:
        authenticator = SoftwareAuthenticator()
        raw = _attestation_object(authenticator, authData=b"\x00" * 36)
        _refused_registration("authenticator_data_invalid", authenticator, attestation_object=raw)

    def test_a_credential_id_longer_than_the_data(self) -> None:
        authenticator = SoftwareAuthenticator()
        auth_data = authenticator_data(
            flags=UP | UV | AT, attested=bytes(16) + (500).to_bytes(2, "big") + b"x" * 10
        )
        raw = _attestation_object(authenticator, authData=auth_data)
        _refused_registration("authenticator_data_invalid", authenticator, attestation_object=raw)

    @pytest.mark.parametrize("length", [0, 15, 1024])
    def test_a_credential_id_of_an_invalid_length(self, length: int) -> None:
        identifier = os.urandom(length)
        _refused_registration(
            "credential_id_invalid", credential_id=identifier, raw_id=identifier or b"\x00"
        )

    def test_a_raw_id_that_is_not_the_credential_id(self) -> None:
        _refused_registration("credential_id_invalid", raw_id=os.urandom(32))


def _ec2() -> dict[int, Any]:
    return SoftwareAuthenticator(ES256).cose_key()


class TestRefusedPublicKeys:
    @pytest.mark.parametrize("algorithm", [-35, -36, -37, -38, -39, -65535, -257 - 1, 0, 1])
    def test_an_algorithm_outside_the_allowlist(self, algorithm: int) -> None:
        _refused_registration("algorithm_not_allowed", public_key=_ec2() | {3: algorithm})

    @pytest.mark.parametrize(
        "key",
        [
            _ec2() | {3: "ES256"},  # the algorithm as text
            {1: 2, -1: 1, -2: b"x" * 32, -3: b"y" * 32},  # no algorithm at all
            _ec2() | {1: 1},  # an OKP key type with ES256
            _ec2() | {1: True},  # true is not 2, nor 1
            _ec2() | {-1: 2},  # P-384 with ES256
            _ec2() | {-2: b"\x01" * 31},
            _ec2() | {-3: b"\x01" * 33},
            _ec2() | {-2: b"\x01" * 32, -3: b"\x02" * 32},  # not on the curve
            _ec2() | {-4: b"\x01" * 32},  # a private key parameter
            {1: 2, 3: -7, -1: 1, -2: b"x" * 32},  # no y
            _ec2() | {-3: True},  # a compressed-point sign bit
        ],
    )
    def test_an_inconsistent_or_invalid_ec2_key(self, key: dict[int, Any]) -> None:
        _refused_registration("public_key_invalid", public_key=key)

    @pytest.mark.parametrize(
        "change",
        [
            {-1: 1},  # the P-256 curve with EdDSA
            {1: 2},  # EC2 with EdDSA
            {-2: b"\x01" * 31},
            {-3: b"\x01" * 32},  # an extra parameter
        ],
    )
    def test_an_inconsistent_okp_key(self, change: dict[int, Any]) -> None:
        authenticator = SoftwareAuthenticator(EDDSA)
        _refused_registration(
            "public_key_invalid", authenticator, public_key=authenticator.cose_key() | change
        )

    @pytest.mark.parametrize(
        "change",
        [
            {-2: b"\x03"},  # exponent 3
            {-2: b"\x00\x01\x00\x01"},  # a leading zero byte
            {-2: 65537},  # an integer, not bytes
            {-1: b"\x00" + b"\xff" * 256},
            {-1: b"\xc0" + b"\x00" * 255},  # an even modulus
            {-1: b"\xff" * 128},  # 1,024 bits
            {-1: b"\xff" * 513},  # 4,104 bits
            {1: 2},
            {-3: b"\x01"},
        ],
    )
    def test_an_invalid_rsa_key(self, change: dict[int, Any]) -> None:
        authenticator = SoftwareAuthenticator(RS256)
        _refused_registration(
            "public_key_invalid", authenticator, public_key=authenticator.cose_key() | change
        )

    @pytest.mark.parametrize(
        "raw",
        [
            encode([1, 2]),
            encode("key"),
            b"\xa5\x01",  # truncated
            b"\xa1\x01\xf9\x00\x00",  # a float
            b"\xbf\x01\x02\xff",  # indefinite length
        ],
    )
    def test_a_public_key_that_is_not_a_cose_map(self, raw: bytes) -> None:
        _refused_registration("public_key_invalid", public_key=raw)


class TestAssertions:
    @pytest.mark.parametrize("algorithm", ALGORITHMS)
    def test_each_algorithm_signs_in(self, algorithm: int) -> None:
        authenticator, stored = _registered(algorithm)
        first = _sign_in(authenticator, stored, os.urandom(32))
        second = _sign_in(authenticator, stored, os.urandom(32))
        assert (first.sign_count, second.sign_count) == (1, 2)
        assert (first.backup_eligible, first.backed_up) == (False, False)

    def test_the_backup_state_is_reported(self) -> None:
        authenticator = SoftwareAuthenticator(backup_eligible=True, backed_up=True)
        stored = _register(authenticator, os.urandom(32))
        verified = _sign_in(authenticator, stored, os.urandom(32))
        assert (verified.backup_eligible, verified.backed_up) == (True, True)

    def test_a_passkey_that_never_counts(self) -> None:
        authenticator = SoftwareAuthenticator(counting=False)
        stored = _register(authenticator, os.urandom(32))
        assert _sign_in(authenticator, stored, os.urandom(32)).sign_count == 0

    def test_the_wrong_ceremony(self) -> None:
        _refused_sign_in("type_mismatch", *_registered(), kind="webauthn.create")

    def test_another_challenge(self) -> None:
        _refused_sign_in("challenge_mismatch", *_registered(), challenge=b64url(os.urandom(32)))

    def test_another_origin(self) -> None:
        _refused_sign_in("origin_not_allowed", *_registered(), origin="https://evil.example")

    def test_another_relying_party(self) -> None:
        _refused_sign_in("rp_id_mismatch", *_registered(), rp_hash=rp_id_hash("evil.example"))

    def test_user_presence_is_required(self) -> None:
        _refused_sign_in("user_not_present", *_registered(), flags=UV)

    def test_user_verification_is_required(self) -> None:
        _refused_sign_in("user_not_verified", *_registered(), flags=UP)

    def test_backed_up_but_not_eligible(self) -> None:
        _refused_sign_in("backup_flags_invalid", *_registered(), flags=UP | UV | BS)

    def test_a_sign_in_carries_no_new_credential(self) -> None:
        authenticator, stored = _registered()
        _refused_sign_in(
            "credential_data_unexpected",
            authenticator,
            stored,
            flags=UP | UV | AT,
            attested=bytes(16) + (32).to_bytes(2, "big") + os.urandom(32),
        )

    @pytest.mark.parametrize(
        "overrides",
        [{"extensions": b"\x00"}, {"flags": UP | UV | ED}, {"extensions": b"\x00" * 4096}],
    )
    def test_authenticator_data_with_anything_after_it(self, overrides: dict[str, Any]) -> None:
        _refused_sign_in("authenticator_data_invalid", *_registered(), **overrides)

    @pytest.mark.parametrize("algorithm", ALGORITHMS)
    @pytest.mark.parametrize("tamper", ["authenticator_data", "client_data", "signature"])
    def test_anything_changed_after_signing(self, algorithm: int, tamper: str) -> None:
        _refused_sign_in("signature_invalid", *_registered(algorithm), tamper=tamper)

    @pytest.mark.parametrize("algorithm", ALGORITHMS)
    def test_a_signature_by_another_key(self, algorithm: int) -> None:
        authenticator, stored = _registered(algorithm)
        other = SoftwareAuthenticator(algorithm).key
        _refused_sign_in("signature_invalid", authenticator, stored, signing_key=other)

    @pytest.mark.parametrize("algorithm", ALGORITHMS)
    def test_a_signature_of_the_wrong_size(self, algorithm: int) -> None:
        authenticator, stored = _registered(algorithm)
        for signature in (b"\x00", b"\x30" * 513):
            _refused_sign_in("signature_invalid", authenticator, stored, signature=signature)

    def test_a_truncated_ed25519_or_rsa_signature(self) -> None:
        for algorithm in (EDDSA, RS256):
            authenticator, stored = _registered(algorithm)
            valid = authenticator.assertion({"challenge": b64url(os.urandom(32))})
            signature = assertion_response(valid).signature
            _refused_sign_in("signature_invalid", authenticator, stored, signature=signature[:-1])

    def test_an_ecdsa_signature_that_is_not_canonical_der(self) -> None:
        authenticator, stored = _registered(ES256)
        challenge = os.urandom(32)
        valid = assertion_response(authenticator.assertion({"challenge": b64url(challenge)}))

        def verify(signature: bytes) -> VerifiedAssertion:
            return VERIFIER.verify_assertion(
                replace(valid, signature=signature),
                challenge=challenge,
                rp=RP,
                public_key=stored.public_key,
                algorithm=stored.algorithm,
            )

        assert verify(valid.signature).sign_count == 1  # the DER form itself verifies
        der = valid.signature
        # SEQUENCE { INTEGER r, INTEGER s }, with r given a redundant leading zero.
        r_length = der[3]
        body = bytes([0x02, r_length + 1, 0x00]) + der[4 : 4 + r_length] + der[4 + r_length :]
        for signature in (bytes([0x30, len(body)]) + body, der + bytes(1)):
            with pytest.raises(PasskeyRejectedError) as refused:
                verify(signature)
            assert refused.value.reason == "signature_invalid"

    @pytest.mark.parametrize(
        ("stored_key", "algorithm"),
        [
            pytest.param("garbage", ES256, id="not-a-key"),
            pytest.param("ed25519", ES256, id="ed25519-as-es256"),
            pytest.param("p384", ES256, id="p384-as-es256"),
            pytest.param("p256", RS256, id="p256-as-rs256"),
            pytest.param("rsa1024", RS256, id="rsa-1024"),
        ],
    )
    def test_a_stored_key_that_does_not_match_its_algorithm(
        self, stored_key: str, algorithm: int
    ) -> None:
        keys = {
            "ed25519": Ed25519PrivateKey.generate(),
            "p384": ec.generate_private_key(ec.SECP384R1()),
            "p256": ec.generate_private_key(ec.SECP256R1()),
            "rsa1024": rsa.generate_private_key(public_exponent=65537, key_size=1024),  # noqa: S505
        }
        public_key = (
            keys[stored_key]
            .public_key()
            .public_bytes(
                serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
            )
            if stored_key in keys
            else b"not a key"
        )
        authenticator = SoftwareAuthenticator(ES256)
        challenge = os.urandom(32)
        response = assertion_response(authenticator.assertion({"challenge": b64url(challenge)}))
        with pytest.raises(PasskeyRejectedError) as refused:
            VERIFIER.verify_assertion(
                response, challenge=challenge, rp=RP, public_key=public_key, algorithm=algorithm
            )
        assert refused.value.reason == "public_key_invalid"

    def test_client_data_is_checked_before_anything_else(self) -> None:
        authenticator, stored = _registered()
        raw = client_data("webauthn.get", b64url(os.urandom(32)), ORIGIN)
        _refused_sign_in("challenge_mismatch", authenticator, stored, client_data_json=raw)
