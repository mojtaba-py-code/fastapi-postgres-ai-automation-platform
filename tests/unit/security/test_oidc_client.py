"""The OpenID Connect client: discovery, key sets, code exchange and ID token
verification against an in-process identity provider (tests/support/oidc.py).

Every refusal the specification demands is exercised: a discovery document
for another issuer, endpoints that are not public HTTPS, ``alg: none``, HS256
signed with the provider's public key, a key of the wrong type for the header's
algorithm, a wrong audience, several audiences without ``azp``, an ``azp`` for
another client, expired or not yet valid tokens, a forged signature - and an
issuer whose name resolves to a private address, which the SSRF guard stops
before any connection is made.
"""

from __future__ import annotations

import hashlib
import ipaddress
import time
from datetime import UTC, datetime
from typing import Any

import pytest

from nexusflow.core.errors import PolicyViolationError
from nexusflow.domain.identity.sso import ProviderMetadata, SsoProtocolError
from nexusflow.domain.shared.url_policy import IPAddress, UrlPolicy
from nexusflow.infrastructure.http.client import HttpClientLimits, SafeHttpClient
from nexusflow.infrastructure.sso.dns import DohTxtResolver, _txt_value
from nexusflow.infrastructure.sso.oidc import IdentityProviderUnavailableError, OidcClient
from tests.support.oidc import (
    RESOLVER_URL,
    FakeIdp,
    FakeNetwork,
    b64url,
    hmac_token,
    public_pem,
    unsigned_token,
)

pytestmark = pytest.mark.security


def _client(network: FakeNetwork, *, cache_seconds: float = 0) -> OidcClient:
    return OidcClient(
        network.client(),
        cache_seconds=cache_seconds,
        leeway_seconds=60,
        max_response_bytes=512 * 1024,
    )


def _now() -> datetime:
    return datetime.now(UTC)


@pytest.fixture
def net() -> FakeNetwork:
    return FakeNetwork()


@pytest.fixture
def idp(net: FakeNetwork) -> FakeIdp:
    return net.add(FakeIdp())


async def _verify(
    client: OidcClient, idp: FakeIdp, token: str, *, client_id: str | None = None
) -> Any:
    metadata = await client.metadata(idp.issuer)
    return await client.verify_id_token(
        token, metadata, client_id=client_id or idp.client_id, now=_now()
    )


async def _refused(client: OidcClient, idp: FakeIdp, token: str) -> str:
    with pytest.raises(SsoProtocolError) as exc:
        await _verify(client, idp, token)
    return exc.value.reason


class TestDiscovery:
    async def test_the_document_is_used_when_it_names_exactly_the_issuer(
        self, net: FakeNetwork, idp: FakeIdp
    ) -> None:
        metadata = await _client(net).metadata(idp.issuer)
        assert metadata.issuer == idp.issuer
        assert metadata.token_endpoint == f"https://{idp.host}/token"
        assert metadata.authorization_endpoint == f"https://{idp.host}/authorize?tenant=t1"
        assert metadata.token_endpoint_auth_methods == ("client_secret_basic",)

    @pytest.mark.parametrize(
        "published",
        [
            "https://evil.example.com",
            "{issuer}/",
            "{issuer}/other",
            "HTTPS://{host}",
        ],
    )
    async def test_a_document_for_another_issuer_is_refused(
        self, net: FakeNetwork, idp: FakeIdp, published: str
    ) -> None:
        idp.discovery_overrides["issuer"] = published.format(issuer=idp.issuer, host=idp.host)
        with pytest.raises(SsoProtocolError) as exc:
            await _client(net).metadata(idp.issuer)
        assert exc.value.reason == "issuer_mismatch"

    @pytest.mark.parametrize(
        ("field", "value"),
        [
            ("token_endpoint", "http://{host}/token"),
            ("jwks_uri", "https://10.0.0.8/jwks"),
            ("authorization_endpoint", "https://localhost/authorize"),
            ("token_endpoint", "https://{host}:8443/token"),
            ("jwks_uri", "https://user:pw@{host}/jwks"),
        ],
    )
    async def test_endpoints_must_be_public_https_on_the_standard_port(
        self, net: FakeNetwork, idp: FakeIdp, field: str, value: str
    ) -> None:
        idp.discovery_overrides[field] = value.format(host=idp.host)
        with pytest.raises(SsoProtocolError) as exc:
            await _client(net).metadata(idp.issuer)
        assert exc.value.reason == "endpoint_not_allowed"

    async def test_a_missing_endpoint_is_refused(self, net: FakeNetwork, idp: FakeIdp) -> None:
        idp.discovery_overrides["jwks_uri"] = None
        with pytest.raises(SsoProtocolError) as exc:
            await _client(net).metadata(idp.issuer)
        assert exc.value.reason == "discovery_incomplete"

    async def test_no_document_at_all_is_refused(self, net: FakeNetwork) -> None:
        with pytest.raises(SsoProtocolError) as exc:
            await _client(net).metadata("https://nobody-here.example.com")
        assert exc.value.reason == "metadata_unavailable"

    async def test_documents_and_keys_are_cached_briefly(
        self, net: FakeNetwork, idp: FakeIdp
    ) -> None:
        client = _client(net, cache_seconds=300)
        for _ in range(3):
            await _verify(client, idp, idp.sign(idp.claims("n")))
        assert sum("openid-configuration" in r for r in net.requests) == 1
        assert idp.jwks_fetches == 1

    async def test_an_issuer_resolving_to_a_private_address_is_never_contacted(self) -> None:
        # The real SSRF-guarded transport: DNS says 10.x, the connection is refused
        # before it is opened (and every answer is checked, not only the first).
        class Resolver:
            async def resolve(self, host: str, port: int) -> list[IPAddress]:
                return [ipaddress.ip_address("93.184.216.34"), ipaddress.ip_address("10.1.2.3")]

        http = SafeHttpClient(
            policy=UrlPolicy(allow_http=False, allowed_ports=frozenset({443})),
            user_agent="nexusflow-tests",
            limits=HttpClientLimits(connect_timeout_seconds=2, total_timeout_seconds=5),
            resolver=Resolver(),
        )
        client = OidcClient(http, cache_seconds=0, leeway_seconds=60, max_response_bytes=65536)
        try:
            with pytest.raises(PolicyViolationError) as exc:
                await client.metadata("https://idp.internal-looking.example.com")
            assert exc.value.code == "address_not_allowed"
        finally:
            await http.aclose()


class TestIdTokens:
    @pytest.mark.parametrize("algorithm", ["RS256", "PS256", "ES256", "EdDSA"])
    async def test_every_allowed_algorithm_verifies(
        self, net: FakeNetwork, idp: FakeIdp, algorithm: str
    ) -> None:
        kid = idp.add_key(algorithm, kid=f"key-{algorithm.lower()}")
        claims = await _verify(
            _client(net), idp, idp.sign(idp.claims("n-1", amr=["pwd", "mfa"]), kid=kid)
        )
        assert (claims.nonce, claims.email_verified, claims.amr) == ("n-1", True, ("pwd", "mfa"))

    async def test_alg_none_is_refused(self, net: FakeNetwork, idp: FakeIdp) -> None:
        assert await _refused(_client(net), idp, unsigned_token(idp.claims("n"))) == (
            "algorithm_not_allowed"
        )

    async def test_hs256_signed_with_the_public_key_is_refused(
        self, net: FakeNetwork, idp: FakeIdp
    ) -> None:
        # The classic confusion: an HMAC "signature" keyed with the RSA public
        # key, which anyone can fetch from the provider's JWKS.
        forged = hmac_token(idp.claims("n"), public_pem(idp.keys["rsa-1"][0]), kid="rsa-1")
        assert await _refused(_client(net), idp, forged) == "algorithm_not_allowed"

    async def test_a_key_is_never_used_with_another_algorithm_family(
        self, net: FakeNetwork, idp: FakeIdp
    ) -> None:
        # EdDSA in the header, the RSA key's kid: no key of that type is chosen.
        idp.add_key("EdDSA", kid="ed-1", publish=False)
        token = idp.sign(idp.claims("n"), kid="ed-1", header={"kid": "rsa-1"})
        assert await _refused(_client(net), idp, token) == "unknown_signing_key"

    async def test_a_forged_signature_is_refused(self, net: FakeNetwork, idp: FakeIdp) -> None:
        token = idp.sign(idp.claims("n"))
        head, payload, signature = token.split(".")
        tampered = f"{head}.{payload}.{signature[:-4]}AAAA"
        assert await _refused(_client(net), idp, tampered) == "invalid_signature"

    async def test_a_token_signed_by_another_key_with_the_same_kid_is_refused(
        self, net: FakeNetwork, idp: FakeIdp
    ) -> None:
        impostor = FakeIdp()  # its own rsa-1: same kid, different key
        token = impostor.sign(idp.claims("n"))
        assert await _refused(_client(net), idp, token) == "invalid_signature"

    @pytest.mark.parametrize(
        ("overrides", "reason"),
        [
            ({"aud": "someone-else"}, "audience_mismatch"),
            ({"iss": "https://evil.example.com"}, "issuer_mismatch"),
            ({"exp": int(time.time()) - 3600}, "id_token_expired"),
            ({"iat": int(time.time()) + 3600}, "id_token_not_current"),
            ({"iat": int(time.time()) - 7200}, "id_token_not_current"),
            ({"nbf": int(time.time()) + 3600}, "id_token_not_yet_valid"),
            ({"sub": None}, "id_token_invalid"),
            ({"exp": None}, "id_token_invalid"),
            ({"exp": "tomorrow"}, "id_token_invalid"),
        ],
    )
    async def test_claims_are_checked_strictly(
        self, net: FakeNetwork, idp: FakeIdp, overrides: dict[str, Any], reason: str
    ) -> None:
        token = idp.sign(idp.claims("n", **overrides))
        assert await _refused(_client(net), idp, token) == reason

    async def test_several_audiences_need_the_client_as_authorized_party(
        self, net: FakeNetwork, idp: FakeIdp
    ) -> None:
        client = _client(net)
        audiences = [idp.client_id, "another-client"]
        without = idp.sign(idp.claims("n", aud=audiences))
        assert await _refused(client, idp, without) == "authorized_party_mismatch"
        wrong = idp.sign(idp.claims("n", aud=audiences, azp="another-client"))
        assert await _refused(client, idp, wrong) == "authorized_party_mismatch"
        right = idp.sign(idp.claims("n", aud=audiences, azp=idp.client_id))
        assert (await _verify(client, idp, right)).subject

    async def test_an_authorized_party_for_another_client_is_refused(
        self, net: FakeNetwork, idp: FakeIdp
    ) -> None:
        token = idp.sign(idp.claims("n", azp="another-client"))
        assert await _refused(_client(net), idp, token) == "authorized_party_mismatch"

    async def test_a_small_clock_difference_is_tolerated(
        self, net: FakeNetwork, idp: FakeIdp
    ) -> None:
        now = int(time.time())
        token = idp.sign(idp.claims("n", iat=now + 30, nbf=now + 30, exp=now - 30))
        assert (await _verify(_client(net), idp, token)).subject

    async def test_an_unknown_kid_fetches_the_keys_again_once(
        self, net: FakeNetwork, idp: FakeIdp
    ) -> None:
        client = _client(net, cache_seconds=300)
        await _verify(client, idp, idp.sign(idp.claims("n")))
        assert idp.jwks_fetches == 1
        # The provider rotated its key: the cached set is fetched again, once.
        idp.add_key("ES256", kid="rotated")
        await _verify(client, idp, idp.sign(idp.claims("n"), kid="rotated"))
        assert idp.jwks_fetches == 2
        await _verify(client, idp, idp.sign(idp.claims("n"), kid="rotated"))
        assert idp.jwks_fetches == 2  # cached again
        # A kid the provider never publishes: one more fetch, then refused.
        idp.add_key("RS256", kid="never-published", publish=False)
        token = idp.sign(idp.claims("n"), kid="never-published")
        assert await _refused(client, idp, token) == "unknown_signing_key"
        assert idp.jwks_fetches == 3

    async def test_without_a_kid_only_a_single_fitting_key_is_used(
        self, net: FakeNetwork, idp: FakeIdp
    ) -> None:
        client = _client(net)
        assert (await _verify(client, idp, idp.sign(idp.claims("n"), with_kid=False))).subject
        idp.add_key("RS256", kid="rsa-2")
        token = idp.sign(idp.claims("n"), with_kid=False)
        assert await _refused(client, idp, token) == "ambiguous_signing_key"

    async def test_critical_header_extensions_are_refused(
        self, net: FakeNetwork, idp: FakeIdp
    ) -> None:
        token = idp.sign(idp.claims("n"), header={"crit": ["exp"], "exp": 1})
        # PyJWT already refuses unknown critical extensions while reading the
        # header; the client's own check stays as a second line.
        assert await _refused(_client(net), idp, token) in {
            "id_token_malformed",
            "unsupported_critical_header",
        }

    async def test_an_encryption_key_never_verifies(self, net: FakeNetwork, idp: FakeIdp) -> None:
        original = idp.jwks

        def enc_only() -> dict[str, Any]:
            document = original()
            for key in document["keys"]:
                key["use"] = "enc"
            return document

        idp.jwks = enc_only  # type: ignore[method-assign]
        assert await _refused(_client(net), idp, idp.sign(idp.claims("n"))) == (
            "unknown_signing_key"
        )

    @pytest.mark.parametrize(("value", "verified"), [(True, True), ("true", True), (False, False)])
    async def test_email_verified_must_be_true(
        self, net: FakeNetwork, idp: FakeIdp, value: object, verified: bool
    ) -> None:
        claims = await _verify(_client(net), idp, idp.sign(idp.claims("n", email_verified=value)))
        assert claims.email_verified is verified

    @pytest.mark.parametrize(
        ("overrides", "verified"),
        [
            ({"email_verified": None, "xms_edov": True}, True),
            ({"email_verified": None, "xms_edov": "true"}, True),
            ({"email_verified": None, "xms_edov": False}, False),
            ({"email_verified": None}, False),
            ({"email_verified": False, "xms_edov": True}, False),  # an explicit "no" wins
        ],
    )
    async def test_entra_ids_domain_verified_claim_stands_in_for_email_verified(
        self, net: FakeNetwork, idp: FakeIdp, overrides: dict[str, object], verified: bool
    ) -> None:
        # Review R14-2: Microsoft Entra ID sends xms_edov, never email_verified.
        claims = await _verify(_client(net), idp, idp.sign(idp.claims("n", **overrides)))
        assert claims.email_verified is verified

    async def test_googles_hosted_domain_is_read(self, net: FakeNetwork, idp: FakeIdp) -> None:
        client = _client(net)
        managed = await _verify(client, idp, idp.sign(idp.claims("n", hd="example.com")))
        personal = await _verify(client, idp, idp.sign(idp.claims("n")))
        assert (managed.hosted_domain, personal.hosted_domain) == ("example.com", None)

    async def test_an_oversized_token_is_refused_before_parsing(
        self, net: FakeNetwork, idp: FakeIdp
    ) -> None:
        token = idp.sign(idp.claims("n", padding="x" * 20_000))
        assert await _refused(_client(net), idp, token) == "id_token_too_large"


class TestCodeExchange:
    async def _exchange(self, client: OidcClient, idp: FakeIdp, code: str) -> str:
        metadata = await client.metadata(idp.issuer)
        return await client.exchange_code(
            metadata,
            client_id=idp.client_id,
            client_secret=idp.client_secret,
            code=code,
            redirect_uri="https://nexusflow.test.example/sso/callback",
            code_verifier="v" * 64,
        )

    def _code(self, idp: FakeIdp) -> str:
        challenge = b64url(hashlib.sha256(b"v" * 64).digest())
        url = (
            f"https://{idp.host}/authorize?response_type=code&client_id={idp.client_id}"
            "&redirect_uri=https%3A%2F%2Fnexusflow.test.example%2Fsso%2Fcallback"
            f"&scope=openid+email+profile&state={'s' * 43}&nonce={'n' * 43}"
            f"&code_challenge={challenge}&code_challenge_method=S256"
        )
        return idp.authorize(url, id_token="id.token.value")

    async def test_the_client_authenticates_with_http_basic_and_sends_the_verifier(
        self, net: FakeNetwork, idp: FakeIdp
    ) -> None:
        idp.client_secret = "sec:ret/with+symbols"  # form-encoded before Basic (RFC 6749)
        assert await self._exchange(_client(net), idp, self._code(idp)) == "id.token.value"
        [request] = idp.token_requests
        assert request["headers"]["authorization"].startswith("Basic ")
        assert "client_secret" not in request["form"]
        assert request["form"]["code_verifier"] == "v" * 64

    async def test_client_secret_post_when_it_is_all_the_provider_takes(
        self, net: FakeNetwork, idp: FakeIdp
    ) -> None:
        idp.auth_methods = ("client_secret_post",)
        await self._exchange(_client(net), idp, self._code(idp))
        [request] = idp.token_requests
        assert "authorization" not in request["headers"]
        assert request["form"]["client_secret"] == idp.client_secret

    async def test_other_client_authentication_methods_are_refused(
        self, net: FakeNetwork, idp: FakeIdp
    ) -> None:
        idp.auth_methods = ("private_key_jwt",)
        with pytest.raises(SsoProtocolError) as exc:
            await self._exchange(_client(net), idp, self._code(idp))
        assert exc.value.reason == "unsupported_client_authentication"
        assert idp.token_requests == []  # nothing sent

    async def test_a_refused_or_replayed_code_is_a_protocol_error(
        self, net: FakeNetwork, idp: FakeIdp
    ) -> None:
        client = _client(net)
        code = self._code(idp)
        await self._exchange(client, idp, code)
        with pytest.raises(SsoProtocolError) as exc:
            await self._exchange(client, idp, code)  # codes are single-use at the provider
        assert exc.value.reason == "code_exchange_refused"

    async def test_an_outage_is_temporary(self, net: FakeNetwork, idp: FakeIdp) -> None:
        idp.token_status = 503
        with pytest.raises(IdentityProviderUnavailableError):
            await self._exchange(_client(net), idp, self._code(idp))

    async def test_a_redirect_from_the_token_endpoint_is_not_followed(
        self, net: FakeNetwork, idp: FakeIdp
    ) -> None:
        idp.token_status = 302
        with pytest.raises(SsoProtocolError) as exc:
            await self._exchange(_client(net), idp, self._code(idp))
        assert exc.value.reason == "code_exchange_refused"
        assert sum(r.startswith("POST") for r in net.requests) == 1


class TestDomainRecords:
    def test_txt_strings_are_joined_and_unquoted(self) -> None:
        assert _txt_value('"nexusflow-verification=" "abc\\"d"') == 'nexusflow-verification=abc"d'
        assert _txt_value("plain-value") == "plain-value"

    async def test_records_are_read_and_absence_proves_nothing(self, net: FakeNetwork) -> None:
        resolver = DohTxtResolver(net.client(), resolver_url=RESOLVER_URL)
        net.publish_txt("_nexusflow-verification.example.org", "nexusflow-verification=abc")
        assert await resolver.txt_records("_nexusflow-verification.example.org") == [
            "nexusflow-verification=abc"
        ]
        assert await resolver.txt_records("_nexusflow-verification.example.net") == []

    async def test_a_resolver_outage_is_temporary(self, net: FakeNetwork) -> None:
        net.resolver_down = True
        resolver = DohTxtResolver(net.client(), resolver_url=RESOLVER_URL)
        with pytest.raises(IdentityProviderUnavailableError):
            await resolver.txt_records("_nexusflow-verification.example.org")


def test_provider_metadata_defaults_to_basic_authentication() -> None:
    metadata = ProviderMetadata(
        issuer="https://idp.example.com",
        authorization_endpoint="https://idp.example.com/a",
        token_endpoint="https://idp.example.com/t",
        jwks_uri="https://idp.example.com/k",
    )
    assert metadata.token_endpoint_auth_methods == ("client_secret_basic",)
