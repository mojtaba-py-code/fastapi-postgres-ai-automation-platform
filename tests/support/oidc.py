"""An in-process OpenID Provider (and DNS-over-HTTPS resolver) for the SSO tests.

:class:`FakeNetwork` answers every outbound request of the SSO client through an
``httpx2.MockTransport``: each :class:`FakeIdp` serves its discovery document,
key set (JWKS) and token endpoint, and the resolver serves TXT records. Nothing
leaves the process.

:meth:`FakeIdp.authorize` plays the browser and the provider's login page: it
checks the authorization request the platform built (client, redirect URI,
PKCE S256, state, nonce) and returns the code the provider would redirect with.
Its token endpoint verifies the client credentials and the PKCE verifier
before it hands out the ID token prepared for that code - signed with a key
generated here by ``cryptography`` (or forged, for the negative tests).
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import parse_qs, parse_qsl, unquote, urlsplit
from uuid import uuid4

import httpx2
import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa

from nexusflow.bootstrap.container import Container
from nexusflow.core.clock import Clock
from nexusflow.domain.audit.recorder import AuditRecorder
from nexusflow.domain.identity.sso_service import SsoPolicy, SsoService
from nexusflow.domain.shared.url_policy import UrlPolicy
from nexusflow.infrastructure.http.client import HttpClientLimits, SafeHttpClient
from nexusflow.infrastructure.security.hashing import SecureTokenGenerator
from nexusflow.infrastructure.sso.dns import DohTxtResolver
from nexusflow.infrastructure.sso.oidc import OidcClient
from tests.support.api import ApiSession

RESOLVER_URL = "https://dns.resolver-test.example.com/dns-query"

type PrivateKey = rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey | ed25519.Ed25519PrivateKey


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


class _Streamed(httpx2.AsyncByteStream):
    """A lazily streamed body, as a real transport produces (the client reads
    the raw stream with a size cap)."""

    def __init__(self, body: bytes) -> None:
        self._body = body

    async def __aiter__(self):  # type: ignore[override]
        yield self._body


def respond(
    status: int, body: bytes = b"", content_type: str | None = None, **headers: str
) -> httpx2.Response:
    fields = {k.replace("_", "-"): v for k, v in headers.items()}
    if content_type is not None:
        fields["content-type"] = content_type
    return httpx2.Response(status, headers=fields, stream=_Streamed(body))


def _json(value: Any, status: int = 200, content_type: str = "application/json") -> httpx2.Response:
    return respond(status, json.dumps(value).encode(), content_type)


def _new_key(algorithm: str) -> PrivateKey:
    if algorithm in ("RS256", "PS256"):
        return rsa.generate_private_key(public_exponent=65537, key_size=2048)
    if algorithm == "ES256":
        return ec.generate_private_key(ec.SECP256R1())
    if algorithm == "EdDSA":
        return ed25519.Ed25519PrivateKey.generate()
    raise ValueError(algorithm)


def _public_jwk(key: PrivateKey, kid: str, algorithm: str) -> dict[str, Any]:
    public = key.public_key()
    if isinstance(public, rsa.RSAPublicKey):
        numbers = public.public_numbers()
        return {
            "kty": "RSA",
            "kid": kid,
            "alg": algorithm,
            "use": "sig",
            "n": b64url(numbers.n.to_bytes((numbers.n.bit_length() + 7) // 8, "big")),
            "e": b64url(numbers.e.to_bytes((numbers.e.bit_length() + 7) // 8, "big")),
        }
    if isinstance(public, ec.EllipticCurvePublicKey):
        numbers_ec = public.public_numbers()
        return {
            "kty": "EC",
            "crv": "P-256",
            "kid": kid,
            "alg": algorithm,
            "use": "sig",
            "x": b64url(numbers_ec.x.to_bytes(32, "big")),
            "y": b64url(numbers_ec.y.to_bytes(32, "big")),
        }
    raw = public.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return {
        "kty": "OKP",
        "crv": "Ed25519",
        "kid": kid,
        "alg": algorithm,
        "use": "sig",
        "x": b64url(raw),
    }


def public_pem(key: PrivateKey) -> bytes:
    return key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )


def unsigned_token(claims: dict[str, Any]) -> str:
    """``alg: none`` - no signature at all."""
    header = b64url(json.dumps({"alg": "none", "typ": "JWT"}).encode())
    payload = b64url(json.dumps(claims).encode())
    return f"{header}.{payload}."


def hmac_token(claims: dict[str, Any], secret: bytes, kid: str | None = None) -> str:
    """HS256 signed with ``secret`` - e.g. the provider's *public* key (the
    classic algorithm-confusion attack)."""
    header_fields: dict[str, Any] = {"alg": "HS256", "typ": "JWT"}
    if kid is not None:
        header_fields["kid"] = kid
    header = b64url(json.dumps(header_fields).encode())
    payload = b64url(json.dumps(claims).encode())
    signature = hmac.new(secret, f"{header}.{payload}".encode(), hashlib.sha256).digest()
    return f"{header}.{payload}.{b64url(signature)}"


@dataclass
class IssuedCode:
    challenge: str
    redirect_uri: str
    id_token: str
    used: bool = False


@dataclass
class FakeIdp:
    """One identity provider on ``https://<host>``."""

    host: str = field(default_factory=lambda: f"idp-{uuid4().hex[:10]}.example.com")
    issuer_suffix: str = ""
    client_id: str = field(default_factory=lambda: f"client-{uuid4().hex[:8]}")
    client_secret: str = field(default_factory=lambda: f"s3cret-{uuid4().hex}")
    auth_methods: tuple[str, ...] = ("client_secret_basic",)
    discovery_overrides: dict[str, Any] = field(default_factory=dict)
    token_status: int = 200
    keys: dict[str, tuple[PrivateKey, str]] = field(default_factory=dict)
    published: list[str] = field(default_factory=list)  # kids in the JWKS
    codes: dict[str, IssuedCode] = field(default_factory=dict)
    token_requests: list[dict[str, Any]] = field(default_factory=list)
    jwks_fetches: int = 0

    def __post_init__(self) -> None:
        self.add_key("RS256", kid="rsa-1")

    @property
    def issuer(self) -> str:
        return f"https://{self.host}{self.issuer_suffix}"

    def add_key(self, algorithm: str, *, kid: str, publish: bool = True) -> str:
        self.keys[kid] = (_new_key(algorithm), algorithm)
        if publish:
            self.published.append(kid)
        return kid

    # --------------------------------------------------------------- tokens

    def claims(self, nonce: str | None, **overrides: Any) -> dict[str, Any]:
        """ID token claims; the subject is stable per address unless given, as
        a real provider's is per person."""
        now = int(time.time())
        email = overrides.get("email") or f"person-{uuid4().hex[:8]}@example.com"
        claims: dict[str, Any] = {
            "iss": self.issuer,
            "sub": "subject-" + hashlib.sha256(str(email).lower().encode()).hexdigest()[:16],
            "aud": self.client_id,
            "iat": now,
            "exp": now + 300,
            "nonce": nonce,
            "email": email,
            "email_verified": True,
            "name": "Idp Person",
        }
        for key, value in overrides.items():
            if value is None:
                claims.pop(key, None)
            else:
                claims[key] = value
        return claims

    def sign(
        self,
        claims: dict[str, Any],
        *,
        kid: str = "rsa-1",
        header: dict[str, Any] | None = None,
        with_kid: bool = True,
    ) -> str:
        key, algorithm = self.keys[kid]
        headers: dict[str, Any] = {"kid": kid} if with_kid else {}
        headers.update(header or {})
        return jwt.encode(claims, key, algorithm=algorithm, headers=headers)

    def authorize(
        self,
        authorization_url: str,
        *,
        id_token: Callable[[dict[str, Any]], str] | str | None = None,
        **claims: Any,
    ) -> str:
        """The browser at the provider: check the request, return the code."""
        parts = urlsplit(authorization_url)
        assert f"{parts.scheme}://{parts.netloc}" == f"https://{self.host}", authorization_url
        query = {k: v[0] for k, v in parse_qs(parts.query).items()}
        assert query["response_type"] == "code"
        assert query["client_id"] == self.client_id
        assert query["scope"].split() == ["openid", "email", "profile"]
        assert query["code_challenge_method"] == "S256"
        assert len(query["state"]) >= 43 and len(query["nonce"]) >= 43  # >= 256 bits
        payload = self.claims(query["nonce"], **claims)
        if callable(id_token):
            token = id_token(payload)
        elif isinstance(id_token, str):
            token = id_token
        else:
            token = self.sign(payload)
        code = f"code-{uuid4().hex}"
        self.codes[code] = IssuedCode(
            challenge=query["code_challenge"], redirect_uri=query["redirect_uri"], id_token=token
        )
        return code

    # --------------------------------------------------------------- endpoints

    def discovery(self) -> dict[str, Any]:
        document = {
            "issuer": self.issuer,
            "authorization_endpoint": f"https://{self.host}/authorize?tenant=t1",
            "token_endpoint": f"https://{self.host}/token",
            "jwks_uri": f"https://{self.host}/jwks",
            "response_types_supported": ["code"],
            "subject_types_supported": ["public"],
            "id_token_signing_alg_values_supported": ["RS256", "ES256", "EdDSA", "PS256"],
            "token_endpoint_auth_methods_supported": list(self.auth_methods),
            "code_challenge_methods_supported": ["S256"],
        }
        document.update(self.discovery_overrides)
        return document

    def jwks(self) -> dict[str, Any]:
        self.jwks_fetches += 1
        return {
            "keys": [
                _public_jwk(self.keys[kid][0], kid, self.keys[kid][1]) for kid in self.published
            ]
        }

    def token(self, request: httpx2.Request) -> httpx2.Response:
        form = dict(parse_qsl(request.content.decode()))
        self.token_requests.append({"form": form, "headers": dict(request.headers)})
        if self.token_status != 200:
            return _json({"error": "server_error"}, self.token_status)
        client_id, client_secret = form.get("client_id"), form.get("client_secret")
        authorization = request.headers.get("authorization", "")
        if authorization.startswith("Basic "):
            decoded = base64.b64decode(authorization[6:]).decode()
            raw_id, _, raw_secret = decoded.partition(":")
            client_id, client_secret = unquote(raw_id), unquote(raw_secret)
        if client_id != self.client_id or client_secret != self.client_secret:
            return _json({"error": "invalid_client"}, 401)
        issued = self.codes.get(form.get("code", ""))
        verifier = form.get("code_verifier", "")
        if (
            form.get("grant_type") != "authorization_code"
            or issued is None
            or issued.used
            or issued.redirect_uri != form.get("redirect_uri")
            or b64url(hashlib.sha256(verifier.encode()).digest()) != issued.challenge
        ):
            return _json({"error": "invalid_grant"}, 400)
        issued.used = True
        return _json(
            {
                "access_token": f"at-{uuid4().hex}",
                "token_type": "Bearer",
                "expires_in": 300,
                "id_token": issued.id_token,
            }
        )


@dataclass
class FakeNetwork:
    """Everything the SSO client can reach in a test."""

    idps: dict[str, FakeIdp] = field(default_factory=dict)
    txt: dict[str, list[str]] = field(default_factory=dict)
    requests: list[str] = field(default_factory=list)
    resolver_down: bool = False

    def add(self, idp: FakeIdp) -> FakeIdp:
        self.idps[idp.host] = idp
        return idp

    def publish_txt(self, name: str, value: str) -> None:
        self.txt.setdefault(name, []).append(value)

    def handle(self, request: httpx2.Request) -> httpx2.Response:
        url = request.url
        self.requests.append(f"{request.method} {url}")
        if f"https://{url.host}{url.path}" == RESOLVER_URL:
            return self._dns(url)
        idp = self.idps.get(url.host)
        if idp is None:
            return respond(404)
        path = url.path
        if request.method == "GET" and path == urlsplit(idp.issuer).path.rstrip("/") + (
            "/.well-known/openid-configuration"
        ):
            return _json(idp.discovery())
        if request.method == "GET" and path == "/jwks":
            return _json(idp.jwks(), content_type="application/jwk-set+json")
        if request.method == "POST" and path == "/token":
            return idp.token(request)
        return respond(404)

    def _dns(self, url: httpx2.URL) -> httpx2.Response:
        if self.resolver_down:
            return respond(503)
        name = url.params.get("name", "")
        records = self.txt.get(name, [])
        if not records:
            return _json(
                {"Status": 3, "Question": [{"name": name, "type": 16}]}, 200, "application/dns-json"
            )
        answers = [{"name": name, "type": 16, "TTL": 300, "data": json.dumps(v)} for v in records]
        return _json({"Status": 0, "Answer": answers}, 200, "application/dns-json")

    def client(self) -> SafeHttpClient:
        return SafeHttpClient(
            policy=UrlPolicy(allow_http=False, allowed_ports=frozenset({443})),
            user_agent="nexusflow-tests",
            limits=HttpClientLimits(max_redirects=0),
            transport=httpx2.MockTransport(self.handle),
        )


def sso_service(
    *,
    network: FakeNetwork,
    uow_factory: Any,
    clock: Clock,
    audit: AuditRecorder,
    cipher: Any,
    token_hasher: Any,
    auth: Any,
    public_base_url: str,
    cache_seconds: float = 0,
) -> SsoService:
    """The platform's SSO service, talking to ``network`` instead of the internet."""
    http = network.client()
    return SsoService(
        uow_factory=uow_factory,
        clock=clock,
        audit=audit,
        cipher=cipher,
        token_hasher=token_hasher,
        token_generator=SecureTokenGenerator(),
        oidc=OidcClient(
            http, cache_seconds=cache_seconds, leeway_seconds=60, max_response_bytes=512 * 1024
        ),
        dns=DohTxtResolver(http, resolver_url=RESOLVER_URL),
        auth=auth,
        policy=SsoPolicy(public_base_url=public_base_url, state_ttl_seconds=600),
    )


@pytest.fixture
def network(container: Container, monkeypatch: pytest.MonkeyPatch) -> FakeNetwork:
    """The container's SSO service, wired to a fresh fake network for one test."""
    fake = FakeNetwork()
    service = sso_service(
        network=fake,
        uow_factory=container.uow_factory,
        clock=container.clock,
        audit=container.audit,
        cipher=container.cipher,
        token_hasher=container.token_hasher,
        auth=container.auth,
        public_base_url=container.settings.app.public_base_url,
    )
    monkeypatch.setattr(container, "sso", service)
    return fake


def fresh_domain() -> str:
    """A domain of its own for each test (verification is per organization)."""
    return f"d{uuid4().hex[:10]}.example.com"


# ------------------------------------------------------------- API helpers

SSO = "/api/v1/organizations/current/sso"


async def configure(
    session: ApiSession,
    idp: FakeIdp,
    domains: list[str],
    **fields: Any,
) -> httpx2.Response:
    body: dict[str, Any] = {
        "issuer": idp.issuer,
        "client_id": idp.client_id,
        "client_secret": idp.client_secret,
        "allowed_domains": domains,
        **fields,
    }
    return await session.client.put(SSO, json=body, headers=session.headers)


async def verify(session: ApiSession, network: FakeNetwork, domain: str) -> dict[str, Any]:
    """Publish the domain's TXT record and have the organization verify it."""
    configuration = (await session.get(SSO)).json()
    [record] = [d for d in configuration["domains"] if d["domain"] == domain]
    network.publish_txt(record["txt_record_name"], record["txt_record_value"])
    response = await session.post(f"{SSO}/domains/verify")
    assert response.status_code == 200, response.text
    body: dict[str, Any] = response.json()
    return body


async def ready(
    session: ApiSession, network: FakeNetwork, idp: FakeIdp, domain: str, **fields: Any
) -> str:
    """Single sign-on configured with ``domain`` verified; returns the slug."""
    network.add(idp)
    configured = await configure(session, idp, [domain], **fields)
    assert configured.status_code == 200, configured.text
    await verify(session, network, domain)
    slug: str = (await session.get("/api/v1/organizations/current")).json()["slug"]
    return slug


@dataclass
class Started:
    authorization_url: str
    state: str
    binding: str


async def start(client: httpx2.AsyncClient, slug: str) -> Started:
    response = await client.post("/api/v1/auth/sso/start", json={"organization": slug})
    assert response.status_code == 200, response.text
    body = response.json()
    return Started(body["authorization_url"], body["state"], body["binding"])


async def finish(
    client: httpx2.AsyncClient, started: Started, code: str, *, binding: str | None = None
) -> httpx2.Response:
    return await client.post(
        "/api/v1/auth/sso/callback",
        json={
            "code": code,
            "state": started.state,
            "binding": started.binding if binding is None else binding,
        },
    )


async def sign_in(
    client: httpx2.AsyncClient, idp: FakeIdp, slug: str, **claims: Any
) -> httpx2.Response:
    started = await start(client, slug)
    return await finish(client, started, idp.authorize(started.authorization_url, **claims))


def session_of(client: httpx2.AsyncClient, response: httpx2.Response, email: str) -> ApiSession:
    assert response.status_code == 200, response.text
    body = response.json()
    return ApiSession(client, body["access_token"], body["refresh_token"], email)
