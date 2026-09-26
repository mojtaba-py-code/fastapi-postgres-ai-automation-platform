"""Composition root: builds every service from :class:`Settings`.

This is the only module that knows the concrete implementations behind the
domain ports. Entry points (API, workers, CLI) call :func:`build_container`
once and pass services around explicitly - there is no service locator and no
hidden module-level state.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field

from redis.asyncio import Redis
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker

from nexusflow.bootstrap.http import build_http_client, build_idp_http_client, build_url_policy
from nexusflow.core.clock import Clock, SystemClock
from nexusflow.core.config import Settings, decode_key_bytes, webauthn_relying_party
from nexusflow.core.resilience import CircuitBreaker
from nexusflow.domain.alerts.service import AlertService
from nexusflow.domain.audit.recorder import AuditRecorder
from nexusflow.domain.audit.service import AuditService
from nexusflow.domain.automation.dead_letters import DeadLetterService
from nexusflow.domain.automation.maintenance import MaintenanceService, RetentionPolicy
from nexusflow.domain.automation.service import AutomationService
from nexusflow.domain.automation.workflows import WorkflowService
from nexusflow.domain.catalog.service import CatalogService
from nexusflow.domain.identity.account_service import AccountService
from nexusflow.domain.identity.auth_service import AuthPolicy, AuthService
from nexusflow.domain.identity.authenticator import Authenticator
from nexusflow.domain.identity.passkeys import PasskeyService
from nexusflow.domain.identity.password_policy import PasswordPolicy
from nexusflow.domain.identity.privacy import PrivacyService
from nexusflow.domain.identity.provisioning import ProvisioningService
from nexusflow.domain.identity.security_emails import SecurityEmailService
from nexusflow.domain.identity.service_accounts import ServiceAccountService
from nexusflow.domain.identity.sso_service import SsoPolicy, SsoService
from nexusflow.domain.identity.webauthn import PasskeySupport, RelyingParty
from nexusflow.domain.integrations.service import IntegrationService
from nexusflow.domain.intelligence.ports import AIProvider
from nexusflow.domain.intelligence.service import IntelligenceService
from nexusflow.domain.intelligence.tools import DatasetOverviewTool, RecordHistoryTool, ToolGateway
from nexusflow.domain.notifications.service import NotificationService
from nexusflow.domain.organizations.service import OrganizationService
from nexusflow.domain.pipeline.collection import CollectionService
from nexusflow.domain.pipeline.ingestion import IngestionService
from nexusflow.domain.records.service import ChangeDetectionService
from nexusflow.domain.reports.service import ReportService
from nexusflow.domain.shared.url_policy import UrlPolicy
from nexusflow.domain.sources.service import SourceService
from nexusflow.domain.uploads.service import UploadService
from nexusflow.domain.webhooks.service import WebhookService
from nexusflow.infrastructure.ai.anthropic_provider import AnthropicProvider
from nexusflow.infrastructure.database.engine import create_engine, create_session_factory
from nexusflow.infrastructure.database.mapping import register_mappings
from nexusflow.infrastructure.database.unit_of_work import SqlUnitOfWorkFactory
from nexusflow.infrastructure.http.client import SafeHttpClient
from nexusflow.infrastructure.n8n.client import N8nClient
from nexusflow.infrastructure.notifications.senders import (
    ChannelSender,
    EmailTransport,
    SmtpEmailTransport,
)
from nexusflow.infrastructure.redis.challenges import RedisChallengeStore
from nexusflow.infrastructure.redis.client import (
    FeatureFlags,
    RedisFailureLedger,
    ReplayGuard,
    create_redis,
)
from nexusflow.infrastructure.redis.rate_limit import RateLimiter
from nexusflow.infrastructure.redis.throttles import ChannelDeliveryThrottle, WebhookDeliveryQuota
from nexusflow.infrastructure.reporting.renderers import ReportRendererRegistry
from nexusflow.infrastructure.scraping.collectors import RestApiCollector
from nexusflow.infrastructure.scraping.extraction import validate_selector
from nexusflow.infrastructure.security.crypto import EnvelopeCipher
from nexusflow.infrastructure.security.files import FileSealer
from nexusflow.infrastructure.security.hashing import HmacTokenHasher, SecureTokenGenerator
from nexusflow.infrastructure.security.jwt_tokens import JwtKeyRing, JwtTokenCodec
from nexusflow.infrastructure.security.passwords import Argon2idPasswordHasher
from nexusflow.infrastructure.security.totp import TotpService
from nexusflow.infrastructure.security.vault import unwrap_keyring
from nexusflow.infrastructure.security.webauthn import StrictWebAuthnVerifier
from nexusflow.infrastructure.sso.dns import DohTxtResolver
from nexusflow.infrastructure.sso.oidc import OidcClient
from nexusflow.infrastructure.storage.local import LocalFileStorage
from nexusflow.infrastructure.storage.scanning import ClamdScanner, NoopScanner


@dataclass
class Container:
    settings: Settings
    clock: Clock
    engine: AsyncEngine
    session_factory: async_sessionmaker[AsyncSession]
    uow_factory: SqlUnitOfWorkFactory
    redis: Redis
    limiter: RateLimiter
    replay_guard: ReplayGuard
    flags: FeatureFlags
    cipher: EnvelopeCipher
    token_hasher: HmacTokenHasher
    token_codec: JwtTokenCodec
    keyring: JwtKeyRing
    password_hasher: Argon2idPasswordHasher
    audit: AuditRecorder
    url_policy: UrlPolicy
    http: SafeHttpClient
    storage: LocalFileStorage
    ai_provider: AIProvider | None
    n8n: N8nClient | None
    rest_collector: RestApiCollector
    auth: AuthService
    passkeys: PasskeyService
    authenticator: Authenticator
    organizations: OrganizationService
    accounts: AccountService
    privacy: PrivacyService
    audit_log: AuditService
    catalog: CatalogService
    integrations: IntegrationService
    sources: SourceService
    webhooks: WebhookService
    uploads: UploadService
    ingestion: IngestionService
    collection: CollectionService
    detection: ChangeDetectionService
    intelligence: IntelligenceService
    alerts: AlertService
    notifications: NotificationService
    reports: ReportService
    workflows: WorkflowService
    automation: AutomationService
    dead_letters: DeadLetterService
    maintenance: MaintenanceService
    security_emails: SecurityEmailService
    service_accounts: ServiceAccountService
    sso: SsoService
    provisioning: ProvisioningService
    closers: list[Callable[[], Awaitable[None]]] = field(default_factory=list)

    async def aclose(self) -> None:
        for close in reversed(self.closers):
            await close()


def build_security(settings: Settings) -> tuple[EnvelopeCipher, HmacTokenHasher, JwtKeyRing]:
    sec = settings.security
    if sec.encryption_keys is None or sec.hmac_pepper is None or sec.jwt_private_key is None:
        raise ValueError("key material missing (validated at settings load)")
    if sec.kek_provider == "vault-transit":
        # The keyring holds Vault ciphertexts: unwrapped once, kept in memory.
        keys = unwrap_keyring(settings.vault, sec.encryption_keys.get_secret_value())
        cipher = EnvelopeCipher(keys, sec.encryption_active_key_id)
    else:
        cipher = EnvelopeCipher.from_config(
            sec.encryption_keys.get_secret_value(), sec.encryption_active_key_id
        )
    hasher = HmacTokenHasher(decode_key_bytes(sec.hmac_pepper.get_secret_value()))
    keyring = JwtKeyRing.from_pem(
        sec.jwt_private_key.get_secret_value(), sec.jwt_key_id, sec.jwt_previous_public_keys
    )
    return cipher, hasher, keyring


def build_passkey_support(settings: Settings, redis: Redis) -> PasskeySupport:
    """The passkey relying party (``None`` where passkeys cannot work), the
    ceremony verifier and the single-use challenge store."""
    resolved, _ = webauthn_relying_party(settings.app, settings.security)
    return PasskeySupport(
        relying_party=(
            RelyingParty(
                id=resolved.rp_id,
                name=settings.security.mfa_issuer,
                origins=frozenset(resolved.origins),
            )
            if resolved is not None
            else None
        ),
        verifier=StrictWebAuthnVerifier(),
        challenges=RedisChallengeStore(redis, prefix=settings.redis.key_prefix),
    )


def build_ai_provider(settings: Settings) -> AIProvider | None:
    ai = settings.ai
    if ai.provider != "anthropic" or ai.api_key is None:
        return None
    return AnthropicProvider(
        api_key=ai.api_key.get_secret_value(),
        model=ai.model,
        timeout_seconds=ai.timeout_seconds,
        max_retries=ai.max_retries,
        effort=ai.effort,
        server_side_fallbacks=ai.server_side_fallbacks,
        breaker=CircuitBreaker(
            "anthropic",
            failure_threshold=ai.circuit_breaker_failures,
            reset_timeout=ai.circuit_breaker_reset_seconds,
        ),
    )


def build_container(
    settings: Settings,
    *,
    application_name: str = "nexusflow",
    clock: Clock | None = None,
    engine: AsyncEngine | None = None,
    redis: Redis | None = None,
    http: SafeHttpClient | None = None,
    ai_provider: AIProvider | None = None,
    idp_http: SafeHttpClient | None = None,
    email: EmailTransport | None = None,
) -> Container:
    register_mappings()
    clock = clock or SystemClock()
    sec = settings.security
    engine = engine or create_engine(settings.database, application_name=application_name)
    session_factory = create_session_factory(engine)
    cipher, token_hasher, keyring = build_security(settings)
    uow_factory = SqlUnitOfWorkFactory(session_factory, cipher=cipher)
    redis_client = redis if redis is not None else create_redis(settings.redis)
    prefix = settings.redis.key_prefix
    limiter = RateLimiter(
        redis_client, prefix=prefix, clock=clock, enabled=settings.rate_limits.enabled
    )
    replay_guard = ReplayGuard(redis_client, prefix=prefix)
    tokens = SecureTokenGenerator()
    token_codec = JwtTokenCodec(
        keyring,
        issuer=sec.jwt_issuer,
        audience=sec.jwt_audience,
        access_ttl_seconds=sec.access_token_ttl_seconds,
        mfa_ttl_seconds=sec.mfa_challenge_ttl_seconds,
    )
    password_hasher = Argon2idPasswordHasher(
        time_cost=sec.argon2_time_cost,
        memory_cost_kib=sec.argon2_memory_cost_kib,
        parallelism=sec.argon2_parallelism,
    )
    audit = AuditRecorder(clock)
    url_policy = build_url_policy(settings.scraping)
    http_client = http or build_http_client(settings.scraping, url_policy)
    storage = LocalFileStorage(settings.storage.root, FileSealer(cipher))
    scanner = (
        ClamdScanner.from_address(settings.storage.clamav_address)
        if settings.storage.clamav_address
        else NoopScanner()
    )
    provider = ai_provider if ai_provider is not None else build_ai_provider(settings)
    n8n = (
        N8nClient(
            webhook_base_url=settings.n8n.webhook_base_url,
            api_base_url=settings.n8n.base_url,
            jwt_secret=settings.n8n.webhook_jwt_secret.get_secret_value(),
            api_key=settings.n8n.api_key.get_secret_value() if settings.n8n.api_key else None,
            timeout_seconds=settings.n8n.request_timeout_seconds,
        )
        if settings.n8n.webhook_jwt_secret is not None
        else None
    )

    passkey_support = build_passkey_support(settings, redis_client)
    auth = AuthService(
        uow_factory=uow_factory,
        clock=clock,
        password_hasher=password_hasher,
        token_codec=token_codec,
        token_hasher=token_hasher,
        token_generator=tokens,
        cipher=cipher,
        totp=TotpService(),
        audit=audit,
        policy=AuthPolicy(
            access_ttl_seconds=sec.access_token_ttl_seconds,
            refresh_ttl_seconds=sec.refresh_token_ttl_seconds,
            session_absolute_ttl_seconds=sec.session_absolute_ttl_seconds,
            lockout_threshold=sec.lockout_threshold,
            lockout_base_seconds=sec.lockout_base_seconds,
            lockout_max_seconds=sec.lockout_max_seconds,
            password_reset_ttl_seconds=sec.password_reset_ttl_seconds,
            signup_link_ttl_seconds=sec.signup_link_ttl_seconds,
            signup_enabled=settings.app.signup_enabled,
            mfa_issuer=sec.mfa_issuer,
            password=PasswordPolicy(
                min_length=sec.password_min_length, max_length=sec.password_max_length
            ),
        ),
        passkeys=passkey_support,
    )
    integrations = IntegrationService(
        uow_factory=uow_factory, clock=clock, audit=audit, cipher=cipher, token_generator=tokens
    )
    detection = ChangeDetectionService(uow_factory=uow_factory, clock=clock, cipher=cipher)
    intelligence = IntelligenceService(
        uow_factory=uow_factory,
        clock=clock,
        audit=audit,
        provider=provider,
        gateway_factory=lambda: ToolGateway(
            tools={
                tool.spec.name: tool
                for tool in (
                    RecordHistoryTool(uow_factory),
                    DatasetOverviewTool(uow_factory, clock),
                )
            }
        ),
        max_input_chars=settings.ai.max_input_chars,
        max_tool_rounds=settings.ai.max_tool_rounds,
        max_output_tokens=settings.ai.max_output_tokens,
    )
    alerts = AlertService(uow_factory=uow_factory, clock=clock, audit=audit)
    dead_letters = DeadLetterService(uow_factory=uow_factory, clock=clock, audit=audit)
    flags = FeatureFlags(redis_client, prefix=prefix)
    ingestion = IngestionService(
        uow_factory=uow_factory,
        clock=clock,
        cipher=cipher,
        hasher=token_hasher,
        max_items_per_run=max(
            settings.scraping.max_items_per_run, settings.storage.max_upload_rows
        ),
    )
    email_transport = email or SmtpEmailTransport(settings.notifications)
    rules = settings.rate_limits.rules
    idp_client = idp_http or build_idp_http_client(settings.sso, settings.scraping)
    sso = SsoService(
        uow_factory=uow_factory,
        clock=clock,
        audit=audit,
        cipher=cipher,
        token_hasher=token_hasher,
        token_generator=tokens,
        oidc=OidcClient(
            idp_client,
            cache_seconds=settings.sso.metadata_cache_seconds,
            leeway_seconds=settings.sso.clock_skew_seconds,
            max_response_bytes=settings.sso.max_response_bytes,
        ),
        dns=DohTxtResolver(idp_client, resolver_url=settings.sso.dns_resolver_url),
        auth=auth,
        policy=SsoPolicy(
            public_base_url=settings.app.public_base_url,
            state_ttl_seconds=settings.sso.state_ttl_seconds,
        ),
    )
    container = Container(
        settings=settings,
        clock=clock,
        engine=engine,
        session_factory=session_factory,
        uow_factory=uow_factory,
        redis=redis_client,
        limiter=limiter,
        replay_guard=replay_guard,
        flags=flags,
        cipher=cipher,
        token_hasher=token_hasher,
        token_codec=token_codec,
        keyring=keyring,
        password_hasher=password_hasher,
        audit=audit,
        url_policy=url_policy,
        http=http_client,
        storage=storage,
        ai_provider=provider,
        n8n=n8n,
        rest_collector=RestApiCollector(
            client=http_client, limiter=limiter, rule=rules["external_api.integration"]
        ),
        auth=auth,
        passkeys=PasskeyService(
            uow_factory=uow_factory,
            clock=clock,
            audit=audit,
            token_hasher=token_hasher,
            confirm_password=auth.confirm_password,
            support=passkey_support,
        ),
        authenticator=Authenticator(
            uow_factory=uow_factory, clock=clock, token_codec=token_codec, token_hasher=token_hasher
        ),
        organizations=OrganizationService(
            uow_factory=uow_factory,
            clock=clock,
            audit=audit,
            token_hasher=token_hasher,
            invitation_ttl_seconds=sec.invitation_ttl_seconds,
        ),
        accounts=AccountService(
            uow_factory=uow_factory,
            clock=clock,
            audit=audit,
            token_hasher=token_hasher,
            confirm_password=auth.confirm_password,
        ),
        privacy=PrivacyService(uow_factory=uow_factory, clock=clock, audit=audit),
        audit_log=AuditService(uow_factory=uow_factory),
        catalog=CatalogService(uow_factory=uow_factory, clock=clock, audit=audit),
        integrations=integrations,
        sources=SourceService(
            uow_factory=uow_factory,
            clock=clock,
            audit=audit,
            url_policy=url_policy,
            selector_validator=validate_selector,
            max_items_per_run=settings.scraping.max_items_per_run,
            javascript_rendering_available=settings.scraping.browser_service_url is not None,
        ),
        webhooks=WebhookService(
            uow_factory=uow_factory,
            clock=clock,
            audit=audit,
            cipher=cipher,
            token_generator=tokens,
            nonces=replay_guard,
            tolerance_seconds=sec.webhook_timestamp_tolerance_seconds,
            max_body_bytes=settings.app.max_request_body_bytes,
            public_base_url=settings.app.public_base_url,
            quota=WebhookDeliveryQuota(limiter, rules["webhook.endpoint"]),
        ),
        uploads=UploadService(
            uow_factory=uow_factory,
            clock=clock,
            audit=audit,
            storage=storage,
            scanner=scanner,
            max_bytes=settings.storage.max_upload_bytes,
        ),
        ingestion=ingestion,
        collection=CollectionService(
            uow_factory=uow_factory,
            clock=clock,
            ingestion=ingestion,
            ticket_hasher=token_hasher,
            max_items_per_run=settings.scraping.max_items_per_run,
            max_upload_rows=settings.storage.max_upload_rows,
            max_upload_columns=settings.storage.max_upload_columns,
        ),
        detection=detection,
        intelligence=intelligence,
        alerts=alerts,
        notifications=NotificationService(
            uow_factory=uow_factory,
            clock=clock,
            audit=audit,
            url_policy=url_policy,
            integrations=integrations,
            sender=ChannelSender(
                client=http_client,
                email=email_transport,
                platform_policy=url_policy,
                telegram_api_base=settings.notifications.telegram_api_base,
                slack_host=settings.notifications.slack_webhook_host,
            ),
            throttle=ChannelDeliveryThrottle(limiter, rules["notifications.channel"]),
        ),
        reports=ReportService(
            uow_factory=uow_factory,
            clock=clock,
            audit=audit,
            storage=storage,
            renderer=ReportRendererRegistry(),
            ttl_days=settings.storage.report_ttl_days,
        ),
        workflows=WorkflowService(uow_factory=uow_factory, clock=clock, audit=audit),
        automation=AutomationService(
            uow_factory=uow_factory,
            clock=clock,
            detection=detection,
            intelligence=intelligence,
            alerts=alerts,
            dead_letters=dead_letters,
            gate=flags,
            nonces=replay_guard,
            ledger=RedisFailureLedger(redis_client, prefix=prefix),
            audit=audit,
        ),
        dead_letters=dead_letters,
        maintenance=MaintenanceService(
            uow_factory=uow_factory,
            clock=clock,
            storage=storage,
            policy=RetentionPolicy(
                collection_runs_days=settings.retention.collection_runs_days,
                webhook_events_days=settings.retention.webhook_events_days,
                notification_deliveries_days=settings.retention.notification_deliveries_days,
                dead_letters_days=settings.retention.dead_letters_days,
                idempotency_keys_hours=settings.retention.idempotency_keys_hours,
                sessions_days=settings.retention.sessions_days,
            ),
            audit=audit,
        ),
        security_emails=SecurityEmailService(
            uow_factory=uow_factory,
            clock=clock,
            email=email_transport,
            token_generator=tokens,
            token_hasher=token_hasher,
            public_base_url=settings.app.public_base_url,
        ),
        service_accounts=ServiceAccountService(
            uow_factory=uow_factory, clock=clock, audit=audit, token_hasher=token_hasher
        ),
        sso=sso,
        provisioning=ProvisioningService(
            uow_factory=uow_factory, clock=clock, audit=audit, token_hasher=token_hasher
        ),
    )
    container.closers.append(engine.dispose)
    container.closers.append(http_client.aclose)
    container.closers.append(idp_client.aclose)
    if redis is None:
        container.closers.append(redis_client.aclose)
    if n8n is not None:
        container.closers.append(n8n.aclose)
    return container
