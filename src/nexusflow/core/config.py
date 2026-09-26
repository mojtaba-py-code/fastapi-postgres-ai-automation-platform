"""Typed, validated configuration.

All configuration comes from the environment (prefix ``NEXUSFLOW_``, nested
sections separated by ``__``). Any variable may instead be provided as a file by
appending ``_FILE`` (e.g. ``NEXUSFLOW_SECURITY__HMAC_PEPPER_FILE=/run/secrets/pepper``),
which is how Docker/Kubernetes secrets are mounted. Secrets are typed as
``SecretStr`` so they never appear in ``repr`` output or logs.

Insecure combinations are rejected at startup (fail-safe defaults): the
application refuses to boot in production with debug mode, plain-HTTP public
URLs, wildcard hosts/origins, or missing key material.
"""

from __future__ import annotations

import base64
import binascii
import os
from collections.abc import Mapping
from enum import StrEnum
from ipaddress import IPv4Network, IPv6Network
from pathlib import Path
from typing import Any, Literal, Self
from urllib.parse import urlsplit

from pydantic import (
    BaseModel,
    ConfigDict,
    EmailStr,
    Field,
    SecretStr,
    field_validator,
    model_validator,
)
from pydantic.fields import FieldInfo
from pydantic_settings import (
    BaseSettings,
    EnvSettingsSource,
    PydanticBaseSettingsSource,
    SettingsConfigDict,
)

ENV_PREFIX = "NEXUSFLOW_"
_MAX_SECRET_FILE_BYTES = 64 * 1024


class Environment(StrEnum):
    DEVELOPMENT = "development"
    TEST = "test"
    STAGING = "staging"
    PRODUCTION = "production"


class _Section(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, validate_default=True)


class AppSettings(_Section):
    name: str = "nexusflow"
    environment: Environment = Environment.DEVELOPMENT
    debug: bool = False
    public_base_url: str = "http://localhost:8000"
    allowed_hosts: list[str] = Field(default_factory=lambda: ["localhost", "127.0.0.1", "api"])
    cors_allowed_origins: list[str] = Field(default_factory=list)
    docs_enabled: bool | None = None
    trusted_proxies: list[IPv4Network | IPv6Network] = Field(default_factory=list)
    max_request_body_bytes: int = Field(default=1024 * 1024, ge=1024, le=64 * 1024 * 1024)
    signup_enabled: bool = True

    @property
    def is_production_like(self) -> bool:
        return self.environment in (Environment.STAGING, Environment.PRODUCTION)

    @property
    def api_docs_enabled(self) -> bool:
        if self.docs_enabled is not None:
            return self.docs_enabled
        return not self.is_production_like


class DatabaseSettings(_Section):
    url: SecretStr = SecretStr(
        "postgresql+asyncpg://nexusflow_app:change-me@localhost:5432/nexusflow"
    )
    migrator_url: SecretStr | None = None
    app_role: str = Field(default="nexusflow_app", pattern=r"^[a-z_][a-z0-9_]{0,62}$")
    pool_size: int = Field(default=10, ge=1, le=200)
    max_overflow: int = Field(default=5, ge=0, le=200)
    pool_timeout_seconds: float = Field(default=5.0, gt=0)
    pool_recycle_seconds: int = Field(default=1800, ge=60)
    statement_timeout_ms: int = Field(default=15_000, ge=100)
    lock_timeout_ms: int = Field(default=5_000, ge=100)
    idle_in_transaction_timeout_ms: int = Field(default=30_000, ge=1_000)
    ssl_mode: Literal["disable", "require", "verify-full"] = "disable"
    ssl_root_cert: Path | None = None
    echo: bool = False


class RedisSettings(_Section):
    url: SecretStr = SecretStr("redis://localhost:6379/0")
    ssl_ca_certs: Path | None = None
    socket_timeout_seconds: float = Field(default=2.0, gt=0)
    connect_timeout_seconds: float = Field(default=2.0, gt=0)
    max_connections: int = Field(default=50, ge=1)
    key_prefix: str = Field(default="nf:", pattern=r"^[a-z0-9:_-]{1,16}$")


class BrokerSettings(_Section):
    url: SecretStr = SecretStr("amqp://guest:guest@localhost:5672//")
    use_ssl: bool = False
    ssl_ca_certs: Path | None = None


class SecuritySettings(_Section):
    # --- JWT (EdDSA / Ed25519). Private key PEM; previous public keys allow rotation.
    jwt_private_key: SecretStr | None = None
    jwt_key_id: str = Field(default="k1", pattern=r"^[A-Za-z0-9._-]{1,32}$")
    jwt_previous_public_keys: dict[str, str] = Field(default_factory=dict)
    jwt_issuer: str = "nexusflow"
    jwt_audience: str = "nexusflow-api"
    access_token_ttl_seconds: int = Field(default=600, ge=60, le=3600)
    refresh_token_ttl_seconds: int = Field(default=14 * 86400, ge=3600, le=90 * 86400)
    session_absolute_ttl_seconds: int = Field(default=30 * 86400, ge=3600, le=180 * 86400)
    mfa_challenge_ttl_seconds: int = Field(default=300, ge=60, le=900)
    # --- Passwords
    password_min_length: int = Field(default=12, ge=8, le=64)
    password_max_length: int = Field(default=128, ge=64, le=1024)
    argon2_time_cost: int = Field(default=3, ge=1, le=10)
    argon2_memory_cost_kib: int = Field(default=65_536, ge=19_456, le=1_048_576)
    argon2_parallelism: int = Field(default=4, ge=1, le=16)
    # --- Brute-force protection
    lockout_threshold: int = Field(default=5, ge=3, le=20)
    lockout_base_seconds: int = Field(default=900, ge=60)
    lockout_max_seconds: int = Field(default=86_400, ge=900)
    # --- Application-level encryption (AES-256-GCM envelope; base64 32-byte KEKs)
    encryption_keys: SecretStr | None = None  # JSON object {"key-id": "<base64>"}
    encryption_active_key_id: str = Field(default="kek-1", pattern=r"^[A-Za-z0-9._-]{1,32}$")
    # --- Keyed hashing of opaque tokens (API keys, refresh tokens, reset tokens)
    hmac_pepper: SecretStr | None = None
    # --- Token lifetimes
    password_reset_ttl_seconds: int = Field(default=1800, ge=300, le=86_400)
    signup_link_ttl_seconds: int = Field(default=86_400, ge=900, le=7 * 86_400)
    invitation_ttl_seconds: int = Field(default=72 * 3600, ge=3600, le=14 * 86_400)
    webhook_timestamp_tolerance_seconds: int = Field(default=300, ge=30, le=900)
    mfa_issuer: str = "NexusFlow AI"


class SsoSettings(_Section):
    """OpenID Connect single sign-on and SCIM provisioning (per organization).

    Identity providers are configured by each organization; these settings
    bound what the platform does with them.
    """

    # How long a started sign-in may take at the identity provider.
    state_ttl_seconds: int = Field(default=600, ge=120, le=1800)
    # Discovery documents and signing keys (JWKS) are cached this long per issuer.
    metadata_cache_seconds: int = Field(default=300, ge=0, le=3600)
    # Tolerated clock difference with the identity provider (exp, iat, nbf).
    clock_skew_seconds: int = Field(default=60, ge=0, le=300)
    http_timeout_seconds: float = Field(default=10.0, gt=0, le=30)
    max_response_bytes: int = Field(default=512 * 1024, ge=16 * 1024, le=4 * 1024 * 1024)
    # DNS-over-HTTPS (JSON API) resolver that checks domain-ownership TXT records.
    dns_resolver_url: str = "https://cloudflare-dns.com/dns-query"

    @field_validator("dns_resolver_url")
    @classmethod
    def _https_resolver(cls, value: str) -> str:
        parts = urlsplit(value)
        if parts.scheme != "https" or not parts.hostname or parts.username or parts.password:
            raise ValueError("sso.dns_resolver_url must be an https URL without credentials")
        return value


class ScrapingSettings(_Section):
    user_agent: str = "NexusFlowBot/0.1 (+https://github.com/mojtaba-py-code/nexusflow-ai)"
    allow_http: bool = False
    allowed_ports: list[int] = Field(default_factory=lambda: [80, 443])
    connect_timeout_seconds: float = Field(default=5.0, gt=0, le=30)
    read_timeout_seconds: float = Field(default=15.0, gt=0, le=120)
    total_timeout_seconds: float = Field(default=30.0, gt=0, le=300)
    max_response_bytes: int = Field(default=5 * 1024 * 1024, ge=1024, le=50 * 1024 * 1024)
    max_redirects: int = Field(default=3, ge=0, le=10)
    min_domain_interval_seconds: float = Field(default=2.0, ge=0.1, le=300)
    robots_cache_ttl_seconds: int = Field(default=86_400, ge=60)
    blocked_domains: list[str] = Field(default_factory=list)
    max_items_per_run: int = Field(default=1000, ge=1, le=100_000)
    browser_service_url: str | None = None
    browser_service_token: SecretStr | None = None


class AISettings(_Section):
    provider: Literal["offline", "anthropic"] = "offline"
    model: str = "claude-opus-5"
    api_key: SecretStr | None = None
    timeout_seconds: float = Field(default=120.0, gt=0, le=900)
    max_retries: int = Field(default=2, ge=0, le=5)
    max_output_tokens: int = Field(default=8000, ge=256, le=64_000)
    effort: Literal["low", "medium", "high", "xhigh", "max"] | None = None
    max_input_chars: int = Field(default=60_000, ge=1_000, le=400_000)
    server_side_fallbacks: bool = True
    max_tool_rounds: int = Field(default=3, ge=0, le=8)
    circuit_breaker_failures: int = Field(default=5, ge=1)
    circuit_breaker_reset_seconds: int = Field(default=60, ge=5)


class NotificationSettings(_Section):
    smtp_host: str | None = None
    smtp_port: int = Field(default=587, ge=1, le=65535)
    smtp_username: str | None = None
    smtp_password: SecretStr | None = None
    smtp_from: EmailStr = "alerts@example.com"
    smtp_tls_mode: Literal["starttls", "tls"] = "starttls"
    # Extra CA bundle for a private relay (e.g. the local demo CA). TLS and
    # certificate validation stay mandatory either way.
    smtp_ca_bundle: Path | None = None
    smtp_timeout_seconds: float = Field(default=15.0, gt=0)
    telegram_api_base: str = "https://api.telegram.org"
    slack_webhook_host: str = "hooks.slack.com"
    operator_emails: list[EmailStr] = Field(default_factory=list)
    per_channel_per_minute: int = Field(default=30, ge=1)


class N8nSettings(_Section):
    # "n8n": n8n workflows drive the pipeline through the internal automation
    # API (events are forwarded to n8n). "internal": the platform drives the
    # pipeline itself - the fallback when n8n is absent or has been cut off
    # during an incident. Events are forwarded to n8n in both modes if configured.
    orchestration: Literal["n8n", "internal"] = "internal"
    base_url: str = "http://n8n:5678"
    api_key: SecretStr | None = None
    webhook_base_url: str = "http://n8n:5678/webhook"
    webhook_jwt_secret: SecretStr | None = None
    request_timeout_seconds: float = Field(default=10.0, gt=0, le=60)


class StorageSettings(_Section):
    root: Path = Path("./var")
    max_upload_bytes: int = Field(default=20 * 1024 * 1024, ge=1024, le=512 * 1024 * 1024)
    max_upload_rows: int = Field(default=100_000, ge=1)
    max_upload_columns: int = Field(default=200, ge=1, le=16_384)
    report_ttl_days: int = Field(default=30, ge=1)
    clamav_address: str | None = None  # host:port of clamd, optional

    @property
    def uploads_dir(self) -> Path:
        return self.root / "uploads"

    @property
    def reports_dir(self) -> Path:
        return self.root / "reports"


class ObservabilitySettings(_Section):
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = "INFO"
    log_format: Literal["json", "console"] = "json"
    metrics_enabled: bool = True
    # Workers expose /metrics on this port (prefork children aggregate through
    # PROMETHEUS_MULTIPROC_DIR). Unset: no worker metrics endpoint.
    worker_metrics_port: int | None = Field(default=None, ge=1024, le=65535)
    otlp_endpoint: str | None = None
    trace_sample_ratio: float = Field(default=0.1, ge=0, le=1)


class RetentionSettings(_Section):
    collection_runs_days: int = Field(default=90, ge=1)
    webhook_events_days: int = Field(default=30, ge=1)
    notification_deliveries_days: int = Field(default=90, ge=1)
    dead_letters_days: int = Field(default=30, ge=1)
    default_record_versions_days: int = Field(default=180, ge=1)
    idempotency_keys_hours: int = Field(default=24, ge=1)
    # Ended sign-in sessions (device, address) are deleted this long after they
    # expire; sign-in risk compares a new sign-in with the last 90 days.
    sessions_days: int = Field(default=90, ge=30)


class RateLimitRule(_Section):
    limit: int = Field(ge=1)
    period_seconds: int = Field(ge=1, le=86_400)
    fail_closed: bool = False


def _default_rate_limits() -> dict[str, RateLimitRule]:
    return {
        "auth.login.ip": RateLimitRule(limit=20, period_seconds=60, fail_closed=True),
        "auth.login.account": RateLimitRule(limit=5, period_seconds=60, fail_closed=True),
        "auth.refresh": RateLimitRule(limit=30, period_seconds=60, fail_closed=True),
        "auth.password_reset": RateLimitRule(limit=5, period_seconds=3600, fail_closed=True),
        "auth.register": RateLimitRule(limit=10, period_seconds=3600, fail_closed=True),
        # Per address: sign-up e-mails must not become a way to flood a mailbox.
        "auth.register.account": RateLimitRule(limit=3, period_seconds=3600, fail_closed=True),
        # Finishing a sign-up or accepting an invitation as a new account: the
        # link's token gates it, so a whole office behind one address can join.
        "auth.register.complete": RateLimitRule(limit=60, period_seconds=3600, fail_closed=True),
        "auth.mfa": RateLimitRule(limit=10, period_seconds=300, fail_closed=True),
        # Per user: a stolen access token must not become a password oracle.
        "auth.password_change": RateLimitRule(limit=5, period_seconds=900, fail_closed=True),
        # Single sign-on, per client address: starting stores a pending sign-in,
        # finishing calls the identity provider.
        "auth.sso.start": RateLimitRule(limit=30, period_seconds=60, fail_closed=True),
        "auth.sso.callback": RateLimitRule(limit=30, period_seconds=60, fail_closed=True),
        # SCIM provisioning, per token (an identity provider's initial sync is bursty).
        "scim.token": RateLimitRule(limit=600, period_seconds=60, fail_closed=True),
        "api.read": RateLimitRule(limit=600, period_seconds=60),
        "api.write": RateLimitRule(limit=120, period_seconds=60),
        "api.export": RateLimitRule(limit=20, period_seconds=3600, fail_closed=True),
        "api.ai": RateLimitRule(limit=30, period_seconds=3600, fail_closed=True),
        "webhook.endpoint": RateLimitRule(limit=120, period_seconds=60, fail_closed=True),
        "webhook.ip": RateLimitRule(limit=600, period_seconds=60, fail_closed=True),
        "automation.service": RateLimitRule(limit=1200, period_seconds=60),
        "sandbox.gateway": RateLimitRule(limit=600, period_seconds=60),
        "notifications.channel": RateLimitRule(limit=30, period_seconds=60),
        "external_api.integration": RateLimitRule(limit=60, period_seconds=60),
    }


class RateLimitSettings(_Section):
    enabled: bool = True
    rules: dict[str, RateLimitRule] = Field(default_factory=_default_rate_limits)

    @field_validator("rules", mode="after")
    @classmethod
    def _merge_defaults(cls, value: dict[str, RateLimitRule]) -> dict[str, RateLimitRule]:
        """Overrides change only the fields they name: tuning a scope's limit keeps
        its failure policy (a fail-closed scope must not start failing open)."""
        merged = _default_rate_limits()
        for scope, rule in value.items():
            default = merged.get(scope)
            merged[scope] = (
                default.model_copy(
                    update={name: getattr(rule, name) for name in rule.model_fields_set}
                )
                if default is not None
                else rule
            )
        return merged


class _EnvSource(EnvSettingsSource):
    """Environment source that leaves ``*_FILE`` indirections to ``_FileSecretsSource``."""

    def _load_env_vars(self) -> Mapping[str, str | None]:
        return {
            k: v for k, v in super()._load_env_vars().items() if not k.lower().endswith("_file")
        }


class _FileSecretsSource(PydanticBaseSettingsSource):
    """Resolve ``NEXUSFLOW_<SECTION>__<FIELD>_FILE`` variables to file contents."""

    def get_field_value(self, field: FieldInfo, field_name: str) -> tuple[Any, str, bool]:
        return None, field_name, False  # pragma: no cover - __call__ is used instead

    def __call__(self) -> dict[str, Any]:
        resolved: dict[str, Any] = {}
        for key, raw_path in os.environ.items():
            upper = key.upper()
            if not (upper.startswith(ENV_PREFIX) and upper.endswith("_FILE")):
                continue
            dotted = upper[len(ENV_PREFIX) : -len("_FILE")].lower()
            path = Path(raw_path)
            if path.stat().st_size > _MAX_SECRET_FILE_BYTES:
                raise ValueError(f"Secret file for {key} exceeds {_MAX_SECRET_FILE_BYTES} bytes")
            value = path.read_text(encoding="utf-8").strip()
            if not value:
                # An empty file is a placeholder for an optional secret that is
                # not configured (yet), e.g. the n8n API key before n8n's setup.
                continue
            target = resolved
            parts = dotted.split("__")
            for part in parts[:-1]:
                target = target.setdefault(part, {})
            target[parts[-1]] = value
        return resolved


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix=ENV_PREFIX,
        env_nested_delimiter="__",
        extra="ignore",
        case_sensitive=False,
        frozen=True,
        # Compose passes unset optional variables as "" (`${VAR:-}`): treat
        # them as unset so the defaults apply instead of empty strings.
        env_ignore_empty=True,
    )

    app: AppSettings = Field(default_factory=AppSettings)
    database: DatabaseSettings = Field(default_factory=DatabaseSettings)
    redis: RedisSettings = Field(default_factory=RedisSettings)
    broker: BrokerSettings = Field(default_factory=BrokerSettings)
    security: SecuritySettings = Field(default_factory=SecuritySettings)
    sso: SsoSettings = Field(default_factory=SsoSettings)
    scraping: ScrapingSettings = Field(default_factory=ScrapingSettings)
    ai: AISettings = Field(default_factory=AISettings)
    notifications: NotificationSettings = Field(default_factory=NotificationSettings)
    n8n: N8nSettings = Field(default_factory=N8nSettings)
    storage: StorageSettings = Field(default_factory=StorageSettings)
    observability: ObservabilitySettings = Field(default_factory=ObservabilitySettings)
    retention: RetentionSettings = Field(default_factory=RetentionSettings)
    rate_limits: RateLimitSettings = Field(default_factory=RateLimitSettings)

    @classmethod
    def settings_customise_sources(
        cls,
        settings_cls: type[BaseSettings],
        init_settings: PydanticBaseSettingsSource,
        env_settings: PydanticBaseSettingsSource,
        dotenv_settings: PydanticBaseSettingsSource,
        file_secret_settings: PydanticBaseSettingsSource,
    ) -> tuple[PydanticBaseSettingsSource, ...]:
        return (init_settings, _EnvSource(settings_cls), _FileSecretsSource(settings_cls))

    @model_validator(mode="after")
    def _enforce_secure_configuration(self) -> Self:
        problems = [*self._key_material_problems()]
        if self.app.is_production_like:
            problems.extend(self._production_problems())
        if problems:
            raise ValueError("Insecure configuration: " + "; ".join(problems))
        return self

    def _key_material_problems(self) -> list[str]:
        problems: list[str] = []
        sec = self.security
        if sec.jwt_private_key is None:
            problems.append("security.jwt_private_key is required")
        if sec.hmac_pepper is None:
            problems.append("security.hmac_pepper is required")
        elif len(_b64_or_raw(sec.hmac_pepper.get_secret_value())) < 32:
            problems.append("security.hmac_pepper must be at least 32 bytes")
        if sec.encryption_keys is None:
            problems.append("security.encryption_keys is required")
        if self.ai.provider == "anthropic" and self.ai.api_key is None:
            problems.append("ai.api_key is required when ai.provider=anthropic")
        return problems

    def _production_problems(self) -> list[str]:
        problems: list[str] = []
        if self.app.debug:
            problems.append("app.debug must be false")
        if urlsplit(self.app.public_base_url).scheme != "https":
            problems.append("app.public_base_url must use https")
        if not self.app.allowed_hosts or "*" in self.app.allowed_hosts:
            problems.append("app.allowed_hosts must be an explicit list")
        problems.extend(
            f"CORS origin {origin!r} must be an explicit https origin"
            for origin in self.app.cors_allowed_origins
            if origin == "*" or urlsplit(origin).scheme != "https"
        )
        if self.scraping.allow_http:
            problems.append("scraping.allow_http must be false")
        if self.n8n.webhook_jwt_secret is None:
            problems.append("n8n.webhook_jwt_secret is required")
        return problems

    def security_warnings(self) -> list[str]:
        """Non-fatal hardening recommendations, logged at startup."""
        warnings: list[str] = []
        if self.app.is_production_like:
            if self.database.ssl_mode == "disable":
                warnings.append("database TLS is disabled (rely on an isolated network)")
            if not self.redis.url.get_secret_value().startswith("rediss://"):
                warnings.append("redis TLS is disabled (rely on an isolated network)")
            if not self.broker.use_ssl:
                warnings.append("broker TLS is disabled (rely on an isolated network)")
            if self.storage.clamav_address is None:
                warnings.append("uploads are not malware-scanned (storage.clamav_address unset)")
            if not self.notifications.smtp_host:
                warnings.append(
                    "e-mail is off (notifications.smtp_host unset): no sign-in notices, "
                    "invitations or password resets are sent"
                )
        return warnings


class SandboxRuntimeSettings(_Section):
    gateway_url: str = "http://api-internal:8001"
    gateway_timeout_seconds: float = Field(default=60.0, gt=0, le=600)
    # Optional, ACL-restricted Redis user limited to the robots/throttle keys.
    redis_url: SecretStr | None = None
    # CA of a rediss:// server with a private certificate (see RedisSettings).
    redis_ssl_ca_certs: Path | None = None


class SandboxSettings(BaseSettings):
    """Configuration of the sandbox worker pool.

    Deliberately narrow: there is no field for a database URL, key material,
    peppers or provider credentials, so none can be configured into the
    process that parses hostile content - even by mistake.
    """

    model_config = SettingsConfigDict(
        env_prefix=ENV_PREFIX,
        env_nested_delimiter="__",
        extra="ignore",
        case_sensitive=False,
        frozen=True,
        # Compose passes unset optional variables as "" (`${VAR:-}`): treat
        # them as unset so the defaults apply instead of empty strings.
        env_ignore_empty=True,
    )

    app: AppSettings = Field(default_factory=AppSettings)
    broker: BrokerSettings = Field(default_factory=BrokerSettings)
    scraping: ScrapingSettings = Field(default_factory=ScrapingSettings)
    storage: StorageSettings = Field(default_factory=StorageSettings)
    observability: ObservabilitySettings = Field(default_factory=ObservabilitySettings)
    sandbox: SandboxRuntimeSettings = Field(default_factory=SandboxRuntimeSettings)

    @classmethod
    def settings_customise_sources(
        cls,
        settings_cls: type[BaseSettings],
        init_settings: PydanticBaseSettingsSource,
        env_settings: PydanticBaseSettingsSource,
        dotenv_settings: PydanticBaseSettingsSource,
        file_secret_settings: PydanticBaseSettingsSource,
    ) -> tuple[PydanticBaseSettingsSource, ...]:
        return (init_settings, _EnvSource(settings_cls), _FileSecretsSource(settings_cls))

    @model_validator(mode="after")
    def _enforce_secure_configuration(self) -> Self:
        if self.app.is_production_like and self.scraping.allow_http:
            raise ValueError("Insecure configuration: scraping.allow_http must be false")
        return self


class BrowserRuntimeSettings(_Section):
    token: SecretStr | None = None  # shared only with the sandbox pool
    max_concurrency: int = Field(default=2, ge=1, le=16)
    queue_timeout_seconds: float = Field(default=10.0, gt=0, le=120)
    navigation_timeout_seconds: float = Field(default=20.0, gt=0, le=120)
    max_html_bytes: int = Field(default=5 * 1024 * 1024, ge=1024, le=50 * 1024 * 1024)
    # Chromium's own sandbox needs user namespaces (custom seccomp profile);
    # without it the hardened container is the isolation boundary.
    chromium_sandbox: bool = False


class BrowserServiceSettings(BaseSettings):
    """Configuration of the isolated rendering service (no platform secrets)."""

    model_config = SettingsConfigDict(
        env_prefix=ENV_PREFIX,
        env_nested_delimiter="__",
        extra="ignore",
        case_sensitive=False,
        frozen=True,
        # Compose passes unset optional variables as "" (`${VAR:-}`): treat
        # them as unset so the defaults apply instead of empty strings.
        env_ignore_empty=True,
    )

    app: AppSettings = Field(default_factory=AppSettings)
    scraping: ScrapingSettings = Field(default_factory=ScrapingSettings)
    observability: ObservabilitySettings = Field(default_factory=ObservabilitySettings)
    browser: BrowserRuntimeSettings = Field(default_factory=BrowserRuntimeSettings)

    @classmethod
    def settings_customise_sources(
        cls,
        settings_cls: type[BaseSettings],
        init_settings: PydanticBaseSettingsSource,
        env_settings: PydanticBaseSettingsSource,
        dotenv_settings: PydanticBaseSettingsSource,
        file_secret_settings: PydanticBaseSettingsSource,
    ) -> tuple[PydanticBaseSettingsSource, ...]:
        return (init_settings, _EnvSource(settings_cls), _FileSecretsSource(settings_cls))

    @model_validator(mode="after")
    def _enforce_secure_configuration(self) -> Self:
        token = self.browser.token
        if token is None or len(token.get_secret_value()) < 32:
            raise ValueError("Insecure configuration: browser.token must be at least 32 characters")
        if self.app.is_production_like and self.scraping.allow_http:
            raise ValueError("Insecure configuration: scraping.allow_http must be false")
        return self


def _b64_or_raw(value: str) -> bytes:
    try:
        return base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError):
        return value.encode()


def decode_key_bytes(value: str) -> bytes:
    """Decode base64 (standard or url-safe) key material."""
    cleaned = value.strip()
    padded = cleaned + "=" * (-len(cleaned) % 4)
    try:
        if "-" in cleaned or "_" in cleaned:
            return base64.urlsafe_b64decode(padded)
        return base64.b64decode(padded, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ValueError("key material must be base64 encoded") from exc
