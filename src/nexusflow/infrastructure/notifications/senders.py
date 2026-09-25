"""Channel senders: e-mail (SMTP/TLS), Slack, Telegram and signed webhooks.

All HTTP-based senders use the SSRF-guarded client. Slack and Telegram are
pinned to their official hosts via a domain allowlist, so a tampered channel
configuration cannot redirect notifications (or credentials) elsewhere.
Messages are plain text - no HTML, no markup parsing - to avoid injection
into recipients' clients.
"""

from __future__ import annotations

import json
import time
from email.message import EmailMessage
from typing import Protocol

import aiosmtplib

from nexusflow.core.config import NotificationSettings
from nexusflow.core.errors import NexusFlowError, PermanentError, TransientError
from nexusflow.core.ids import uuid7
from nexusflow.core.text import single_line, truncate
from nexusflow.domain.integrations.model import IntegrationKind, ResolvedCredential
from nexusflow.domain.notifications.model import (
    ChannelKind,
    EmailChannelConfig,
    NotificationChannel,
    OutboundMessage,
    TelegramChannelConfig,
    WebhookChannelConfig,
)
from nexusflow.domain.shared.url_policy import UrlPolicy
from nexusflow.domain.webhooks.signatures import (
    DELIVERY_HEADER,
    SIGNATURE_HEADER,
    build_signature_header,
)
from nexusflow.infrastructure.http.client import SafeHttpClient
from nexusflow.infrastructure.observability import metrics

_TRANSIENT_SMTP = (
    aiosmtplib.SMTPServerDisconnected,
    aiosmtplib.SMTPConnectError,
    aiosmtplib.SMTPTimeoutError,
    aiosmtplib.SMTPReadTimeoutError,
)


class EmailTransport(Protocol):
    async def send_email(self, recipients: list[str], subject: str, body: str) -> None: ...


class SmtpEmailTransport:
    def __init__(self, settings: NotificationSettings) -> None:
        self._settings = settings

    async def send_email(self, recipients: list[str], subject: str, body: str) -> None:
        settings = self._settings
        if not settings.smtp_host:
            raise PermanentError(code="smtp_not_configured")
        message = EmailMessage()
        message["From"] = str(settings.smtp_from)
        message["To"] = ", ".join(recipients)
        message["Subject"] = single_line(subject, 200)  # no header injection via CR/LF
        message["Message-ID"] = f"<{uuid7()}@nexusflow>"
        message.set_content(truncate(body, 20_000))
        try:
            await aiosmtplib.send(
                message,
                hostname=settings.smtp_host,
                port=settings.smtp_port,
                username=settings.smtp_username,
                password=settings.smtp_password.get_secret_value()
                if settings.smtp_password
                else None,
                use_tls=settings.smtp_tls_mode == "tls",
                start_tls=settings.smtp_tls_mode == "starttls",
                validate_certs=True,
                # A private relay's CA (e.g. the demo CA) is trusted on top of the
                # system store; certificate validation itself is never switched off.
                cert_bundle=str(settings.smtp_ca_bundle) if settings.smtp_ca_bundle else None,
                timeout=settings.smtp_timeout_seconds,
            )
        except _TRANSIENT_SMTP as exc:
            raise TransientError(
                code="smtp_unavailable", internal_detail=type(exc).__name__
            ) from exc
        except aiosmtplib.SMTPException as exc:
            if _temporary_reply(exc):
                # 4yz: greylisting, throttling, a full queue - retried with backoff.
                raise TransientError(
                    code="smtp_deferred", internal_detail=type(exc).__name__
                ) from exc
            raise PermanentError(code="smtp_rejected", internal_detail=type(exc).__name__) from exc


def _temporary_reply(exc: aiosmtplib.SMTPException) -> bool:
    """RFC 5321 4.2.1: a 4yz reply is a transient failure, a 5yz one is permanent."""
    if isinstance(exc, aiosmtplib.SMTPRecipientsRefused):
        codes = [refusal.code for refusal in exc.recipients]
        return bool(codes) and all(400 <= code < 500 for code in codes)
    return isinstance(exc, aiosmtplib.SMTPResponseException) and 400 <= exc.code < 500


def _text(message: OutboundMessage) -> str:
    return f"{message.title}\n\n{message.body}"


class ChannelSender:
    """Dispatches an alert to the channel's provider."""

    def __init__(
        self,
        *,
        client: SafeHttpClient,
        email: EmailTransport,
        platform_policy: UrlPolicy,
        telegram_api_base: str,
        slack_host: str,
    ) -> None:
        self._client = client
        self._email = email
        self._platform_policy = platform_policy
        self._telegram_base = telegram_api_base.rstrip("/")
        self._slack_policy = UrlPolicy(allowed_domains=frozenset({slack_host}))
        telegram_host = telegram_api_base.split("/")[2]
        self._telegram_policy = UrlPolicy(allowed_domains=frozenset({telegram_host}))

    async def send(
        self,
        channel: NotificationChannel,
        message: OutboundMessage,
        credential: ResolvedCredential | None,
    ) -> None:
        try:
            await self._dispatch(channel, message, credential)
        except NexusFlowError:  # including a destination the URL policy blocks
            metrics.NOTIFICATIONS.labels(channel=channel.kind.value, result="failure").inc()
            raise
        metrics.NOTIFICATIONS.labels(channel=channel.kind.value, result="success").inc()

    async def _dispatch(
        self,
        channel: NotificationChannel,
        message: OutboundMessage,
        credential: ResolvedCredential | None,
    ) -> None:
        config = channel.parsed_config
        if channel.kind is ChannelKind.EMAIL and isinstance(config, EmailChannelConfig):
            await self._email.send_email(
                [str(r) for r in config.recipients], message.title, message.body
            )
            return
        if credential is None:
            raise PermanentError(code="credential_missing")
        if channel.kind is ChannelKind.SLACK and credential.kind is IntegrationKind.SLACK_WEBHOOK:
            await self._client.request(
                "POST",
                credential.secret,
                json_body={"text": _text(message)},
                policy=self._slack_policy,
                follow_redirects=False,
            )
            return
        if (
            channel.kind is ChannelKind.TELEGRAM
            and isinstance(config, TelegramChannelConfig)
            and credential.kind is IntegrationKind.TELEGRAM_BOT
        ):
            await self._client.request(
                "POST",
                f"{self._telegram_base}/bot{credential.secret}/sendMessage",
                json_body={
                    "chat_id": config.chat_id,
                    "text": truncate(_text(message), 4000),
                    "disable_web_page_preview": True,
                },
                policy=self._telegram_policy,
                follow_redirects=False,
            )
            return
        if (
            channel.kind is ChannelKind.WEBHOOK
            and isinstance(config, WebhookChannelConfig)
            and credential.kind is IntegrationKind.WEBHOOK_SIGNING
        ):
            await self._signed_webhook(config.url, message, credential.secret)
            return
        raise PermanentError(code="channel_misconfigured")

    async def _signed_webhook(self, url: str, message: OutboundMessage, secret: str) -> None:
        body = json.dumps(
            {
                "type": "alert",
                "delivery_id": message.idempotency_key,
                "alert": {
                    "title": message.title,
                    "body": message.body,
                    "severity": message.severity,
                },
            },
            separators=(",", ":"),
        ).encode()
        timestamp = int(time.time())
        await self._client.request(
            "POST",
            url,
            content=body,
            headers={
                "Content-Type": "application/json",
                SIGNATURE_HEADER: build_signature_header(
                    secret.encode(),
                    timestamp=timestamp,
                    delivery_id=message.idempotency_key,
                    body=body,
                ),
                DELIVERY_HEADER: message.idempotency_key,
            },
            policy=self._platform_policy,
            follow_redirects=False,
        )
