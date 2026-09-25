"""Notification channel senders (``infrastructure.notifications.senders``).

Slack, Telegram and signed-webhook deliveries go through the real SSRF-guarded
client over an in-memory transport; e-mail goes through ``SmtpEmailTransport``
with ``aiosmtplib.send`` replaced at the call boundary. Covers payload shapes,
host pinning, the webhook signature (checked with the domain verifier), secret
hygiene in errors, failure classification, metrics and SMTP configuration.
"""

from __future__ import annotations

import json
import re
import time
from datetime import UTC, datetime
from email.message import EmailMessage
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from uuid import uuid4

import aiosmtplib
import httpx2
import pytest
from prometheus_client import REGISTRY

from nexusflow.core.config import NotificationSettings
from nexusflow.core.errors import (
    AuthenticationError,
    NexusFlowError,
    PermanentError,
    PolicyViolationError,
    TransientError,
)
from nexusflow.domain.integrations.model import IntegrationKind, ResolvedCredential
from nexusflow.domain.notifications.model import ChannelKind, NotificationChannel, OutboundMessage
from nexusflow.domain.shared.url_policy import UrlPolicy
from nexusflow.domain.webhooks.signatures import (
    DELIVERY_HEADER,
    SIGNATURE_HEADER,
    ParsedSignature,
    parse_signature_header,
    verify_signature,
)
from nexusflow.infrastructure.http.client import (
    OutboundConnectionError,
    OutboundTimeoutError,
    RetryableUpstreamStatusError,
    UpstreamStatusError,
)
from nexusflow.infrastructure.notifications import senders as senders_module
from nexusflow.infrastructure.notifications.senders import ChannelSender, SmtpEmailTransport
from tests.unit.adapters.fakes import (
    Handler,
    RecordingHandler,
    SafeClientFactory,
    fail_on_request,
    respond,
)

NOW = datetime(2026, 9, 24, 12, 0, tzinfo=UTC)
SLACK_WEBHOOK = "https://hooks.slack.com/services/T0123ABCD/B0456EFGH/abcdefghijklmnopqrstuvwx"
TELEGRAM_TOKEN = "123456789:AAH-telegram-bot-token-abcdefghijklmn"
SIGNING_SECRET = "whsec_" + "q7" * 20
WEBHOOK_URL = "https://hooks.customer.example/nexusflow"
DELIVERY_ID = "0192f0c1-7a2b-7c3d-8e4f-5a6b7c8d9e0f"
SMTP_PASSWORD = "smtp-relay-password-0xDEADBEEF"
FIXED_TIMESTAMP = 1_790_000_000

MESSAGE = OutboundMessage(
    title="Price drop: Blue Widget",
    body="Blue Widget fell 25% to EUR 7.49.\nCheck the dashboard.",
    severity="high",
    link=None,
    idempotency_key=DELIVERY_ID,
)
TEXT = "Price drop: Blue Widget\n\nBlue Widget fell 25% to EUR 7.49.\nCheck the dashboard."

SLACK_CREDENTIAL = ResolvedCredential(IntegrationKind.SLACK_WEBHOOK, SLACK_WEBHOOK, {})
TELEGRAM_CREDENTIAL = ResolvedCredential(IntegrationKind.TELEGRAM_BOT, TELEGRAM_TOKEN, {})
SIGNING_CREDENTIAL = ResolvedCredential(IntegrationKind.WEBHOOK_SIGNING, SIGNING_SECRET, {})


def _channel(kind: ChannelKind, config: dict[str, Any]) -> NotificationChannel:
    return NotificationChannel(
        id=uuid4(),
        org_id=uuid4(),
        name=f"{kind.value} alerts",
        kind=kind,
        config=config,
        integration_id=None if kind is ChannelKind.EMAIL else uuid4(),
        created_at=NOW,
        updated_at=NOW,
    )


SLACK = _channel(ChannelKind.SLACK, {"kind": "slack"})
TELEGRAM = _channel(ChannelKind.TELEGRAM, {"kind": "telegram", "chat_id": "-1001234567890"})
WEBHOOK = _channel(ChannelKind.WEBHOOK, {"kind": "webhook", "url": WEBHOOK_URL})
EMAIL = _channel(
    ChannelKind.EMAIL, {"kind": "email", "recipients": ["ops@example.com", "cto@example.com"]}
)
MESSAGE_ID = re.compile(
    r"<[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}@nexusflow>"
)


class FakeEmail:
    def __init__(self) -> None:
        self.sent: list[tuple[list[str], str, str]] = []

    async def send_email(self, recipients: list[str], subject: str, body: str) -> None:
        self.sent.append((recipients, subject, body))


def _accepting() -> RecordingHandler:
    return RecordingHandler(lambda request: respond(200, "ok", content_type="text/plain"))


def _answering(status: int, **headers: str) -> RecordingHandler:
    return RecordingHandler(lambda request: respond(status, "nope", headers=headers))


def _raising(failure: type[httpx2.TransportError]) -> RecordingHandler:
    def handle(request: httpx2.Request) -> httpx2.Response:
        raise failure("simulated", request=request)

    return RecordingHandler(handle)


def _sender(
    factory: SafeClientFactory,
    handler: Handler,
    *,
    email: FakeEmail | None = None,
    platform_policy: UrlPolicy | None = None,
    telegram_api_base: str = "https://api.telegram.org",
) -> ChannelSender:
    return ChannelSender(
        client=factory(handler),
        email=email or FakeEmail(),
        platform_policy=platform_policy or UrlPolicy(),
        telegram_api_base=telegram_api_base,
        slack_host="hooks.slack.com",
    )


def _notifications(channel: str, result: str) -> float:
    labels = {"channel": channel, "result": result}
    return REGISTRY.get_sample_value("nexusflow_notifications_total", labels) or 0.0


def _error_text(error: NexusFlowError) -> str:
    return f"{error!r} {error} {error.message} {error.internal_detail} {error.details}"


async def _outcome(
    sender: ChannelSender,
    channel: NotificationChannel,
    credential: ResolvedCredential | None,
) -> NexusFlowError | None:
    try:
        await sender.send(channel, MESSAGE, credential)
    except NexusFlowError as error:
        return error
    return None


class TestSlack:
    async def test_posts_plain_text_to_the_incoming_webhook(
        self, safe_client_factory: SafeClientFactory
    ) -> None:
        slack = _accepting()
        before = _notifications("slack", "success")

        await _sender(safe_client_factory, slack).send(SLACK, MESSAGE, SLACK_CREDENTIAL)

        [request] = slack.requests
        assert request.method == "POST"
        assert str(request.url) == SLACK_WEBHOOK
        assert request.headers["content-type"] == "application/json"
        assert json.loads(request.content) == {"text": TEXT}
        assert _notifications("slack", "success") == before + 1

    @pytest.mark.security
    @pytest.mark.parametrize(
        "webhook",
        [
            "https://hooks.slack.com.evil.example/services/T0123ABCD/B0456EFGH/abcdefghijklmnop",
            "https://evil.example/services/T0123ABCD/B0456EFGH/abcdefghijklmnopqrstuvwx",
            "http://hooks.slack.com/services/T0123ABCD/B0456EFGH/abcdefghijklmnopqrstuvwx",
            "https://127.0.0.1/services/T0123ABCD/B0456EFGH/abcdefghijklmnopqrstuvwx",
        ],
    )
    async def test_webhooks_outside_the_slack_host_are_refused(
        self, safe_client_factory: SafeClientFactory, webhook: str
    ) -> None:
        slack = _accepting()
        credential = ResolvedCredential(IntegrationKind.SLACK_WEBHOOK, webhook, {})

        with pytest.raises(PolicyViolationError) as exc:
            await _sender(safe_client_factory, slack).send(SLACK, MESSAGE, credential)

        assert slack.requests == []
        assert webhook not in _error_text(exc.value)

    async def test_redirects_are_not_followed(self, safe_client_factory: SafeClientFactory) -> None:
        slack = _answering(302, location="https://collector.evil.example/steal")
        await _outcome(_sender(safe_client_factory, slack), SLACK, SLACK_CREDENTIAL)
        assert slack.urls == [SLACK_WEBHOOK]


class TestTelegram:
    async def test_sends_through_the_bot_api(self, safe_client_factory: SafeClientFactory) -> None:
        telegram = _accepting()

        await _sender(safe_client_factory, telegram).send(TELEGRAM, MESSAGE, TELEGRAM_CREDENTIAL)

        [request] = telegram.requests
        assert request.method == "POST"
        assert str(request.url) == f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage"
        assert json.loads(request.content) == {
            "chat_id": "-1001234567890",
            "text": TEXT,
            "disable_web_page_preview": True,
        }

    async def test_text_is_capped_at_the_telegram_limit(
        self, safe_client_factory: SafeClientFactory
    ) -> None:
        telegram = _accepting()
        long_message = OutboundMessage(
            title="Digest",
            body="x" * 10_000,
            severity="low",
            link=None,
            idempotency_key=DELIVERY_ID,
        )

        await _sender(safe_client_factory, telegram).send(
            TELEGRAM, long_message, TELEGRAM_CREDENTIAL
        )

        text = json.loads(telegram.requests[0].content)["text"]
        assert len(text) == 4_000
        assert text.startswith("Digest\n\nxxx")
        assert text.endswith("…")

    async def test_a_self_hosted_bot_api_base_is_used(
        self, safe_client_factory: SafeClientFactory
    ) -> None:
        telegram = _accepting()
        sender = _sender(
            safe_client_factory, telegram, telegram_api_base="https://tg-relay.example.com/api/"
        )

        await sender.send(TELEGRAM, MESSAGE, TELEGRAM_CREDENTIAL)

        assert telegram.urls == [
            f"https://tg-relay.example.com/api/bot{TELEGRAM_TOKEN}/sendMessage"
        ]

    @pytest.mark.security
    @pytest.mark.parametrize(
        ("handler", "error", "base"),
        [
            pytest.param(_answering(401), UpstreamStatusError, PermanentError, id="401"),
            pytest.param(_answering(404), UpstreamStatusError, PermanentError, id="404"),
            pytest.param(
                _answering(429, **{"retry-after": "5"}),
                RetryableUpstreamStatusError,
                TransientError,
                id="429",
            ),
            pytest.param(_answering(502), RetryableUpstreamStatusError, TransientError, id="502"),
            pytest.param(
                _raising(httpx2.ConnectError), OutboundConnectionError, TransientError, id="refused"
            ),
            pytest.param(
                _raising(httpx2.ReadTimeout), OutboundTimeoutError, TransientError, id="timeout"
            ),
        ],
    )
    async def test_failures_are_classified_and_never_reveal_the_bot_token(
        self,
        safe_client_factory: SafeClientFactory,
        handler: RecordingHandler,
        error: type[NexusFlowError],
        base: type[NexusFlowError],
    ) -> None:
        sender = _sender(safe_client_factory, handler)
        before = _notifications("telegram", "failure")

        with pytest.raises(error) as exc:
            await sender.send(TELEGRAM, MESSAGE, TELEGRAM_CREDENTIAL)

        assert isinstance(exc.value, base)
        assert TELEGRAM_TOKEN not in _error_text(exc.value)
        assert TELEGRAM_TOKEN.split(":")[1] not in _error_text(exc.value)
        assert _notifications("telegram", "failure") == before + 1


class TestSignedWebhook:
    @pytest.fixture
    def fixed_time(self, monkeypatch: pytest.MonkeyPatch) -> int:
        monkeypatch.setattr(senders_module, "time", SimpleNamespace(time=lambda: 1_790_000_000.9))
        return FIXED_TIMESTAMP

    async def test_payload_headers_and_signature(
        self, safe_client_factory: SafeClientFactory, fixed_time: int
    ) -> None:
        endpoint = _accepting()

        await _sender(safe_client_factory, endpoint).send(WEBHOOK, MESSAGE, SIGNING_CREDENTIAL)

        [request] = endpoint.requests
        assert request.method == "POST"
        assert str(request.url) == WEBHOOK_URL
        assert request.headers["content-type"] == "application/json"
        assert request.headers[DELIVERY_HEADER] == DELIVERY_ID
        payload = {
            "type": "alert",
            "delivery_id": DELIVERY_ID,
            "alert": {"title": MESSAGE.title, "body": MESSAGE.body, "severity": "high"},
        }
        assert request.content == json.dumps(payload, separators=(",", ":")).encode()
        header = request.headers[SIGNATURE_HEADER]
        assert re.fullmatch(rf"t={fixed_time},v1=[0-9a-f]{{64}}", header)
        assert verify_signature(
            secrets=[SIGNING_SECRET.encode()],
            header=header,
            delivery_id=request.headers[DELIVERY_HEADER],
            body=request.content,
            now_timestamp=fixed_time,
            tolerance_seconds=300,
        ) == parse_signature_header(header)

    @pytest.mark.security
    async def test_the_signature_binds_secret_body_delivery_and_time(
        self, safe_client_factory: SafeClientFactory, fixed_time: int
    ) -> None:
        endpoint = _accepting()
        await _sender(safe_client_factory, endpoint).send(WEBHOOK, MESSAGE, SIGNING_CREDENTIAL)
        [request] = endpoint.requests
        signed = {
            "secrets": [SIGNING_SECRET.encode()],
            "header": request.headers[SIGNATURE_HEADER],
            "delivery_id": DELIVERY_ID,
            "body": request.content,
            "now_timestamp": fixed_time,
            "tolerance_seconds": 300,
        }
        tampered: list[dict[str, Any]] = [
            {"secrets": [b"whsec_" + b"x" * 40]},
            {"body": request.content.replace(b'"high"', b'"low"')},
            {"delivery_id": "0192f0c1-0000-7000-8000-000000000000"},
            {"now_timestamp": fixed_time + 3_600},
        ]
        for change in tampered:
            with pytest.raises(AuthenticationError):
                verify_signature(**{**signed, **change})

    async def test_the_timestamp_is_the_current_time(
        self, safe_client_factory: SafeClientFactory
    ) -> None:
        endpoint = _accepting()
        await _sender(safe_client_factory, endpoint).send(WEBHOOK, MESSAGE, SIGNING_CREDENTIAL)
        [request] = endpoint.requests
        parsed = verify_signature(
            secrets=[SIGNING_SECRET.encode()],
            header=request.headers[SIGNATURE_HEADER],
            delivery_id=DELIVERY_ID,
            body=request.content,
            now_timestamp=int(time.time()),
            tolerance_seconds=60,
        )
        assert isinstance(parsed, ParsedSignature)

    @pytest.mark.security
    async def test_the_signing_secret_is_never_sent_or_reported(
        self, safe_client_factory: SafeClientFactory
    ) -> None:
        endpoint = RecordingHandler(lambda request: respond(500, "upstream exploded"))
        with pytest.raises(RetryableUpstreamStatusError) as exc:
            await _sender(safe_client_factory, endpoint).send(WEBHOOK, MESSAGE, SIGNING_CREDENTIAL)
        [request] = endpoint.requests
        assert SIGNING_SECRET.encode() not in request.content
        assert SIGNING_SECRET not in str(request.headers)
        assert SIGNING_SECRET not in _error_text(exc.value)

    @pytest.mark.security
    @pytest.mark.parametrize(
        "url",
        [
            "https://169.254.169.254/latest/meta-data/",
            "https://localhost/hook",
            "https://10.1.2.3/hook",
            "https://[::1]/hook",
            "https://hooks.internal/hook",
            "http://hooks.customer.example/nexusflow",
            "https://hooks.customer.example:8443/nexusflow",
        ],
    )
    async def test_internal_or_unsafe_targets_are_refused(
        self, safe_client_factory: SafeClientFactory, url: str
    ) -> None:
        endpoint = _accepting()
        with pytest.raises(PolicyViolationError):
            await _sender(safe_client_factory, endpoint).send(
                _channel(ChannelKind.WEBHOOK, {"kind": "webhook", "url": url}),
                MESSAGE,
                SIGNING_CREDENTIAL,
            )
        assert endpoint.requests == []

    @pytest.mark.security
    async def test_the_platform_blocklist_applies(
        self, safe_client_factory: SafeClientFactory
    ) -> None:
        endpoint = _accepting()
        sender = _sender(
            safe_client_factory,
            endpoint,
            platform_policy=UrlPolicy(blocked_domains=frozenset({"customer.example"})),
        )
        before = _notifications("webhook", "failure")
        with pytest.raises(PolicyViolationError):
            await sender.send(WEBHOOK, MESSAGE, SIGNING_CREDENTIAL)
        assert endpoint.requests == []
        assert _notifications("webhook", "failure") == before + 1  # counted as a failure

    @pytest.mark.parametrize(
        ("status", "error", "base"),
        [
            (400, UpstreamStatusError, PermanentError),
            (410, UpstreamStatusError, PermanentError),
            (429, RetryableUpstreamStatusError, TransientError),
            (503, RetryableUpstreamStatusError, TransientError),
        ],
    )
    async def test_receiver_errors_are_classified(
        self,
        safe_client_factory: SafeClientFactory,
        status: int,
        error: type[NexusFlowError],
        base: type[NexusFlowError],
    ) -> None:
        with pytest.raises(error) as exc:
            await _sender(safe_client_factory, _answering(status)).send(
                WEBHOOK, MESSAGE, SIGNING_CREDENTIAL
            )
        assert isinstance(exc.value, base)

    async def test_redirects_are_not_followed(self, safe_client_factory: SafeClientFactory) -> None:
        endpoint = _answering(307, location="https://other.example/hook")
        await _outcome(_sender(safe_client_factory, endpoint), WEBHOOK, SIGNING_CREDENTIAL)
        assert endpoint.urls == [WEBHOOK_URL]


@pytest.mark.parametrize(
    ("channel", "credential"),
    [
        pytest.param(SLACK, SLACK_CREDENTIAL, id="slack"),
        pytest.param(TELEGRAM, TELEGRAM_CREDENTIAL, id="telegram"),
        pytest.param(WEBHOOK, SIGNING_CREDENTIAL, id="webhook"),
    ],
)
async def test_a_redirect_answer_is_not_a_successful_delivery(
    safe_client_factory: SafeClientFactory,
    channel: NotificationChannel,
    credential: ResolvedCredential,
) -> None:
    endpoint = _answering(301, location="https://moved.example/hook")
    before = _notifications(channel.kind.value, "failure")
    outcome = await _outcome(_sender(safe_client_factory, endpoint), channel, credential)
    assert isinstance(outcome, PermanentError), "the alert was never delivered"
    assert outcome.code == "redirect_not_followed"
    assert _notifications(channel.kind.value, "failure") == before + 1


class TestDispatch:
    async def test_email_channels_use_the_email_transport(
        self, safe_client_factory: SafeClientFactory
    ) -> None:
        email = FakeEmail()
        before = _notifications("email", "success")

        await _sender(safe_client_factory, fail_on_request, email=email).send(EMAIL, MESSAGE, None)

        assert email.sent == [(["ops@example.com", "cto@example.com"], MESSAGE.title, MESSAGE.body)]
        assert _notifications("email", "success") == before + 1

    @pytest.mark.parametrize("channel", [SLACK, TELEGRAM, WEBHOOK], ids=["slack", "tg", "hook"])
    async def test_a_missing_credential_is_permanent(
        self, safe_client_factory: SafeClientFactory, channel: NotificationChannel
    ) -> None:
        before = _notifications(channel.kind.value, "failure")
        with pytest.raises(PermanentError) as exc:
            await _sender(safe_client_factory, fail_on_request).send(channel, MESSAGE, None)
        assert exc.value.code == "credential_missing"
        assert _notifications(channel.kind.value, "failure") == before + 1

    @pytest.mark.parametrize(
        ("channel", "credential"),
        [
            pytest.param(SLACK, TELEGRAM_CREDENTIAL, id="slack-with-telegram-token"),
            pytest.param(SLACK, SIGNING_CREDENTIAL, id="slack-with-signing-secret"),
            pytest.param(TELEGRAM, SLACK_CREDENTIAL, id="telegram-with-slack-webhook"),
            pytest.param(
                WEBHOOK,
                ResolvedCredential(IntegrationKind.HTTP_BEARER, "bearer-" + "t" * 30, {}),
                id="webhook-with-bearer",
            ),
            pytest.param(
                _channel(ChannelKind.TELEGRAM, {"kind": "webhook", "url": WEBHOOK_URL}),
                TELEGRAM_CREDENTIAL,
                id="telegram-with-webhook-config",
            ),
        ],
    )
    async def test_mismatched_channels_and_credentials_are_refused(
        self,
        safe_client_factory: SafeClientFactory,
        channel: NotificationChannel,
        credential: ResolvedCredential,
    ) -> None:
        with pytest.raises(PermanentError) as exc:
            await _sender(safe_client_factory, fail_on_request).send(channel, MESSAGE, credential)
        assert exc.value.code == "channel_misconfigured"
        assert credential.secret not in _error_text(exc.value)


class FakeSmtp:
    """Replaces ``aiosmtplib.send``: records the message and connection options."""

    def __init__(self) -> None:
        self.error: BaseException | None = None
        self.calls: list[tuple[EmailMessage, dict[str, Any]]] = []

    async def send(self, message: EmailMessage, /, **options: Any) -> tuple[dict[str, Any], str]:
        self.calls.append((message, options))
        if self.error is not None:
            raise self.error
        return {}, "250 2.0.0 queued"


@pytest.fixture
def smtp(monkeypatch: pytest.MonkeyPatch) -> FakeSmtp:
    fake = FakeSmtp()
    monkeypatch.setattr(aiosmtplib, "send", fake.send)
    return fake


def _smtp_settings(**overrides: Any) -> NotificationSettings:
    values: dict[str, Any] = {
        "smtp_host": "smtp.example.com",
        "smtp_port": 587,
        "smtp_username": "alerts",
        "smtp_password": SMTP_PASSWORD,
        "smtp_from": "alerts@nexusflow.example",
        "smtp_timeout_seconds": 7.5,
    }
    values.update(overrides)
    return NotificationSettings.model_validate(values)


class TestSmtpTransport:
    async def test_an_unconfigured_relay_is_a_permanent_error(self, smtp: FakeSmtp) -> None:
        with pytest.raises(PermanentError) as exc:
            await SmtpEmailTransport(NotificationSettings()).send_email(
                ["ops@example.com"], "Subject", "Body"
            )
        assert exc.value.code == "smtp_not_configured"
        assert smtp.calls == []

    async def test_the_message_is_plain_text_with_safe_headers(self, smtp: FakeSmtp) -> None:
        await SmtpEmailTransport(_smtp_settings()).send_email(
            ["ops@example.com", "cto@example.com"], "Price drop", "Line one\nLine two"
        )

        [(message, _)] = smtp.calls
        assert message["From"] == "alerts@nexusflow.example"
        assert message["To"] == "ops@example.com, cto@example.com"
        assert message["Subject"] == "Price drop"
        assert MESSAGE_ID.fullmatch(message["Message-ID"])
        assert message.get_content_type() == "text/plain"
        assert message.get_content() == "Line one\nLine two\n"

    async def test_every_message_gets_a_fresh_message_id(self, smtp: FakeSmtp) -> None:
        transport = SmtpEmailTransport(_smtp_settings())
        for _ in range(2):
            await transport.send_email(["ops@example.com"], "Subject", "Body")
        first, second = (message["Message-ID"] for message, _ in smtp.calls)
        assert first != second

    @pytest.mark.parametrize(
        ("mode", "port", "use_tls", "start_tls"),
        [("tls", 465, True, False), ("starttls", 587, False, True)],
    )
    async def test_connection_options(
        self, smtp: FakeSmtp, mode: str, port: int, use_tls: bool, start_tls: bool
    ) -> None:
        settings = _smtp_settings(smtp_tls_mode=mode, smtp_port=port)
        await SmtpEmailTransport(settings).send_email(["ops@example.com"], "Subject", "Body")

        [(_, options)] = smtp.calls
        assert {
            key: options[key]
            for key in (
                "hostname",
                "port",
                "username",
                "password",
                "use_tls",
                "start_tls",
                "validate_certs",
                "timeout",
            )
        } == {
            "hostname": "smtp.example.com",
            "port": port,
            "username": "alerts",
            "password": SMTP_PASSWORD,
            "use_tls": use_tls,
            "start_tls": start_tls,
            "validate_certs": True,
            "timeout": 7.5,
        }

    async def test_anonymous_relays_get_no_credentials(self, smtp: FakeSmtp) -> None:
        settings = _smtp_settings(smtp_username=None, smtp_password=None)
        await SmtpEmailTransport(settings).send_email(["ops@example.com"], "Subject", "Body")
        [(_, options)] = smtp.calls
        assert (options["username"], options["password"]) == (None, None)

    @pytest.mark.security
    async def test_a_private_ca_is_trusted_without_disabling_validation(
        self, smtp: FakeSmtp, tmp_path: Path
    ) -> None:
        ca_file = tmp_path / "relay-ca.pem"
        ca_file.write_text("-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n")
        transport = SmtpEmailTransport(_smtp_settings(smtp_ca_bundle=ca_file))
        await transport.send_email(["ops@example.com"], "Subject", "Body")
        await SmtpEmailTransport(_smtp_settings()).send_email(["ops@example.com"], "S", "B")

        (_, with_ca), (_, without_ca) = smtp.calls
        assert with_ca["cert_bundle"] == str(ca_file)
        assert with_ca["validate_certs"] is True
        assert without_ca.get("cert_bundle") is None  # only the system trust store
        assert without_ca["validate_certs"] is True

    @pytest.mark.security
    async def test_header_injection_through_the_subject_is_neutralised(
        self, smtp: FakeSmtp
    ) -> None:
        subject = "Stock alert\r\nBcc: attacker@evil.example\r\n\r\nInjected body"
        await SmtpEmailTransport(_smtp_settings()).send_email(["ops@example.com"], subject, "Body")

        [(message, _)] = smtp.calls
        assert "\r" not in message["Subject"]
        assert "\n" not in message["Subject"]
        assert message["Bcc"] is None
        header_block = message.as_string().split("\n\n", 1)[0]
        assert not any(line.startswith("Bcc:") for line in header_block.splitlines())

    async def test_subject_and_body_are_bounded(self, smtp: FakeSmtp) -> None:
        await SmtpEmailTransport(_smtp_settings()).send_email(
            ["ops@example.com"], "S" * 500, "b" * 25_000
        )
        [(message, _)] = smtp.calls
        assert len(message["Subject"]) <= 200
        body = message.get_content().rstrip("\n")
        assert len(body) == 20_000
        assert body.endswith("…")

    @pytest.mark.parametrize(
        "failure",
        [
            aiosmtplib.SMTPServerDisconnected("Unexpected EOF received"),
            aiosmtplib.SMTPConnectError("Error connecting to smtp.example.com on port 587"),
            aiosmtplib.SMTPConnectTimeoutError("Timed out connecting to smtp.example.com"),
            aiosmtplib.SMTPTimeoutError("Timed out waiting for server response"),
            aiosmtplib.SMTPReadTimeoutError("Timed out waiting for server response"),
        ],
        ids=lambda failure: type(failure).__name__,
    )
    async def test_connection_problems_are_transient(
        self, smtp: FakeSmtp, failure: aiosmtplib.SMTPException
    ) -> None:
        smtp.error = failure
        with pytest.raises(TransientError) as exc:
            await SmtpEmailTransport(_smtp_settings()).send_email(["ops@example.com"], "S", "B")
        assert exc.value.code == "smtp_unavailable"
        assert exc.value.internal_detail == type(failure).__name__
        assert SMTP_PASSWORD not in _error_text(exc.value)

    @pytest.mark.parametrize(
        "failure",
        [
            aiosmtplib.SMTPAuthenticationError(535, "5.7.8 Authentication credentials invalid"),
            aiosmtplib.SMTPRecipientsRefused(
                [aiosmtplib.SMTPRecipientRefused(550, "5.1.1 No such user", "ops@example.com")]
            ),
            aiosmtplib.SMTPSenderRefused(553, "5.7.1 Sender not allowed", "alerts@example.com"),
            aiosmtplib.SMTPDataError(554, "5.7.1 Message rejected as spam"),
            aiosmtplib.SMTPNotSupported("STARTTLS extension not supported by server"),
        ],
        ids=lambda failure: type(failure).__name__,
    )
    async def test_rejections_are_permanent(
        self, smtp: FakeSmtp, failure: aiosmtplib.SMTPException
    ) -> None:
        smtp.error = failure
        with pytest.raises(PermanentError) as exc:
            await SmtpEmailTransport(_smtp_settings()).send_email(["ops@example.com"], "S", "B")
        assert exc.value.code == "smtp_rejected"
        assert exc.value.internal_detail == type(failure).__name__
        assert SMTP_PASSWORD not in _error_text(exc.value)

    @pytest.mark.parametrize(
        "failure",
        [
            aiosmtplib.SMTPDataError(451, "4.3.0 Temporary system problem, try again later"),
            aiosmtplib.SMTPSenderRefused(
                454, "4.7.0 Throttling failure: Maximum sending rate exceeded", "alerts@x.example"
            ),
            aiosmtplib.SMTPAuthenticationError(454, "4.7.0 Temporary authentication failure"),
            aiosmtplib.SMTPRecipientsRefused(
                [aiosmtplib.SMTPRecipientRefused(450, "4.2.0 Mailbox busy", "ops@example.com")]
            ),
        ],
        ids=lambda failure: type(failure).__name__,
    )
    async def test_temporary_smtp_replies_are_transient(
        self, smtp: FakeSmtp, failure: aiosmtplib.SMTPException
    ) -> None:
        smtp.error = failure
        with pytest.raises(TransientError) as exc:
            await SmtpEmailTransport(_smtp_settings()).send_email(["ops@example.com"], "S", "B")
        assert exc.value.code == "smtp_deferred"
