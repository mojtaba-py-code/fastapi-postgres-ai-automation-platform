"""Public inbound webhook receiver: ``POST /api/v1/webhooks/{org_id}/{endpoint_id}``.

Unauthenticated by bearer token by design - authenticity comes from the
HMAC-SHA256 signature over ``timestamp.delivery_id.body`` with a per-endpoint
secret, a timestamp window and a delivery-id replay guard. Every rejection
before signature verification looks identical (and costs the same HMAC work),
so the endpoint cannot be used to probe which organizations or endpoints
exist. Before verification only the per-IP limit applies; the per-endpoint
quota is charged by the service after verification, so forged traffic cannot
exhaust it. The body is read raw (the signature covers the exact bytes) and is
bounded by the body-size middleware.
"""

from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, Depends, Request, Response, status

from nexusflow.apps.api.dependencies import ContainerDep, rate_limited
from nexusflow.apps.api.schemas.business import WebhookReceiptOut
from nexusflow.apps.api.schemas.common import ERROR_RESPONSES
from nexusflow.core.errors import (
    AuthenticationError,
    NexusFlowError,
    RateLimitedError,
    UnsupportedMediaTypeError,
)
from nexusflow.infrastructure.observability import metrics

_JSON_TYPES = frozenset({"application/json", "application/cloudevents+json"})

router = APIRouter(prefix="/webhooks", tags=["webhooks"], responses=ERROR_RESPONSES)


@router.post(
    "/{org_id}/{endpoint_id}",
    response_model=WebhookReceiptOut,
    status_code=status.HTTP_202_ACCEPTED,
    dependencies=[Depends(rate_limited("webhook.ip"))],
    summary="Receive a signed webhook delivery (X-NexusFlow-Signature / X-NexusFlow-Delivery)",
)
async def receive_webhook(
    org_id: UUID,
    endpoint_id: UUID,
    request: Request,
    response: Response,
    container: ContainerDep,
) -> WebhookReceiptOut:
    media_type = request.headers.get("content-type", "").split(";", 1)[0].strip().lower()
    if media_type not in _JSON_TYPES:
        raise UnsupportedMediaTypeError("Webhook bodies must be JSON.")
    body = await request.body()
    try:
        result = await container.webhooks.receive(
            org_id=org_id, endpoint_id=endpoint_id, headers=request.headers, body=body
        )
    except AuthenticationError:
        metrics.WEBHOOK_EVENTS.labels(result="rejected").inc()  # alerting: forgery attempts
        raise
    except RateLimitedError:
        metrics.WEBHOOK_EVENTS.labels(result="throttled").inc()
        raise
    except NexusFlowError:
        metrics.WEBHOOK_EVENTS.labels(result="failed").inc()
        raise
    metrics.WEBHOOK_EVENTS.labels(result=result.status).inc()
    if result.status == "duplicate":
        response.status_code = status.HTTP_200_OK
    return WebhookReceiptOut(status=result.status, run_id=result.run_id, truncated=result.truncated)
