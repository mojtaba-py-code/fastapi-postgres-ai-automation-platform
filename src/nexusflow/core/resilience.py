"""Resilience primitives: exponential backoff with jitter and a circuit breaker.

Retries are never blind: callers decide *what* is retryable (only
``TransientError``s, and only for idempotent operations); these helpers only
decide *when*.
"""

from __future__ import annotations

import random
import time
from dataclasses import dataclass, field
from enum import StrEnum

from nexusflow.core.errors import ServiceUnavailableError


def backoff_delay(
    attempt: int, *, base_seconds: float = 2.0, cap_seconds: float = 3600.0, jitter: float = 0.2
) -> float:
    """Exponential backoff ``base * 2**(attempt-1)`` capped, with +/- jitter.

    Jitter de-synchronizes retries of many clients after a shared outage
    (thundering herd).
    """
    exponent = max(0, attempt - 1)
    delay = min(cap_seconds, base_seconds * (2.0**exponent))
    spread = delay * jitter
    return max(0.0, delay + random.uniform(-spread, spread))  # nosec B311


class CircuitState(StrEnum):
    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"


@dataclass
class CircuitBreaker:
    """In-process circuit breaker for a flaky dependency.

    After ``failure_threshold`` consecutive failures the circuit opens and calls
    fail fast for ``reset_timeout`` seconds; then one trial call is let through
    (half-open) and its outcome closes or re-opens the circuit.
    """

    name: str
    failure_threshold: int = 5
    reset_timeout: float = 60.0
    failures: int = 0
    state: CircuitState = CircuitState.CLOSED
    opened_at: float = field(default=0.0)

    def before_call(self) -> None:
        if self.state is CircuitState.OPEN:
            if time.monotonic() - self.opened_at >= self.reset_timeout:
                self.state = CircuitState.HALF_OPEN
            else:
                raise ServiceUnavailableError(
                    f"{self.name} is temporarily unavailable.",
                    code="circuit_open",
                    internal_detail=f"circuit {self.name} open",
                )

    def record_success(self) -> None:
        self.failures = 0
        self.state = CircuitState.CLOSED

    def record_failure(self) -> None:
        self.failures += 1
        if self.state is CircuitState.HALF_OPEN or self.failures >= self.failure_threshold:
            self.state = CircuitState.OPEN
            self.opened_at = time.monotonic()

    @property
    def is_open(self) -> bool:
        return self.state is CircuitState.OPEN
