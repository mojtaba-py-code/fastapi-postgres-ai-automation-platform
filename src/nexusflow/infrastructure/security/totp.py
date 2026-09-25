"""RFC 6238 TOTP (via pyotp) with replay protection.

``verify`` returns the matched time-step counter. Callers persist the highest
accepted step and pass it back as ``last_used_step``; any code at or below that
step is rejected, so an intercepted code cannot be replayed within its window.
"""

from __future__ import annotations

import hmac
import re
from datetime import datetime

import pyotp

_CODE_PATTERN = re.compile(r"^\d{6}$")
_VALID_WINDOW = 1  # accept the previous/next 30s step to tolerate clock skew


class TotpService:
    def generate_secret(self) -> str:
        return pyotp.random_base32(length=32)  # 160 bits

    def provisioning_uri(self, secret: str, *, account_name: str, issuer: str) -> str:
        return pyotp.TOTP(secret).provisioning_uri(name=account_name, issuer_name=issuer)

    def verify(
        self, secret: str, code: str, *, now: datetime, last_used_step: int | None
    ) -> int | None:
        candidate = code.strip().replace(" ", "")
        if not _CODE_PATTERN.fullmatch(candidate):
            return None
        totp = pyotp.TOTP(secret)
        current_step = totp.timecode(now)
        matched: int | None = None
        for offset in range(-_VALID_WINDOW, _VALID_WINDOW + 1):
            step = current_step + offset
            expected = totp.generate_otp(step)
            # Evaluate every offset (no early exit) to keep timing uniform.
            if hmac.compare_digest(expected, candidate) and matched is None:
                matched = step
        if matched is None:
            return None
        if last_used_step is not None and matched <= last_used_step:
            return None
        return matched
