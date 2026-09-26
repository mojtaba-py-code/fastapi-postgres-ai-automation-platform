"""Token contracts for the identity context (implemented in infrastructure)."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Protocol
from uuid import UUID


@dataclass(frozen=True, slots=True)
class AccessTokenClaims:
    user_id: UUID
    org_id: UUID | None
    session_id: UUID
    token_version: int
    token_id: str
    issued_at: datetime
    expires_at: datetime


@dataclass(frozen=True, slots=True)
class MfaChallengeClaims:
    user_id: UUID
    org_id: UUID | None
    challenge_id: str
    expires_at: datetime


@dataclass(frozen=True, slots=True)
class IssuedToken:
    token: str
    expires_at: datetime
    expires_in: int


class TokenCodec(Protocol):
    def issue_access_token(
        self,
        *,
        user_id: UUID,
        org_id: UUID | None,
        session_id: UUID,
        token_version: int,
        now: datetime,
    ) -> IssuedToken: ...

    def decode_access_token(self, token: str, *, now: datetime) -> AccessTokenClaims: ...

    def issue_mfa_challenge(
        self, *, user_id: UUID, org_id: UUID | None, now: datetime
    ) -> IssuedToken: ...

    def decode_mfa_challenge(self, token: str, *, now: datetime) -> MfaChallengeClaims: ...
