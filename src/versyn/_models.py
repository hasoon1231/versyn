"""Pydantic models for Versyn SDK and API payloads."""

from __future__ import annotations

import uuid
from typing import Any, Optional

from pydantic import BaseModel, ConfigDict, Field

__all__ = [
    "CertifyRequest",
    "CertifyResponse",
    "CreditsResponse",
    "ComplianceScoreResponse",
    "VerifyResponse",
    "DebtReport",
]

_KEY_ID_DEFAULT = "versyn-root-2024-v1"


def _new_idempotency_key() -> str:
    """Generate a fresh idempotency key."""
    return str(uuid.uuid4())


class CertifyRequest(BaseModel):
    """A request to certify an event."""

    model_config = ConfigDict(populate_by_name=True)

    event: dict[str, Any]
    hash: Optional[str] = Field(default=None, alias="__hash")
    schema_version: str = Field(default="v2.0", alias="__schema_version")
    key_id: str = Field(default=_KEY_ID_DEFAULT, alias="__key_id")
    idempotency_key: str = Field(default_factory=_new_idempotency_key)


class CertifyResponse(BaseModel):
    """The certificate returned by a successful certify call."""

    model_config = ConfigDict(extra="allow")

    certificate_id: str
    hash: str
    signature: str
    timestamp_iso: Optional[str] = None
    key_id: Optional[str] = None
    status: Optional[str] = None


class CreditsResponse(BaseModel):
    """Remaining credit balance for the current account."""

    remaining: int
    monthly_limit: int
    overage_count: int = 0
    expires_at: Optional[str] = None


class ComplianceScoreResponse(BaseModel):
    """How much of recent activity has been certified, as transparent ratio."""

    score: float = Field(..., ge=0.0, le=100.0)
    attested_count: int
    total_count: int
    gap_count: int
    period_days: int = 30


class VerifyResponse(BaseModel):
    """Result of verifying a certificate."""

    certificate_id: str
    verified: bool
    tampered: bool
    hash_match: bool
    issued_at: Optional[str] = None
    expires_at: Optional[str] = None


class DebtReport(BaseModel):
    """A transparent summary of locally queued, un-settled work."""

    count: int
    oldest: Optional[str] = None
    newest: Optional[str] = None
    estimated_exposure: float
