"""Configuration for the Versyn billing/compliance backend."""

from __future__ import annotations

from typing import Optional

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Backend settings, populated from environment variables."""

    model_config = SettingsConfigDict(
        env_file=".env", env_file_encoding="utf-8", extra="ignore"
    )

    app_name: str = "Versyn API"
    api_v1_prefix: str = "/v1"

    database_url: str = Field(
        default="postgresql+asyncpg://versyn:versyn@localhost:5432/versyn_billing"
    )
    redis_url: str = Field(default="redis://localhost:6379/0")

    sovereign_mode: bool = False
    license_key: Optional[str] = None

    rate_limit_per_minute: int = 100
    max_event_size_bytes: int = 1_048_576

    default_credit_monthly: int = 500
    credit_overage_price_usd: float = 0.20

    signature_algorithm: str = "ed25519"
    hash_algorithm: str = "sha256"
    certificate_expiry_days: int = 365

    idempotency_ttl_seconds: int = 86_400


settings = Settings()
