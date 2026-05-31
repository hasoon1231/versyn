"""Credit accounting with race-safe deduction."""

from __future__ import annotations

from typing import Any

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

__all__ = ["CreditService", "CreditError"]


class CreditError(Exception):
    """Raised for credit accounting failures (e.g. unknown account)."""


class CreditService:
    """Race-safe credit balance operations backed by a SQL database."""

    def __init__(self, session_factory: Any, dialect: str = "postgresql") -> None:
        """Initialize with an async session factory and SQL dialect."""
        self._session_factory = session_factory
        self._for_update = " FOR UPDATE" if dialect.startswith("postgres") else ""

    async def ensure_account(self, user_id: str, monthly_limit: int) -> None:
        """Create a credit row for a user if absent (idempotent)."""
        async with self._session_factory() as session:
            await session.execute(
                text(
                    "INSERT INTO credits (user_id, remaining, monthly_limit, "
                    "overage_count) VALUES (:uid, :rem, :lim, 0) "
                    "ON CONFLICT (user_id) DO NOTHING"
                ),
                {"uid": user_id, "rem": monthly_limit, "lim": monthly_limit},
            )
            await session.commit()

    async def deduct(self, user_id: str, count: int = 1) -> bool:
        """Atomically deduct credits via a conditional UPDATE. Race-proof.

        Returns True if deducted, False if insufficient.
        Raises CreditError if the account does not exist.
        """
        async with self._session_factory() as session:
            async with session.begin():
                exists = (
                    await session.execute(
                        text("SELECT 1 FROM credits WHERE user_id = :uid"),
                        {"uid": user_id},
                    )
                ).first()
                if exists is None:
                    raise CreditError(f"no credit account for user '{user_id}'")
                result = await session.execute(
                    text(
                        "UPDATE credits SET remaining = remaining - :n "
                        "WHERE user_id = :uid AND remaining >= :n"
                    ),
                    {"n": count, "uid": user_id},
                )
                return result.rowcount == 1

    async def get_balance(self, user_id: str) -> dict[str, Any]:
        """Return the current balance. Raises CreditError if account absent."""
        async with self._session_factory() as session:
            row = (
                await session.execute(
                    text(
                        "SELECT remaining, monthly_limit, overage_count "
                        "FROM credits WHERE user_id = :uid"
                    ),
                    {"uid": user_id},
                )
            ).first()
            if row is None:
                raise CreditError(f"no credit account for user '{user_id}'")
            return {
                "remaining": row[0],
                "monthly_limit": row[1],
                "overage_count": row[2],
            }

    async def add_credits(self, user_id: str, count: int) -> None:
        """Add credits to an account (e.g. on payment or monthly reset)."""
        async with self._session_factory() as session:
            async with session.begin():
                await session.execute(
                    text(
                        "UPDATE credits SET remaining = remaining + :n "
                        "WHERE user_id = :uid"
                    ),
                    {"n": count, "uid": user_id},
                )
