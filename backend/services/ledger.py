"""Append-only certificate ledger and event logging."""

from __future__ import annotations

from typing import Any, Optional

from sqlalchemy import text

__all__ = ["LedgerService", "EventLogService"]


class LedgerService:
    """Append-only store of issued certificates, plus compliance scoring."""

    def __init__(self, session_factory: Any) -> None:
        """Initialize with an async session factory."""
        self._session_factory = session_factory

    async def append(self, certificate: dict[str, Any], user_id: str) -> None:
        """Insert a certificate. Append-only: never updates or deletes."""
        async with self._session_factory() as session:
            async with session.begin():
                await session.execute(
                    text(
                        "INSERT INTO certificates "
                        "(certificate_id, user_id, hash, signature, "
                        " timestamp_iso, expires_at, key_id) "
                        "VALUES (:cid, :uid, :h, :sig, :ts, :exp, :kid) "
                        "ON CONFLICT (certificate_id) DO NOTHING"
                    ),
                    {
                        "cid": certificate["certificate_id"],
                        "uid": user_id,
                        "h": certificate["hash"],
                        "sig": certificate["signature"],
                        "ts": certificate.get("timestamp_iso"),
                        "exp": certificate.get("expires_at"),
                        "kid": certificate.get("key_id"),
                    },
                )

    async def get(self, certificate_id: str) -> Optional[dict[str, Any]]:
        """Fetch a certificate by id, or None if absent."""
        async with self._session_factory() as session:
            row = (
                await session.execute(
                    text(
                        "SELECT certificate_id, user_id, hash, signature, "
                        "timestamp_iso, expires_at, key_id "
                        "FROM certificates WHERE certificate_id = :cid"
                    ),
                    {"cid": certificate_id},
                )
            ).first()
            if row is None:
                return None
            return {
                "certificate_id": row[0],
                "user_id": row[1],
                "hash": row[2],
                "signature": row[3],
                "timestamp_iso": row[4],
                "expires_at": row[5],
                "key_id": row[6],
            }

    async def get_range(
        self, user_id: str, start: str, end: str
    ) -> list[dict[str, Any]]:
        """Return certificates for a user within an inclusive ISO date range."""
        async with self._session_factory() as session:
            rows = (
                await session.execute(
                    text(
                        "SELECT certificate_id, hash, signature, timestamp_iso, "
                        "expires_at, key_id FROM certificates "
                        "WHERE user_id = :uid AND timestamp_iso >= :start "
                        "AND timestamp_iso <= :end ORDER BY timestamp_iso"
                    ),
                    {"uid": user_id, "start": start, "end": end},
                )
            ).all()
            return [
                {
                    "certificate_id": r[0], "hash": r[1], "signature": r[2],
                    "timestamp_iso": r[3], "expires_at": r[4], "key_id": r[5],
                }
                for r in rows
            ]

    async def get_compliance_score(
        self, user_id: str, days: int = 30
    ) -> dict[str, Any]:
        """Compute attested/total ratio over a recent window."""
        async with self._session_factory() as session:
            total = (
                await session.execute(
                    text("SELECT COUNT(*) FROM event_logs WHERE user_id = :uid"),
                    {"uid": user_id},
                )
            ).scalar() or 0
            attested = (
                await session.execute(
                    text("SELECT COUNT(*) FROM certificates WHERE user_id = :uid"),
                    {"uid": user_id},
                )
            ).scalar() or 0
            gap = max(total - attested, 0)
            score = 100.0 if total == 0 else round((attested / total) * 100, 2)
            return {
                "score": score,
                "attested_count": attested,
                "total_count": total,
                "gap_count": gap,
                "period_days": days,
            }


class EventLogService:
    """Records every event that arrives, certified or not."""

    def __init__(self, session_factory: Any) -> None:
        """Initialize with an async session factory."""
        self._session_factory = session_factory

    async def log_event(self, user_id: str, event_kind: str) -> None:
        """Append an event-arrival record (the compliance denominator)."""
        async with self._session_factory() as session:
            async with session.begin():
                await session.execute(
                    text(
                        "INSERT INTO event_logs (user_id, event_kind) "
                        "VALUES (:uid, :k)"
                    ),
                    {"uid": user_id, "k": event_kind},
                )
