"""Compliance and audit routes."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request

router = APIRouter()


async def _current_user(request: Request) -> str:
    """Resolve the account id from the Bearer API key."""
    auth = request.headers.get("authorization", "")
    if not auth.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="missing bearer token")
    return auth[7:].strip()


def get_services(request: Request) -> Any:
    """Fetch the service bundle attached to app state."""
    return request.app.state.services


@router.get("/v1/compliance-score")
async def compliance_score(
    request: Request, days: int = 30, user_id: str = Depends(_current_user)
) -> dict[str, Any]:
    """Return the attested/total ratio for the account over ``days``."""
    services = get_services(request)
    return await services.ledger.get_compliance_score(user_id, days=days)


@router.get("/v1/compliance/gap")
async def compliance_gap(
    request: Request, days: int = 30, user_id: str = Depends(_current_user)
) -> dict[str, Any]:
    """Report how many logged events are not yet certified (count only)."""
    services = get_services(request)
    score = await services.ledger.get_compliance_score(user_id, days=days)
    return {
        "uncertified_event_count": score["gap_count"],
        "attested_count": score["attested_count"],
        "total_count": score["total_count"],
        "period_days": days,
        "note": (
            "Counts only. Versyn provides verifiable evidence, not a "
            "regulatory determination."
        ),
    }


@router.get("/v1/audit")
async def audit(
    request: Request,
    start: str,
    end: str,
    user_id: str = Depends(_current_user),
) -> dict[str, Any]:
    """Return the certificates issued for the account in a date range."""
    services = get_services(request)
    certificates = await services.ledger.get_range(user_id, start, end)
    return {
        "user_id": user_id,
        "start": start,
        "end": end,
        "count": len(certificates),
        "certificates": certificates,
    }
