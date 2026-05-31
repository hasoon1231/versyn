"""Certification and verification routes."""

from __future__ import annotations

from datetime import datetime, timezone
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


@router.post("/v1/certify")
async def certify(request: Request, user_id: str = Depends(_current_user)) -> dict[str, Any]:
    """Certify a single event."""
    services = get_services(request)
    body = await request.json()
    event = body.get("event")
    if not isinstance(event, dict) or "kind" not in event:
        raise HTTPException(status_code=422, detail="event must include 'kind'")

    if not services.policy.skip_credit_check:
        await services.credits.ensure_account(user_id, services.default_monthly)
        ok = await services.credits.deduct(user_id, 1)
        if not ok:
            raise HTTPException(status_code=402, detail="credits exhausted")

    await services.events.log_event(user_id, event["kind"])
    hash_field = services.hasher(event)
    certificate = services.signer.sign(hash_field)
    await services.ledger.append(certificate, user_id)
    return certificate


@router.post("/v1/certify/batch")
async def certify_batch(request: Request, user_id: str = Depends(_current_user)) -> dict[str, Any]:
    """Certify many events; partial success when credits run out mid-batch."""
    services = get_services(request)
    body = await request.json()
    events = body.get("events")
    if not isinstance(events, list) or not events:
        raise HTTPException(status_code=422, detail="events must be a non-empty list")

    certificates: list[dict[str, Any]] = []
    failed = 0
    for event in events:
        if not isinstance(event, dict) or "kind" not in event:
            failed += 1
            continue
        if not services.policy.skip_credit_check:
            await services.credits.ensure_account(user_id, services.default_monthly)
            if not await services.credits.deduct(user_id, 1):
                failed += 1
                continue
        await services.events.log_event(user_id, event["kind"])
        cert = services.signer.sign(services.hasher(event))
        await services.ledger.append(cert, user_id)
        certificates.append(cert)

    return {"certificates": certificates, "partial": failed > 0, "failed_count": failed}


@router.get("/v1/verify/{certificate_id}")
async def verify(request: Request, certificate_id: str) -> dict[str, Any]:
    """Look up a certificate and report verification status, including expiry."""
    services = get_services(request)
    cert = await services.ledger.get(certificate_id)
    if cert is None:
        raise HTTPException(status_code=404, detail="certificate not found")

    expired = False
    expires_at = cert.get("expires_at")
    if expires_at:
        try:
            expired = datetime.now(timezone.utc) >= datetime.fromisoformat(expires_at)
        except ValueError:
            expired = False

    return {
        "certificate_id": cert["certificate_id"],
        "hash": cert["hash"],
        "signature": cert["signature"],
        "expires_at": expires_at,
        "expired": expired,
        "key_id": cert.get("key_id"),
    }
