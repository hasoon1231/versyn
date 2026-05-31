"""The Versyn client: certify events, verify offline, survive outages."""

from __future__ import annotations

import uuid
import warnings
from typing import Any, Optional

import httpx

from . import _crypto
from ._exceptions import (
    VersynAuthError,
    VersynCreditExhaustedError,
    VersynError,
    VersynNetworkError,
    VersynRateLimitError,
)
from ._queue import OfflineQueue

__all__ = ["VersynClient"]

_DEFAULT_BASE = "https://api.versyn.dev"
_USER_AGENT = "versyn-python/0.2.2"


class VersynClient:
    """Client for certifying AI decisions and verifying them offline."""

    def __init__(
        self,
        api_key: str,
        api_base: str = _DEFAULT_BASE,
        auto_queue: bool = True,
        queue_path: str = "~/.versyn/queue.json",
        timeout: float = 20.0,
    ) -> None:
        """Create a client and load any previously queued work."""
        self._api_key = api_key
        self._api_base = api_base.rstrip("/")
        self._auto_queue = auto_queue
        self._queue = OfflineQueue(persist_path=queue_path)
        self._queue.load()
        self._http = httpx.Client(
            timeout=timeout,
            headers={"User-Agent": _USER_AGENT},
        )

    def _post(self, path: str, payload: dict[str, Any]) -> httpx.Response:
        """POST JSON to the API with auth and an idempotency key."""
        headers = {
            "Authorization": f"Bearer {self._api_key}",
            "Content-Type": "application/json",
            "Idempotency-Key": str(uuid.uuid4()),
        }
        try:
            return self._http.post(
                f"{self._api_base}{path}", json=payload, headers=headers
            )
        except httpx.HTTPError as exc:
            raise VersynNetworkError(f"network error on {path}: {exc}") from None

    def certify(self, event: dict[str, Any], hash_only: bool = False) -> dict[str, Any]:
        """Certify an event, returning its certificate."""
        if not isinstance(event, dict) or "kind" not in event or "payload" not in event:
            from ._exceptions import VersynValidationError

            raise VersynValidationError("event must be a dict with 'kind' and 'payload'")

        if hash_only:
            warnings.warn(
                "hash_only mode requires server-side verbatim-hash signing; "
                "until then, offline_verify(original_event=...) will not bind. "
                "Sending precomputed hash.",
                stacklevel=2,
            )
            body = {"event": {"__hash": _crypto.local_hash(event), "__key_id": _crypto.KEY_ID}}
        else:
            body = {"event": event}

        response = self._post("/v1/certify", body)
        status = response.status_code

        if status == 200:
            return response.json()
        if status == 402:
            if self._auto_queue:
                self._queue.add(event)
                raise VersynCreditExhaustedError(
                    "credits exhausted; event queued locally for later flush",
                    debt_report=self._queue.get_debt_report(),
                )
            raise VersynCreditExhaustedError(
                "credits exhausted and auto_queue is disabled; event not stored"
            )
        if status == 401:
            raise VersynAuthError("invalid API key", status_code=401)
        if status == 429:
            retry = int(response.headers.get("Retry-After", "60"))
            raise VersynRateLimitError("rate limit exceeded", retry_after=retry)
        raise VersynError(
            f"certify failed: HTTP {status}", status_code=status,
            response_body=response.text[:500],
        )

    def verify(
        self,
        certificate: dict[str, Any],
        original_event: Optional[dict[str, Any]] = None,
    ) -> bool:
        """Verify a certificate offline. Never contacts the network."""
        return _crypto.offline_verify(certificate, original_event=original_event)

    def flush_queue(self) -> dict[str, Any]:
        """Try to certify all locally queued events. Returns a flush summary."""
        return self._queue.flush(self)

    def get_debt_report(self) -> dict[str, Any]:
        """Return a transparent summary of locally queued (un-settled) work."""
        return self._queue.get_debt_report()

    def credits_remaining(self) -> int:
        """Return remaining monthly credits (best-effort; 0 on missing field)."""
        response = self._post("/v1/credits", {})
        if response.status_code == 200:
            return int(response.json().get("remaining", 0))
        raise VersynError(
            f"credits check failed: HTTP {response.status_code}",
            status_code=response.status_code,
        )

    def _post_batch(self, events: list[dict[str, Any]]) -> dict[str, Any]:
        """Certify many events; per-event fallback (no batch endpoint yet)."""
        results = []
        for event in events:
            response = self._post("/v1/certify", {"event": event})
            if response.status_code != 200:
                raise VersynError(
                    f"batch element failed: HTTP {response.status_code}",
                    status_code=response.status_code,
                )
            results.append(response.json())
        return {"certificates": results, "count": len(results)}

    def close(self) -> None:
        """Close the HTTP client and persist the queue as a final backup."""
        self._http.close()
        self._queue.persist()

    def __enter__(self) -> "VersynClient":
        """Enter a context manager."""
        return self

    def __exit__(self, *exc: object) -> None:
        """Close resources on context exit."""
        self.close()


def register(email: str, api_base: str = _DEFAULT_BASE) -> str:
    """Register for a free API key. Returns the new API key string."""
    with httpx.Client(timeout=20.0, headers={"User-Agent": _USER_AGENT}) as http:
        try:
            resp = http.post(
                f"{api_base.rstrip('/')}/v1/register",
                json={"email": email},
                headers={"Content-Type": "application/json"},
            )
        except httpx.HTTPError as exc:
            raise VersynNetworkError(f"network error on /v1/register: {exc}") from None
    if resp.status_code != 200:
        raise VersynError(
            f"registration failed: HTTP {resp.status_code}",
            status_code=resp.status_code,
        )
    key = resp.json().get("api_key")
    if not key:
        raise VersynError("registration succeeded but no api_key returned")
    return key
