"""Offline queue for the Versyn SDK.

When the API cannot accept a certification right now — credits exhausted, or
the network is down — the event is not lost. It is appended to a local,
durable queue so it can be certified later.
"""

from __future__ import annotations

import json
import os
import threading
import uuid
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any, Optional

from ._exceptions import VersynError

if TYPE_CHECKING:
    from ._client import VersynClient

__all__ = ["OfflineQueue"]

_EXPOSURE_PER_EVENT_USD = 500.0


class OfflineQueue:
    """A durable, thread-safe queue of events awaiting certification."""

    def __init__(
        self,
        max_size: int = 10_000,
        persist_path: str = "~/.versyn/queue.json",
    ) -> None:
        """Initialize the queue and ensure its storage directory exists."""
        self._lock = threading.Lock()
        self._queue: list[dict[str, Any]] = []
        self._max_size = max_size
        self._persist_path = os.path.expanduser(persist_path)
        self._ensure_dir()

    def _ensure_dir(self) -> None:
        """Create the parent directory of the persist path if missing."""
        directory = os.path.dirname(self._persist_path)
        if directory:
            os.makedirs(directory, exist_ok=True)

    def _persist_locked(self) -> None:
        """Atomically write the current queue to disk. Lock must be held."""
        tmp_path = f"{self._persist_path}.tmp"
        with open(tmp_path, "w", encoding="utf-8") as handle:
            json.dump(self._queue, handle, indent=2, ensure_ascii=False)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp_path, self._persist_path)

    def add(self, event: dict[str, Any]) -> None:
        """Append an event to the queue and persist immediately."""
        with self._lock:
            if len(self._queue) >= self._max_size:
                raise VersynError(
                    f"offline queue full (max_size={self._max_size}); "
                    "flush queued events before adding more"
                )
            self._queue.append(
                {
                    "id": str(uuid.uuid4()),
                    "event": event,
                    "queued_at": datetime.now(timezone.utc).isoformat(),
                }
            )
            self._persist_locked()

    def persist(self) -> None:
        """Atomically write the queue to disk (public, lock-acquiring)."""
        with self._lock:
            self._persist_locked()

    def load(self) -> None:
        """Load the queue from disk, replacing the in-memory contents."""
        with self._lock:
            if not os.path.exists(self._persist_path):
                self._queue = []
                return
            try:
                with open(self._persist_path, encoding="utf-8") as handle:
                    loaded = json.load(handle)
                self._queue = loaded if isinstance(loaded, list) else []
            except (json.JSONDecodeError, OSError) as exc:
                import warnings

                warnings.warn(
                    f"could not read queue file {self._persist_path} ({exc}); "
                    "starting with an empty queue",
                    stacklevel=2,
                )
                self._queue = []

    def flush(self, client: "VersynClient") -> dict[str, Any]:
        """Attempt to certify all queued events via the client, in one batch."""
        with self._lock:
            if not self._queue:
                return {"flushed": 0, "failed": 0}
            events = [item["event"] for item in self._queue]
            try:
                client._post_batch(events)
            except Exception as exc:  # noqa: BLE001
                return {"flushed": 0, "failed": len(events), "error": str(exc)}
            count = len(events)
            self._queue = []
            self._persist_locked()
            return {"flushed": count, "failed": 0}

    def get_debt_report(self) -> dict[str, Any]:
        """Summarize un-settled work for transparent risk visibility."""
        with self._lock:
            count = len(self._queue)
            oldest = self._queue[0]["queued_at"] if count else None
            newest = self._queue[-1]["queued_at"] if count else None
            return {
                "count": count,
                "oldest": oldest,
                "newest": newest,
                "estimated_exposure": count * _EXPOSURE_PER_EVENT_USD,
            }

    def clear(self) -> None:
        """Empty the queue and persist the empty state."""
        with self._lock:
            self._queue = []
            self._persist_locked()

    def __len__(self) -> int:
        """Return the number of queued events."""
        with self._lock:
            return len(self._queue)
