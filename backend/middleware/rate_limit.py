"""Request safety middleware: body-size cap and rate limiting."""

from __future__ import annotations

import time
from typing import Any, Optional, Protocol

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

__all__ = [
    "MaxBodySizeMiddleware",
    "RateLimitMiddleware",
    "CounterBackend",
    "InMemoryCounter",
    "RedisCounter",
]


class MaxBodySizeMiddleware(BaseHTTPMiddleware):
    """Reject requests whose body exceeds a byte ceiling (HTTP 413)."""

    def __init__(self, app: Any, max_bytes: int = 1_048_576) -> None:
        """Initialize with the wrapped app and the maximum body size."""
        super().__init__(app)
        self._max_bytes = max_bytes

    async def dispatch(self, request: Request, call_next: Any) -> Response:
        """Reject oversized bodies up front; otherwise pass through."""
        content_length = request.headers.get("content-length")
        if content_length is not None:
            try:
                if int(content_length) > self._max_bytes:
                    return JSONResponse(
                        {"detail": f"payload too large (max {self._max_bytes} bytes)"},
                        status_code=413,
                    )
            except ValueError:
                return JSONResponse({"detail": "invalid Content-Length"}, status_code=400)
        return await call_next(request)


class CounterBackend(Protocol):
    """A windowed counter: increment a key and report its count."""

    async def incr(self, key: str, window_seconds: int) -> int:
        """Increment ``key`` within a window, returning the new count."""
        ...


class InMemoryCounter:
    """In-process windowed counter for tests. Not for multi-worker production."""

    def __init__(self) -> None:
        """Initialize the counter store."""
        self._store: dict[str, tuple[int, float]] = {}

    async def incr(self, key: str, window_seconds: int) -> int:
        """Increment within the current window, resetting when it expires."""
        now = time.time()
        count, window_start = self._store.get(key, (0, now))
        if now - window_start >= window_seconds:
            count, window_start = 0, now
        count += 1
        self._store[key] = (count, window_start)
        return count


class RedisCounter:
    """Production windowed counter backed by Redis INCR + EXPIRE."""

    def __init__(self, redis: Any) -> None:
        """Initialize with an async redis client."""
        self._redis = redis

    async def incr(self, key: str, window_seconds: int) -> int:
        """INCR the key; set EXPIRE on first hit so the window resets."""
        count = await self._redis.incr(key)
        if count == 1:
            await self._redis.expire(key, window_seconds)
        return count


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Limit requests per API key within a fixed window (HTTP 429)."""

    def __init__(
        self,
        app: Any,
        counter: CounterBackend,
        limit_per_minute: int = 100,
        enabled: bool = True,
    ) -> None:
        """Initialize with a counter backend and per-minute limit."""
        super().__init__(app)
        self._counter = counter
        self._limit = limit_per_minute
        self._enabled = enabled

    def _key_for(self, request: Request) -> str:
        """Derive the rate-limit key from the API key (or client host)."""
        auth = request.headers.get("authorization", "")
        token = auth[7:] if auth.lower().startswith("bearer ") else ""
        ident = token or (request.client.host if request.client else "anon")
        return f"rl:{ident}:{request.url.path}"

    async def dispatch(self, request: Request, call_next: Any) -> Response:
        """Count the request; return 429 past the limit, else pass through."""
        if not self._enabled or request.method != "POST":
            return await call_next(request)
        count = await self._counter.incr(self._key_for(request), 60)
        if count > self._limit:
            return JSONResponse(
                {"detail": "rate limit exceeded"},
                status_code=429,
                headers={"Retry-After": "60"},
            )
        return await call_next(request)
