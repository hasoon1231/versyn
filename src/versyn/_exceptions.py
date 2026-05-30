"""Typed exceptions for the Versyn SDK."""
from __future__ import annotations
from typing import Optional


class VersynError(Exception):
    """Base error. Carries optional HTTP context."""
    def __init__(self, message: str, status_code: Optional[int] = None,
                 response_body: Optional[str] = None) -> None:
        super().__init__(message)
        self.message = message
        self.status_code = status_code
        self.response_body = response_body
    def __str__(self) -> str:
        return self.message


class VersynAuthError(VersynError):
    """Invalid or missing API key (HTTP 401)."""


class VersynNetworkError(VersynError):
    """Transport-level failure reaching the API."""


class VersynValidationError(VersynError):
    """Malformed input or a hash that does not match the original event."""


class VersynRateLimitError(VersynError):
    """Rate limit exceeded (HTTP 429)."""
    def __init__(self, message: str, retry_after: int = 60) -> None:
        super().__init__(message, status_code=429)
        self.retry_after = retry_after


class VersynCreditExhaustedError(VersynError):
    """Credits exhausted (HTTP 402). Event is queued when auto_queue is on."""
    def __init__(self, message: str, debt_report: Optional[dict] = None) -> None:
        super().__init__(message, status_code=402)
        self.debt_report = debt_report
