"""Sovereign-mode policy: licensed, air-gapped operation."""

from __future__ import annotations

import base64
import json
import time
from typing import Any, Optional

from nacl.signing import VerifyKey
from nacl.exceptions import BadSignatureError

__all__ = ["SovereignPolicy", "LicenseError", "verify_license"]

VERSYN_MASTER_PUBKEY_B64 = "REPLACE_WITH_VERSYN_MASTER_LICENSE_PUBKEY"


class LicenseError(Exception):
    """Raised when a sovereign license is missing, malformed, or invalid."""


def _b64url_decode(segment: str) -> bytes:
    """Decode a base64url segment, restoring padding."""
    padding = "=" * (-len(segment) % 4)
    return base64.urlsafe_b64decode(segment + padding)


def verify_license(
    license_key: str,
    master_pubkey_b64: str = VERSYN_MASTER_PUBKEY_B64,
    now: Optional[int] = None,
) -> dict[str, Any]:
    """Verify a signed sovereign license token, fully offline."""
    if not license_key or "." not in license_key:
        raise LicenseError("license token is missing or malformed")
    payload_seg, _, sig_seg = license_key.partition(".")
    try:
        signature = _b64url_decode(sig_seg)
        verify_key = VerifyKey(base64.b64decode(master_pubkey_b64))
        verify_key.verify(payload_seg.encode("ascii"), signature)
    except (BadSignatureError, ValueError, TypeError) as exc:
        raise LicenseError(f"license signature is invalid: {exc}") from None
    try:
        claims = json.loads(_b64url_decode(payload_seg))
    except (ValueError, TypeError) as exc:
        raise LicenseError(f"license payload is not valid JSON: {exc}") from None
    current = int(now if now is not None else time.time())
    exp = claims.get("exp")
    if exp is None or current >= int(exp):
        raise LicenseError("license has expired")
    if not claims.get("sub"):
        raise LicenseError("license is missing a subject (sub)")
    return claims


class SovereignPolicy:
    """Decides whether the credit gate applies, based on deployment mode."""

    def __init__(
        self,
        sovereign_mode: bool,
        license_key: Optional[str] = None,
        master_pubkey_b64: str = VERSYN_MASTER_PUBKEY_B64,
    ) -> None:
        """Initialize the policy. Sovereign mode verifies the license now."""
        self._sovereign = sovereign_mode
        self._claims: Optional[dict[str, Any]] = None
        if sovereign_mode:
            if not license_key:
                raise LicenseError("sovereign_mode requires a license_key")
            self._claims = verify_license(license_key, master_pubkey_b64)

    @property
    def skip_credit_check(self) -> bool:
        """True when signing should bypass the credit gate (sovereign mode)."""
        return self._sovereign

    @property
    def license_subject(self) -> Optional[str]:
        """The licensed customer id, if running in sovereign mode."""
        return self._claims.get("sub") if self._claims else None
