"""versyn — Cryptographic proof for AI decisions."""

from ._client import VersynClient, register
from ._crypto import (
    VERSYN_PUBKEY_B64,
    KEY_ID,
    canonical_json,
    local_hash,
    offline_verify,
)
from ._exceptions import (
    VersynError,
    VersynAuthError,
    VersynCreditExhaustedError,
    VersynNetworkError,
    VersynValidationError,
    VersynRateLimitError,
)

__version__ = "0.2.2"
__all__ = [
    "VersynClient", "register", "offline_verify", "local_hash", "canonical_json",
    "VERSYN_PUBKEY_B64", "KEY_ID", "VersynError", "VersynAuthError",
    "VersynCreditExhaustedError", "VersynNetworkError", "VersynValidationError",
    "VersynRateLimitError", "__version__",
]
