"""Cryptographic core for the Versyn SDK.

This module is the trust boundary of the client. It does two things and does
them honestly:

1. Computes a deterministic, canonical hash of an event locally, so the client
   can hash *before* anything leaves the machine.
2. Verifies a certificate's Ed25519 signature entirely offline, against a
   pinned public key — and, when given the original event, verifies that the
   certificate's hash actually *binds* to that event.

The second part closes the deepest flaw a naive verifier has: a signature can
be valid in isolation yet belong to a *different* payload. Verifying the
signature without re-deriving the hash from the caller's own event proves only
"the server signed some hash," not "the server signed *my* event." When
``original_event`` is supplied, this module re-derives the hash and refuses any
mismatch.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
from typing import Any, Optional

from nacl.signing import VerifyKey
from nacl.exceptions import BadSignatureError

from ._exceptions import VersynValidationError

__all__ = [
    "canonical_json",
    "local_hash",
    "decode_signature",
    "offline_verify",
    "VERSYN_PUBKEY_B64",
    "KEY_ID",
]

# Pinned Versyn root signing key (base64, 32-byte Ed25519 public key).
# Also published at https://versyn.dev/.well-known/versyn-pubkey.txt for
# independent retrieval. Pinned here so offline verification never depends on
# a live fetch from Versyn.
VERSYN_PUBKEY_B64: str = "awqwxC/EeDsEotx0SV3500l+OEi688gF9FgeIzs84wU="

# Identifies which signing key produced a certificate. When the root key is
# rotated, certificates carry a new key_id and verifiers can select the
# matching pinned key instead of failing blindly.
KEY_ID: str = "versyn-root-2024-v1"

# Hash algorithms this client is willing to compute/verify, by prefix label.
_SUPPORTED_HASHES = {"sha256": hashlib.sha256, "sha3-256": hashlib.sha3_256}


def canonical_json(event: dict[str, Any]) -> bytes:
    """Serialize a dict to canonical JSON bytes.

    The encoding is deterministic: keys are sorted, no insignificant
    whitespace, UTF-8. The same logical dict always produces identical bytes
    regardless of key insertion order, so a hash computed here matches a hash
    computed anywhere else over the same data.

    Args:
        event: The event mapping to serialize.

    Returns:
        The canonical UTF-8 encoded JSON bytes.

    Raises:
        VersynValidationError: If ``event`` is not a dict or is not
            JSON-serializable.
    """
    if not isinstance(event, dict):
        raise VersynValidationError(
            f"event must be a dict, got {type(event).__name__}"
        )
    try:
        return json.dumps(
            event, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise VersynValidationError(f"event is not JSON-serializable: {exc}") from None


def local_hash(event: dict[str, Any], algorithm: str = "sha256") -> str:
    """Compute a prefixed canonical hash of an event, locally.

    The event is first encoded with :func:`canonical_json`, then hashed with
    the named algorithm. The return value carries an ``algorithm:`` prefix so
    callers can stay algorithm-agile (e.g. migrate to ``sha3-256`` later)
    without ambiguity about how a given digest was produced.

    Args:
        event: The event mapping to hash.
        algorithm: Hash algorithm label. One of ``"sha256"`` or ``"sha3-256"``.

    Returns:
        A string of the form ``"<algorithm>:<hexdigest>"``,
        e.g. ``"sha256:dd98...5d2c"``.

    Raises:
        VersynValidationError: If the algorithm is unsupported or the event
            cannot be canonicalized.
    """
    func = _SUPPORTED_HASHES.get(algorithm)
    if func is None:
        raise VersynValidationError(
            f"unsupported hash algorithm '{algorithm}'; "
            f"supported: {sorted(_SUPPORTED_HASHES)}"
        )
    digest = func(canonical_json(event)).hexdigest()
    return f"{algorithm}:{digest}"


def _split_hash(hash_field: str) -> tuple[str, str]:
    """Split a stored hash into (algorithm, hexdigest).

    Accepts both prefixed (``"sha256:abc..."``) and bare (``"abc..."``) forms.
    A bare digest is assumed to be sha256, matching the current server format.

    Args:
        hash_field: The ``hash`` value from a certificate.

    Returns:
        A ``(algorithm, hexdigest)`` tuple.

    Raises:
        VersynValidationError: If the hash field is not a non-empty string.
    """
    if not isinstance(hash_field, str) or not hash_field:
        raise VersynValidationError("certificate 'hash' must be a non-empty string")
    if ":" in hash_field:
        algorithm, _, hexdigest = hash_field.partition(":")
        return algorithm, hexdigest
    return "sha256", hash_field


def decode_signature(signature: str) -> bytes:
    """Decode a certificate signature into raw bytes.

    Strips an optional ``ed25519:`` prefix, then base64-decodes the remainder.

    Args:
        signature: The signature string, with or without the ``ed25519:``
            prefix.

    Returns:
        The raw signature bytes.

    Raises:
        VersynValidationError: If the signature is not a valid base64 string.
    """
    if not isinstance(signature, str) or not signature:
        raise VersynValidationError("signature must be a non-empty string")
    payload = signature.split(":", 1)[1] if signature.startswith("ed25519:") else signature
    try:
        return base64.b64decode(payload, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise VersynValidationError(f"signature is not valid base64: {exc}") from None


def offline_verify(
    certificate: dict[str, Any],
    original_event: Optional[dict[str, Any]] = None,
    pubkey_b64: str = VERSYN_PUBKEY_B64,
) -> bool:
    """Verify a certificate fully offline. No network access.

    Two independent checks, in order:

    1. **Hash binding (only if ``original_event`` is provided).** Re-derives the
       canonical hash of the caller's own event and compares it to the
       certificate's hash. If they differ, the certificate does not describe
       this event — a mismatch raises rather than returning ``False``, because
       it signals tampering or a wrong certificate, not an ordinary bad
       signature. This closes the "blind verification" gap where a
       signature-only check would accept a valid signature bound to a
       *different* payload.
    2. **Signature.** Verifies the Ed25519 signature over the certificate's
       hash bytes against the pinned public key.

    Args:
        certificate: The certificate dict, requiring at least ``hash`` and
            ``signature`` keys.
        original_event: Optional. The exact event that was certified. When
            supplied, the certificate's hash must match this event.
        pubkey_b64: Base64 Ed25519 public key to verify against. Defaults to
            the pinned Versyn root key.

    Returns:
        ``True`` if the signature is valid (and, when ``original_event`` is
        given, the hash binds to it); ``False`` if the signature does not
        verify.

    Raises:
        VersynValidationError: If the certificate is malformed, the public key
            is invalid, or the hash does not match a supplied
            ``original_event``.
    """
    if not isinstance(certificate, dict):
        raise VersynValidationError(
            f"certificate must be a dict, got {type(certificate).__name__}"
        )
    try:
        hash_field = certificate["hash"]
        signature = certificate["signature"]
    except (KeyError, TypeError) as exc:
        raise VersynValidationError(
            f"certificate missing required 'hash'/'signature': {exc}"
        ) from None

    algorithm, hexdigest = _split_hash(hash_field)

    # Check 1: hash binding (the fix for the blind-verification flaw).
    if original_event is not None:
        expected = local_hash(original_event, algorithm=algorithm)
        _, expected_hex = _split_hash(expected)
        if expected_hex != hexdigest:
            raise VersynValidationError(
                "certificate hash does not match the provided original_event; "
                "the certificate does not describe this event (possible "
                "tampering or wrong certificate)."
            )

    # Check 2: signature over the hash bytes against the pinned key.
    try:
        signed_bytes = bytes.fromhex(hexdigest)
    except ValueError as exc:
        raise VersynValidationError(f"certificate hash is not valid hex: {exc}") from None

    try:
        verify_key = VerifyKey(base64.b64decode(pubkey_b64, validate=True))
    except (binascii.Error, ValueError) as exc:
        raise VersynValidationError(f"public key is not valid base64: {exc}") from None

    try:
        verify_key.verify(signed_bytes, decode_signature(signature))
        return True
    except BadSignatureError:
        return False
