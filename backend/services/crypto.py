"""Server-side signing and key management. Private key sealed with AES-256-GCM."""

from __future__ import annotations

import base64
import os
from datetime import datetime, timedelta, timezone
from typing import Any

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from nacl.signing import SigningKey, VerifyKey

__all__ = ["SigningService", "SovereignKeyManager"]

_ENC_KEY_ENV = "SOVEREIGN_ENCRYPTION_KEY"
_NONCE_BYTES = 12


def _load_aes_key() -> bytes:
    raw = os.environ.get(_ENC_KEY_ENV)
    if not raw:
        raise RuntimeError(
            f"{_ENC_KEY_ENV} is required to seal/open the signing key; "
            "supply it as a mounted secret, never hard-code it"
        )
    try:
        key = base64.b64decode(raw)
    except Exception as exc:  # noqa: BLE001
        raise RuntimeError(f"{_ENC_KEY_ENV} is not valid base64: {exc}") from None
    if len(key) != 32:
        raise RuntimeError(f"{_ENC_KEY_ENV} must decode to 32 bytes, got {len(key)}")
    return key


def _seal(plaintext: bytes, aes_key: bytes) -> bytes:
    nonce = os.urandom(_NONCE_BYTES)
    ct = AESGCM(aes_key).encrypt(nonce, plaintext, associated_data=None)
    return nonce + ct


def _open(blob: bytes, aes_key: bytes) -> bytes:
    nonce, ct = blob[:_NONCE_BYTES], blob[_NONCE_BYTES:]
    return AESGCM(aes_key).decrypt(nonce, ct, associated_data=None)


class SovereignKeyManager:
    """Generates and loads the signing key, sealed at rest with AES-256-GCM."""

    def __init__(self, data_dir: str = "/app/data") -> None:
        self._data_dir = data_dir
        self._key_path = os.path.join(data_dir, "sovereign.key")
        self._pub_path = os.path.join(data_dir, "sovereign.pub")

    def generate_root_key(self) -> None:
        os.makedirs(self._data_dir, exist_ok=True)
        if os.path.exists(self._key_path):
            return
        signing_key = SigningKey.generate()
        sealed = _seal(bytes(signing_key), _load_aes_key())
        fd = os.open(self._key_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "wb") as handle:
            handle.write(sealed)
        pub_b64 = base64.b64encode(bytes(signing_key.verify_key)).decode()
        with open(self._pub_path, "w", encoding="utf-8") as handle:
            handle.write(pub_b64)

    def load_private_key(self) -> SigningKey:
        if not os.path.exists(self._key_path):
            raise RuntimeError(
                f"no signing key at {self._key_path}; run generate_root_key first"
            )
        with open(self._key_path, "rb") as handle:
            sealed = handle.read()
        return SigningKey(_open(sealed, _load_aes_key()))

    def public_key_b64(self) -> str:
        with open(self._pub_path, encoding="utf-8") as handle:
            return handle.read().strip()


class SigningService:
    """Signs certificate hashes with Ed25519 and stamps expiry."""

    def __init__(self, key_manager: SovereignKeyManager, expiry_days: int = 365,
                 key_id: str = "versyn-root-2024-v1") -> None:
        self._signing_key = key_manager.load_private_key()
        self._expiry_days = expiry_days
        self._key_id = key_id

    def sign(self, hash_field: str) -> dict[str, Any]:
        hexdigest = hash_field.split(":", 1)[1] if ":" in hash_field else hash_field
        signed = self._signing_key.sign(bytes.fromhex(hexdigest)).signature
        now = datetime.now(timezone.utc)
        expires = now + timedelta(days=self._expiry_days)
        return {
            "certificate_id": f"cert_{os.urandom(8).hex()}",
            "hash": hash_field,
            "signature": "ed25519:" + base64.b64encode(signed).decode(),
            "timestamp_iso": now.isoformat(),
            "expires_at": expires.isoformat(),
            "key_id": self._key_id,
        }

    def public_key_b64(self) -> str:
        return base64.b64encode(bytes(self._signing_key.verify_key)).decode()
