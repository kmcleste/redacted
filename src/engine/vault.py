"""
Reversible-map vault — the crown jewel of the engine.

Design invariants (D1):
- Lives entirely in the consumer's process / trust boundary.
- Values are encrypted at rest inside the vault using a per-instance Fernet key.
- TTL is enforced lazily on every read (no background thread required).
- The vault object's __repr__ and __str__ never expose plaintext values or the map.
- The vault is never serialized, logged, or transmitted.

Encryption note: Fernet = AES-128-CBC + HMAC-SHA256. The key lives in process
memory alongside the ciphertext, so the encryption principally prevents
accidental logging via object repr or debug dumps. Production should pair this
with OS-level memory locking (mlock) where available.
"""

from __future__ import annotations

import os
import time
from base64 import urlsafe_b64encode

from cryptography.fernet import Fernet, InvalidToken


class VaultExpiredError(Exception):
    """Raised when a vault entry has exceeded its TTL."""


class VaultNotFoundError(KeyError):
    """Raised when a correlation ID has no vault entry."""


class _VaultEntry:
    __slots__ = ("_fernet", "_encrypted_map", "_expires_at")

    def __init__(
        self,
        fernet: Fernet,
        placeholder_map: dict[str, str],
        ttl_seconds: float,
    ) -> None:
        self._fernet = fernet
        self._encrypted_map: dict[str, bytes] = {
            k: fernet.encrypt(v.encode()) for k, v in placeholder_map.items()
        }
        self._expires_at = time.monotonic() + ttl_seconds

    def is_expired(self) -> bool:
        return time.monotonic() > self._expires_at

    def get_map(self) -> dict[str, str]:
        return {k: self._fernet.decrypt(v).decode() for k, v in self._encrypted_map.items()}

    def extend_ttl(self, additional_seconds: float) -> None:
        self._expires_at = max(self._expires_at, time.monotonic() + additional_seconds)

    def add(self, placeholder: str, original: str) -> None:
        self._encrypted_map[placeholder] = self._fernet.encrypt(original.encode())

    def __repr__(self) -> str:
        return f"<VaultEntry keys={list(self._encrypted_map.keys())} expires_in={self._expires_at - time.monotonic():.1f}s>"


class Vault:
    """
    In-process vault storing {correlation_id → {placeholder → original}}.

    Thread-safety: not thread-safe by default. Wrap with a lock if the engine
    is called concurrently from multiple threads within the same process.
    """

    DEFAULT_TTL: float = 300.0  # 5 minutes per request lifecycle.
    CONVERSATION_TTL: float = 3600.0  # 1 hour for conversation-scoped entries.

    def __init__(self) -> None:
        self._key = Fernet.generate_key()
        self._fernet = Fernet(self._key)
        self._entries: dict[str, _VaultEntry] = {}

    def store(
        self,
        correlation_id: str,
        placeholder_map: dict[str, str],
        *,
        ttl: float = DEFAULT_TTL,
        extend_if_exists: bool = True,
    ) -> None:
        """Store or merge a placeholder map for a correlation ID."""
        existing = self._entries.get(correlation_id)
        if existing and not existing.is_expired():
            if extend_if_exists:
                existing.extend_ttl(ttl)
            for k, v in placeholder_map.items():
                existing.add(k, v)
        else:
            self._entries[correlation_id] = _VaultEntry(
                self._fernet, placeholder_map, ttl
            )

    def get(self, correlation_id: str) -> dict[str, str]:
        """Retrieve the placeholder map. Raises on miss or expiry."""
        entry = self._entries.get(correlation_id)
        if entry is None:
            raise VaultNotFoundError(correlation_id)
        if entry.is_expired():
            del self._entries[correlation_id]
            raise VaultExpiredError(f"Vault entry for {correlation_id!r} has expired")
        return entry.get_map()

    def delete(self, correlation_id: str) -> bool:
        """Purge a vault entry (right-to-erasure, D12). Returns True if deleted."""
        entry = self._entries.pop(correlation_id, None)
        if entry is not None:
            # Overwrite encrypted map before releasing reference.
            for k in list(entry._encrypted_map.keys()):
                entry._encrypted_map[k] = os.urandom(32)
            return True
        return False

    def purge_expired(self) -> int:
        """Remove all expired entries. Call periodically to reclaim memory."""
        expired = [cid for cid, e in self._entries.items() if e.is_expired()]
        for cid in expired:
            del self._entries[cid]
        return len(expired)

    def __contains__(self, correlation_id: str) -> bool:
        entry = self._entries.get(correlation_id)
        if entry is None:
            return False
        if entry.is_expired():
            del self._entries[correlation_id]
            return False
        return True

    def __len__(self) -> int:
        return sum(1 for e in self._entries.values() if not e.is_expired())

    def __repr__(self) -> str:
        return f"<Vault entries={len(self)}>"
