"""
Idempotency cache for SyncDecision RPC.

Design basis: 04-policy-decision-and-fallback.md section 11.4.

- Cache request_id -> response mapping.
- TTL = max(deadline_ms * 3, 5000ms).
- Same request_id returns identical response without re-evaluation.
- Expired entries are treated as new requests.
"""

from __future__ import annotations

import asyncio
import threading
import time
from typing import Any, Optional


class IdempotencyCache:
    """
    Thread-safe in-memory idempotency cache with TTL-based eviction.

    Each entry stores the full response and expires after the configured TTL.
    Bounded by max_size to prevent memory exhaustion.
    """

    MIN_TTL_MS = 5000
    DEFAULT_MAX_SIZE = 50_000

    def __init__(self, max_size: int = DEFAULT_MAX_SIZE) -> None:
        self._store: dict[str, tuple[Any, float]] = {}  # key -> (response, expire_at)
        self._lock = threading.Lock()
        self._max_size = max_size

    def get(self, request_id: str) -> Optional[Any]:
        """
        Retrieve a cached response for the given request_id.

        Returns None if not found or expired.
        """
        with self._lock:
            entry = self._store.get(request_id)
            if entry is None:
                return None
            response, expire_at = entry
            if time.monotonic() > expire_at:
                del self._store[request_id]
                return None
            return response

    def put(self, request_id: str, response: Any, deadline_ms: int) -> bool:
        """
        Store a response if not already cached (unexpired).

        TTL = max(deadline_ms * 3, 5000ms).
        Returns True if stored, False if an unexpired entry already exists.
        Evicts oldest entries when max_size is exceeded.
        """
        ttl_ms = max(deadline_ms * 3, self.MIN_TTL_MS)
        expire_at = time.monotonic() + ttl_ms / 1000.0
        with self._lock:
            existing = self._store.get(request_id)
            if existing is not None:
                _, existing_expire = existing
                if time.monotonic() <= existing_expire:
                    return False  # Already cached and valid
            # Evict oldest entries if at capacity
            while len(self._store) >= self._max_size:
                oldest_key = next(iter(self._store))
                del self._store[oldest_key]
            self._store[request_id] = (response, expire_at)
            return True

    def cleanup(self) -> int:
        """
        Remove all expired entries. Returns count of removed entries.
        """
        now = time.monotonic()
        removed = 0
        with self._lock:
            expired_keys = [
                k for k, (_, expire_at) in self._store.items()
                if now > expire_at
            ]
            for k in expired_keys:
                del self._store[k]
                removed += 1
        return removed

    def size(self) -> int:
        """Return the number of entries (including potentially expired ones)."""
        with self._lock:
            return len(self._store)

    def clear(self) -> None:
        """Remove all entries."""
        with self._lock:
            self._store.clear()


async def periodic_cleanup(cache: IdempotencyCache, interval_seconds: float = 10.0) -> None:
    """Background task that periodically cleans expired entries."""
    try:
        while True:
            await asyncio.sleep(interval_seconds)
            cache.cleanup()
    except asyncio.CancelledError:
        pass
