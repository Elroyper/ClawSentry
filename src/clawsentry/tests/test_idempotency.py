"""
Unit tests for idempotency cache — Gate 3 verification.

Covers: cache hit, cache miss, TTL expiry, TTL calculation,
concurrent access, cleanup.
"""

import time
import threading
import pytest

from clawsentry.gateway.storage.idempotency import IdempotencyCache


class TestIdempotencyCache:
    def test_cache_miss(self):
        cache = IdempotencyCache()
        assert cache.get("nonexistent") is None

    def test_put_and_get(self):
        cache = IdempotencyCache()
        response = {"decision": "allow", "request_id": "req-1"}
        cache.put("req-1", response, deadline_ms=100)
        assert cache.get("req-1") == response

    def test_same_request_id_returns_identical_response(self):
        cache = IdempotencyCache()
        response = {"decision": "block", "reason": "dangerous"}
        cache.put("req-2", response, deadline_ms=200)
        # Multiple gets should return the exact same response
        assert cache.get("req-2") == response
        assert cache.get("req-2") == response
        assert cache.get("req-2") is response  # Same object

    def test_ttl_minimum_5000ms(self):
        """TTL = max(deadline_ms * 3, 5000ms). For deadline=100ms, TTL=5000ms."""
        cache = IdempotencyCache()
        cache.put("req-3", "response", deadline_ms=100)
        # Should still be available (TTL=5s, well within bounds)
        assert cache.get("req-3") == "response"

    def test_ttl_scales_with_deadline(self):
        """For deadline=2000ms, TTL=6000ms > 5000ms."""
        cache = IdempotencyCache()
        cache.put("req-4", "response", deadline_ms=2000)
        # TTL = max(2000*3, 5000) = 6000ms
        assert cache.get("req-4") == "response"

    def test_expiry(self):
        """Entries should expire after TTL."""
        cache = IdempotencyCache()
        # Use the internal store directly to set a very short TTL for testing
        cache._store["req-expired"] = ("old_response", time.monotonic() - 1)
        assert cache.get("req-expired") is None

    def test_cleanup_removes_expired(self):
        cache = IdempotencyCache()
        # Add expired entry
        cache._store["req-old"] = ("old", time.monotonic() - 1)
        # Add valid entry
        cache.put("req-new", "new", deadline_ms=100)
        removed = cache.cleanup()
        assert removed == 1
        assert cache.get("req-old") is None
        assert cache.get("req-new") == "new"

    def test_size(self):
        cache = IdempotencyCache()
        assert cache.size() == 0
        cache.put("a", 1, deadline_ms=100)
        cache.put("b", 2, deadline_ms=100)
        assert cache.size() == 2

    def test_clear(self):
        cache = IdempotencyCache()
        cache.put("a", 1, deadline_ms=100)
        cache.put("b", 2, deadline_ms=100)
        cache.clear()
        assert cache.size() == 0
        assert cache.get("a") is None

    def test_put_if_absent_rejects_duplicate(self):
        """Same request_id returns False and preserves original response."""
        cache = IdempotencyCache()
        assert cache.put("req-1", "first", deadline_ms=100) is True
        assert cache.put("req-1", "second", deadline_ms=100) is False
        assert cache.get("req-1") == "first"  # Original preserved

    def test_put_after_expiry_accepts(self):
        """Expired entry allows re-put."""
        cache = IdempotencyCache()
        cache._store["req-1"] = ("old", time.monotonic() - 1)
        assert cache.put("req-1", "new", deadline_ms=100) is True
        assert cache.get("req-1") == "new"

    def test_concurrent_access(self):
        """Verify no race conditions with concurrent reads and writes."""
        cache = IdempotencyCache()
        errors = []

        def writer(key_prefix: str, count: int):
            try:
                for i in range(count):
                    cache.put(f"{key_prefix}-{i}", f"val-{i}", deadline_ms=100)
            except Exception as e:
                errors.append(e)

        def reader(key_prefix: str, count: int):
            try:
                for i in range(count):
                    cache.get(f"{key_prefix}-{i}")
            except Exception as e:
                errors.append(e)

        threads = []
        for prefix in ("A", "B", "C"):
            threads.append(threading.Thread(target=writer, args=(prefix, 100)))
            threads.append(threading.Thread(target=reader, args=(prefix, 100)))

        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(errors) == 0, f"Concurrent access errors: {errors}"
        # All written entries should be retrievable
        for prefix in ("A", "B", "C"):
            for i in range(100):
                assert cache.get(f"{prefix}-{i}") == f"val-{i}"
