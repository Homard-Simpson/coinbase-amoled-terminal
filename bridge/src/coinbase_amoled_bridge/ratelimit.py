"""In-memory token-bucket controls for basic public endpoint abuse."""

from __future__ import annotations

import hashlib
import math
import secrets
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass


@dataclass(slots=True)
class _Bucket:
    tokens: float
    updated_at: float
    last_seen: float


class TokenBucketLimiter:
    def __init__(
        self,
        rate_per_minute: int,
        burst: int,
        *,
        max_entries: int = 20_000,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if rate_per_minute <= 0 or burst <= 0 or max_entries <= 0:
            raise ValueError("rate, burst, and max_entries must be positive")
        self.rate_per_second = rate_per_minute / 60.0
        self.burst = float(burst)
        self.max_entries = max_entries
        self.clock = clock
        self._buckets: dict[str, _Bucket] = {}
        self._lock = threading.Lock()
        self._next_cleanup = 0.0

    def allow(self, key: str, *, cost: float = 1.0) -> tuple[bool, int]:
        if cost <= 0:
            raise ValueError("cost must be positive")
        now = float(self.clock())
        with self._lock:
            if now >= self._next_cleanup or len(self._buckets) > self.max_entries:
                self._cleanup(now)
            bucket = self._buckets.get(key)
            if bucket is None:
                bucket = _Bucket(tokens=self.burst, updated_at=now, last_seen=now)
                self._buckets[key] = bucket
            elapsed = max(0.0, now - bucket.updated_at)
            bucket.tokens = min(
                self.burst, bucket.tokens + elapsed * self.rate_per_second
            )
            bucket.updated_at = now
            bucket.last_seen = now
            if bucket.tokens >= cost:
                bucket.tokens -= cost
                return True, 0
            deficit = cost - bucket.tokens
            retry = max(1, math.ceil(deficit / self.rate_per_second))
            return False, retry

    def _cleanup(self, now: float) -> None:
        # Idle buckets are disposable; no authentication state lives here.
        idle_cutoff = now - max(300.0, self.burst / self.rate_per_second * 4)
        stale = [
            key
            for key, bucket in self._buckets.items()
            if bucket.last_seen < idle_cutoff
        ]
        for key in stale:
            self._buckets.pop(key, None)
        if len(self._buckets) > self.max_entries:
            overflow = len(self._buckets) - self.max_entries
            oldest = sorted(self._buckets.items(), key=lambda item: item[1].last_seen)[
                :overflow
            ]
            for key, _ in oldest:
                self._buckets.pop(key, None)
        self._next_cleanup = now + 60.0


class ClientHasher:
    """Avoid writing raw client addresses into logs or limiter diagnostics."""

    def __init__(self, salt: bytes | None = None) -> None:
        self._salt = salt or secrets.token_bytes(32)

    def digest(self, address: str) -> str:
        return hashlib.sha256(
            self._salt + address.encode("utf-8", "replace")
        ).hexdigest()[:16]
