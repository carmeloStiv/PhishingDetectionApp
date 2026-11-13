"""In-memory sliding-window rate limiter (per client address)."""
from __future__ import annotations

import threading
import time
from collections import defaultdict, deque


class RateLimiter:
    def __init__(self, limit: int, window: float = 60.0) -> None:
        self.limit, self.window = limit, window
        self._hits: dict[str, deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()

    def check(self, key: str) -> tuple[bool, int]:
        """Returns (allowed, seconds_until_retry)."""
        if self.limit <= 0:
            return True, 0
        now = time.monotonic()
        with self._lock:
            q = self._hits[key]
            while q and now - q[0] > self.window:
                q.popleft()
            if len(q) >= self.limit:
                return False, max(int(self.window - (now - q[0])) + 1, 1)
            q.append(now)
            if len(self._hits) > 20000:   # bound memory under address churn
                for k in [k for k, v in self._hits.items() if not v or now - v[-1] > self.window]:
                    del self._hits[k]
            return True, 0
