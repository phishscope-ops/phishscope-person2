"""Request limits (security 10): sliding window per client key, in memory, no extra service."""
import time
from collections import defaultdict, deque


class RateLimiter:
    def __init__(self, per_minute: int):
        self.per_minute = per_minute
        self.hits = defaultdict(deque)

    def allow(self, key: str, now: float = None) -> bool:
        now = time.monotonic() if now is None else now
        q = self.hits[key]
        while q and q[0] <= now - 60:
            q.popleft()
        if len(q) >= self.per_minute:
            return False
        q.append(now)
        if len(self.hits) > 10000:  # keep memory bounded
            for k in [k for k, v in self.hits.items() if not v or v[-1] <= now - 60][:5000]:
                self.hits.pop(k, None)
        return True
