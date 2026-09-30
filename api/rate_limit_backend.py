"""Optional distributed rate-limit backend.

The application keeps its safe in-process default. Deployments with multiple
workers can inject this backend with a Redis client; no Redis service is
pretended or started by the application.
"""

from dataclasses import dataclass
from typing import Any, Protocol


@dataclass(frozen=True)
class BackendRateLimitResult:
    allowed: bool
    retry_after: int


class RateLimitBackend(Protocol):
    def check(
        self, key: str, limit: int, window_seconds: int
    ) -> BackendRateLimitResult:
        """Atomically register a request and return the decision."""


class RedisRateLimitBackend:
    """Fixed-window Redis backend, supplied with an already configured client."""

    def __init__(self, client: Any, namespace: str = "anti-grooming:ratelimit") -> None:
        self.client = client
        self.namespace = namespace

    def check(
        self, key: str, limit: int, window_seconds: int
    ) -> BackendRateLimitResult:
        redis_key = f"{self.namespace}:{key}"
        pipeline = self.client.pipeline(transaction=True)
        pipeline.incr(redis_key)
        pipeline.expire(redis_key, window_seconds)
        count, _ = pipeline.execute()
        return BackendRateLimitResult(
            allowed=int(count) <= limit,
            retry_after=window_seconds if int(count) > limit else 0,
        )
