"""JWT revocation backends with safe single- and multi-worker behavior."""

from __future__ import annotations

import hashlib
import math
import os
import threading
import time
from typing import Any, Protocol


class RevocationBackendUnavailable(RuntimeError):
    """Raised when the selected revocation backend cannot be used safely."""


class RevocationCapacityExceeded(RuntimeError):
    """Raised instead of evicting an active revocation entry."""


class TokenRevocationBackend(Protocol):
    def revoke(self, token_id: str, expires_at: float) -> None:
        """Revoke token_id until expires_at."""

    def is_revoked(self, token_id: str) -> bool:
        """Return whether token_id is currently revoked."""


class MemoryTokenRevocationBackend:
    """Single-process revocation backend.

    Active entries are never evicted to make room. When capacity is exhausted,
    logout fails explicitly instead of silently making an older revoked token
    valid again.
    """

    def __init__(self, max_entries: int = 10_000) -> None:
        if max_entries <= 0:
            raise ValueError("max_entries must be greater than zero")
        self.max_entries = max_entries
        self._tokens: dict[str, float] = {}
        self._lock = threading.Lock()

    def _prune_expired(self, now: float) -> None:
        expired = [
            token_id for token_id, expiry in self._tokens.items() if expiry <= now
        ]
        for token_id in expired:
            self._tokens.pop(token_id, None)

    def revoke(self, token_id: str, expires_at: float) -> None:
        now = time.time()
        if expires_at <= now:
            return
        with self._lock:
            self._prune_expired(now)
            if token_id not in self._tokens and len(self._tokens) >= self.max_entries:
                raise RevocationCapacityExceeded("JWT revocation store is at capacity")
            self._tokens[token_id] = expires_at

    def is_revoked(self, token_id: str) -> bool:
        now = time.time()
        with self._lock:
            expiry = self._tokens.get(token_id)
            if expiry is None:
                return False
            if expiry <= now:
                self._tokens.pop(token_id, None)
                return False
            return True

    def clear(self) -> None:
        with self._lock:
            self._tokens.clear()


class RedisTokenRevocationBackend:
    """Shared revocation backend for multi-worker deployments."""

    def __init__(
        self, client: Any, namespace: str = "anti-grooming:jwt-revoked:v1"
    ) -> None:
        self.client = client
        self.namespace = namespace

    def _key(self, token_id: str) -> str:
        digest = hashlib.sha256(token_id.encode("utf-8")).hexdigest()
        return f"{self.namespace}:{digest}"

    def revoke(self, token_id: str, expires_at: float) -> None:
        ttl = math.ceil(expires_at - time.time())
        if ttl <= 0:
            return
        self.client.set(self._key(token_id), "1", ex=ttl)

    def is_revoked(self, token_id: str) -> bool:
        return bool(self.client.exists(self._key(token_id)))


class TokenRevocationStore:
    """Select the configured backend and fail closed when it is unavailable."""

    def __init__(self, max_memory_entries: int = 10_000) -> None:
        self._memory = MemoryTokenRevocationBackend(max_memory_entries)
        self._redis_backend: RedisTokenRevocationBackend | None = None
        self._redis_url: str | None = None

    def validate_configuration(self) -> None:
        mode = os.getenv("TOKEN_REVOCATION_BACKEND", "memory").strip().lower()
        if mode not in {"memory", "redis"}:
            raise RuntimeError("TOKEN_REVOCATION_BACKEND debe ser 'memory' o 'redis'")
        if mode == "redis" and not os.getenv("REDIS_URL", "").strip():
            raise RuntimeError(
                "REDIS_URL es obligatorio cuando TOKEN_REVOCATION_BACKEND=redis"
            )

    def _selected_backend(self) -> TokenRevocationBackend:
        mode = os.getenv("TOKEN_REVOCATION_BACKEND", "memory").strip().lower()
        if mode == "memory":
            return self._memory
        if mode != "redis":
            raise RevocationBackendUnavailable("Unsupported JWT revocation backend")

        url = os.getenv("REDIS_URL", "").strip()
        if not url:
            raise RevocationBackendUnavailable(
                "REDIS_URL is required for the Redis revocation backend"
            )

        if self._redis_backend is None or self._redis_url != url:
            try:
                import redis  # type: ignore[import-not-found]

                client = redis.Redis.from_url(url, decode_responses=True)
            except (ImportError, ValueError) as exc:
                raise RevocationBackendUnavailable(
                    "Redis revocation backend could not be configured"
                ) from exc
            self._redis_backend = RedisTokenRevocationBackend(client)
            self._redis_url = url

        return self._redis_backend

    def revoke(self, token_id: str, expires_at: float) -> None:
        backend = self._selected_backend()
        try:
            backend.revoke(token_id, expires_at)
        except RevocationCapacityExceeded:
            raise
        except Exception as exc:
            raise RevocationBackendUnavailable(
                "JWT revocation backend is unavailable"
            ) from exc

    def is_revoked(self, token_id: str) -> bool:
        backend = self._selected_backend()
        try:
            return backend.is_revoked(token_id)
        except Exception as exc:
            raise RevocationBackendUnavailable(
                "JWT revocation backend is unavailable"
            ) from exc

    def clear(self) -> None:
        """Reset local state for tests without deleting shared Redis data."""

        self._memory.clear()
        self._redis_backend = None
        self._redis_url = None
