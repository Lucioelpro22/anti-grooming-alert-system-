"""Distributed login/MFA failure rate limiting."""

from __future__ import annotations

import hashlib
import os
import threading
import time
from dataclasses import dataclass
from typing import Any, Protocol


class LoginRateLimitConfigurationError(RuntimeError):
    """Login rate-limit configuration is invalid."""


class LoginRateLimitBackendUnavailable(RuntimeError):
    """Shared login rate-limit state cannot be consulted safely."""


class LoginRateLimitCapacityExceeded(RuntimeError):
    """In-memory limiter reached capacity without stale entries to prune."""


@dataclass(frozen=True)
class LoginRateLimitDecision:
    allowed: bool
    retry_after: int


class LoginRateLimitBackend(Protocol):
    def check(
        self, key: str, attempts: int, window_seconds: int
    ) -> LoginRateLimitDecision: ...

    def failure(self, key: str, attempts: int, window_seconds: int) -> None: ...

    def success(self, key: str) -> None: ...


def opaque_login_key(client: str, username: str) -> str:
    normalized = f"{client.strip().lower()}:{username.strip().lower()}"
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


class MemoryLoginRateLimitBackend:
    """Single-process limiter that counts only failed logins."""

    def __init__(self, max_keys: int = 10_000) -> None:
        if max_keys <= 0:
            raise ValueError("max_keys must be greater than zero")
        self.max_keys = max_keys
        self._failures: dict[str, list[float]] = {}
        self._lock = threading.Lock()

    def _recent(self, key: str, window_seconds: int) -> list[float]:
        cutoff = time.monotonic() - window_seconds
        return [value for value in self._failures.get(key, []) if value > cutoff]

    def _prune(self, window_seconds: int) -> None:
        cutoff = time.monotonic() - window_seconds
        stale = [
            key
            for key, values in self._failures.items()
            if not values or values[-1] <= cutoff
        ]
        for key in stale:
            self._failures.pop(key, None)

    def check(
        self, key: str, attempts: int, window_seconds: int
    ) -> LoginRateLimitDecision:
        with self._lock:
            recent = self._recent(key, window_seconds)
            if recent:
                self._failures[key] = recent
            else:
                self._failures.pop(key, None)
            if len(recent) >= attempts:
                retry_after = max(
                    1,
                    int(window_seconds - (time.monotonic() - recent[0])),
                )
                return LoginRateLimitDecision(False, retry_after)
            return LoginRateLimitDecision(True, 0)

    def failure(self, key: str, attempts: int, window_seconds: int) -> None:
        del attempts
        with self._lock:
            recent = self._recent(key, window_seconds)
            if key not in self._failures and len(self._failures) >= self.max_keys:
                self._prune(window_seconds)
                if len(self._failures) >= self.max_keys:
                    raise LoginRateLimitCapacityExceeded(
                        "Login rate-limit store is at capacity"
                    )
            recent.append(time.monotonic())
            self._failures[key] = recent

    def success(self, key: str) -> None:
        with self._lock:
            self._failures.pop(key, None)

    def clear(self) -> None:
        with self._lock:
            self._failures.clear()


class RedisLoginRateLimitBackend:
    """Shared failed-login counter for multi-worker deployments."""

    _FAILURE_SCRIPT = """
local count = redis.call('INCR', KEYS[1])
if count == 1 then
  redis.call('EXPIRE', KEYS[1], ARGV[1])
end
return count
"""

    def __init__(
        self,
        client: Any,
        namespace: str = "anti-grooming:login-ratelimit:v1",
    ) -> None:
        self.client = client
        self.namespace = namespace

    def _key(self, key: str) -> str:
        return f"{self.namespace}:{key}"

    def check(
        self, key: str, attempts: int, window_seconds: int
    ) -> LoginRateLimitDecision:
        redis_key = self._key(key)
        pipeline = self.client.pipeline(transaction=True)
        pipeline.get(redis_key)
        pipeline.ttl(redis_key)
        raw_count, raw_ttl = pipeline.execute()
        count = int(raw_count or 0)
        ttl = int(raw_ttl)
        if count <= 0:
            return LoginRateLimitDecision(True, 0)
        if ttl <= 0:
            raise LoginRateLimitBackendUnavailable(
                "Contador Redis de login sin expiración válida"
            )
        if count >= attempts:
            return LoginRateLimitDecision(False, min(ttl, window_seconds))
        return LoginRateLimitDecision(True, 0)

    def failure(self, key: str, attempts: int, window_seconds: int) -> None:
        del attempts
        self.client.eval(
            self._FAILURE_SCRIPT,
            1,
            self._key(key),
            window_seconds,
        )

    def success(self, key: str) -> None:
        self.client.delete(self._key(key))


class LoginRateLimitStore:
    """Select memory or Redis failed-login state and fail closed on outages."""

    def __init__(self, max_memory_keys: int = 10_000) -> None:
        self._memory = MemoryLoginRateLimitBackend(max_memory_keys)
        self._redis_backend: RedisLoginRateLimitBackend | None = None
        self._redis_url: str | None = None

    def attempts(self) -> int:
        return self._positive_int("LOGIN_RATE_LIMIT_ATTEMPTS", 5)

    def window_seconds(self) -> int:
        return self._positive_int("LOGIN_RATE_LIMIT_WINDOW_SECONDS", 300)

    @staticmethod
    def _positive_int(name: str, default: int) -> int:
        raw = os.getenv(name, str(default))
        try:
            value = int(raw)
        except ValueError as exc:
            raise LoginRateLimitConfigurationError(f"{name} inválido") from exc
        if value <= 0:
            raise LoginRateLimitConfigurationError(f"{name} debe ser mayor que cero")
        return value

    def validate_configuration(self) -> None:
        mode = os.getenv("LOGIN_RATE_LIMIT_BACKEND", "memory").strip().lower()
        if mode not in {"memory", "redis"}:
            raise LoginRateLimitConfigurationError(
                "LOGIN_RATE_LIMIT_BACKEND debe ser 'memory' o 'redis'"
            )
        if mode == "redis" and not os.getenv("REDIS_URL", "").strip():
            raise LoginRateLimitConfigurationError(
                "REDIS_URL es obligatorio cuando LOGIN_RATE_LIMIT_BACKEND=redis"
            )
        self.attempts()
        self.window_seconds()

    def _selected_backend(self) -> LoginRateLimitBackend:
        mode = os.getenv("LOGIN_RATE_LIMIT_BACKEND", "memory").strip().lower()
        if mode == "memory":
            return self._memory
        if mode != "redis":
            raise LoginRateLimitBackendUnavailable(
                "Backend de rate limit de login no soportado"
            )

        url = os.getenv("REDIS_URL", "").strip()
        if not url:
            raise LoginRateLimitBackendUnavailable(
                "REDIS_URL requerido para rate limit de login"
            )
        if self._redis_backend is None or self._redis_url != url:
            try:
                import redis  # type: ignore[import-not-found]

                client = redis.Redis.from_url(url, decode_responses=True)
            except (ImportError, ValueError) as exc:
                raise LoginRateLimitBackendUnavailable(
                    "Redis de rate limit de login no disponible"
                ) from exc
            self._redis_backend = RedisLoginRateLimitBackend(client)
            self._redis_url = url
        return self._redis_backend

    def check(self, key: str) -> LoginRateLimitDecision:
        try:
            return self._selected_backend().check(
                key,
                self.attempts(),
                self.window_seconds(),
            )
        except (
            LoginRateLimitBackendUnavailable,
            LoginRateLimitCapacityExceeded,
        ):
            raise
        except Exception as exc:
            raise LoginRateLimitBackendUnavailable(
                "Rate limit de login no disponible"
            ) from exc

    def failure(self, key: str) -> None:
        try:
            self._selected_backend().failure(
                key,
                self.attempts(),
                self.window_seconds(),
            )
        except (
            LoginRateLimitBackendUnavailable,
            LoginRateLimitCapacityExceeded,
        ):
            raise
        except Exception as exc:
            raise LoginRateLimitBackendUnavailable(
                "Rate limit de login no disponible"
            ) from exc

    def success(self, key: str) -> None:
        try:
            self._selected_backend().success(key)
        except LoginRateLimitBackendUnavailable:
            raise
        except Exception as exc:
            raise LoginRateLimitBackendUnavailable(
                "Rate limit de login no disponible"
            ) from exc

    def clear(self) -> None:
        self._memory.clear()
        self._redis_backend = None
        self._redis_url = None
