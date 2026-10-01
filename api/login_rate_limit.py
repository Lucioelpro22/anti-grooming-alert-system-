"""Distributed login/MFA failure rate limiting and stuffing defenses."""

from __future__ import annotations

import hashlib
import math
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


@dataclass(frozen=True)
class LoginRateLimitPolicy:
    attempts: int
    window_seconds: int
    backoff_base_seconds: int
    backoff_max_seconds: int


@dataclass
class _MemoryState:
    count: int
    window_started: float
    penalty_level: int
    block_until: float


class LoginRateLimitBackend(Protocol):
    def check(
        self, key: str, policy: LoginRateLimitPolicy
    ) -> LoginRateLimitDecision: ...

    def failure(self, key: str, policy: LoginRateLimitPolicy) -> None: ...

    def success(self, key: str) -> None: ...


def opaque_scope_key(scope: str, value: str) -> str:
    normalized = f"{scope.strip().lower()}:{value.strip().lower()}"
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def opaque_login_key(client: str, username: str) -> str:
    return opaque_scope_key(
        "pair",
        f"{client.strip().lower()}:{username.strip().lower()}",
    )


class MemoryLoginRateLimitBackend:
    """Single-process multi-scope limiter with progressive backoff."""

    def __init__(self, max_keys: int = 20_000) -> None:
        if max_keys <= 0:
            raise ValueError("max_keys must be greater than zero")
        self.max_keys = max_keys
        self._states: dict[str, _MemoryState] = {}
        self._lock = threading.Lock()

    @staticmethod
    def _expired(
        state: _MemoryState,
        policy: LoginRateLimitPolicy,
        now: float,
    ) -> bool:
        return (
            now - state.window_started >= policy.window_seconds
            and now >= state.block_until
        )

    def _prune(self, policy: LoginRateLimitPolicy, now: float) -> None:
        stale = [
            key
            for key, state in self._states.items()
            if self._expired(state, policy, now)
        ]
        for key in stale:
            self._states.pop(key, None)

    def check(
        self, key: str, policy: LoginRateLimitPolicy
    ) -> LoginRateLimitDecision:
        now = time.monotonic()
        with self._lock:
            state = self._states.get(key)
            if state is None:
                return LoginRateLimitDecision(True, 0)
            if self._expired(state, policy, now):
                self._states.pop(key, None)
                return LoginRateLimitDecision(True, 0)
            if state.block_until > now:
                return LoginRateLimitDecision(
                    False,
                    max(1, math.ceil(state.block_until - now)),
                )
            return LoginRateLimitDecision(True, 0)

    def failure(self, key: str, policy: LoginRateLimitPolicy) -> None:
        now = time.monotonic()
        with self._lock:
            state = self._states.get(key)
            if state is not None and self._expired(state, policy, now):
                self._states.pop(key, None)
                state = None

            if state is None:
                if len(self._states) >= self.max_keys:
                    self._prune(policy, now)
                    if len(self._states) >= self.max_keys:
                        raise LoginRateLimitCapacityExceeded(
                            "Login rate-limit store is at capacity"
                        )
                state = _MemoryState(
                    count=0,
                    window_started=now,
                    penalty_level=0,
                    block_until=0.0,
                )
                self._states[key] = state

            state.count += 1
            if state.count >= policy.attempts:
                state.penalty_level += 1
                delay = min(
                    policy.backoff_max_seconds,
                    policy.backoff_base_seconds
                    * (2 ** (state.penalty_level - 1)),
                )
                state.block_until = max(state.block_until, now + delay)

    def success(self, key: str) -> None:
        with self._lock:
            self._states.pop(key, None)

    def clear(self) -> None:
        with self._lock:
            self._states.clear()


class RedisLoginRateLimitBackend:
    """Shared multi-scope limiter with Redis-time progressive backoff."""

    _CHECK_SCRIPT = """
local now_parts = redis.call('TIME')
local now = tonumber(now_parts[1])
local block_until = tonumber(redis.call('HGET', KEYS[1], 'block_until') or '0')
if block_until > now then
  return {0, block_until - now}
end
return {1, 0}
"""

    _FAILURE_SCRIPT = """
local now_parts = redis.call('TIME')
local now = tonumber(now_parts[1])
local count = redis.call('HINCRBY', KEYS[1], 'count', 1)
local ttl = redis.call('TTL', KEYS[1])
if count == 1 or ttl < 0 then
  redis.call('EXPIRE', KEYS[1], tonumber(ARGV[2]))
end

if count >= tonumber(ARGV[1]) then
  local level = redis.call('HINCRBY', KEYS[1], 'level', 1)
  local delay = tonumber(ARGV[3]) * (2 ^ (level - 1))
  local max_delay = tonumber(ARGV[4])
  if delay > max_delay then
    delay = max_delay
  end
  local block_until = now + delay
  redis.call('HSET', KEYS[1], 'block_until', block_until)
  ttl = redis.call('TTL', KEYS[1])
  if ttl < delay then
    redis.call('EXPIRE', KEYS[1], delay)
  end
end
return count
"""

    def __init__(
        self,
        client: Any,
        namespace: str = "anti-grooming:login-ratelimit:v2",
    ) -> None:
        self.client = client
        self.namespace = namespace

    def _key(self, key: str) -> str:
        return f"{self.namespace}:{key}"

    def check(
        self, key: str, policy: LoginRateLimitPolicy
    ) -> LoginRateLimitDecision:
        result = self.client.eval(
            self._CHECK_SCRIPT,
            1,
            self._key(key),
        )
        allowed, retry_after = int(result[0]), int(result[1])
        return LoginRateLimitDecision(
            allowed=bool(allowed),
            retry_after=max(0, min(retry_after, policy.backoff_max_seconds)),
        )

    def failure(self, key: str, policy: LoginRateLimitPolicy) -> None:
        self.client.eval(
            self._FAILURE_SCRIPT,
            1,
            self._key(key),
            policy.attempts,
            policy.window_seconds,
            policy.backoff_base_seconds,
            policy.backoff_max_seconds,
        )

    def success(self, key: str) -> None:
        self.client.delete(self._key(key))


class LoginRateLimitStore:
    """Select memory or Redis rate-limit state and expose scope policies."""

    def __init__(self, max_memory_keys: int = 20_000) -> None:
        self._memory = MemoryLoginRateLimitBackend(max_memory_keys)
        self._redis_backend: RedisLoginRateLimitBackend | None = None
        self._redis_url: str | None = None

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

    def backoff_base_seconds(self) -> int:
        return self._positive_int("LOGIN_BACKOFF_BASE_SECONDS", 30)

    def backoff_max_seconds(self) -> int:
        value = self._positive_int("LOGIN_BACKOFF_MAX_SECONDS", 900)
        if value < self.backoff_base_seconds():
            raise LoginRateLimitConfigurationError(
                "LOGIN_BACKOFF_MAX_SECONDS debe ser >= LOGIN_BACKOFF_BASE_SECONDS"
            )
        return value

    def policy(self, scope: str) -> LoginRateLimitPolicy:
        base = self.backoff_base_seconds()
        maximum = self.backoff_max_seconds()
        if scope == "pair":
            attempts = self._positive_int(
                "LOGIN_PAIR_ATTEMPTS",
                self._positive_int("LOGIN_RATE_LIMIT_ATTEMPTS", 5),
            )
            window = self._positive_int(
                "LOGIN_PAIR_WINDOW_SECONDS",
                self._positive_int("LOGIN_RATE_LIMIT_WINDOW_SECONDS", 300),
            )
        elif scope == "account":
            attempts = self._positive_int("LOGIN_ACCOUNT_ATTEMPTS", 10)
            window = self._positive_int("LOGIN_ACCOUNT_WINDOW_SECONDS", 900)
        elif scope == "client":
            attempts = self._positive_int("LOGIN_CLIENT_ATTEMPTS", 20)
            window = self._positive_int("LOGIN_CLIENT_WINDOW_SECONDS", 300)
        else:
            raise LoginRateLimitConfigurationError("Scope de login inválido")
        return LoginRateLimitPolicy(
            attempts=attempts,
            window_seconds=window,
            backoff_base_seconds=base,
            backoff_max_seconds=maximum,
        )

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
        for scope in ("pair", "account", "client"):
            self.policy(scope)

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

    def check(
        self,
        key: str,
        policy: LoginRateLimitPolicy,
    ) -> LoginRateLimitDecision:
        try:
            return self._selected_backend().check(key, policy)
        except (
            LoginRateLimitBackendUnavailable,
            LoginRateLimitCapacityExceeded,
        ):
            raise
        except Exception as exc:
            raise LoginRateLimitBackendUnavailable(
                "Rate limit de login no disponible"
            ) from exc

    def failure(self, key: str, policy: LoginRateLimitPolicy) -> None:
        try:
            self._selected_backend().failure(key, policy)
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
