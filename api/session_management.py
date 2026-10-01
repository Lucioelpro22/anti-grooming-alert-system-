"""Refresh-token rotation and per-user session invalidation."""

from __future__ import annotations

import hashlib
import json
import math
import os
import secrets
import threading
import time
import uuid
from dataclasses import dataclass
from typing import Any, Protocol


class SessionBackendUnavailable(RuntimeError):
    """Raised when session state cannot be consulted safely."""


class SessionCapacityExceeded(RuntimeError):
    """Raised instead of evicting live refresh-session state."""


class InvalidRefreshToken(RuntimeError):
    """Raised when a refresh token is unknown, expired, or superseded."""


class RefreshReuseDetected(RuntimeError):
    """Raised when an already-consumed refresh token is presented again."""


@dataclass(frozen=True)
class RefreshResult:
    username: str
    role: str
    refresh_token: str
    refresh_expires_in: int
    session_version: int


@dataclass
class _RefreshRecord:
    username: str
    role: str
    expires_at: float
    session_version: int
    family_id: str
    state: str = "active"


class SessionBackend(Protocol):
    def issue(self, username: str, role: str, ttl_seconds: int) -> RefreshResult: ...

    def rotate(self, refresh_token: str, ttl_seconds: int) -> RefreshResult: ...

    def current_version(self, username: str) -> int: ...

    def logout_all(self, username: str) -> int: ...


def _digest(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _new_refresh_token() -> str:
    return secrets.token_urlsafe(32)


class MemorySessionBackend:
    """Single-process refresh-session backend with replay detection."""

    def __init__(self, max_entries: int = 20_000) -> None:
        if max_entries <= 0:
            raise ValueError("max_entries must be greater than zero")
        self.max_entries = max_entries
        self._records: dict[str, _RefreshRecord] = {}
        self._versions: dict[str, int] = {}
        self._lock = threading.Lock()

    def _prune(self, now: float) -> None:
        expired = [
            digest
            for digest, record in self._records.items()
            if record.expires_at <= now
        ]
        for digest in expired:
            self._records.pop(digest, None)

    def _version(self, username: str) -> int:
        return self._versions.get(username, 0)

    def issue(self, username: str, role: str, ttl_seconds: int) -> RefreshResult:
        now = time.time()
        with self._lock:
            self._prune(now)
            if len(self._records) >= self.max_entries:
                raise SessionCapacityExceeded("Refresh-session store is at capacity")
            token = _new_refresh_token()
            expires_at = now + ttl_seconds
            version = self._version(username)
            self._records[_digest(token)] = _RefreshRecord(
                username=username,
                role=role,
                expires_at=expires_at,
                session_version=version,
                family_id=str(uuid.uuid4()),
            )
            return RefreshResult(username, role, token, ttl_seconds, version)

    def rotate(self, refresh_token: str, ttl_seconds: int) -> RefreshResult:
        now = time.time()
        digest = _digest(refresh_token)
        with self._lock:
            self._prune(now)
            record = self._records.get(digest)
            if record is None or record.expires_at <= now:
                raise InvalidRefreshToken("Refresh token inválido")
            current_version = self._version(record.username)
            if record.state != "active":
                self._versions[record.username] = current_version + 1
                raise RefreshReuseDetected("Refresh token reutilizado")
            if record.session_version != current_version:
                raise InvalidRefreshToken("Sesión revocada")
            if len(self._records) >= self.max_entries:
                raise SessionCapacityExceeded("Refresh-session store is at capacity")

            record.state = "used"
            new_token = _new_refresh_token()
            expires_at = now + ttl_seconds
            self._records[_digest(new_token)] = _RefreshRecord(
                username=record.username,
                role=record.role,
                expires_at=expires_at,
                session_version=current_version,
                family_id=record.family_id,
            )
            return RefreshResult(
                record.username,
                record.role,
                new_token,
                ttl_seconds,
                current_version,
            )

    def current_version(self, username: str) -> int:
        with self._lock:
            return self._version(username)

    def logout_all(self, username: str) -> int:
        with self._lock:
            version = self._version(username) + 1
            self._versions[username] = version
            for record in self._records.values():
                if record.username == username and record.state == "active":
                    record.state = "used"
            return version

    def clear(self) -> None:
        with self._lock:
            self._records.clear()
            self._versions.clear()


class RedisSessionBackend:
    """Shared session backend for multi-worker deployments."""

    def __init__(
        self, client: Any, namespace: str = "anti-grooming:sessions:v1"
    ) -> None:
        self.client = client
        self.namespace = namespace

    def _refresh_key(self, digest: str) -> str:
        return f"{self.namespace}:refresh:{digest}"

    def _version_key(self, username: str) -> str:
        user_hash = hashlib.sha256(username.encode("utf-8")).hexdigest()
        return f"{self.namespace}:version:{user_hash}"

    def current_version(self, username: str) -> int:
        raw = self.client.get(self._version_key(username))
        return int(raw or 0)

    def issue(self, username: str, role: str, ttl_seconds: int) -> RefreshResult:
        token = _new_refresh_token()
        version = self.current_version(username)
        expires_at = time.time() + ttl_seconds
        payload = {
            "username": username,
            "role": role,
            "expires_at": expires_at,
            "session_version": version,
            "family_id": str(uuid.uuid4()),
            "state": "active",
        }
        key = self._refresh_key(_digest(token))
        created = self.client.set(
            key,
            json.dumps(payload, separators=(",", ":")),
            ex=ttl_seconds,
            nx=True,
        )
        if not created:
            raise SessionBackendUnavailable("No se pudo crear la sesión")
        return RefreshResult(username, role, token, ttl_seconds, version)

    def rotate(self, refresh_token: str, ttl_seconds: int) -> RefreshResult:
        try:
            import redis  # type: ignore[import-not-found]
        except ImportError as exc:
            raise SessionBackendUnavailable("Redis no disponible") from exc

        old_key = self._refresh_key(_digest(refresh_token))
        while True:
            new_token = _new_refresh_token()
            new_key = self._refresh_key(_digest(new_token))
            try:
                with self.client.pipeline() as pipe:
                    pipe.watch(old_key)
                    raw = pipe.get(old_key)
                    if raw is None:
                        raise InvalidRefreshToken("Refresh token inválido")
                    record = json.loads(raw)
                    username = str(record["username"])
                    version_key = self._version_key(username)
                    pipe.watch(version_key)
                    current_version = int(pipe.get(version_key) or 0)
                    expires_at = float(record["expires_at"])

                    if expires_at <= time.time():
                        raise InvalidRefreshToken("Refresh token expirado")
                    if record.get("state") != "active":
                        pipe.unwatch()
                        self.client.incr(version_key)
                        raise RefreshReuseDetected("Refresh token reutilizado")
                    if int(record["session_version"]) != current_version:
                        raise InvalidRefreshToken("Sesión revocada")

                    old_ttl = max(1, math.ceil(expires_at - time.time()))
                    new_expires_at = time.time() + ttl_seconds
                    record["state"] = "used"
                    new_record = {
                        "username": username,
                        "role": str(record["role"]),
                        "expires_at": new_expires_at,
                        "session_version": current_version,
                        "family_id": str(record["family_id"]),
                        "state": "active",
                    }
                    pipe.multi()
                    pipe.set(
                        old_key,
                        json.dumps(record, separators=(",", ":")),
                        ex=old_ttl,
                    )
                    pipe.set(
                        new_key,
                        json.dumps(new_record, separators=(",", ":")),
                        ex=ttl_seconds,
                        nx=True,
                    )
                    results = pipe.execute()
                    if results[-1] is not True:
                        continue
                    return RefreshResult(
                        username,
                        str(record["role"]),
                        new_token,
                        ttl_seconds,
                        current_version,
                    )
            except redis.WatchError:
                continue
            except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
                raise SessionBackendUnavailable("Estado de sesión corrupto") from exc

    def logout_all(self, username: str) -> int:
        return int(self.client.incr(self._version_key(username)))


class SessionStore:
    """Select a safe session backend and expose refresh/session operations."""

    def __init__(self, max_memory_entries: int = 20_000) -> None:
        self._memory = MemorySessionBackend(max_memory_entries)
        self._redis_backend: RedisSessionBackend | None = None
        self._redis_url: str | None = None

    def validate_configuration(self) -> None:
        mode = os.getenv("SESSION_BACKEND", "memory").strip().lower()
        if mode not in {"memory", "redis"}:
            raise RuntimeError("SESSION_BACKEND debe ser 'memory' o 'redis'")
        if mode == "redis" and not os.getenv("REDIS_URL", "").strip():
            raise RuntimeError("REDIS_URL es obligatorio cuando SESSION_BACKEND=redis")
        self.refresh_ttl_seconds()

    def refresh_ttl_seconds(self) -> int:
        raw = os.getenv("REFRESH_TOKEN_DAYS", "7")
        try:
            days = int(raw)
        except ValueError as exc:
            raise RuntimeError("REFRESH_TOKEN_DAYS inválido") from exc
        if days < 1 or days > 30:
            raise RuntimeError("REFRESH_TOKEN_DAYS debe estar entre 1 y 30")
        return days * 24 * 60 * 60

    def _selected_backend(self) -> SessionBackend:
        mode = os.getenv("SESSION_BACKEND", "memory").strip().lower()
        if mode == "memory":
            return self._memory
        if mode != "redis":
            raise SessionBackendUnavailable("Backend de sesión no soportado")

        url = os.getenv("REDIS_URL", "").strip()
        if not url:
            raise SessionBackendUnavailable("REDIS_URL requerido para sesiones Redis")
        if self._redis_backend is None or self._redis_url != url:
            try:
                import redis  # type: ignore[import-not-found]

                client = redis.Redis.from_url(url, decode_responses=True)
            except (ImportError, ValueError) as exc:
                raise SessionBackendUnavailable("Redis no disponible") from exc
            self._redis_backend = RedisSessionBackend(client)
            self._redis_url = url
        return self._redis_backend

    def issue(self, username: str, role: str) -> RefreshResult:
        backend = self._selected_backend()
        try:
            return backend.issue(username, role, self.refresh_ttl_seconds())
        except (SessionCapacityExceeded, InvalidRefreshToken, RefreshReuseDetected):
            raise
        except Exception as exc:
            raise SessionBackendUnavailable("Backend de sesión no disponible") from exc

    def rotate(self, refresh_token: str) -> RefreshResult:
        backend = self._selected_backend()
        try:
            return backend.rotate(refresh_token, self.refresh_ttl_seconds())
        except (SessionCapacityExceeded, InvalidRefreshToken, RefreshReuseDetected):
            raise
        except Exception as exc:
            raise SessionBackendUnavailable("Backend de sesión no disponible") from exc

    def current_version(self, username: str) -> int:
        try:
            return self._selected_backend().current_version(username)
        except Exception as exc:
            raise SessionBackendUnavailable("Backend de sesión no disponible") from exc

    def logout_all(self, username: str) -> int:
        try:
            return self._selected_backend().logout_all(username)
        except Exception as exc:
            raise SessionBackendUnavailable("Backend de sesión no disponible") from exc

    def clear(self) -> None:
        self._memory.clear()
        self._redis_backend = None
        self._redis_url = None
