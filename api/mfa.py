"""TOTP MFA and one-time recovery-code verification."""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import os
import re
import struct
import threading
import time
from dataclasses import dataclass
from typing import Any, Protocol

from api.production_security import is_production
from api.redis_security import (
    RedisSecurityConfigurationError,
    create_redis_client,
    validate_redis_url,
)


class MFAConfigurationError(RuntimeError):
    """MFA configuration is missing or invalid."""


class MFABackendUnavailable(RuntimeError):
    """MFA replay/recovery state cannot be consulted safely."""


@dataclass(frozen=True)
class MFAConfig:
    secret: bytes
    recovery_code_hashes: tuple[str, ...]


class MFAStateBackend(Protocol):
    def consume_totp(self, username: str, counter: int) -> bool: ...

    def consume_recovery(self, username: str, code_hash: str) -> bool: ...


def _user_key(username: str) -> str:
    return hashlib.sha256(username.encode("utf-8")).hexdigest()


def _normalize_recovery_code(code: str) -> str:
    return re.sub(r"[-\s]", "", code).upper()


def recovery_code_hash(code: str) -> str:
    normalized = _normalize_recovery_code(code)
    if not re.fullmatch(r"[A-Z0-9]{12,64}", normalized):
        raise ValueError("Código de recuperación inválido")
    return hashlib.sha256(normalized.encode("ascii")).hexdigest()


def _decode_totp_secret(raw: str) -> bytes:
    normalized = re.sub(r"\s", "", raw).upper()
    if not normalized or not re.fullmatch(r"[A-Z2-7]+", normalized):
        raise MFAConfigurationError("Secreto TOTP inválido")
    padding = "=" * ((8 - len(normalized) % 8) % 8)
    try:
        secret = base64.b32decode(normalized + padding, casefold=True)
    except (binascii.Error, ValueError) as exc:
        raise MFAConfigurationError("Secreto TOTP inválido") from exc
    if len(secret) < 20:
        raise MFAConfigurationError("El secreto TOTP debe tener al menos 160 bits")
    return secret


def _required_roles() -> set[str]:
    raw = os.getenv(
        "MFA_REQUIRED_ROLES_JSON",
        '["admin","supervisor","auditor"]',
    )
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise MFAConfigurationError("MFA_REQUIRED_ROLES_JSON inválido") from exc
    allowed = {"admin", "analyst", "supervisor", "auditor"}
    if (
        not isinstance(parsed, list)
        or not all(isinstance(role, str) for role in parsed)
        or any(role not in allowed for role in parsed)
    ):
        raise MFAConfigurationError("MFA_REQUIRED_ROLES_JSON inválido")
    return set(parsed)


def load_mfa_configs() -> dict[str, MFAConfig]:
    raw = os.getenv("MFA_USERS_JSON", "{}")
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise MFAConfigurationError("MFA_USERS_JSON inválido") from exc
    if not isinstance(parsed, dict):
        raise MFAConfigurationError("MFA_USERS_JSON inválido")

    configs: dict[str, MFAConfig] = {}
    for raw_username, raw_config in parsed.items():
        username = str(raw_username).strip().lower()
        if not username or not isinstance(raw_config, dict):
            raise MFAConfigurationError("MFA_USERS_JSON inválido")

        secret_raw = raw_config.get("totp_secret")
        recovery_raw = raw_config.get("recovery_code_hashes")
        if not isinstance(secret_raw, str) or not isinstance(recovery_raw, list):
            raise MFAConfigurationError("MFA_USERS_JSON inválido")
        if len(recovery_raw) < 4 or not all(
            isinstance(value, str) for value in recovery_raw
        ):
            raise MFAConfigurationError(
                "Cada usuario MFA necesita al menos 4 códigos de recuperación"
            )
        recovery_hashes = tuple(value.lower() for value in recovery_raw)
        if len(set(recovery_hashes)) != len(recovery_hashes) or any(
            not re.fullmatch(r"[0-9a-f]{64}", value) for value in recovery_hashes
        ):
            raise MFAConfigurationError("Hashes de recuperación inválidos")

        configs[username] = MFAConfig(
            secret=_decode_totp_secret(secret_raw),
            recovery_code_hashes=recovery_hashes,
        )
    return configs


class MemoryMFAStateBackend:
    """Single-process replay protection and recovery-code consumption."""

    def __init__(self) -> None:
        self._last_totp_counter: dict[str, int] = {}
        self._used_recovery: set[tuple[str, str]] = set()
        self._lock = threading.Lock()

    def consume_totp(self, username: str, counter: int) -> bool:
        with self._lock:
            last = self._last_totp_counter.get(username, -1)
            if counter <= last:
                return False
            self._last_totp_counter[username] = counter
            return True

    def consume_recovery(self, username: str, code_hash: str) -> bool:
        key = (username, code_hash)
        with self._lock:
            if key in self._used_recovery:
                return False
            self._used_recovery.add(key)
            return True

    def clear(self) -> None:
        with self._lock:
            self._last_totp_counter.clear()
            self._used_recovery.clear()


class RedisMFAStateBackend:
    """Shared replay protection for multi-worker deployments."""

    _TOTP_SCRIPT = """
local current = redis.call('GET', KEYS[1])
if current and tonumber(current) >= tonumber(ARGV[1]) then
  return 0
end
redis.call('SET', KEYS[1], ARGV[1])
return 1
"""

    def __init__(self, client: Any, namespace: str = "anti-grooming:mfa:v1") -> None:
        self.client = client
        self.namespace = namespace

    def _totp_key(self, username: str) -> str:
        return f"{self.namespace}:totp:{_user_key(username)}"

    def _recovery_key(self, username: str) -> str:
        return f"{self.namespace}:recovery:{_user_key(username)}"

    def consume_totp(self, username: str, counter: int) -> bool:
        result = self.client.eval(
            self._TOTP_SCRIPT,
            1,
            self._totp_key(username),
            counter,
        )
        return bool(result)

    def consume_recovery(self, username: str, code_hash: str) -> bool:
        return bool(self.client.sadd(self._recovery_key(username), code_hash))


class MFAStateStore:
    """Select memory or Redis replay state and fail closed on backend errors."""

    def __init__(self) -> None:
        self._memory = MemoryMFAStateBackend()
        self._redis_backend: RedisMFAStateBackend | None = None
        self._redis_url: str | None = None

    def validate_configuration(self) -> None:
        mode = self._mode()
        if mode not in {"memory", "redis"}:
            raise MFAConfigurationError("MFA_STATE_BACKEND debe ser 'memory' o 'redis'")
        if mode == "redis":
            url = os.getenv("REDIS_URL", "").strip()
            if not url:
                raise MFAConfigurationError(
                    "REDIS_URL es obligatorio cuando MFA_STATE_BACKEND=redis"
                )
            try:
                validate_redis_url(url, production=is_production())
            except RedisSecurityConfigurationError as exc:
                raise MFAConfigurationError("REDIS_URL insegura o inválida") from exc

    def _mode(self) -> str:
        return (
            os.getenv(
                "MFA_STATE_BACKEND",
                os.getenv("SESSION_BACKEND", "memory"),
            )
            .strip()
            .lower()
        )

    def _selected_backend(self) -> MFAStateBackend:
        mode = self._mode()
        if mode == "memory":
            return self._memory
        if mode != "redis":
            raise MFABackendUnavailable("Backend MFA no soportado")

        url = os.getenv("REDIS_URL", "").strip()
        if not url:
            raise MFABackendUnavailable("REDIS_URL requerido para MFA Redis")
        if self._redis_backend is None or self._redis_url != url:
            try:
                client = create_redis_client(url, production=is_production())
            except RedisSecurityConfigurationError as exc:
                raise MFABackendUnavailable("Redis MFA no disponible") from exc
            self._redis_backend = RedisMFAStateBackend(client)
            self._redis_url = url
        return self._redis_backend

    def consume_totp(self, username: str, counter: int) -> bool:
        try:
            return self._selected_backend().consume_totp(username, counter)
        except Exception as exc:
            if isinstance(exc, MFABackendUnavailable):
                raise
            raise MFABackendUnavailable("Estado MFA no disponible") from exc

    def consume_recovery(self, username: str, code_hash: str) -> bool:
        try:
            return self._selected_backend().consume_recovery(username, code_hash)
        except Exception as exc:
            if isinstance(exc, MFABackendUnavailable):
                raise
            raise MFABackendUnavailable("Estado MFA no disponible") from exc

    def clear(self) -> None:
        self._memory.clear()
        self._redis_backend = None
        self._redis_url = None


MFA_STATE = MFAStateStore()


def validate_mfa_configuration(
    users: dict[str, tuple[str, bool]],
) -> None:
    """Validate MFA policy against configured users at startup."""

    MFA_STATE.validate_configuration()
    required = _required_roles()
    configs = load_mfa_configs()

    unknown_users = set(configs) - set(users)
    if unknown_users:
        raise MFAConfigurationError("MFA configurado para usuario inexistente")

    missing = [
        username
        for username, (role, disabled) in users.items()
        if not disabled and role in required and username not in configs
    ]
    if missing:
        raise MFAConfigurationError(
            "MFA obligatorio no configurado para roles sensibles"
        )


def _totp(secret: bytes, counter: int, digits: int = 6) -> str:
    digest = hmac.new(
        secret,
        struct.pack(">Q", counter),
        hashlib.sha1,
    ).digest()
    offset = digest[-1] & 0x0F
    value = struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF
    return str(value % (10**digits)).zfill(digits)


def totp_code(secret: bytes, at_time: float | None = None) -> str:
    moment = time.time() if at_time is None else at_time
    return _totp(secret, int(moment // 30))


def is_mfa_required(username: str, role: str) -> bool:
    configs = load_mfa_configs()
    return role in _required_roles() or username.strip().lower() in configs


def verify_mfa(username: str, role: str, code: str | None) -> bool:
    normalized_username = username.strip().lower()
    configs = load_mfa_configs()
    required = role in _required_roles() or normalized_username in configs
    if not required:
        return True
    config = configs.get(normalized_username)
    if config is None or code is None:
        return False

    candidate = code.strip()
    if re.fullmatch(r"\d{6}", candidate):
        current = int(time.time() // 30)
        matched_counter: int | None = None
        for counter in (current, current - 1, current + 1):
            if hmac.compare_digest(candidate, _totp(config.secret, counter)):
                matched_counter = counter
                break
        if matched_counter is None:
            return False
        return MFA_STATE.consume_totp(normalized_username, matched_counter)

    try:
        digest = recovery_code_hash(candidate)
    except (UnicodeError, ValueError):
        return False
    matched = any(
        hmac.compare_digest(digest, expected)
        for expected in config.recovery_code_hashes
    )
    if not matched:
        return False
    return MFA_STATE.consume_recovery(normalized_username, digest)
