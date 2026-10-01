"""Fail-closed production deployment security profile."""

from __future__ import annotations

import ipaddress
import json
import os
import stat
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from api.redis_security import (
    RedisSecurityConfigurationError,
    validate_redis_url,
)

_ALLOWED_ENVIRONMENTS = {"development", "test", "staging", "production"}
_REQUIRED_REDIS_BACKENDS = {
    "RATE_LIMIT_BACKEND",
    "LOGIN_RATE_LIMIT_BACKEND",
    "TOKEN_REVOCATION_BACKEND",
    "SESSION_BACKEND",
    "MFA_STATE_BACKEND",
}
_SENSITIVE_MFA_ROLES = {"admin", "supervisor", "auditor"}


class ProductionSecurityError(RuntimeError):
    """Production security invariants are not satisfied."""


def app_environment() -> str:
    value = os.getenv("APP_ENV", "development").strip().lower()
    if value not in _ALLOWED_ENVIRONMENTS:
        raise ProductionSecurityError("APP_ENV inválido")
    return value


def is_production() -> bool:
    return app_environment() == "production"


def _json_string_list(name: str) -> list[str]:
    raw = os.getenv(name, "[]")
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ProductionSecurityError(f"{name} inválido") from exc
    if not isinstance(parsed, list) or not all(
        isinstance(value, str) and value.strip() for value in parsed
    ):
        raise ProductionSecurityError(f"{name} inválido")
    return [value.strip() for value in parsed]


def _is_loopback(host: str) -> bool:
    lowered = host.strip().lower().rstrip(".")
    if lowered == "localhost":
        return True
    try:
        return ipaddress.ip_address(lowered).is_loopback
    except ValueError:
        return False


def _validate_hosts() -> None:
    hosts = _json_string_list("ALLOWED_HOSTS_JSON")
    if not hosts:
        raise ProductionSecurityError(
            "ALLOWED_HOSTS_JSON no puede estar vacío en producción"
        )
    for host in hosts:
        normalized = host.lower()
        if "*" in normalized or _is_loopback(normalized):
            raise ProductionSecurityError(
                "ALLOWED_HOSTS_JSON contiene un host inseguro para producción"
            )


def _validate_origins() -> None:
    for origin in _json_string_list("ALLOWED_ORIGINS_JSON"):
        try:
            parsed = urlparse(origin)
        except ValueError as exc:
            raise ProductionSecurityError(
                "ALLOWED_ORIGINS_JSON contiene un origen inválido"
            ) from exc
        if (
            parsed.scheme != "https"
            or not parsed.hostname
            or parsed.username
            or parsed.password
            or parsed.query
            or parsed.fragment
            or _is_loopback(parsed.hostname)
        ):
            raise ProductionSecurityError(
                "Los orígenes de producción deben ser HTTPS exactos"
            )


def _validate_path(name: str, *, directory: bool = False) -> Path:
    raw = os.getenv(name, "").strip()
    if not raw:
        raise ProductionSecurityError(f"{name} es obligatorio en producción")
    path = Path(raw)
    if not path.is_absolute():
        raise ProductionSecurityError(f"{name} debe ser una ruta absoluta")

    protected = path if directory else path.parent
    if protected.exists():
        try:
            mode = stat.S_IMODE(protected.stat().st_mode)
        except OSError as exc:
            raise ProductionSecurityError(
                f"No se pudieron verificar permisos de {name}"
            ) from exc
        if mode & stat.S_IWOTH:
            raise ProductionSecurityError(
                f"{name} no puede depender de una ruta world-writable"
            )
    return path.resolve()


def _validate_storage_paths() -> None:
    audit_state = _validate_path("AUDIT_STATE_DB")
    security_dir = _validate_path("SECURITY_AUDIT_DIR", directory=True)
    security_state = _validate_path("SECURITY_AUDIT_STATE_DB")

    if security_state.is_relative_to(security_dir):
        raise ProductionSecurityError(
            "SECURITY_AUDIT_STATE_DB debe estar fuera de SECURITY_AUDIT_DIR"
        )
    if audit_state == security_state:
        raise ProductionSecurityError(
            "Los checkpoints de evidencia y seguridad deben estar separados"
        )


def _validate_database_url() -> None:
    raw = os.getenv("DATABASE_URL", "").strip()
    if not raw:
        return
    try:
        parsed = urlparse(raw)
    except ValueError as exc:
        raise ProductionSecurityError("DATABASE_URL inválida") from exc

    if parsed.scheme not in {"postgresql", "postgresql+psycopg"} or not parsed.hostname:
        raise ProductionSecurityError(
            "DATABASE_URL de producción debe usar PostgreSQL"
        )
    if _is_loopback(parsed.hostname):
        raise ProductionSecurityError(
            "DATABASE_URL de producción no admite loopback/local"
        )
    sslmode = parse_qs(parsed.query).get("sslmode", [""])[-1].lower()
    if sslmode != "verify-full":
        raise ProductionSecurityError(
            "PostgreSQL de producción requiere sslmode=verify-full"
        )


def _validate_mfa_policy() -> None:
    configured = set(_json_string_list("MFA_REQUIRED_ROLES_JSON"))
    if not _SENSITIVE_MFA_ROLES.issubset(configured):
        raise ProductionSecurityError(
            "Producción requiere MFA para admin, supervisor y auditor"
        )


def validate_production_security() -> None:
    """Validate environment-wide invariants before accepting traffic."""

    environment = app_environment()
    if environment != "production":
        return

    wrong_backends = [
        name
        for name in sorted(_REQUIRED_REDIS_BACKENDS)
        if os.getenv(name, "memory").strip().lower() != "redis"
    ]
    if wrong_backends:
        raise ProductionSecurityError(
            "Producción requiere Redis en todos los backends críticos: "
            + ", ".join(wrong_backends)
        )

    redis_url = os.getenv("REDIS_URL", "").strip()
    if not redis_url:
        raise ProductionSecurityError("REDIS_URL es obligatorio en producción")
    try:
        validate_redis_url(redis_url, production=True)
    except RedisSecurityConfigurationError as exc:
        raise ProductionSecurityError("Configuración Redis insegura") from exc

    _validate_hosts()
    _validate_origins()
    _validate_storage_paths()
    _validate_database_url()
    _validate_mfa_policy()
