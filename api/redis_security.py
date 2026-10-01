"""Central Redis connection security policy."""

from __future__ import annotations

import ipaddress
from urllib.parse import parse_qs, urlparse


class RedisSecurityConfigurationError(RuntimeError):
    """Redis URL or TLS/authentication settings are unsafe."""


def _is_loopback_host(hostname: str) -> bool:
    lowered = hostname.strip().lower().rstrip(".")
    if lowered == "localhost":
        return True
    try:
        return ipaddress.ip_address(lowered).is_loopback
    except ValueError:
        return False


def validate_redis_url(raw_url: str, *, production: bool = False) -> None:
    """Validate Redis transport and authentication without exposing the URL."""

    try:
        parsed = urlparse(raw_url)
    except ValueError as exc:
        raise RedisSecurityConfigurationError("REDIS_URL inválida") from exc

    if parsed.scheme not in {"redis", "rediss"} or not parsed.hostname:
        raise RedisSecurityConfigurationError("REDIS_URL inválida")
    if parsed.fragment:
        raise RedisSecurityConfigurationError("REDIS_URL no admite fragmentos")

    query = parse_qs(parsed.query, keep_blank_values=True)
    cert_reqs = query.get("ssl_cert_reqs", ["required"])[-1].strip().lower()
    check_hostname = query.get("ssl_check_hostname", ["true"])[-1].strip().lower()

    if cert_reqs not in {"required", "cert_required"}:
        raise RedisSecurityConfigurationError(
            "Redis TLS debe verificar el certificado del servidor"
        )
    if check_hostname not in {"1", "true", "yes", "on"}:
        raise RedisSecurityConfigurationError(
            "Redis TLS debe verificar el hostname del certificado"
        )

    if not production:
        return

    if parsed.scheme != "rediss":
        raise RedisSecurityConfigurationError(
            "APP_ENV=production requiere Redis sobre TLS (rediss://)"
        )
    if _is_loopback_host(parsed.hostname):
        raise RedisSecurityConfigurationError(
            "APP_ENV=production no admite Redis loopback/local"
        )

    has_password = bool(parsed.password)
    has_client_cert = bool(query.get("ssl_certfile", [""])[-1].strip())
    has_client_key = bool(query.get("ssl_keyfile", [""])[-1].strip())
    if has_client_cert != has_client_key:
        raise RedisSecurityConfigurationError(
            "Redis mTLS requiere certificado y clave de cliente"
        )
    if not has_password and not (has_client_cert and has_client_key):
        raise RedisSecurityConfigurationError(
            "Redis de producción requiere autenticación por password/token o mTLS"
        )


def create_redis_client(raw_url: str, *, production: bool = False):
    """Create a redis-py client after applying the shared security policy."""

    validate_redis_url(raw_url, production=production)
    try:
        import redis  # type: ignore[import-not-found]

        return redis.Redis.from_url(
            raw_url,
            decode_responses=True,
            socket_connect_timeout=5,
            socket_timeout=5,
            health_check_interval=30,
        )
    except (ImportError, ValueError) as exc:
        raise RedisSecurityConfigurationError(
            "No se pudo configurar el cliente Redis"
        ) from exc
