import pytest

from api.production_security import (
    ProductionSecurityError,
    app_environment,
    validate_production_security,
)


def configure_valid_production(monkeypatch):
    monkeypatch.setenv("APP_ENV", "production")
    for name in (
        "RATE_LIMIT_BACKEND",
        "LOGIN_RATE_LIMIT_BACKEND",
        "TOKEN_REVOCATION_BACKEND",
        "SESSION_BACKEND",
        "MFA_STATE_BACKEND",
    ):
        monkeypatch.setenv(name, "redis")
    monkeypatch.setenv(
        "REDIS_URL",
        "rediss://redis.example.org:6380/0"
        "?ssl_cert_reqs=required&ssl_check_hostname=true"
        "&ssl_certfile=/run/secrets/redis-client.crt"
        "&ssl_keyfile=/run/secrets/redis-client.key",
    )
    monkeypatch.setenv("ALLOWED_HOSTS_JSON", '["api.example.org"]')
    monkeypatch.setenv("ALLOWED_ORIGINS_JSON", '["https://app.example.org"]')
    monkeypatch.setenv(
        "MFA_REQUIRED_ROLES_JSON",
        '["admin","supervisor","auditor"]',
    )
    monkeypatch.setenv(
        "AUDIT_STATE_DB",
        "/var/lib/anti-grooming-audit/checkpoint.sqlite",
    )
    monkeypatch.setenv(
        "SECURITY_AUDIT_DIR",
        "/var/log/anti-grooming-security",
    )
    monkeypatch.setenv(
        "SECURITY_AUDIT_STATE_DB",
        "/var/lib/anti-grooming-security/checkpoint.sqlite",
    )
    monkeypatch.delenv("DATABASE_URL", raising=False)


def test_valid_production_profile_passes(monkeypatch):
    configure_valid_production(monkeypatch)
    validate_production_security()


@pytest.mark.parametrize(
    "backend",
    [
        "RATE_LIMIT_BACKEND",
        "LOGIN_RATE_LIMIT_BACKEND",
        "TOKEN_REVOCATION_BACKEND",
        "SESSION_BACKEND",
        "MFA_STATE_BACKEND",
    ],
)
def test_production_rejects_memory_critical_backends(monkeypatch, backend):
    configure_valid_production(monkeypatch)
    monkeypatch.setenv(backend, "memory")

    with pytest.raises(ProductionSecurityError, match="Redis"):
        validate_production_security()


def test_production_rejects_plaintext_redis(monkeypatch):
    configure_valid_production(monkeypatch)
    monkeypatch.setenv(
        "REDIS_URL",
        "redis://redis.example.org:6379/0"
        "?ssl_certfile=/run/secrets/redis-client.crt"
        "&ssl_keyfile=/run/secrets/redis-client.key",
    )

    with pytest.raises(ProductionSecurityError, match="Redis"):
        validate_production_security()


@pytest.mark.parametrize(
    ("name", "value"),
    [
        ("ALLOWED_HOSTS_JSON", '["*"]'),
        ("ALLOWED_HOSTS_JSON", '["localhost"]'),
        ("ALLOWED_HOSTS_JSON", '["https://api.example.org"]'),
        ("ALLOWED_ORIGINS_JSON", '["http://app.example.org"]'),
        ("ALLOWED_ORIGINS_JSON", '["https://localhost"]'),
        ("ALLOWED_ORIGINS_JSON", '["https://app.example.org/path"]'),
    ],
)
def test_production_rejects_unsafe_http_perimeter(monkeypatch, name, value):
    configure_valid_production(monkeypatch)
    monkeypatch.setenv(name, value)

    with pytest.raises(ProductionSecurityError):
        validate_production_security()


def test_production_requires_mfa_for_sensitive_roles(monkeypatch):
    configure_valid_production(monkeypatch)
    monkeypatch.setenv("MFA_REQUIRED_ROLES_JSON", '["admin"]')

    with pytest.raises(ProductionSecurityError, match="MFA"):
        validate_production_security()


def test_production_rejects_shared_audit_checkpoints(monkeypatch):
    configure_valid_production(monkeypatch)
    monkeypatch.setenv(
        "SECURITY_AUDIT_STATE_DB",
        "/var/lib/anti-grooming-audit/checkpoint.sqlite",
    )

    with pytest.raises(ProductionSecurityError, match="checkpoints"):
        validate_production_security()


def test_production_database_requires_verify_full_tls(monkeypatch):
    configure_valid_production(monkeypatch)
    monkeypatch.setenv(
        "DATABASE_URL",
        "postgresql+psycopg://db.example.org/app?sslmode=require",
    )

    with pytest.raises(ProductionSecurityError, match="verify-full"):
        validate_production_security()


def test_production_accepts_postgres_verify_full(monkeypatch):
    configure_valid_production(monkeypatch)
    monkeypatch.setenv(
        "DATABASE_URL",
        "postgresql+psycopg://db.example.org/app?sslmode=verify-full",
    )

    validate_production_security()


def test_invalid_app_environment_is_rejected(monkeypatch):
    monkeypatch.setenv("APP_ENV", "prod-ish")

    with pytest.raises(ProductionSecurityError):
        app_environment()
