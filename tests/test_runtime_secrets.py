import os

import pytest

from api.runtime_secrets import RuntimeSecretError, load_runtime_secrets


def test_runtime_secret_file_populates_target_environment(tmp_path, monkeypatch):
    secret = tmp_path / "jwt"
    secret.write_text(
        "runtime-secret-value\n", encoding="utf-8"
    )  # pragma: allowlist secret
    monkeypatch.delenv("JWT_SECRET", raising=False)
    monkeypatch.setenv("JWT_SECRET_FILE", str(secret))

    load_runtime_secrets()

    assert (
        os.environ["JWT_SECRET"] == "runtime-secret-value"
    )  # pragma: allowlist secret


def test_runtime_secret_rejects_direct_and_file_ambiguity(tmp_path, monkeypatch):
    secret = tmp_path / "jwt"
    secret.write_text("file-secret", encoding="utf-8")  # pragma: allowlist secret
    monkeypatch.setenv(
        "JWT_SECRET",
        "direct-secret",  # pragma: allowlist secret
    )
    monkeypatch.setenv("JWT_SECRET_FILE", str(secret))

    with pytest.raises(RuntimeSecretError):
        load_runtime_secrets()


def test_runtime_secret_rejects_missing_file(monkeypatch, tmp_path):
    monkeypatch.delenv("REDIS_URL", raising=False)
    monkeypatch.setenv("REDIS_URL_FILE", str(tmp_path / "missing"))

    with pytest.raises(RuntimeSecretError):
        load_runtime_secrets()


def test_runtime_secret_rejects_empty_file(tmp_path, monkeypatch):
    secret = tmp_path / "audit-key"
    secret.write_text("\n", encoding="utf-8")
    monkeypatch.delenv("AUDIT_HMAC_KEY", raising=False)
    monkeypatch.setenv("AUDIT_HMAC_KEY_FILE", str(secret))

    with pytest.raises(RuntimeSecretError):
        load_runtime_secrets()


def test_runtime_secret_rejects_oversized_file(tmp_path, monkeypatch):
    secret = tmp_path / "users"
    secret.write_text("x" * 65_537, encoding="utf-8")
    monkeypatch.delenv("AUTH_USERS_JSON", raising=False)
    monkeypatch.setenv("AUTH_USERS_JSON_FILE", str(secret))

    with pytest.raises(RuntimeSecretError):
        load_runtime_secrets()
