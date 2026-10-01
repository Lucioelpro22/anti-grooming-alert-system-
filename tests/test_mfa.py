import base64
import json
import os
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from pwdlib import PasswordHash

from api import report_generator, security_audit
from api.auth import LOGIN_LIMITER, SESSIONS, TOKEN_REVOCATIONS
from api.mfa import (
    MFA_STATE,
    RECOVERY_PASSWORD_HASH,
    MFAConfigurationError,
    MFAStateStore,
    RedisMFAStateBackend,
    load_mfa_configs,
    recovery_code_hash,
    totp_code,
    validate_mfa_configuration,
    verify_mfa,
)
from api.security import API_LIMITER, REPORT_LIMITER

PASSWORD = "correct-horse-battery-staple"  # pragma: allowlist secret
TOTP_SECRET_BYTES = b"m" * 20
TOTP_SECRET = base64.b32encode(TOTP_SECRET_BYTES).decode("ascii").rstrip("=")
RECOVERY_CODES = (
    "ABCD-EF01-2345-6789-ABCD-EF01",
    "BCDE-F012-3456-789A-BCDE-F012",
    "CDEF-0123-4567-89AB-CDEF-0123",
    "DEF0-1234-5678-9ABC-DEF0-1234",
)
EVIDENCE_KEY = base64.urlsafe_b64encode(b"e" * 32).decode("ascii")
AUDIT_KEY = base64.urlsafe_b64encode(b"a" * 32).decode("ascii")
PSEUDONYM_KEY = base64.urlsafe_b64encode(b"p" * 32).decode("ascii")


@pytest.fixture()
def mfa_client(monkeypatch, tmp_path):
    users = [
        {
            "username": "admin",
            "password_hash": PasswordHash.recommended().hash(PASSWORD),
            "role": "admin",
        },
        {
            "username": "analyst",
            "password_hash": PasswordHash.recommended().hash(PASSWORD),
            "role": "analyst",
        },
    ]
    mfa_users = {
        "admin": {
            "totp_secret": TOTP_SECRET,
            "recovery_code_hashes": [
                recovery_code_hash(code) for code in RECOVERY_CODES
            ],
        }
    }

    monkeypatch.setenv("JWT_SECRET", "test-secret-that-is-longer-than-32-bytes")
    monkeypatch.setenv("AUTH_USERS_JSON", json.dumps(users))
    monkeypatch.setenv("MFA_REQUIRED_ROLES_JSON", '["admin"]')
    monkeypatch.setenv("MFA_USERS_JSON", json.dumps(mfa_users))
    monkeypatch.setenv("MFA_STATE_BACKEND", "memory")
    monkeypatch.setenv("LOGIN_RATE_LIMIT_BACKEND", "memory")
    monkeypatch.setenv("LOGIN_RATE_LIMIT_ATTEMPTS", "5")
    monkeypatch.setenv("LOGIN_RATE_LIMIT_WINDOW_SECONDS", "300")
    monkeypatch.setenv("SESSION_BACKEND", "memory")
    monkeypatch.setenv("TOKEN_REVOCATION_BACKEND", "memory")
    monkeypatch.setenv("REFRESH_TOKEN_DAYS", "7")
    monkeypatch.setenv("EVIDENCE_ENCRYPTION_KEY", EVIDENCE_KEY)
    monkeypatch.setenv("AUDIT_HMAC_KEY", AUDIT_KEY)
    monkeypatch.setenv("PSEUDONYMIZATION_HMAC_KEY", PSEUDONYM_KEY)
    monkeypatch.setenv("ALLOWED_ORIGINS_JSON", "[]")
    monkeypatch.setenv("ALLOWED_HOSTS_JSON", '["testserver"]')
    monkeypatch.setenv("MAX_REQUEST_BODY_BYTES", "65536")
    monkeypatch.setenv("API_RATE_LIMIT", "1000")
    monkeypatch.setenv("API_RATE_WINDOW_SECONDS", "60")
    monkeypatch.delenv("REDIS_URL", raising=False)
    monkeypatch.setattr(report_generator, "CARPETA_INFORMES", tmp_path)
    monkeypatch.setenv(
        "AUDIT_STATE_DB",
        str(tmp_path.parent / (tmp_path.name + "-state") / "audit.sqlite"),
    )
    monkeypatch.setenv(
        "SECURITY_AUDIT_DIR",
        str(tmp_path.parent / (tmp_path.name + "-security-audit")),
    )
    monkeypatch.setenv(
        "SECURITY_AUDIT_STATE_DB",
        str(
            tmp_path.parent / (tmp_path.name + "-security-state") / "checkpoint.sqlite"
        ),
    )

    REPORT_LIMITER.clear()
    LOGIN_LIMITER.clear()
    API_LIMITER.clear()
    TOKEN_REVOCATIONS.clear()
    SESSIONS.clear()
    MFA_STATE.clear()

    from api.main import app

    with TestClient(app) as test_client:
        yield test_client

    API_LIMITER.clear()
    TOKEN_REVOCATIONS.clear()
    SESSIONS.clear()
    MFA_STATE.clear()


def login(client, username, *, mfa_code=None):
    data = {"username": username, "password": PASSWORD}
    if mfa_code is not None:
        data["mfa_code"] = mfa_code
    return client.post("/token", data=data)


def test_sensitive_role_requires_mfa(mfa_client):
    response = login(mfa_client, "admin")
    assert response.status_code == 401
    assert response.json()["detail"] == "Usuario, contraseña o MFA inválidos"


def test_valid_totp_allows_login_and_same_code_cannot_be_replayed(mfa_client):
    code = totp_code(TOTP_SECRET_BYTES)

    first = login(mfa_client, "admin", mfa_code=code)
    assert first.status_code == 200

    replay = login(mfa_client, "admin", mfa_code=code)
    assert replay.status_code == 401


def test_mfa_code_and_username_never_appear_in_security_log(mfa_client):
    code = totp_code(TOTP_SECRET_BYTES)
    response = login(mfa_client, "admin", mfa_code=code)
    assert response.status_code == 200

    path = Path(os.environ["SECURITY_AUDIT_DIR"]) / security_audit.LOG_FILENAME
    raw = path.read_text(encoding="utf-8")
    assert code not in raw
    assert PASSWORD not in raw

    events = security_audit.read_security_events()
    assert events[-1]["event"] == "login_success"
    assert events[-1]["subject_ref"]


def test_recovery_code_is_one_time(mfa_client):
    first = login(mfa_client, "admin", mfa_code=RECOVERY_CODES[0])
    assert first.status_code == 200

    replay = login(mfa_client, "admin", mfa_code=RECOVERY_CODES[0])
    assert replay.status_code == 401


def test_non_required_role_can_login_without_mfa(mfa_client):
    response = login(mfa_client, "analyst")
    assert response.status_code == 200


def test_bad_mfa_code_does_not_issue_tokens(mfa_client):
    response = login(mfa_client, "admin", mfa_code="000000")
    assert response.status_code == 401
    assert "access_token" not in response.text
    assert "refresh_token" not in response.text


def test_repeated_mfa_failures_share_login_rate_limit(mfa_client):
    for _ in range(5):
        response = login(mfa_client, "admin", mfa_code="000000")
        assert response.status_code == 401

    blocked = login(mfa_client, "admin", mfa_code="000000")
    assert blocked.status_code == 429
    assert int(blocked.headers["retry-after"]) >= 1


def test_mfa_configuration_requires_active_sensitive_users():
    with pytest.raises(MFAConfigurationError):
        validate_mfa_configuration({"admin": ("admin", False)})


def test_disabled_sensitive_user_does_not_require_mfa(monkeypatch):
    monkeypatch.setenv("MFA_REQUIRED_ROLES_JSON", '["admin"]')
    monkeypatch.setenv("MFA_USERS_JSON", "{}")
    monkeypatch.setenv("MFA_STATE_BACKEND", "memory")

    validate_mfa_configuration({"admin": ("admin", True)})


def test_malformed_recovery_code_is_rejected_without_error(monkeypatch):
    monkeypatch.setenv(
        "MFA_USERS_JSON",
        json.dumps(
            {
                "admin": {
                    "totp_secret": TOTP_SECRET,
                    "recovery_code_hashes": [
                        recovery_code_hash(code) for code in RECOVERY_CODES
                    ],
                }
            }
        ),
    )
    monkeypatch.setenv("MFA_REQUIRED_ROLES_JSON", '["admin"]')
    monkeypatch.setenv("MFA_STATE_BACKEND", "memory")
    MFA_STATE.clear()

    assert verify_mfa("admin", "admin", "🔥-invalid") is False


def test_mfa_redis_mode_requires_redis_url(monkeypatch):
    monkeypatch.setenv("MFA_STATE_BACKEND", "redis")
    monkeypatch.delenv("REDIS_URL", raising=False)

    with pytest.raises(MFAConfigurationError):
        MFAStateStore().validate_configuration()


def test_recovery_hash_is_salted_argon2id():
    first = recovery_code_hash(RECOVERY_CODES[0])
    second = recovery_code_hash(RECOVERY_CODES[0])
    assert first.startswith("$argon2id$v=19$m=65536,t=3,p=4$")
    assert first != second
    assert RECOVERY_PASSWORD_HASH.verify(RECOVERY_CODES[0].replace("-", ""), first)


def set_recovery_configuration(monkeypatch, hashes):
    monkeypatch.setenv(
        "MFA_USERS_JSON",
        json.dumps(
            {"admin": {"totp_secret": TOTP_SECRET, "recovery_code_hashes": hashes}}
        ),
    )
    monkeypatch.setenv("MFA_REQUIRED_ROLES_JSON", '["admin"]')
    monkeypatch.setenv("MFA_STATE_BACKEND", "memory")
    MFA_STATE.clear()


@pytest.mark.parametrize("hash_value", ["a" * 64, "$argon2id$invalid"])
def test_legacy_or_malformed_recovery_hash_rejected(monkeypatch, hash_value):
    hashes = [recovery_code_hash(code) for code in RECOVERY_CODES]
    hashes[0] = hash_value
    set_recovery_configuration(monkeypatch, hashes)
    with pytest.raises(MFAConfigurationError):
        load_mfa_configs()


def test_recovery_hash_resource_limits_rejected(monkeypatch):
    hashes = [recovery_code_hash(code) for code in RECOVERY_CODES]
    hashes[0] = hashes[0].replace("m=65536", "m=999999999")
    set_recovery_configuration(monkeypatch, hashes)
    with pytest.raises(MFAConfigurationError):
        load_mfa_configs()


def test_salted_rehash_or_duplicate_cannot_reenable_consumed_code(monkeypatch):
    hashes = [recovery_code_hash(code) for code in RECOVERY_CODES]
    hashes.append(recovery_code_hash(RECOVERY_CODES[0]))
    set_recovery_configuration(monkeypatch, hashes)
    assert verify_mfa("admin", "admin", RECOVERY_CODES[0].lower().replace("-", " "))
    assert not verify_mfa("admin", "admin", RECOVERY_CODES[0])
    hashes[0] = recovery_code_hash(RECOVERY_CODES[0])
    monkeypatch.setenv(
        "MFA_USERS_JSON",
        json.dumps(
            {"admin": {"totp_secret": TOTP_SECRET, "recovery_code_hashes": hashes}}
        ),
    )
    assert not verify_mfa("admin", "admin", RECOVERY_CODES[0])


def test_recovery_consumption_shared_by_redis_workers(monkeypatch):
    class SharedRedis:
        def __init__(self):
            self.used = set()

        def sadd(self, key, member):
            item = (key, member)
            if item in self.used:
                return 0
            self.used.add(item)
            return 1

    hashes = [recovery_code_hash(code) for code in RECOVERY_CODES]
    set_recovery_configuration(monkeypatch, hashes)
    client = SharedRedis()
    workers = [RedisMFAStateBackend(client), RedisMFAStateBackend(client)]
    monkeypatch.setattr(MFA_STATE, "_selected_backend", lambda: workers[0])
    assert verify_mfa("admin", "admin", RECOVERY_CODES[0])
    monkeypatch.setattr(MFA_STATE, "_selected_backend", lambda: workers[1])
    assert not verify_mfa("admin", "admin", RECOVERY_CODES[0])
    assert RECOVERY_CODES[0] not in repr(client.used)
    assert hashes[0] not in repr(client.used)
