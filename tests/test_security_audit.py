import base64
import json
import os
from pathlib import Path

import pytest
from fastapi import Request

from api import security_audit
from api.pseudonymization import pseudonymize


@pytest.fixture()
def audit_env(tmp_path, monkeypatch):
    monkeypatch.setenv(
        "AUDIT_HMAC_KEY",
        base64.urlsafe_b64encode(b"a" * 32).decode("ascii"),
    )
    monkeypatch.setenv(
        "PSEUDONYMIZATION_HMAC_KEY",
        base64.urlsafe_b64encode(b"p" * 32).decode("ascii"),
    )
    monkeypatch.setenv(
        "SECURITY_AUDIT_DIR",
        str(tmp_path / "security-log"),
    )
    monkeypatch.setenv(
        "SECURITY_AUDIT_STATE_DB",
        str(tmp_path / "security-state" / "checkpoint.sqlite"),
    )
    security_audit.verify_security_audit()
    return tmp_path


def _request() -> Request:
    return Request(
        {
            "type": "http",
            "method": "POST",
            "scheme": "https",
            "path": "/token",
            "raw_path": b"/token",
            "query_string": b"",
            "headers": [(b"user-agent", b"secret-test-agent/1.0")],
            "client": ("203.0.113.9", 12345),
            "server": ("testserver", 443),
            "state": {"request_id": "request-12345678"},
        }
    )


def test_security_event_is_pseudonymized_and_secret_free(audit_env):
    security_audit.record_security_event(
        "login_success",
        request=_request(),
        username="Sensitive.User",
        role="admin",
    )

    path = Path(os.environ["SECURITY_AUDIT_DIR"]) / security_audit.LOG_FILENAME
    raw = path.read_text(encoding="utf-8")

    assert "Sensitive.User" not in raw
    assert "sensitive.user" not in raw
    assert "203.0.113.9" not in raw
    assert "secret-test-agent/1.0" not in raw

    entries = security_audit.read_security_events()
    assert entries[0]["event"] == "login_success"
    assert entries[0]["severity"] == "info"
    assert entries[0]["alert"] is False
    assert entries[0]["subject_ref"]
    assert entries[0]["client_ip_ref"]
    assert entries[0]["user_agent_ref"]
    assert entries[0]["request_id"] == "request-12345678"


def test_warning_and_critical_events_are_alerts(audit_env):
    security_audit.record_security_event(
        "login_failed",
        username="alice",
        severity="warning",
        reason="credentials",
    )
    security_audit.record_security_event(
        "refresh_reuse_detected",
        username="alice",
        severity="critical",
        reason="replay",
    )

    entries = security_audit.read_security_events()
    assert [entry["alert"] for entry in entries] == [True, True]


def test_tampered_security_log_is_rejected(audit_env):
    security_audit.record_security_event("login_success", username="alice")
    path = Path(os.environ["SECURITY_AUDIT_DIR"]) / security_audit.LOG_FILENAME
    raw = path.read_text(encoding="utf-8")
    path.write_text(raw.replace("login_success", "login_failed"), encoding="utf-8")

    with pytest.raises(security_audit.SecurityAuditError):
        security_audit.verify_security_audit()


def test_truncated_security_log_is_rejected(audit_env):
    security_audit.record_security_event("login_success", username="alice")
    security_audit.record_security_event("logout", username="alice")
    path = Path(os.environ["SECURITY_AUDIT_DIR"]) / security_audit.LOG_FILENAME
    first_line = path.read_text(encoding="utf-8").splitlines()[0]
    path.write_text(first_line + "\n", encoding="utf-8")

    with pytest.raises(security_audit.SecurityAuditError):
        security_audit.verify_security_audit()


def test_missing_security_checkpoint_fails_closed(audit_env):
    security_audit.record_security_event("login_success", username="alice")
    Path(os.environ["SECURITY_AUDIT_STATE_DB"]).unlink()

    with pytest.raises(security_audit.SecurityAuditError):
        security_audit.verify_security_audit()


def test_checkpoint_cannot_live_inside_security_log_directory(audit_env, monkeypatch):
    log_dir = Path(os.environ["SECURITY_AUDIT_DIR"])
    monkeypatch.setenv(
        "SECURITY_AUDIT_STATE_DB",
        str(log_dir / "checkpoint.sqlite"),
    )

    with pytest.raises(security_audit.SecurityAuditError):
        security_audit.validate_security_audit_configuration()


def test_security_log_supports_audit_key_rotation(audit_env, monkeypatch):
    legacy = base64.urlsafe_b64encode(b"a" * 32).decode("ascii")
    rotated = base64.urlsafe_b64encode(b"b" * 32).decode("ascii")

    security_audit.record_security_event("login_success", username="alice")
    monkeypatch.setenv(
        "AUDIT_HMAC_KEYS_JSON",
        json.dumps({"legacy": legacy, "v2": rotated}),
    )
    monkeypatch.setenv("AUDIT_HMAC_CURRENT_KEY_ID", "v2")
    monkeypatch.delenv("AUDIT_HMAC_KEY", raising=False)
    security_audit.record_security_event("logout", username="alice")

    entries = security_audit.read_security_events()
    assert entries[0]["audit_key_id"] == "legacy"
    assert entries[1]["audit_key_id"] == "v2"


def test_security_audit_prefers_resolved_client_ip_over_proxy_peer(audit_env):
    request = _request()
    request.scope["state"]["client_ip"] = "198.51.100.77"

    security_audit.record_security_event(
        "login_success",
        request=request,
        username="alice",
    )

    entry = security_audit.read_security_events()[-1]
    assert entry["client_ip_ref"] == pseudonymize(
        "security-ip:198.51.100.77"
    )
    assert entry["client_ip_ref"] != pseudonymize(
        "security-ip:203.0.113.9"
    )
