import base64
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import jwt
import pytest
from fastapi.testclient import TestClient
from pwdlib import PasswordHash

from api import report_generator
from api.auth import LOGIN_LIMITER, TOKEN_REVOCATIONS
from api.auth import JWT_AUDIENCE, JWT_ISSUER
from api.security import API_LIMITER


PASSWORD = "correct-horse-battery-staple"  # pragma: allowlist secret
EVIDENCE_KEY = base64.urlsafe_b64encode(b"e" * 32).decode("ascii")
AUDIT_KEY = base64.urlsafe_b64encode(b"a" * 32).decode("ascii")


@pytest.fixture()
def client(monkeypatch, tmp_path):
    users = [
        {
            "username": "admin",
            "password_hash": PasswordHash.recommended().hash(PASSWORD),
            "role": "admin",
        },
        {
            "username": "analyst-a",
            "password_hash": PasswordHash.recommended().hash(PASSWORD),
            "role": "analyst",
        },
        {
            "username": "analyst-b",
            "password_hash": PasswordHash.recommended().hash(PASSWORD),
            "role": "analyst",
        },
        {
            "username": "auditor",
            "password_hash": PasswordHash.recommended().hash(PASSWORD),
            "role": "auditor",
        },
    ]
    monkeypatch.setenv("JWT_SECRET", "test-secret-that-is-longer-than-32-bytes")
    monkeypatch.setenv("AUTH_USERS_JSON", json.dumps(users))
    monkeypatch.setenv("EVIDENCE_ENCRYPTION_KEY", EVIDENCE_KEY)
    monkeypatch.setenv("AUDIT_HMAC_KEY", AUDIT_KEY)
    monkeypatch.setenv("ALLOWED_ORIGINS_JSON", '["https://app.example.org"]')
    monkeypatch.setenv("ALLOWED_HOSTS_JSON", '["testserver"]')
    monkeypatch.setenv("MAX_REQUEST_BODY_BYTES", "65536")
    monkeypatch.setenv("API_RATE_LIMIT", "1000")
    monkeypatch.setenv("API_RATE_WINDOW_SECONDS", "60")
    monkeypatch.setattr(report_generator, "CARPETA_INFORMES", tmp_path)
    LOGIN_LIMITER._failures.clear()
    TOKEN_REVOCATIONS.clear()
    API_LIMITER.clear()
    TOKEN_REVOCATIONS.clear()
    from api.main import app

    with TestClient(app) as test_client:
        yield test_client
    API_LIMITER.clear()


def token(client, username, password=PASSWORD):
    response = client.post("/token", data={"username": username, "password": password})
    assert response.status_code == 200
    return response.json()["access_token"]


def headers(client, username):
    return {"Authorization": f"Bearer {token(client, username)}"}


def message_payload():
    return {
        "remitente_id": "sender",
        "destinatario_id": "recipient",
        "contenido": "hola, cómo estás",
    }


def test_protected_endpoint_rejects_anonymous(client):
    assert client.post("/analizar-mensaje", json=message_payload()).status_code == 401


def test_logout_revokes_token_and_prevents_replay(client):
    auth = headers(client, "analyst-a")
    assert client.get("/estado", headers=auth).status_code == 200
    logout = client.post("/logout", headers=auth)
    assert logout.status_code == 200
    assert client.get("/informe/deadbeef", headers=auth).status_code == 401


def test_logout_requires_authentication(client):
    assert client.post("/logout").status_code == 401


def test_invalid_password_is_rejected(client):
    response = client.post("/token", data={"username": "admin", "password": "wrong"})
    assert response.status_code == 401


def test_analyst_can_create_and_read_own_report(client):
    auth = headers(client, "analyst-a")
    created = client.post("/analizar-mensaje", json=message_payload(), headers=auth)
    assert created.status_code == 200
    report_id = created.json()["informe_id"]
    assert client.get(f"/informe/{report_id}", headers=auth).status_code == 200


def test_analyst_cannot_read_another_analysts_report(client):
    created = client.post(
        "/analizar-mensaje",
        json=message_payload(),
        headers=headers(client, "analyst-a"),
    )
    report_id = created.json()["informe_id"]
    response = client.get(f"/informe/{report_id}", headers=headers(client, "analyst-b"))
    assert response.status_code == 404


def test_auditor_can_read_but_cannot_create(client):
    created = client.post(
        "/analizar-mensaje",
        json=message_payload(),
        headers=headers(client, "analyst-a"),
    )
    report_id = created.json()["informe_id"]
    auditor_headers = headers(client, "auditor")
    assert (
        client.get(f"/informe/{report_id}", headers=auditor_headers).status_code == 200
    )
    assert (
        client.post(
            "/analizar-mensaje", json=message_payload(), headers=auditor_headers
        ).status_code
        == 403
    )


def test_admin_can_read_any_report(client):
    created = client.post(
        "/analizar-mensaje",
        json=message_payload(),
        headers=headers(client, "analyst-a"),
    )
    report_id = created.json()["informe_id"]
    assert (
        client.get(
            f"/informe/{report_id}", headers=headers(client, "admin")
        ).status_code
        == 200
    )


def test_tampered_token_is_rejected(client):
    bad_token = token(client, "analyst-a") + "tampered"
    response = client.get(
        "/informe/deadbeef", headers={"Authorization": f"Bearer {bad_token}"}
    )
    assert response.status_code == 401


def test_expired_token_is_rejected(client):
    now = datetime.now(timezone.utc)
    expired = jwt.encode(
        {
            "sub": "analyst-a",
            "role": "analyst",
            "iat": now - timedelta(minutes=20),
            "nbf": now - timedelta(minutes=20),
            "exp": now - timedelta(minutes=5),
            "jti": "expired-test-token",
            "iss": JWT_ISSUER,
            "aud": JWT_AUDIENCE,
        },
        "test-secret-that-is-longer-than-32-bytes",
        algorithm="HS256",
    )
    response = client.get(
        "/informe/deadbeef", headers={"Authorization": f"Bearer {expired}"}
    )
    assert response.status_code == 401


def test_missing_jwt_secret_fails_closed(client, monkeypatch):
    monkeypatch.delenv("JWT_SECRET")
    response = client.post("/token", data={"username": "admin", "password": PASSWORD})
    assert response.status_code == 503


def test_login_rate_limit(client):
    for _ in range(5):
        response = client.post(
            "/token",
            data={
                "username": "blocked",
                "password": "wrong",  # pragma: allowlist secret
            },
        )
        assert response.status_code == 401
    response = client.post(
        "/token",
        data={"username": "blocked", "password": "wrong"},  # pragma: allowlist secret
    )
    assert response.status_code == 429


def test_extra_message_fields_are_rejected(client):
    payload = message_payload() | {"unexpected": "value"}
    response = client.post(
        "/analizar-mensaje", json=payload, headers=headers(client, "analyst-a")
    )
    assert response.status_code == 422


def test_corrupt_report_metadata_fails_closed(client, tmp_path):
    report_id = "d" * 32
    Path(tmp_path, f"informe_{report_id}.enc").write_bytes(b"sensitive")
    Path(tmp_path, f"informe_{report_id}.json").write_text("not-json", encoding="utf-8")
    response = client.get(f"/informe/{report_id}", headers=headers(client, "admin"))
    assert response.status_code == 404


def test_report_is_encrypted_at_rest(client, tmp_path):
    payload = message_payload() | {"contenido": "frase-secreta-evidencia-123"}
    response = client.post(
        "/analizar-mensaje", json=payload, headers=headers(client, "analyst-a")
    )
    report_id = response.json()["informe_id"]
    ciphertext = Path(tmp_path, f"informe_{report_id}.enc").read_bytes()
    assert b"frase-secreta-evidencia-123" not in ciphertext
    assert not Path(tmp_path, f"informe_{report_id}.txt").exists()


def test_tampered_ciphertext_is_rejected(client, tmp_path):
    auth = headers(client, "analyst-a")
    created = client.post("/analizar-mensaje", json=message_payload(), headers=auth)
    report_id = created.json()["informe_id"]
    path = Path(tmp_path, f"informe_{report_id}.enc")
    ciphertext = bytearray(path.read_bytes())
    ciphertext[0] ^= 1
    path.write_bytes(ciphertext)
    assert client.get(f"/informe/{report_id}", headers=auth).status_code == 404


def test_tampered_authenticated_metadata_is_rejected(client, tmp_path):
    auth = headers(client, "analyst-a")
    created = client.post("/analizar-mensaje", json=message_payload(), headers=auth)
    report_id = created.json()["informe_id"]
    path = Path(tmp_path, f"informe_{report_id}.json")
    metadata = json.loads(path.read_text(encoding="utf-8"))
    metadata["owner"] = "admin"
    path.write_text(json.dumps(metadata), encoding="utf-8")
    response = client.get(f"/informe/{report_id}", headers=headers(client, "admin"))
    assert response.status_code == 404


def test_audit_chain_verifies(client):
    auth = headers(client, "analyst-a")
    created = client.post("/analizar-mensaje", json=message_payload(), headers=auth)
    client.get(f"/informe/{created.json()['informe_id']}", headers=auth)
    verification = report_generator.verificar_auditoria()
    assert verification["valid"] is True
    assert verification["entries"] == 2


def test_tampered_audit_log_fails_closed(client, tmp_path):
    auth = headers(client, "analyst-a")
    created = client.post("/analizar-mensaje", json=message_payload(), headers=auth)
    report_id = created.json()["informe_id"]
    audit_path = Path(tmp_path, report_generator.AUDIT_FILENAME)
    audit_path.write_text(
        audit_path.read_text(encoding="utf-8").replace(
            "report_created", "report_deleted"
        ),
        encoding="utf-8",
    )
    response = client.get(f"/informe/{report_id}", headers=auth)
    assert response.status_code == 503


def test_missing_evidence_key_fails_closed(client, monkeypatch):
    monkeypatch.delenv("EVIDENCE_ENCRYPTION_KEY")
    response = client.post(
        "/analizar-mensaje",
        json=message_payload(),
        headers=headers(client, "analyst-a"),
    )
    assert response.status_code == 503


def test_security_headers_are_added(client):
    response = client.get("/estado")
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["referrer-policy"] == "no-referrer"
    assert response.headers["cache-control"] == "no-store"
    assert response.headers["content-security-policy"] == (
        "default-src 'none'; frame-ancestors 'none'"
    )
    assert response.headers["strict-transport-security"].startswith("max-age=")
    assert len(response.headers["x-request-id"]) == 32


def test_valid_request_id_is_preserved(client):
    request_id = "request-12345678"
    response = client.get("/estado", headers={"X-Request-ID": request_id})
    assert response.headers["x-request-id"] == request_id


def test_untrusted_host_is_rejected(client):
    response = client.get("/estado", headers={"Host": "attacker.example"})
    assert response.status_code == 400
    assert response.json()["detail"] == "Host no permitido"


def test_oversized_request_is_rejected_before_validation(client):
    response = client.post(
        "/analizar-mensaje",
        content=b"x" * 65_537,
        headers={"Content-Type": "application/json"},
    )
    assert response.status_code == 413


def test_cors_allows_only_configured_origin(client):
    allowed = client.options(
        "/analizar-mensaje",
        headers={
            "Origin": "https://app.example.org",
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "authorization,content-type",
        },
    )
    assert allowed.status_code == 200
    assert allowed.headers["access-control-allow-origin"] == "https://app.example.org"

    denied = client.options(
        "/analizar-mensaje",
        headers={
            "Origin": "https://attacker.example",
            "Access-Control-Request-Method": "POST",
        },
    )
    assert denied.status_code == 400
    assert "access-control-allow-origin" not in denied.headers


def test_global_rate_limit_returns_retry_after(client, monkeypatch):
    monkeypatch.setenv("API_RATE_LIMIT", "2")
    API_LIMITER.clear()
    assert client.get("/estado").status_code == 200
    assert client.get("/estado").status_code == 200
    blocked = client.get("/estado")
    assert blocked.status_code == 429
    assert int(blocked.headers["retry-after"]) >= 1
