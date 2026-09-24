import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import jwt
import pytest
from fastapi.testclient import TestClient
from pwdlib import PasswordHash

from api import report_generator
from api.auth import LOGIN_LIMITER
from api.auth import JWT_AUDIENCE, JWT_ISSUER


PASSWORD = "correct-horse-battery-staple"  # pragma: allowlist secret


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
    monkeypatch.setattr(report_generator, "CARPETA_INFORMES", tmp_path)
    LOGIN_LIMITER._failures.clear()
    from api.main import app

    with TestClient(app) as test_client:
        yield test_client


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
        "/analizar-mensaje", json=message_payload(), headers=headers(client, "analyst-a")
    )
    report_id = created.json()["informe_id"]
    response = client.get(f"/informe/{report_id}", headers=headers(client, "analyst-b"))
    assert response.status_code == 404


def test_auditor_can_read_but_cannot_create(client):
    created = client.post(
        "/analizar-mensaje", json=message_payload(), headers=headers(client, "analyst-a")
    )
    report_id = created.json()["informe_id"]
    auditor_headers = headers(client, "auditor")
    assert client.get(f"/informe/{report_id}", headers=auditor_headers).status_code == 200
    assert (
        client.post("/analizar-mensaje", json=message_payload(), headers=auditor_headers).status_code
        == 403
    )


def test_admin_can_read_any_report(client):
    created = client.post(
        "/analizar-mensaje", json=message_payload(), headers=headers(client, "analyst-a")
    )
    report_id = created.json()["informe_id"]
    assert client.get(f"/informe/{report_id}", headers=headers(client, "admin")).status_code == 200


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
        response = client.post("/token", data={"username": "blocked", "password": "wrong"})
        assert response.status_code == 401
    response = client.post("/token", data={"username": "blocked", "password": "wrong"})
    assert response.status_code == 429


def test_extra_message_fields_are_rejected(client):
    payload = message_payload() | {"unexpected": "value"}
    response = client.post(
        "/analizar-mensaje", json=payload, headers=headers(client, "analyst-a")
    )
    assert response.status_code == 422


def test_corrupt_report_metadata_fails_closed(client, tmp_path):
    Path(tmp_path, "informe_deadbeef.txt").write_text("sensitive", encoding="utf-8")
    Path(tmp_path, "informe_deadbeef.json").write_text("not-json", encoding="utf-8")
    response = client.get("/informe/deadbeef", headers=headers(client, "admin"))
    assert response.status_code == 404
