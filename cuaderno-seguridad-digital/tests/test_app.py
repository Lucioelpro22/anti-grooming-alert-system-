from fastapi.testclient import TestClient

from api.main import app

client = TestClient(app)


def test_health():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_home_contains_core_modules():
    response = client.get("/")
    assert response.status_code == 200
    body = response.text
    assert "Mi Cuaderno" in body
    assert "Aprendo jugando" in body
    assert "No me siento bien / Necesito ayuda" in body
    assert "Línea 102" in body


def test_no_remote_assets_in_home():
    body = client.get("/").text.lower()
    assert "https://" not in body
    assert "http://" not in body
