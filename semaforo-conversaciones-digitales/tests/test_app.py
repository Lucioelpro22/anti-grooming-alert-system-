from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path

from fastapi.testclient import TestClient

PROJECT_DIR = Path(__file__).resolve().parents[1]
MAIN_PATH = PROJECT_DIR / "api" / "main.py"

spec = spec_from_file_location("semaforo_conversaciones_api_main", MAIN_PATH)
assert spec is not None and spec.loader is not None
module = module_from_spec(spec)
spec.loader.exec_module(module)

client = TestClient(module.app)


def test_health():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {
        "status": "ok",
        "app": "semaforo-conversaciones-digitales",
    }


def test_home_contains_project_modules():
    response = client.get("/")
    assert response.status_code == 200
    body = response.text
    assert "Semáforo de Conversaciones Digitales" in body
    assert "Mi semáforo" in body
    assert "Practico con situaciones" in body
    assert "Mis límites" in body
    assert "Mi plan de salida" in body


def test_home_does_not_load_remote_resources():
    body = client.get("/").text.lower()
    assert "https://" not in body
    assert "http://" not in body


def test_security_headers():
    response = client.get("/")
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["referrer-policy"] == "no-referrer"
    assert "default-src 'self'" in response.headers["content-security-policy"]
    assert "camera=()" in response.headers["permissions-policy"]
