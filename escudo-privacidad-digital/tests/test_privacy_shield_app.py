from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path

from fastapi.testclient import TestClient

PROJECT_DIR = Path(__file__).resolve().parents[1]
MAIN_PATH = PROJECT_DIR / "api" / "main.py"

spec = spec_from_file_location("escudo_privacidad_api_main", MAIN_PATH)
assert spec is not None and spec.loader is not None
module = module_from_spec(spec)
spec.loader.exec_module(module)

client = TestClient(module.app)


def test_health():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {
        "status": "ok",
        "app": "escudo-privacidad-digital",
    }


def test_home_contains_core_modules():
    response = client.get("/")
    assert response.status_code == 200
    body = response.text
    assert "Escudo de Privacidad Digital" in body
    assert "Mis datos" in body
    assert "Mis llaves" in body
    assert "Permisos de las apps" in body
    assert "Verifico primero" in body
    assert "Mi escudo" in body


def test_home_has_no_remote_assets_or_password_field():
    body = client.get("/").text.lower()
    assert "https://" not in body
    assert "http://" not in body
    assert 'type="password"' not in body


def test_security_headers_are_restrictive():
    response = client.get("/")
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["referrer-policy"] == "no-referrer"
    assert "default-src 'self'" in response.headers["content-security-policy"]
    permissions = response.headers["permissions-policy"]
    assert "camera=()" in permissions
    assert "microphone=()" in permissions
    assert "geolocation=()" in permissions
