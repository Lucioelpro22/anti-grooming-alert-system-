from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path

from fastapi.testclient import TestClient

PROJECT_DIR = Path(__file__).resolve().parents[1]
MAIN_PATH = PROJECT_DIR / "api" / "main.py"

spec = spec_from_file_location("laboratorio_huella_api_main", MAIN_PATH)
assert spec is not None and spec.loader is not None
module = module_from_spec(spec)
spec.loader.exec_module(module)

client = TestClient(module.app)


def test_health():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {
        "status": "ok",
        "app": "laboratorio-huella-digital",
    }


def test_home_contains_core_modules():
    response = client.get("/")
    assert response.status_code == 200
    body = response.text
    assert "Laboratorio de Huella Digital" in body
    assert "Mi huella" in body
    assert "Antes de publicar" in body
    assert "Fotos y permiso" in body
    assert "Simulador de publicación" in body
    assert "Reviso mi huella" in body


def test_home_has_no_remote_assets_or_file_upload():
    body = client.get("/").text.lower()
    assert "https://" not in body
    assert "http://" not in body
    assert 'type="file"' not in body


def test_security_headers_are_restrictive():
    response = client.get("/")
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["referrer-policy"] == "no-referrer"
    assert "default-src 'self'" in response.headers["content-security-policy"]
    permissions = response.headers["permissions-policy"]
    assert "camera=()" in permissions
    assert "microphone=()" in permissions
    assert "geolocation=()" in permissions
