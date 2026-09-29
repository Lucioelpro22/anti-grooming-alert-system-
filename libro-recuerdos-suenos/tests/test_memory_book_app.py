from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path

from fastapi.testclient import TestClient

PROJECT_DIR = Path(__file__).resolve().parents[1]
MAIN_PATH = PROJECT_DIR / "api" / "main.py"

spec = spec_from_file_location("libro_recuerdos_api_main", MAIN_PATH)
assert spec is not None and spec.loader is not None
module = module_from_spec(spec)
spec.loader.exec_module(module)

client = TestClient(module.app)


def test_health():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {
        "status": "ok",
        "app": "libro-recuerdos-suenos",
    }


def test_home_contains_core_modules():
    response = client.get("/")
    assert response.status_code == 200
    body = response.text
    assert "Libro de Recuerdos y Sueños" in body
    assert "Mis recuerdos" in body
    assert "Mis sueños" in body
    assert "Carta a mi yo del futuro" in body
    assert "Respaldo cifrado" in body


def test_home_has_no_remote_assets():
    body = client.get("/").text.lower()
    assert "https://" not in body
    assert "http://" not in body


def test_security_headers_are_restrictive():
    response = client.get("/")
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["referrer-policy"] == "no-referrer"
    assert "default-src 'self'" in response.headers["content-security-policy"]
    permissions = response.headers["permissions-policy"]
    assert "camera=()" in permissions
    assert "microphone=()" in permissions
    assert "geolocation=()" in permissions


def test_client_uses_local_encryption_contract():
    script = (PROJECT_DIR / "static" / "app.js").read_text(encoding="utf-8")
    assert "indexedDB" in script
    assert "PBKDF2" in script
    assert "AES-GCM" in script
    assert "crypto.subtle" in script
    assert "localStorage" not in script
    assert "fetch(" not in script
