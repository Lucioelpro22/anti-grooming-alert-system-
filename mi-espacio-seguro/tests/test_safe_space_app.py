from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path

from fastapi.testclient import TestClient

PROJECT_DIR = Path(__file__).resolve().parents[1]
MAIN_PATH = PROJECT_DIR / "api" / "main.py"
spec = spec_from_file_location("mi_espacio_seguro_api_main", MAIN_PATH)
assert spec is not None and spec.loader is not None
module = module_from_spec(spec)
spec.loader.exec_module(module)
client = TestClient(module.app)


def test_health():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok", "app": "mi-espacio-seguro"}


def test_home_has_core_safety_features():
    body = client.get("/").text
    assert "Mi Espacio Seguro" in body
    assert "No me siento bien" in body
    assert "Guardar lo que pasó" in body
    assert "Persona de confianza" in body
    assert "Nunca se envía automáticamente" in body


def test_security_headers():
    response = client.get("/")
    assert "default-src 'self'" in response.headers["content-security-policy"]
    assert response.headers["referrer-policy"] == "no-referrer"
    assert "geolocation=()" in response.headers["permissions-policy"]


def test_client_uses_encryption_and_no_remote_fetch():
    script = (PROJECT_DIR / "static" / "app.js").read_text(encoding="utf-8")
    assert "indexedDB" in script
    assert "PBKDF2" in script
    assert "AES-GCM" in script
    assert "crypto.subtle" in script
    assert "fetch(" not in script
