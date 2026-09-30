from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path

from fastapi.testclient import TestClient

PROJECT_DIR = Path(__file__).resolve().parents[1]
MAIN_PATH = PROJECT_DIR / "api" / "main.py"
spec = spec_from_file_location("rincon_metas_api_main", MAIN_PATH)
assert spec is not None and spec.loader is not None
module = module_from_spec(spec)
spec.loader.exec_module(module)
client = TestClient(module.app)


def test_health():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok", "app": "rincon-metas-crecimiento"}


def test_home_has_original_modules():
    body = client.get("/").text
    assert "Mi Rincón de Metas y Crecimiento" in body
    assert "Mis metas" in body
    assert "Mis logros" in body
    assert "Celebramos juntos" in body
    assert "Mi crecimiento" in body


def test_no_remote_assets():
    body = client.get("/").text.lower()
    assert "https://" not in body
    assert "http://" not in body


def test_security_headers():
    response = client.get("/")
    assert "default-src 'self'" in response.headers["content-security-policy"]
    assert response.headers["referrer-policy"] == "no-referrer"
    assert "geolocation=()" in response.headers["permissions-policy"]
