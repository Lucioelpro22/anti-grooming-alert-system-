from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path

from fastapi.testclient import TestClient

PROJECT_DIR = Path(__file__).resolve().parents[1]
MAIN_PATH = PROJECT_DIR / "api" / "main.py"

spec = spec_from_file_location("cuaderno_seguridad_api_main", MAIN_PATH)
assert spec is not None and spec.loader is not None
module = module_from_spec(spec)
spec.loader.exec_module(module)

client = TestClient(module.app)


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
