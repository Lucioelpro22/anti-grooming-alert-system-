from pathlib import Path

from api.detect_patterns import evaluar_texto, identificar_perfil
from api.ip_analysis import analizar_ip
from api.pseudonymization import pseudonymize
from api.report_generator import leer_informe


def test_critical_multi_indicator_message():
    assert (
        evaluar_texto("dime tu edad no le cuentes a nadie")["nivel_riesgo"] == "CRÍTICO"
    )


def test_critical_photo_request():
    assert evaluar_texto("estas sola manda foto")["nivel_riesgo"] == "CRÍTICO"


def test_high_risk_secret_message():
    assert evaluar_texto("secreto entre nosotros")["nivel_riesgo"] == "ALTO"


def test_medium_risk_message():
    assert evaluar_texto("que haces")["nivel_riesgo"] == "MEDIO"


def test_nested_phrase_is_not_double_counted():
    result = evaluar_texto("hola guapa")
    assert result["nivel_riesgo"] == "BAJO"
    assert result["indicadores"] == ["[BAJA] hola guapa"]


def test_neutral_message():
    assert evaluar_texto("buen día")["nivel_riesgo"] == "SIN INDICADORES DETECTADOS"


def test_ip_validation():
    assert analizar_ip("192.168.1.1")["valida"] is True
    assert analizar_ip("999.999.999.999")["valida"] is False


def test_report_reader_rejects_path_and_glob_injection(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    Path("informes_generados").mkdir()
    Path("informes_generados/informe_safe.enc").write_bytes(b"secret")
    assert leer_informe("../*", requester="analyst") == {}


def test_profile_categories_are_neutral_and_require_human_review():
    result = evaluar_texto("dime tu edad no le cuentes a nadie")
    profile = identificar_perfil(result)
    assert profile == "CRITICAL_RISK_HUMAN_REVIEW_REQUIRED"
    assert "AGRESOR" not in profile


def test_pseudonymization_is_stable_and_non_reversible(monkeypatch):
    monkeypatch.setenv("PSEUDONYMIZATION_HMAC_KEY", "test-pseudonym-key")
    first = pseudonymize("external-user-123")
    assert first == pseudonymize(" external-user-123 ")
    assert first != "external-user-123"
