from pathlib import Path

import pytest

from api.detect_patterns import evaluar_texto
from api.ip_analysis import analizar_ip
from api.jurisdictions import get_policy
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


def test_single_high_risk_keyword_still_marks_aggressor():
    result = evaluar_texto("foto")
    assert result["nivel_riesgo"] == "SIN RIESGO"
    assert result["indicadores"] == []


def test_neutral_message():
    assert evaluar_texto("buen día")["nivel_riesgo"] == "SIN RIESGO"


def test_ip_validation():
    assert analizar_ip("192.168.1.1")["valida"] is True
    assert analizar_ip("999.999.999.999")["valida"] is False


def test_ipv6_and_invalid_variants():
    assert analizar_ip("2001:db8::1")["valida"] is True
    assert analizar_ip(" ")["valida"] is False
    assert analizar_ip("")["valida"] is False
    assert analizar_ip(" 192.168.1.1 ")["valida"] is True


def test_report_reader_rejects_path_and_glob_injection(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    Path("informes_generados").mkdir()
    Path("informes_generados/informe_safe.enc").write_bytes(b"secret")
    assert leer_informe("../*", requester="analyst") == {}


def test_empty_text_is_treated_as_safe():
    result = evaluar_texto("   ")
    assert result["nivel_riesgo"] == "SIN RIESGO"
    assert result["indicadores"] == []


@pytest.mark.parametrize(
    "country_code, expected",
    [
        (" ar ", "AR"),
        ("us", "US"),
        ("br", "BR"),
    ],
)
def test_supported_jurisdiction_is_normalized(country_code, expected):
    policy = get_policy(country_code)
    assert policy.code == expected


def test_unknown_jurisdiction_fails_closed():
    with pytest.raises(ValueError):
        get_policy("ZZ")
