import base64
import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from api.detect_patterns import evaluar_texto, identificar_perfil
from api.ip_analysis import analizar_ip
from api.key_management import current_key
from api.pseudonymization import pseudonymize
from api.rate_limit_backend import RedisRateLimitBackend
from api.report_generator import leer_informe
from api.security import RateLimitBackendUnavailable, SlidingWindowRateLimiter
from api.retention import EvidenceStatus, can_transition, retention_deadline


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
    key = base64.urlsafe_b64encode(b"p" * 32).decode()
    monkeypatch.setenv("PSEUDONYMIZATION_HMAC_KEY", key)
    first = pseudonymize("external-user-123")
    assert first == pseudonymize(" external-user-123 ")
    assert first != "external-user-123"


def test_key_ring_selects_current_version_without_exposing_material(monkeypatch):
    old = base64.urlsafe_b64encode(b"o" * 32).decode()
    current = base64.urlsafe_b64encode(b"c" * 32).decode()
    monkeypatch.delenv("EVIDENCE_ENCRYPTION_KEY", raising=False)
    monkeypatch.setenv(
        "EVIDENCE_ENCRYPTION_KEYS_JSON", json.dumps({"v1": old, "v2": current})
    )
    monkeypatch.setenv("EVIDENCE_ENCRYPTION_CURRENT_KEY_ID", "v2")
    key_id, key = current_key()
    assert key_id == "v2"
    assert key == b"c" * 32


def test_legal_hold_cannot_be_deleted():
    assert can_transition(EvidenceStatus.ACTIVE, EvidenceStatus.LEGAL_HOLD)
    assert not can_transition(
        EvidenceStatus.LEGAL_HOLD, EvidenceStatus.DELETION_PENDING
    )
    created = datetime(2026, 1, 1, tzinfo=timezone.utc)
    assert retention_deadline(created, 30).day == 31


def test_redis_rate_limit_backend_uses_atomic_pipeline():
    class Pipeline:
        def incr(self, key):
            self.key = key

        def expire(self, key, seconds):
            self.seconds = seconds

        def execute(self):
            return (2, True)

    class Client:
        def pipeline(self, transaction=True):
            assert transaction is True
            return Pipeline()

    result = RedisRateLimitBackend(Client()).check("user", 1, 60)
    assert not result.allowed
    assert result.retry_after == 60


def test_http_rate_limiter_fails_closed_when_redis_is_unavailable(monkeypatch):
    monkeypatch.setenv("RATE_LIMIT_BACKEND", "redis")
    monkeypatch.delenv("REDIS_URL", raising=False)
    limiter = SlidingWindowRateLimiter()

    with pytest.raises(RateLimitBackendUnavailable):
        limiter.check("client")
