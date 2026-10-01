import base64
import hashlib
import hmac
import json

import pytest

from api import audit_state
from api import report_generator as rg
from api.audit_key_management import (
    audit_key_for,
    current_audit_key,
    load_audit_keyring,
)


def _b64(byte: bytes) -> str:
    return base64.urlsafe_b64encode(byte * 32).decode("ascii")


@pytest.fixture()
def audit_storage(tmp_path, monkeypatch):
    folder = tmp_path / "reports"
    monkeypatch.setattr(rg, "CARPETA_INFORMES", folder)
    monkeypatch.setenv(
        "AUDIT_STATE_DB", str(tmp_path / "state" / "audit-checkpoint.sqlite")
    )
    monkeypatch.setenv("AUDIT_HMAC_KEY", _b64(b"a"))
    monkeypatch.delenv("AUDIT_HMAC_KEYS_JSON", raising=False)
    monkeypatch.delenv("AUDIT_HMAC_CURRENT_KEY_ID", raising=False)
    rg.verificar_auditoria()
    return folder


def test_legacy_single_key_configuration_still_loads(monkeypatch):
    monkeypatch.setenv("AUDIT_HMAC_KEY", _b64(b"a"))
    monkeypatch.delenv("AUDIT_HMAC_KEYS_JSON", raising=False)
    monkeypatch.delenv("AUDIT_HMAC_CURRENT_KEY_ID", raising=False)

    key_id, key = current_audit_key()

    assert key_id == "legacy"
    assert key == b"a" * 32
    assert load_audit_keyring() == {"legacy": b"a" * 32}


def test_rotation_preserves_legacy_history_and_signs_new_entries(
    audit_storage, monkeypatch
):
    rg._append_audit("legacy_event", "legacy-report", "legacy-actor")

    audit_path = audit_storage / rg.AUDIT_FILENAME
    legacy_entry = json.loads(audit_path.read_text(encoding="utf-8"))
    legacy_entry.pop("entry_hash")
    legacy_entry.pop("audit_key_id")
    legacy_hash = hmac.new(
        b"a" * 32, rg._canonical(legacy_entry), hashlib.sha256
    ).hexdigest()
    legacy_entry["entry_hash"] = legacy_hash
    audit_path.write_text(
        json.dumps(legacy_entry, ensure_ascii=False, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    audit_state.advance(audit_storage, 1, legacy_hash)

    monkeypatch.setenv(
        "AUDIT_HMAC_KEYS_JSON",
        json.dumps({"legacy": _b64(b"a"), "v2": _b64(b"b")}),
    )
    monkeypatch.setenv("AUDIT_HMAC_CURRENT_KEY_ID", "v2")
    monkeypatch.delenv("AUDIT_HMAC_KEY", raising=False)

    assert rg.verificar_auditoria()["entries"] == 1
    rg._append_audit("rotated_event", "new-report", "new-actor")

    entries = [
        json.loads(line) for line in audit_path.read_text(encoding="utf-8").splitlines()
    ]
    assert "audit_key_id" not in entries[0]
    assert entries[1]["audit_key_id"] == "v2"
    assert entries[1]["previous_hash"] == entries[0]["entry_hash"]
    assert rg.verificar_auditoria()["entries"] == 2


def test_removing_required_historical_key_fails_closed(audit_storage, monkeypatch):
    rg._append_audit("legacy_event", "legacy-report", "legacy-actor")
    monkeypatch.setenv("AUDIT_HMAC_KEYS_JSON", json.dumps({"v2": _b64(b"b")}))
    monkeypatch.setenv("AUDIT_HMAC_CURRENT_KEY_ID", "v2")
    monkeypatch.delenv("AUDIT_HMAC_KEY", raising=False)

    with pytest.raises(rg.EvidenceSecurityError, match="histórica"):
        rg.verificar_auditoria()


def test_current_audit_key_id_must_exist(monkeypatch):
    monkeypatch.setenv("AUDIT_HMAC_KEYS_JSON", json.dumps({"v2": _b64(b"b")}))
    monkeypatch.setenv("AUDIT_HMAC_CURRENT_KEY_ID", "missing")

    with pytest.raises(rg.EvidenceSecurityError, match="CURRENT_KEY_ID"):
        current_audit_key()


def test_audit_key_for_rejects_unknown_historical_id(monkeypatch):
    monkeypatch.setenv("AUDIT_HMAC_KEYS_JSON", json.dumps({"v2": _b64(b"b")}))

    with pytest.raises(rg.EvidenceSecurityError, match="histórica"):
        audit_key_for("legacy")


@pytest.mark.parametrize(
    "raw",
    ["{}", "[]", "not-json", '{"v2":"not-base64"}'],
)
def test_invalid_audit_keyring_is_rejected(monkeypatch, raw):
    monkeypatch.setenv("AUDIT_HMAC_KEYS_JSON", raw)

    with pytest.raises(rg.EvidenceSecurityError):
        load_audit_keyring()
