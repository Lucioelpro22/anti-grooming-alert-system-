import base64
import hashlib
import json
import multiprocessing
import os
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from fastapi import HTTPException
from fastapi.testclient import TestClient
from pydantic import ValidationError

from api import audit_state
from api import report_generator as rg
from api.auth import validate_configuration, validate_encryption_keys
from api.detect_patterns import evaluar_texto
from scripts.migrate_audit import migrate


@pytest.fixture()
def storage(tmp_path, monkeypatch):
    folder = tmp_path / "reports"
    monkeypatch.setattr(rg, "CARPETA_INFORMES", folder)
    monkeypatch.setenv("AUDIT_STATE_DB", str(tmp_path / "state" / "audit.sqlite"))
    monkeypatch.setenv("EVIDENCE_ENCRYPTION_KEY", base64.b64encode(b"e" * 32).decode())
    monkeypatch.setenv("AUDIT_HMAC_KEY", base64.b64encode(b"a" * 32).decode())
    return folder


def create():
    from api.main import Mensaje

    message = Mensaje(
        remitente_id="a", destinatario_id="b", contenido="  texto\nexacto  "
    )
    return rg.crear_informe(
        message, evaluar_texto(message.contenido), {}, "SEGUIMIENTO", "a"
    )


def test_exact_original_and_legacy_response_field(storage):
    result = rg.leer_informe(create(), "a")
    assert result["original_message_content"] == "  texto\nexacto  "
    assert result["contenido"] == result["report_text"]


@pytest.mark.parametrize("operation", ["truncate", "delete", "empty"])
def test_audit_loss_is_detected(storage, operation):
    rid = create()
    rg.leer_informe(rid, "a")
    path = storage / rg.AUDIT_FILENAME
    if operation == "delete":
        path.unlink()
    elif operation == "empty":
        path.write_text("")
    else:
        path.write_text(path.read_text().splitlines()[0] + "\n")
    with pytest.raises(rg.EvidenceSecurityError):
        rg.leer_informe(rid, "a")


@pytest.mark.parametrize("bundle", [False, True])
def test_legacy_v1_plaintext_and_json_remain_readable(storage, bundle):
    rid = create()
    path = storage / f"informe_{rid}.json"
    metadata = json.loads(path.read_text())
    metadata["schema_version"] = 1
    aad = {
        k: metadata[k]
        for k in ("schema_version", "id", "owner", "created_at", "cipher")
    }
    text = "informe anterior"
    plaintext = (
        json.dumps({"report_text": text, "original_message_content": "original"})
        if bundle
        else text
    )
    ciphertext = AESGCM(rg._decode_key("EVIDENCE_ENCRYPTION_KEY")).encrypt(
        base64.urlsafe_b64decode(metadata["nonce"]),
        plaintext.encode(),
        rg._canonical(aad),
    )
    metadata["ciphertext_sha256"] = hashlib.sha256(ciphertext).hexdigest()
    path.write_text(json.dumps(metadata))
    (storage / f"informe_{rid}.enc").write_bytes(ciphertext)
    result = rg.leer_informe(rid, "a")
    assert result["contenido"] == text
    assert result["original_message_content"] == ("original" if bundle else None)


@pytest.mark.parametrize(
    "field",
    ["fecha_hora", "ip_origen", "plataforma", "remitente_id", "destinatario_id"],
)
@pytest.mark.parametrize("separator", ["\n", "\r", "\u2028", "\u0085", "\u202e"])
def test_metadata_cannot_insert_lines_or_direction_controls(field, separator):
    from api.main import Mensaje

    data = {"remitente_id": "a", "destinatario_id": "b", "contenido": "hola"}
    data[field] = "a" + separator + "CONCLUSIONES"
    with pytest.raises(ValidationError):
        Mensaje(**data)


@pytest.mark.parametrize("value", ["", "invalid", base64.b64encode(b"short").decode()])
def test_bad_keys_fail_validation(storage, monkeypatch, value):
    monkeypatch.setenv("EVIDENCE_ENCRYPTION_KEY", value)
    with pytest.raises(rg.EvidenceSecurityError):
        validate_encryption_keys()


def test_identical_keys_rejected(storage, monkeypatch):
    monkeypatch.setenv("EVIDENCE_ENCRYPTION_KEY", os.environ["AUDIT_HMAC_KEY"])
    with pytest.raises(RuntimeError):
        validate_encryption_keys()


def test_example_secret_rejected_before_startup(storage, monkeypatch):
    monkeypatch.setenv("JWT_SECRET", "replace-with-at-least-32-random-characters")
    with pytest.raises(HTTPException, match="JWT_SECRET"):
        validate_configuration()


@pytest.mark.parametrize(
    "variable", ["EVIDENCE_ENCRYPTION_KEY", "AUDIT_HMAC_KEY", "AUDIT_STATE_DB"]
)
def test_startup_refuses_missing_configuration(storage, monkeypatch, variable):
    from api.auth import DUMMY_PASSWORD_HASH
    from api.main import app

    monkeypatch.setenv("JWT_SECRET", "test-secret-that-is-longer-than-32-bytes")
    monkeypatch.setenv(
        "AUTH_USERS_JSON",
        json.dumps(
            [
                {
                    "username": "test-user",
                    "role": "analyst",
                    "password_hash": DUMMY_PASSWORD_HASH,
                }
            ]
        ),
    )
    monkeypatch.delenv(variable)
    with pytest.raises(rg.EvidenceSecurityError), TestClient(app):
        pytest.fail("The server must not start")


def test_checkpoint_cannot_share_evidence_directory(storage, monkeypatch):
    monkeypatch.setenv("AUDIT_STATE_DB", str(storage / "state.sqlite"))
    with pytest.raises(rg.EvidenceSecurityError):
        rg.verificar_auditoria()


@pytest.mark.parametrize(
    "text",
    ["estás sola", "¿Cuántos años tienes?", "manda  foto", "manda\nfoto", "mandá foto"],
)
def test_normalized_detection(text):
    assert evaluar_texto(text)["nivel_riesgo"] == "ALTO"


def _worker(folder, db, barrier):
    rg.CARPETA_INFORMES = Path(folder)
    os.environ["AUDIT_STATE_DB"] = db
    os.environ["AUDIT_HMAC_KEY"] = base64.b64encode(b"a" * 32).decode()
    barrier.wait(timeout=20)
    for _ in range(4):
        rg._append_audit("test_event", "test-report", "test-actor")


def test_multiple_processes_do_not_lose_audit_events(storage):
    rg.verificar_auditoria()
    context = multiprocessing.get_context("spawn")
    barrier = context.Barrier(2)
    workers = [
        context.Process(
            target=_worker, args=(str(storage), os.environ["AUDIT_STATE_DB"], barrier)
        )
        for _ in range(2)
    ]
    for worker in workers:
        worker.start()
    for worker in workers:
        worker.join(timeout=40)
        if worker.is_alive():
            worker.terminate()
            worker.join()
        assert worker.exitcode == 0
    assert rg.verificar_auditoria()["entries"] == 8


def test_deleted_checkpoint_requires_explicit_migration(storage):
    rid = create()
    state = rg.verificar_auditoria()
    Path(os.environ["AUDIT_STATE_DB"]).unlink()
    with pytest.raises(rg.EvidenceSecurityError):
        rg.leer_informe(rid, "a")
    with pytest.raises(rg.EvidenceSecurityError):
        migrate(state["entries"], "0" * 64)
    migrate(state["entries"], state["final_hash"])
    assert rg.leer_informe(rid, "a")["original_message_content"]


def test_failed_checkpoint_commit_fails_closed(storage, monkeypatch):
    create()

    def fail(*args):
        raise rg.EvidenceSecurityError("simulated checkpoint failure")

    with monkeypatch.context() as patch:
        patch.setattr(audit_state, "advance", fail)
        with pytest.raises(rg.EvidenceSecurityError):
            rg._append_audit("test", "report", "actor")
    with pytest.raises(rg.EvidenceSecurityError):
        rg.verificar_auditoria()
