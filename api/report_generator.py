import base64
import binascii
import hashlib
import hmac
import json
import os
import re
import tempfile
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

CARPETA_INFORMES = Path("informes_generados")
AUDIT_FILENAME = "audit.jsonl"
SCHEMA_VERSION = 1
AUDIT_LOCK = threading.RLock()


class EvidenceSecurityError(RuntimeError):
    """Secure evidence storage is unavailable or its integrity cannot be trusted."""


def _decode_key(variable: str) -> bytes:
    raw = os.getenv(variable)
    if not raw:
        raise EvidenceSecurityError("Configuración de seguridad incompleta")
    try:
        key = base64.b64decode(raw, altchars=b"-_", validate=True)
    except (ValueError, binascii.Error) as exc:
        raise EvidenceSecurityError("Configuración de seguridad inválida") from exc
    if len(key) != 32:
        raise EvidenceSecurityError("Configuración de seguridad inválida")
    return key


def _canonical(data: dict[str, Any]) -> bytes:
    return json.dumps(
        data, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def _atomic_write(path: Path, data: bytes) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    temporary: str | None = None
    try:
        with tempfile.NamedTemporaryFile(dir=path.parent, delete=False) as handle:
            temporary = handle.name
            os.chmod(temporary, 0o600)
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        temporary = None
    finally:
        if temporary is not None:
            Path(temporary).unlink(missing_ok=True)


def _audit_path() -> Path:
    return CARPETA_INFORMES / AUDIT_FILENAME


def _read_verified_audit() -> list[dict[str, Any]]:
    path = _audit_path()
    if not path.exists():
        return []
    key = _decode_key("AUDIT_HMAC_KEY")
    previous_hash = "0" * 64
    entries: list[dict[str, Any]] = []
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise EvidenceSecurityError("No se pudo verificar la auditoría") from exc
    for line in lines:
        try:
            entry = json.loads(line)
            entry_hash = entry.pop("entry_hash")
        except (json.JSONDecodeError, KeyError, TypeError, AttributeError) as exc:
            raise EvidenceSecurityError("Registro de auditoría corrupto") from exc
        if entry.get("previous_hash") != previous_hash:
            raise EvidenceSecurityError("Cadena de auditoría inválida")
        expected = hmac.new(key, _canonical(entry), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(entry_hash, expected):
            raise EvidenceSecurityError("Firma de auditoría inválida")
        entry["entry_hash"] = entry_hash
        entries.append(entry)
        previous_hash = entry_hash
    return entries


def verificar_auditoria() -> dict[str, Any]:
    with AUDIT_LOCK:
        entries = _read_verified_audit()
    return {
        "valid": True,
        "entries": len(entries),
        "final_hash": entries[-1]["entry_hash"] if entries else "0" * 64,
    }


def _append_audit(action: str, report_id: str, actor: str) -> None:
    with AUDIT_LOCK:
        entries = _read_verified_audit()
        previous_hash = entries[-1]["entry_hash"] if entries else "0" * 64
        entry: dict[str, Any] = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "action": action,
            "report_id": report_id,
            "actor": actor,
            "previous_hash": previous_hash,
        }
        entry["entry_hash"] = hmac.new(
            _decode_key("AUDIT_HMAC_KEY"), _canonical(entry), hashlib.sha256
        ).hexdigest()
        lines = [
            json.dumps(item, ensure_ascii=False, sort_keys=True) for item in entries
        ]
        lines.append(json.dumps(entry, ensure_ascii=False, sort_keys=True))
        _atomic_write(_audit_path(), ("\n".join(lines) + "\n").encode("utf-8"))


def _render_report(
    mensaje: Any, analisis: dict, ip_info: dict, perfil: str, report_id: str
) -> str:
    fecha_emision = datetime.now(timezone.utc).strftime("%d/%m/%Y %H:%M:%S UTC")
    contenido = f"""
======================================================================
                    INFORME TÉCNICO DE DETECCIÓN
                SISTEMA DE ALERTA TEMPRANA — ANTI-GROOMING
======================================================================
ID INFORME: {report_id}
FECHA EMISIÓN: {fecha_emision}
PLATAFORMA: {mensaje.plataforma or "No especificada"}
----------------------------------------------------------------------
DATOS DE LA COMUNICACIÓN
----------------------------------------------------------------------
Remitente: {mensaje.remitente_id}
Destinatario: {mensaje.destinatario_id}
Fecha mensaje: {mensaje.fecha_hora}
IP origen: {mensaje.ip_origen or "No registrada"}

----------------------------------------------------------------------
ANÁLISIS DE RIESGO
----------------------------------------------------------------------
Nivel de riesgo: {analisis["nivel_riesgo"]}
Puntaje: {analisis["puntaje"]}

INDICADORES DETECTADOS:
{chr(10).join(f"- {i}" for i in analisis["indicadores"]) if analisis["indicadores"] else "- Ninguno"}

PERFIL IDENTIFICADO: {perfil}

----------------------------------------------------------------------
ANÁLISIS DE IP
----------------------------------------------------------------------
IP válida: {ip_info.get("valida", "No disponible")}
{ip_info.get("ambito", "")}
Nota: {ip_info.get("nota", "Sin observaciones")}

----------------------------------------------------------------------
CONCLUSIONES
----------------------------------------------------------------------
"""
    if "AGRESOR" in perfil:
        contenido += """⚠️ RIESGO ELEVADO — ACCIONES RECOMENDADAS:
- Preservar toda la evidencia sin modificar
- Bloquear al usuario inmediatamente
- Presentar denuncia ante autoridad competente
- Solicitar datos reales del titular por mandamiento judicial
- Acompañar a la persona menor con adultos de confianza
"""
    elif analisis["puntaje"] > 0:
        contenido += """ℹ️ Señales de riesgo — mantener vigilancia y conversar con la persona menor"""
    else:
        contenido += """✅ Sin indicadores de riesgo detectados"""
    return (
        contenido
        + """
----------------------------------------------------------------------
Documento generado por Sistema Anti-Grooming
NO SUSTITUYE DENUNCIA FORMAL ANTE AUTORIDADES
======================================================================
"""
    )


def crear_informe(
    mensaje: Any, analisis: dict, ip_info: dict, perfil: str, owner: str
) -> str:
    _decode_key("AUDIT_HMAC_KEY")
    report_id = uuid.uuid4().hex
    created_at = datetime.now(timezone.utc).isoformat()
    authenticated_metadata: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "id": report_id,
        "owner": owner,
        "created_at": created_at,
        "cipher": "AES-256-GCM",
    }
    nonce = os.urandom(12)
    ciphertext = AESGCM(_decode_key("EVIDENCE_ENCRYPTION_KEY")).encrypt(
        nonce,
        _render_report(mensaje, analisis, ip_info, perfil, report_id).encode("utf-8"),
        _canonical(authenticated_metadata),
    )
    metadata = authenticated_metadata | {
        "nonce": base64.urlsafe_b64encode(nonce).decode("ascii"),
        "ciphertext_sha256": hashlib.sha256(ciphertext).hexdigest(),
    }
    with AUDIT_LOCK:
        _read_verified_audit()
        _atomic_write(CARPETA_INFORMES / f"informe_{report_id}.enc", ciphertext)
        _atomic_write(
            CARPETA_INFORMES / f"informe_{report_id}.json",
            json.dumps(metadata, ensure_ascii=False, sort_keys=True).encode("utf-8"),
        )
        _append_audit("report_created", report_id, owner)
    return report_id


def leer_informe(informe_id: str, requester: str, can_read_all: bool = False) -> dict:
    if not re.fullmatch(r"[0-9a-f]{32}", informe_id):
        return {}
    encrypted_path = CARPETA_INFORMES / f"informe_{informe_id}.enc"
    metadata_path = CARPETA_INFORMES / f"informe_{informe_id}.json"
    if not encrypted_path.is_file() or not metadata_path.is_file():
        return {}
    with AUDIT_LOCK:
        _read_verified_audit()
        try:
            metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
            ciphertext = encrypted_path.read_bytes()
            nonce = base64.b64decode(metadata["nonce"], altchars=b"-_", validate=True)
        except (OSError, json.JSONDecodeError, KeyError, TypeError, ValueError):
            return {}
        if (
            metadata.get("id") != informe_id
            or metadata.get("schema_version") != SCHEMA_VERSION
            or metadata.get("cipher") != "AES-256-GCM"
            or not hmac.compare_digest(
                metadata.get("ciphertext_sha256", ""),
                hashlib.sha256(ciphertext).hexdigest(),
            )
        ):
            return {}
        try:
            authenticated_metadata = {
                key: metadata[key]
                for key in ("schema_version", "id", "owner", "created_at", "cipher")
            }
            plaintext = AESGCM(_decode_key("EVIDENCE_ENCRYPTION_KEY")).decrypt(
                nonce, ciphertext, _canonical(authenticated_metadata)
            )
            content = plaintext.decode("utf-8")
        except (InvalidTag, ValueError, KeyError, UnicodeDecodeError):
            return {}
        if not can_read_all and metadata.get("owner") != requester:
            _append_audit("report_access_denied", informe_id, requester)
            return {}
        _append_audit("report_read", informe_id, requester)
        return {"id": informe_id, "contenido": content}
