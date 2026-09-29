import base64
import binascii
import hashlib
import hmac
import json
import os
import re
import tempfile
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from api import audit_state
from api.audit_state import EvidenceSecurityError
from api.detect_patterns import RiskAnalysis
from api.key_management import current_key, key_for
from api.pseudonymization import pseudonymize
from api.retention import EvidenceStatus, can_transition

CARPETA_INFORMES = Path("informes_generados")
AUDIT_FILENAME = "audit.jsonl"
SCHEMA_VERSION = 2


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


def _validated_report_id(raw_id: str) -> str:
    """Return a canonical filename-safe UUID after strict validation."""
    if not re.fullmatch(
        r"(?:[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}|[0-9a-f]{32})",
        raw_id,
        flags=re.IGNORECASE,
    ):
        raise EvidenceSecurityError("Identificador de informe inválido")
    try:
        parsed = uuid.UUID(raw_id)
    except ValueError as exc:
        raise EvidenceSecurityError("Identificador de informe inválido") from exc
    return parsed.hex if len(raw_id) == 32 else str(parsed)


def _atomic_write(path: Path, data: bytes) -> None:
    temporary: str | None = None
    try:
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(dir=path.parent, delete=False) as handle:
            temporary = handle.name
            os.chmod(temporary, 0o600)
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        temporary = None
    except OSError as exc:
        raise EvidenceSecurityError(f"Fallo al escribir evidencia: {exc}") from exc
    finally:
        if temporary is not None:
            Path(temporary).unlink(missing_ok=True)


def _audit_path() -> Path:
    return CARPETA_INFORMES / AUDIT_FILENAME


def _read_verified_audit(*, check_checkpoint: bool = True) -> list[dict[str, Any]]:
    path = _audit_path()
    if not path.exists():
        if check_checkpoint:
            audit_state.verify(CARPETA_INFORMES, 0, "0" * 64)
        return []
    key = _decode_key("AUDIT_HMAC_KEY")
    previous_hash = "0" * 64
    entries: list[dict[str, Any]] = []
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError) as exc:
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
        if not isinstance(entry_hash, str) or not hmac.compare_digest(
            entry_hash, expected
        ):
            raise EvidenceSecurityError("Firma de auditoría inválida")
        entry["entry_hash"] = entry_hash
        entries.append(entry)
        previous_hash = entry_hash
    if check_checkpoint:
        audit_state.verify(CARPETA_INFORMES, len(entries), previous_hash)
    return entries


def verificar_auditoria() -> dict[str, Any]:
    with audit_state.transaction(CARPETA_INFORMES):
        entries = _read_verified_audit()
    return {
        "valid": True,
        "entries": len(entries),
        "final_hash": entries[-1]["entry_hash"] if entries else "0" * 64,
    }


def _append_audit(action: str, report_id: str, actor: str) -> None:
    with audit_state.transaction(CARPETA_INFORMES):
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
        audit_state.advance(CARPETA_INFORMES, len(entries) + 1, entry["entry_hash"])


def _render_report(
    mensaje: Any, analisis: RiskAnalysis, ip_info: dict, perfil: str, report_id: str
) -> str:
    """Render report text. Original message content is stored separately in ciphertext."""
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
Remitente pseudonimizado: {pseudonymize(mensaje.remitente_id)}
Destinatario pseudonimizado: {pseudonymize(mensaje.destinatario_id)}
Fecha mensaje: {mensaje.fecha_hora}
IP declarada por la fuente: {mensaje.ip_origen or "No registrada"}
Fuente IP: {getattr(mensaje, "ip_source", "CLIENT_DECLARED")}
IP verificada: {getattr(mensaje, "ip_verified", False)}

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
    if analisis["puntaje"] > 0:
        contenido += """ℹ️ Indicadores detectados — preservar evidencia y solicitar revisión humana.
El resultado automatizado es apoyo técnico y no identifica culpables ni reemplaza una decisión humana.
"""
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
    mensaje: Any, analisis: RiskAnalysis, ip_info: dict, perfil: str, owner: str
) -> str:
    """Create and encrypt report with original message content preserved."""
    try:
        _decode_key("AUDIT_HMAC_KEY")
    except EvidenceSecurityError as exc:
        raise EvidenceSecurityError("Claves de auditoría no configuradas") from exc

    # New reports use a complete canonical UUID. Legacy 32-hex IDs remain
    # readable for backwards compatibility, but are never generated again.
    report_id = str(uuid.uuid4())
    created_at = datetime.now(timezone.utc).isoformat()
    authenticated_metadata: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "id": report_id,
        "owner": owner,
        "created_at": created_at,
        "cipher": "AES-256-GCM",
        "retention_status": EvidenceStatus.ACTIVE.value,
    }

    # Preserve original message content and normalized analysis result
    evidence_bundle: dict[str, Any] = {
        "original_message_content": mensaje.contenido,
        "report_text": _render_report(mensaje, analisis, ip_info, perfil, report_id),
        "analysis_result": analisis,
        "detector_version": 1,
    }

    key_id, encryption_key = current_key()
    nonce = os.urandom(12)
    authenticated_metadata["key_id"] = key_id
    evidence_bundle["retention_status"] = EvidenceStatus.ACTIVE.value
    try:
        ciphertext = AESGCM(encryption_key).encrypt(
            nonce,
            json.dumps(evidence_bundle, ensure_ascii=False).encode("utf-8"),
            _canonical(authenticated_metadata),
        )
    except EvidenceSecurityError as exc:
        raise EvidenceSecurityError("Claves de cifrado no configuradas") from exc

    metadata = authenticated_metadata | {
        "nonce": base64.urlsafe_b64encode(nonce).decode("ascii"),
        "ciphertext_sha256": hashlib.sha256(ciphertext).hexdigest(),
    }
    with audit_state.transaction(CARPETA_INFORMES):
        _read_verified_audit()
        _atomic_write(CARPETA_INFORMES / f"informe_{report_id}.enc", ciphertext)
        _atomic_write(
            CARPETA_INFORMES / f"informe_{report_id}.json",
            json.dumps(metadata, ensure_ascii=False, sort_keys=True).encode("utf-8"),
        )
        _append_audit("report_created", report_id, owner)
    return report_id


def leer_informe(informe_id: str, requester: str, can_read_all: bool = False) -> dict:
    """Read and decrypt report, returning original message and analysis."""
    try:
        safe_id = _validated_report_id(informe_id)
    except EvidenceSecurityError:
        return {}
    encrypted_path = CARPETA_INFORMES / f"informe_{safe_id}.enc"
    metadata_path = CARPETA_INFORMES / f"informe_{safe_id}.json"
    if not encrypted_path.is_file() or not metadata_path.is_file():
        return {}
    with audit_state.transaction(CARPETA_INFORMES):
        _read_verified_audit()
        try:
            metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
            ciphertext = encrypted_path.read_bytes()
            nonce = base64.b64decode(metadata["nonce"], altchars=b"-_", validate=True)
        except (OSError, json.JSONDecodeError, KeyError, TypeError, ValueError):
            return {}
        if not isinstance(metadata, dict):
            return {}
        if (
            metadata.get("id") != informe_id
            or metadata.get("schema_version") not in {1, SCHEMA_VERSION}
            or metadata.get("cipher") != "AES-256-GCM"
            or not isinstance(metadata.get("ciphertext_sha256"), str)
            or not hmac.compare_digest(
                metadata.get("ciphertext_sha256", ""),
                hashlib.sha256(ciphertext).hexdigest(),
            )
        ):
            return {}
        try:
            authenticated_fields: tuple[str, ...] = (
                "schema_version",
                "id",
                "owner",
                "created_at",
                "cipher",
            )
            if metadata.get("schema_version") == SCHEMA_VERSION and metadata.get(
                "key_id"
            ):
                authenticated_fields += ("key_id",)
            if metadata.get("schema_version") == SCHEMA_VERSION and metadata.get(
                "retention_status"
            ):
                authenticated_fields += ("retention_status",)
            authenticated_metadata = {
                key: metadata[key] for key in authenticated_fields
            }
            encryption_key = key_for(str(metadata.get("key_id", "legacy")))
            plaintext = AESGCM(encryption_key).decrypt(
                nonce, ciphertext, _canonical(authenticated_metadata)
            )
            content = plaintext.decode("utf-8")
            if metadata["schema_version"] == 1:
                # The unreleased hardening branch also wrote JSON with version 1.
                try:
                    evidence_bundle = json.loads(content)
                except json.JSONDecodeError:
                    evidence_bundle = {"report_text": content}
            else:
                evidence_bundle = json.loads(content)
            if not isinstance(evidence_bundle, dict) or not isinstance(
                evidence_bundle.get("report_text"), str
            ):
                return {}
        except (InvalidTag, ValueError, KeyError, UnicodeDecodeError):
            return {}
        if not can_read_all and metadata.get("owner") != requester:
            _append_audit("report_access_denied", informe_id, requester)
            return {}
        _append_audit("report_read", informe_id, requester)
        return {
            "id": informe_id,
            "contenido": evidence_bundle["report_text"],
            "original_message_content": evidence_bundle.get("original_message_content"),
            "report_text": evidence_bundle.get("report_text"),
            "analysis_result": evidence_bundle.get("analysis_result"),
            "retention_status": evidence_bundle.get(
                "retention_status", EvidenceStatus.ACTIVE.value
            ),
        }


def actualizar_estado_informe(
    informe_id: str,
    nuevo_estado: EvidenceStatus,
    actor: str,
) -> EvidenceStatus:
    """Change evidence lifecycle state while re-authenticating the ciphertext.

    A legal hold cannot be removed through this operation. Every transition is
    appended to the tamper-evident audit chain.
    """
    safe_id = _validated_report_id(informe_id)
    encrypted_path = CARPETA_INFORMES / f"informe_{safe_id}.enc"
    metadata_path = CARPETA_INFORMES / f"informe_{safe_id}.json"
    with audit_state.transaction(CARPETA_INFORMES):
        _read_verified_audit()
        try:
            metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
            ciphertext = encrypted_path.read_bytes()
            nonce = base64.b64decode(metadata["nonce"], altchars=b"-_", validate=True)
        except (OSError, json.JSONDecodeError, KeyError, TypeError, ValueError) as exc:
            raise EvidenceSecurityError("Informe no disponible") from exc
        if not isinstance(metadata, dict) or metadata.get("id") != informe_id:
            raise EvidenceSecurityError("Informe no disponible")
        current_status = EvidenceStatus(
            metadata.get("retention_status", EvidenceStatus.ACTIVE.value)
        )
        if not can_transition(current_status, nuevo_estado):
            raise EvidenceSecurityError("Transición de retención no permitida")
        fields: tuple[str, ...] = (
            "schema_version",
            "id",
            "owner",
            "created_at",
            "cipher",
        )
        if metadata.get("schema_version") == SCHEMA_VERSION and metadata.get("key_id"):
            fields += ("key_id",)
        if metadata.get("schema_version") == SCHEMA_VERSION and metadata.get(
            "retention_status"
        ):
            fields += ("retention_status",)
        authenticated_metadata = {key: metadata[key] for key in fields}
        try:
            plaintext = AESGCM(key_for(str(metadata.get("key_id", "legacy")))).decrypt(
                nonce, ciphertext, _canonical(authenticated_metadata)
            )
            bundle = json.loads(plaintext.decode("utf-8"))
        except (
            InvalidTag,
            ValueError,
            KeyError,
            UnicodeDecodeError,
            json.JSONDecodeError,
        ) as exc:
            raise EvidenceSecurityError("Evidencia no pudo ser verificada") from exc
        if not isinstance(bundle, dict):
            raise EvidenceSecurityError("Evidencia no pudo ser verificada")
        bundle["retention_status"] = nuevo_estado.value
        key_id, encryption_key = current_key()
        metadata["key_id"] = key_id
        metadata["retention_status"] = nuevo_estado.value
        authenticated_metadata = {
            key: metadata[key]
            for key in (
                "schema_version",
                "id",
                "owner",
                "created_at",
                "cipher",
                "key_id",
                "retention_status",
            )
        }
        new_nonce = os.urandom(12)
        new_ciphertext = AESGCM(encryption_key).encrypt(
            new_nonce,
            json.dumps(bundle, ensure_ascii=False).encode("utf-8"),
            _canonical(authenticated_metadata),
        )
        metadata["nonce"] = base64.urlsafe_b64encode(new_nonce).decode("ascii")
        metadata["ciphertext_sha256"] = hashlib.sha256(new_ciphertext).hexdigest()
        _atomic_write(encrypted_path, new_ciphertext)
        _atomic_write(
            metadata_path,
            json.dumps(metadata, ensure_ascii=False, sort_keys=True).encode("utf-8"),
        )
        _append_audit("evidence_status_changed", informe_id, actor)
    return nuevo_estado
