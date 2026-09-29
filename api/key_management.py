"""Versioned evidence-key loading with backwards compatibility."""

import base64
import binascii
import json
import os

from api.audit_state import EvidenceSecurityError


def _decode(raw: str) -> bytes:
    try:
        value = base64.b64decode(raw, altchars=b"-_", validate=True)
    except (ValueError, binascii.Error) as exc:
        raise EvidenceSecurityError("Configuración de seguridad inválida") from exc
    if len(value) != 32:
        raise EvidenceSecurityError("Las claves de evidencia deben tener 32 bytes")
    return value


def load_keyring() -> dict[str, bytes]:
    """Load a key ring from the environment without logging key material."""
    raw_ring = os.getenv("EVIDENCE_ENCRYPTION_KEYS_JSON")
    if raw_ring:
        try:
            parsed = json.loads(raw_ring)
            if not isinstance(parsed, dict) or not parsed:
                raise ValueError
            return {
                str(version): _decode(str(value)) for version, value in parsed.items()
            }
        except (json.JSONDecodeError, TypeError, ValueError) as exc:
            raise EvidenceSecurityError(
                "EVIDENCE_ENCRYPTION_KEYS_JSON inválido"
            ) from exc

    legacy = os.getenv("EVIDENCE_ENCRYPTION_KEY")
    if not legacy:
        raise EvidenceSecurityError("EVIDENCE_ENCRYPTION_KEY no configurada")
    return {"legacy": _decode(legacy)}


def current_key() -> tuple[str, bytes]:
    raw_current = os.getenv("EVIDENCE_ENCRYPTION_CURRENT_KEY_ID")
    keyring = load_keyring()
    key_id = raw_current or (next(reversed(keyring)) if len(keyring) == 1 else None)
    if key_id is None or key_id not in keyring:
        raise EvidenceSecurityError("EVIDENCE_ENCRYPTION_CURRENT_KEY_ID inválido")
    return key_id, keyring[key_id]


def key_for(key_id: str) -> bytes:
    keyring = load_keyring()
    try:
        return keyring[key_id]
    except KeyError as exc:
        raise EvidenceSecurityError(
            "Clave histórica de evidencia no disponible"
        ) from exc
