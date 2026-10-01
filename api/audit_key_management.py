"""Versioned audit HMAC key loading with legacy compatibility."""

import base64
import binascii
import json
import os

from api.audit_state import EvidenceSecurityError


def _decode(raw: str) -> bytes:
    try:
        value = base64.b64decode(raw, altchars=b"-_", validate=True)
    except (ValueError, binascii.Error) as exc:
        raise EvidenceSecurityError("Configuración de auditoría inválida") from exc
    if len(value) != 32:
        raise EvidenceSecurityError("Las claves de auditoría deben tener 32 bytes")
    return value


def load_audit_keyring() -> dict[str, bytes]:
    """Load all audit verification keys from the environment."""

    raw_ring = os.getenv("AUDIT_HMAC_KEYS_JSON")
    if raw_ring:
        try:
            parsed = json.loads(raw_ring)
            if not isinstance(parsed, dict) or not parsed:
                raise ValueError
            keyring = {
                str(version): _decode(str(value)) for version, value in parsed.items()
            }
        except (json.JSONDecodeError, TypeError, ValueError) as exc:
            raise EvidenceSecurityError("AUDIT_HMAC_KEYS_JSON inválido") from exc
        if any(not key_id.strip() for key_id in keyring):
            raise EvidenceSecurityError("AUDIT_HMAC_KEYS_JSON inválido")
        return keyring

    legacy = os.getenv("AUDIT_HMAC_KEY")
    if not legacy:
        raise EvidenceSecurityError("AUDIT_HMAC_KEY no configurada")
    return {"legacy": _decode(legacy)}


def current_audit_key() -> tuple[str, bytes]:
    """Return the key used to sign new audit entries."""

    keyring = load_audit_keyring()
    raw_current = os.getenv("AUDIT_HMAC_CURRENT_KEY_ID")
    key_id = raw_current or (next(reversed(keyring)) if len(keyring) == 1 else None)
    if key_id is None or key_id not in keyring:
        raise EvidenceSecurityError("AUDIT_HMAC_CURRENT_KEY_ID inválido")
    return key_id, keyring[key_id]


def audit_key_for(key_id: str) -> bytes:
    """Return a historical audit key required to verify an existing entry."""

    keyring = load_audit_keyring()
    try:
        return keyring[key_id]
    except KeyError as exc:
        raise EvidenceSecurityError(
            "Clave histórica de auditoría no disponible"
        ) from exc
