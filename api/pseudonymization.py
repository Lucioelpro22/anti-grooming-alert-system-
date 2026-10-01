"""Privacy-preserving identifiers for reports and audit metadata."""

import base64
import binascii
import hashlib
import hmac
import os


def pseudonymization_key() -> bytes:
    """Load the dedicated 32-byte pseudonymization key.

    This key must be independent from audit and evidence-encryption keys.
    Reusing another security key couples otherwise separate trust domains.
    """

    raw = os.getenv("PSEUDONYMIZATION_HMAC_KEY")
    if not raw:
        raise RuntimeError("PSEUDONYMIZATION_HMAC_KEY no configurada")
    try:
        key = base64.b64decode(raw, altchars=b"-_", validate=True)
    except (ValueError, binascii.Error) as exc:
        raise RuntimeError("PSEUDONYMIZATION_HMAC_KEY inválida") from exc
    if len(key) != 32:
        raise RuntimeError("PSEUDONYMIZATION_HMAC_KEY inválida")
    return key


def pseudonymize(value: str) -> str:
    """Return a stable, non-reversible subject identifier."""

    return hmac.new(
        pseudonymization_key(),
        value.strip().encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
