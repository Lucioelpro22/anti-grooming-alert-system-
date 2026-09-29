"""Privacy-preserving identifiers for reports and audit metadata."""

import hashlib
import hmac
import os


def pseudonymize(value: str) -> str:
    """Return a stable, non-reversible subject identifier.

    A dedicated key is preferred. The audit key is only a backwards-compatible
    fallback for existing installations that have not added the new variable.
    """
    key = os.getenv("PSEUDONYMIZATION_HMAC_KEY") or os.getenv("AUDIT_HMAC_KEY")
    if not key:
        raise RuntimeError("PSEUDONYMIZATION_HMAC_KEY no configurada")
    return hmac.new(
        key.encode("utf-8"), value.strip().encode("utf-8"), hashlib.sha256
    ).hexdigest()
