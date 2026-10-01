"""Load sensitive configuration from mounted secret files.

Each supported secret may be provided either directly in its environment
variable or through the matching `<NAME>_FILE` variable, never both.
"""

from __future__ import annotations

import os
from pathlib import Path

_MAX_SECRET_BYTES = 65_536

_SECRET_NAMES = (
    "JWT_SECRET",
    "JWT_SECRETS_JSON",
    "AUTH_USERS_JSON",
    "MFA_USERS_JSON",
    "EVIDENCE_ENCRYPTION_KEY",
    "EVIDENCE_ENCRYPTION_KEYS_JSON",
    "AUDIT_HMAC_KEY",
    "AUDIT_HMAC_KEYS_JSON",
    "PSEUDONYMIZATION_HMAC_KEY",
    "REDIS_URL",
    "DATABASE_URL",
)


class RuntimeSecretError(RuntimeError):
    """A mounted runtime secret is missing, ambiguous, or unsafe to load."""


def _load_secret_file(path_value: str, name: str) -> str:
    path = Path(path_value)
    try:
        if not path.is_file():
            raise RuntimeSecretError(f"{name}_FILE no apunta a un archivo regular")
        size = path.stat().st_size
        if size <= 0 or size > _MAX_SECRET_BYTES:
            raise RuntimeSecretError(f"{name}_FILE tiene un tamaño inválido")
        value = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        raise RuntimeSecretError(f"No se pudo leer {name}_FILE") from exc

    if "\x00" in value:
        raise RuntimeSecretError(f"{name}_FILE contiene bytes no válidos")
    value = value.strip()
    if not value:
        raise RuntimeSecretError(f"{name}_FILE está vacío")
    return value


def load_runtime_secrets() -> None:
    """Populate supported secret env vars from read-only mounted files."""

    for name in _SECRET_NAMES:
        file_name = f"{name}_FILE"
        direct = os.getenv(name, "").strip()
        secret_file = os.getenv(file_name, "").strip()

        if direct and secret_file:
            raise RuntimeSecretError(
                f"{name} y {file_name} no pueden configurarse simultáneamente"
            )
        if not secret_file:
            continue

        os.environ[name] = _load_secret_file(secret_file, name)
