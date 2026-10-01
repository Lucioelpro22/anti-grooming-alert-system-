"""Versioned JWT signing-key loading with legacy compatibility."""

import json
import os


class JWTKeyConfigurationError(RuntimeError):
    """JWT signing-key configuration is missing or invalid."""


class JWTKeyNotFound(RuntimeError):
    """A token references a signing key that is no longer available."""


BLACKLISTED_JWT_SECRETS = {
    "replace-with-at-least-32-random-characters",
    "insecure_example_do_not_use_in_production_generate_new_secret_with_openssl",
}


def _validate_secret(raw: str) -> str:
    secret = raw
    if len(secret) < 32:
        raise JWTKeyConfigurationError(
            "Las claves JWT deben tener al menos 32 caracteres"
        )
    if secret.lower() in BLACKLISTED_JWT_SECRETS:
        raise JWTKeyConfigurationError("JWT secret usa un valor de ejemplo")
    return secret


def load_jwt_keyring() -> dict[str, str]:
    """Load all JWT signing/verification keys from the environment."""

    raw_ring = os.getenv("JWT_SECRETS_JSON")
    if raw_ring:
        try:
            parsed = json.loads(raw_ring)
            if (
                not isinstance(parsed, dict)
                or not parsed
                or not all(isinstance(secret, str) for secret in parsed.values())
            ):
                raise ValueError
            keyring = {
                str(key_id): _validate_secret(secret)
                for key_id, secret in parsed.items()
            }
        except (json.JSONDecodeError, TypeError, ValueError) as exc:
            raise JWTKeyConfigurationError("JWT_SECRETS_JSON inválido") from exc

        if any(not key_id.strip() or len(key_id) > 64 for key_id in keyring):
            raise JWTKeyConfigurationError("JWT_SECRETS_JSON inválido")
        if len(set(keyring.values())) != len(keyring):
            raise JWTKeyConfigurationError(
                "Cada JWT key ID debe usar un secreto distinto"
            )
        return keyring

    legacy = os.getenv("JWT_SECRET", "")
    if not legacy:
        raise JWTKeyConfigurationError("JWT_SECRET no configurado")
    return {"legacy": _validate_secret(legacy)}


def current_jwt_key() -> tuple[str, str]:
    """Return the signing key used for newly issued tokens."""

    keyring = load_jwt_keyring()
    raw_current = os.getenv("JWT_CURRENT_KEY_ID")
    key_id = raw_current or (next(reversed(keyring)) if len(keyring) == 1 else None)
    if key_id is None or key_id not in keyring:
        raise JWTKeyConfigurationError("JWT_CURRENT_KEY_ID inválido")
    return key_id, keyring[key_id]


def jwt_key_for(key_id: str) -> str:
    """Return a verification key referenced by a token's kid header."""

    try:
        return load_jwt_keyring()[key_id]
    except KeyError as exc:
        raise JWTKeyNotFound("Clave JWT histórica no disponible") from exc
