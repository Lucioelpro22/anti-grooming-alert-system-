import json
import os
import threading
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Annotated

import jwt
from argon2 import extract_parameters
from argon2.exceptions import InvalidHashError
from fastapi import Depends, HTTPException, Request, status
from fastapi.security import OAuth2PasswordBearer
from jwt.exceptions import InvalidTokenError
from pwdlib import PasswordHash

from api.audit_key_management import current_audit_key, load_audit_keyring
from api.audit_state import EvidenceSecurityError
from api.jwt_key_management import (
    JWTKeyConfigurationError,
    JWTKeyNotFound,
    current_jwt_key,
    jwt_key_for,
)
from api.key_management import current_key, load_keyring
from api.pseudonymization import pseudonymization_key
from api.token_revocation import (
    RevocationBackendUnavailable,
    RevocationCapacityExceeded,
    TokenRevocationStore,
)


class Role(str, Enum):
    ADMIN = "admin"
    ANALYST = "analyst"
    SUPERVISOR = "supervisor"
    AUDITOR = "auditor"


@dataclass(frozen=True)
class User:
    username: str
    role: Role
    token_id: str | None = field(default=None, kw_only=True)
    token_expires_at: float | None = field(default=None, kw_only=True)


@dataclass(frozen=True)
class StoredUser(User):
    password_hash: str
    disabled: bool = False


PASSWORD_HASH = PasswordHash.recommended()
DUMMY_PASSWORD_HASH = PASSWORD_HASH.hash("dummy-password-used-only-for-timing")
OAUTH2_SCHEME = OAuth2PasswordBearer(tokenUrl="token")
JWT_ALGORITHM = "HS256"
JWT_ISSUER = "anti-grooming-alert-system"
JWT_AUDIENCE = "anti-grooming-api"
ACCESS_TOKEN_MINUTES = 15
TOKEN_REVOCATIONS = TokenRevocationStore()

# Known example/placeholder values that must never be used in production
BLACKLISTED_PASSWORD_HASHES = {
    "$argon2id$REPLACE_ME",
    "$argon2id$v=19$m=65540,t=3,p=4$REPLACE_WITH_ACTUAL_HASH$REPLACE_WITH_ACTUAL_HASH",
}

BLACKLISTED_KEYS = {
    "insecure_example_replace_with_generated_base64_key_32_bytes",
    "replace-with-generated-base64-key",
    "replace-with-a-different-generated-base64-key",
}


def _jwt_secret() -> str:
    """Backwards-compatible accessor for the current JWT signing secret."""

    try:
        return current_jwt_key()[1]
    except JWTKeyConfigurationError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"JWT_SECRET/JWT_SECRETS_JSON inválido: {exc}",
        ) from exc


def load_users() -> dict[str, StoredUser]:
    raw = os.getenv("AUTH_USERS_JSON", "[]")
    try:
        records = json.loads(raw)
        if not isinstance(records, list):
            raise TypeError
        users: dict[str, StoredUser] = {}
        for record in records:
            username = str(record["username"]).strip().lower()
            if not username or username in users:
                raise TypeError
            password_hash = str(record["password_hash"])
            # Reject known example/placeholder password hashes
            if password_hash in BLACKLISTED_PASSWORD_HASHES:
                raise TypeError(
                    f"Usuario {username} usa hash de ejemplo — generar nuevo hash"
                )
            extract_parameters(password_hash)
            users[username] = StoredUser(
                username=username,
                password_hash=password_hash,
                role=Role(record["role"]),
                disabled=bool(record.get("disabled", False)),
            )
        return users
    except (
        KeyError,
        TypeError,
        ValueError,
        InvalidHashError,
        json.JSONDecodeError,
    ) as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Configuración de usuarios inválida",
        ) from exc


def validate_encryption_keys() -> None:
    current_key()
    current_audit_key()
    evidence_keys = set(load_keyring().values())
    audit_keys = set(load_audit_keyring().values())
    try:
        pseudonym_key = pseudonymization_key()
    except RuntimeError as exc:
        raise EvidenceSecurityError("Clave de seudonimización inválida") from exc
    if evidence_keys & audit_keys or pseudonym_key in evidence_keys | audit_keys:
        raise RuntimeError(
            "Las claves de cifrado, auditoría y seudonimización deben ser distintas"
        )


def validate_configuration() -> None:
    TOKEN_REVOCATIONS.validate_configuration()
    _jwt_secret()
    users = load_users()
    if not users or not any(not user.disabled for user in users.values()):
        raise RuntimeError("Debe configurar al menos un usuario activo")
    validate_encryption_keys()


def authenticate_user(username: str, password: str) -> StoredUser | None:
    user = load_users().get(username.strip().lower())
    if user is None or user.disabled:
        PASSWORD_HASH.verify(password, DUMMY_PASSWORD_HASH)
        return None
    if not PASSWORD_HASH.verify(password, user.password_hash):
        return None
    return user


def create_access_token(user: User) -> tuple[str, int]:
    now = datetime.now(timezone.utc)
    expires = now + timedelta(minutes=ACCESS_TOKEN_MINUTES)
    payload = {
        "sub": user.username,
        "role": user.role.value,
        "iat": now,
        "nbf": now,
        "exp": expires,
        "jti": str(uuid.uuid4()),
        "iss": JWT_ISSUER,
        "aud": JWT_AUDIENCE,
    }
    try:
        key_id, signing_key = current_jwt_key()
    except JWTKeyConfigurationError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"JWT_SECRET/JWT_SECRETS_JSON inválido: {exc}",
        ) from exc
    token = jwt.encode(
        payload,
        signing_key,
        algorithm=JWT_ALGORITHM,
        headers={"kid": key_id},
    )
    return token, int((expires - now).total_seconds())


def decode_access_token(token: str) -> User:
    credentials_error = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Credenciales inválidas",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        header = jwt.get_unverified_header(token)
        if header.get("alg") != JWT_ALGORITHM:
            raise InvalidTokenError
        raw_key_id = header.get("kid")
        if raw_key_id is None:
            key_id = "legacy"
        elif (
            not isinstance(raw_key_id, str)
            or not raw_key_id
            or len(raw_key_id) > 64
        ):
            raise InvalidTokenError
        else:
            key_id = raw_key_id
        try:
            verification_key = jwt_key_for(key_id)
        except JWTKeyNotFound as exc:
            raise InvalidTokenError from exc
        payload = jwt.decode(
            token,
            verification_key,
            algorithms=[JWT_ALGORITHM],
            audience=JWT_AUDIENCE,
            issuer=JWT_ISSUER,
            options={"require": ["sub", "role", "iat", "nbf", "exp", "jti"]},
        )
        username = payload.get("sub")
        token_id = payload.get("jti")
        expires_at = payload.get("exp")
        role = Role(payload.get("role"))
        if (
            not isinstance(username, str)
            or not username
            or not isinstance(token_id, str)
            or not token_id
            or len(token_id) > 128
            or not isinstance(expires_at, (int, float))
            or isinstance(expires_at, bool)
        ):
            raise InvalidTokenError
        try:
            revoked = TOKEN_REVOCATIONS.is_revoked(token_id)
        except RevocationBackendUnavailable as exc:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Servicio de revocación no disponible",
            ) from exc
        if revoked:
            raise InvalidTokenError
    except JWTKeyConfigurationError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"JWT_SECRET/JWT_SECRETS_JSON inválido: {exc}",
        ) from exc
    except (InvalidTokenError, ValueError) as exc:
        raise credentials_error from exc

    stored = load_users().get(username)
    if stored is None or stored.disabled or stored.role != role:
        raise credentials_error
    return User(
        username=stored.username,
        role=stored.role,
        token_id=token_id,
        token_expires_at=float(expires_at),
    )


def revoke_access_token(user: User) -> None:
    if user.token_id is None or user.token_expires_at is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token inválido",
            headers={"WWW-Authenticate": "Bearer"},
        )
    try:
        TOKEN_REVOCATIONS.revoke(user.token_id, user.token_expires_at)
    except (RevocationBackendUnavailable, RevocationCapacityExceeded) as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Servicio de revocación no disponible",
        ) from exc


def get_current_user(token: Annotated[str, Depends(OAUTH2_SCHEME)]) -> User:
    return decode_access_token(token)


def require_roles(*allowed: Role):
    def dependency(user: Annotated[User, Depends(get_current_user)]) -> User:
        if user.role not in allowed:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Permisos insuficientes",
            )
        return user

    return dependency


class LoginRateLimiter:
    def __init__(self, attempts: int = 5, window_seconds: int = 300) -> None:
        self.attempts = attempts
        self.window_seconds = window_seconds
        self._failures: dict[str, list[float]] = {}
        self._lock = threading.Lock()

    def _key(self, request: Request, username: str) -> str:
        client = request.client.host if request.client else "unknown"
        return f"{client}:{username.strip().lower()}"

    def check(self, request: Request, username: str) -> None:
        key = self._key(request, username)
        cutoff = time.monotonic() - self.window_seconds
        with self._lock:
            if len(self._failures) > 10_000 and key not in self._failures:
                self._failures = {
                    name: values
                    for name, values in self._failures.items()
                    if values and values[-1] > cutoff
                }
            recent = [value for value in self._failures.get(key, []) if value > cutoff]
            self._failures[key] = recent
            if len(recent) >= self.attempts:
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail="Demasiados intentos; probá más tarde",
                    headers={"Retry-After": str(self.window_seconds)},
                )

    def failure(self, request: Request, username: str) -> None:
        key = self._key(request, username)
        with self._lock:
            self._failures.setdefault(key, []).append(time.monotonic())

    def success(self, request: Request, username: str) -> None:
        key = self._key(request, username)
        with self._lock:
            self._failures.pop(key, None)


LOGIN_LIMITER = LoginRateLimiter()
