import json
import os
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
from api.login_rate_limit import (
    LoginRateLimitBackendUnavailable,
    LoginRateLimitCapacityExceeded,
    LoginRateLimitConfigurationError,
    LoginRateLimitStore,
    opaque_login_key,
    opaque_scope_key,
)
from api.mfa import (
    MFABackendUnavailable,
    MFAConfigurationError,
    validate_mfa_configuration,
    verify_mfa,
)
from api.production_security import validate_production_security
from api.pseudonymization import pseudonymization_key
from api.security_audit import (
    SecurityAuditError,
    record_security_event,
    validate_security_audit_configuration,
)
from api.session_management import (
    InvalidRefreshToken,
    RefreshReuseDetected,
    SessionBackendUnavailable,
    SessionCapacityExceeded,
    SessionStore,
)
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
SESSIONS = SessionStore()

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
    validate_production_security()
    TOKEN_REVOCATIONS.validate_configuration()
    SESSIONS.validate_configuration()
    LOGIN_LIMITER.validate_configuration()
    _jwt_secret()
    users = load_users()
    if not users or not any(not user.disabled for user in users.values()):
        raise RuntimeError("Debe configurar al menos un usuario activo")
    validate_mfa_configuration(
        {username: (user.role.value, user.disabled) for username, user in users.items()}
    )
    validate_encryption_keys()
    validate_security_audit_configuration()


def authenticate_user(username: str, password: str) -> StoredUser | None:
    user = load_users().get(username.strip().lower())
    if user is None or user.disabled:
        PASSWORD_HASH.verify(password, DUMMY_PASSWORD_HASH)
        return None
    if not PASSWORD_HASH.verify(password, user.password_hash):
        return None
    return user


def authenticate_mfa(user: StoredUser, code: str | None) -> bool:
    try:
        return verify_mfa(user.username, user.role.value, code)
    except (MFAConfigurationError, MFABackendUnavailable) as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Servicio MFA no disponible",
        ) from exc


def create_access_token(
    user: User, session_version: int | None = None
) -> tuple[str, int]:
    if session_version is None:
        try:
            session_version = SESSIONS.current_version(user.username)
        except SessionBackendUnavailable as exc:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Servicio de sesiones no disponible",
            ) from exc
    now = datetime.now(timezone.utc)
    expires = now + timedelta(minutes=ACCESS_TOKEN_MINUTES)
    payload = {
        "sub": user.username,
        "role": user.role.value,
        "iat": now,
        "nbf": now,
        "exp": expires,
        "jti": str(uuid.uuid4()),
        "sv": session_version,
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
        elif not isinstance(raw_key_id, str) or not raw_key_id or len(raw_key_id) > 64:
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
        raw_session_version = payload.get("sv", 0)
        role = Role(payload.get("role"))
        if (
            not isinstance(username, str)
            or not username
            or not isinstance(token_id, str)
            or not token_id
            or len(token_id) > 128
            or not isinstance(expires_at, (int, float))
            or isinstance(expires_at, bool)
            or not isinstance(raw_session_version, int)
            or isinstance(raw_session_version, bool)
            or raw_session_version < 0
        ):
            raise InvalidTokenError
        try:
            current_session_version = SESSIONS.current_version(username)
        except SessionBackendUnavailable as exc:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Servicio de sesiones no disponible",
            ) from exc
        if raw_session_version != current_session_version:
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


def create_refresh_session(user: User) -> tuple[str, int, int]:
    try:
        result = SESSIONS.issue(user.username, user.role.value)
    except (SessionBackendUnavailable, SessionCapacityExceeded) as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Servicio de sesiones no disponible",
        ) from exc
    return result.refresh_token, result.refresh_expires_in, result.session_version


def rotate_refresh_session(refresh_token: str) -> tuple[User, str, int, int]:
    try:
        result = SESSIONS.rotate(refresh_token)
    except RefreshReuseDetected as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token reutilizado; sesiones revocadas",
        ) from exc
    except InvalidRefreshToken as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token inválido",
        ) from exc
    except (SessionBackendUnavailable, SessionCapacityExceeded) as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Servicio de sesiones no disponible",
        ) from exc

    stored = load_users().get(result.username)
    try:
        role = Role(result.role)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Sesión inválida",
        ) from exc
    if stored is None or stored.disabled or stored.role != role:
        try:
            SESSIONS.logout_all(result.username)
        except SessionBackendUnavailable:
            pass
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Sesión inválida",
        )
    return (
        User(username=stored.username, role=stored.role),
        result.refresh_token,
        result.refresh_expires_in,
        result.session_version,
    )


def revoke_all_user_sessions(user: User) -> None:
    try:
        SESSIONS.logout_all(user.username)
    except SessionBackendUnavailable as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Servicio de sesiones no disponible",
        ) from exc


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


def get_current_user(
    request: Request,
    token: Annotated[str, Depends(OAUTH2_SCHEME)],
) -> User:
    try:
        return decode_access_token(token)
    except HTTPException as exc:
        if exc.status_code == status.HTTP_503_SERVICE_UNAVAILABLE:
            try:
                record_security_event(
                    "auth_backend_error",
                    request=request,
                    severity="critical",
                    reason="access_token_validation",
                )
            except SecurityAuditError:
                pass
        raise


def require_roles(*allowed: Role):
    def dependency(user: Annotated[User, Depends(get_current_user)]) -> User:
        if user.role not in allowed:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Permisos insuficientes",
            )
        return user

    return dependency


class LoginRateLimitExceeded(HTTPException):
    def __init__(self, retry_after: int, scope: str) -> None:
        super().__init__(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Demasiados intentos; probá más tarde",
            headers={"Retry-After": str(retry_after)},
        )
        self.rate_limit_scope = scope


class LoginRateLimiter:
    def __init__(self) -> None:
        self._store = LoginRateLimitStore()

    def validate_configuration(self) -> None:
        try:
            self._store.validate_configuration()
        except LoginRateLimitConfigurationError as exc:
            raise RuntimeError("Configuración de rate limit de login inválida") from exc

    def _keys(self, request: Request, username: str) -> dict[str, str]:
        client = request.client.host if request.client else "unknown"
        normalized_username = username.strip().lower()
        return {
            "pair": opaque_login_key(client, normalized_username),
            "account": opaque_scope_key("account", normalized_username),
            "client": opaque_scope_key("client", client),
        }

    @staticmethod
    def _backend_unavailable() -> HTTPException:
        return HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Rate limit de autenticación no disponible",
        )

    def check(self, request: Request, username: str) -> None:
        blocked: list[tuple[str, int]] = []
        try:
            for scope, key in self._keys(request, username).items():
                decision = self._store.check(key, self._store.policy(scope))
                if not decision.allowed:
                    blocked.append((scope, decision.retry_after))
        except (
            LoginRateLimitBackendUnavailable,
            LoginRateLimitCapacityExceeded,
            LoginRateLimitConfigurationError,
        ) as exc:
            raise self._backend_unavailable() from exc

        if blocked:
            scopes = {scope for scope, _ in blocked}
            if "account" in scopes:
                scope = "account"
            elif "client" in scopes:
                scope = "client"
            else:
                scope = "pair"
            raise LoginRateLimitExceeded(
                max(retry_after for _, retry_after in blocked),
                scope,
            )

    def failure(self, request: Request, username: str) -> None:
        try:
            for scope, key in self._keys(request, username).items():
                self._store.failure(key, self._store.policy(scope))
        except (
            LoginRateLimitBackendUnavailable,
            LoginRateLimitCapacityExceeded,
            LoginRateLimitConfigurationError,
        ) as exc:
            raise self._backend_unavailable() from exc

    def success(self, request: Request, username: str) -> None:
        keys = self._keys(request, username)
        try:
            self._store.success(keys["pair"])
            self._store.success(keys["account"])
        except (
            LoginRateLimitBackendUnavailable,
            LoginRateLimitCapacityExceeded,
            LoginRateLimitConfigurationError,
        ) as exc:
            raise self._backend_unavailable() from exc

    def clear(self) -> None:
        self._store.clear()


LOGIN_LIMITER = LoginRateLimiter()
