import json
import os
import threading
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Annotated

import jwt
from fastapi import Depends, HTTPException, Request, status
from fastapi.security import OAuth2PasswordBearer
from jwt.exceptions import InvalidTokenError
from pwdlib import PasswordHash


class Role(str, Enum):
    ADMIN = "admin"
    ANALYST = "analyst"
    AUDITOR = "auditor"


@dataclass(frozen=True)
class User:
    username: str
    role: Role


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


def _jwt_secret() -> str:
    secret = os.getenv("JWT_SECRET", "")
    if len(secret) < 32:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Autenticación no configurada",
        )
    return secret


def load_users() -> dict[str, StoredUser]:
    raw = os.getenv("AUTH_USERS_JSON", "[]")
    try:
        records = json.loads(raw)
        if not isinstance(records, list):
            raise ValueError
        users: dict[str, StoredUser] = {}
        for record in records:
            username = str(record["username"]).strip().lower()
            if not username or username in users:
                raise ValueError
            users[username] = StoredUser(
                username=username,
                password_hash=str(record["password_hash"]),
                role=Role(record["role"]),
                disabled=bool(record.get("disabled", False)),
            )
        return users
    except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Configuración de usuarios inválida",
        ) from exc


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
    token = jwt.encode(payload, _jwt_secret(), algorithm=JWT_ALGORITHM)
    return token, int((expires - now).total_seconds())


def decode_access_token(token: str) -> User:
    credentials_error = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Credenciales inválidas",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(
            token,
            _jwt_secret(),
            algorithms=[JWT_ALGORITHM],
            audience=JWT_AUDIENCE,
            issuer=JWT_ISSUER,
            options={"require": ["sub", "role", "iat", "nbf", "exp", "jti"]},
        )
        username = payload.get("sub")
        role = Role(payload.get("role"))
        if not isinstance(username, str) or not username:
            raise InvalidTokenError
    except (InvalidTokenError, ValueError) as exc:
        raise credentials_error from exc

    stored = load_users().get(username)
    if stored is None or stored.disabled or stored.role != role:
        raise credentials_error
    return User(username=stored.username, role=stored.role)


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
