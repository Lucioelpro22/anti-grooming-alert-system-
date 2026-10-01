"""Tamper-evident security-event audit log for authentication activity."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import sqlite3
import tempfile
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from fastapi import Request

from api.audit_key_management import audit_key_for, current_audit_key
from api.pseudonymization import pseudonymize

LOG_FILENAME = "security-events.jsonl"
_ALLOWED_SEVERITIES = {"info", "warning", "critical"}
_LOCK = threading.RLock()
_LOCAL = threading.local()


class SecurityAuditError(RuntimeError):
    """Security-event audit state or integrity cannot be trusted."""


def _log_dir() -> Path:
    raw = os.getenv("SECURITY_AUDIT_DIR", "").strip()
    if not raw:
        raise SecurityAuditError("SECURITY_AUDIT_DIR no configurado")
    return Path(raw).resolve()


def _log_path() -> Path:
    return _log_dir() / LOG_FILENAME


def _state_path() -> Path:
    raw = os.getenv("SECURITY_AUDIT_STATE_DB", "").strip()
    if not raw:
        raise SecurityAuditError("SECURITY_AUDIT_STATE_DB no configurado")
    path = Path(raw).resolve()
    if path.is_relative_to(_log_dir()):
        raise SecurityAuditError(
            "El checkpoint de seguridad debe estar fuera del directorio del log"
        )
    return path


@contextmanager
def _transaction() -> Iterator[sqlite3.Connection]:
    with _LOCK:
        active = getattr(_LOCAL, "connection", None)
        if active is not None:
            yield active
            return

        connection: sqlite3.Connection | None = None
        try:
            state = _state_path()
            state.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            connection = sqlite3.connect(state, timeout=30)
            connection.execute("PRAGMA synchronous=FULL")
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(
                "CREATE TABLE IF NOT EXISTS security_checkpoint "
                "(id INTEGER PRIMARY KEY CHECK(id=1), entries INTEGER, head TEXT)"
            )
            _LOCAL.connection = connection
            yield connection
            connection.commit()
        except (OSError, sqlite3.Error) as exc:
            raise SecurityAuditError("Estado de auditoría de seguridad no disponible") from exc
        finally:
            _LOCAL.connection = None
            if connection is not None:
                connection.close()


def _canonical(data: dict[str, Any]) -> bytes:
    return json.dumps(
        data, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


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
        raise SecurityAuditError("No se pudo escribir la auditoría de seguridad") from exc
    finally:
        if temporary is not None:
            Path(temporary).unlink(missing_ok=True)


def _checkpoint_verify(
    connection: sqlite3.Connection,
    count: int,
    head: str,
) -> None:
    expected = connection.execute(
        "SELECT entries, head FROM security_checkpoint WHERE id=1"
    ).fetchone()
    path = _log_path()
    if expected is None:
        if count or path.exists():
            raise SecurityAuditError(
                "Se requiere un checkpoint confiable para el historial de seguridad"
            )
        connection.execute(
            "INSERT INTO security_checkpoint VALUES (1, ?, ?)",
            (count, head),
        )
    elif expected != (count, head):
        raise SecurityAuditError(
            "Auditoría de seguridad truncada, borrada o desactualizada"
        )


def _checkpoint_advance(
    connection: sqlite3.Connection,
    count: int,
    head: str,
) -> None:
    connection.execute(
        "INSERT OR REPLACE INTO security_checkpoint VALUES (1, ?, ?)",
        (count, head),
    )


def _read_verified(
    connection: sqlite3.Connection,
) -> list[dict[str, Any]]:
    path = _log_path()
    if not path.exists():
        _checkpoint_verify(connection, 0, "0" * 64)
        return []

    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError) as exc:
        raise SecurityAuditError("No se pudo leer la auditoría de seguridad") from exc

    previous_hash = "0" * 64
    entries: list[dict[str, Any]] = []
    for line in lines:
        try:
            parsed = json.loads(line)
            if not isinstance(parsed, dict):
                raise TypeError
            entry = dict(parsed)
            entry_hash = entry.pop("entry_hash")
        except (json.JSONDecodeError, KeyError, TypeError) as exc:
            raise SecurityAuditError("Registro de seguridad corrupto") from exc

        if entry.get("previous_hash") != previous_hash:
            raise SecurityAuditError("Cadena de seguridad inválida")
        key_id = entry.get("audit_key_id", "legacy")
        if not isinstance(key_id, str) or not key_id:
            raise SecurityAuditError("Registro de seguridad corrupto")
        try:
            key = audit_key_for(key_id)
        except RuntimeError as exc:
            raise SecurityAuditError("Clave histórica de seguridad no disponible") from exc
        expected = hmac.new(key, _canonical(entry), hashlib.sha256).hexdigest()
        if not isinstance(entry_hash, str) or not hmac.compare_digest(
            entry_hash, expected
        ):
            raise SecurityAuditError("Firma de seguridad inválida")

        entry["entry_hash"] = entry_hash
        entries.append(entry)
        previous_hash = entry_hash

    _checkpoint_verify(connection, len(entries), previous_hash)
    return entries


def validate_security_audit_configuration() -> None:
    log_dir = _log_dir()
    state = _state_path()
    if state == log_dir:
        raise SecurityAuditError("Configuración de auditoría de seguridad inválida")
    current_audit_key()


def verify_security_audit() -> dict[str, Any]:
    with _transaction() as connection:
        entries = _read_verified(connection)
    return {
        "valid": True,
        "entries": len(entries),
        "final_hash": entries[-1]["entry_hash"] if entries else "0" * 64,
    }


def read_security_events() -> list[dict[str, Any]]:
    """Return verified events for trusted local administration/tests."""

    with _transaction() as connection:
        return _read_verified(connection)


def _request_context(request: Request | None) -> tuple[str | None, str | None, str | None]:
    if request is None:
        return None, None, None

    client_host = request.client.host if request.client else "unknown"
    user_agent = request.headers.get("user-agent", "")[:512]
    request_id = getattr(request.state, "request_id", None)
    return (
        pseudonymize(f"security-ip:{client_host}"),
        pseudonymize(f"security-ua:{user_agent}") if user_agent else None,
        request_id if isinstance(request_id, str) else None,
    )


def record_security_event(
    event: str,
    *,
    request: Request | None = None,
    username: str | None = None,
    role: str | None = None,
    severity: str = "info",
    reason: str | None = None,
) -> None:
    """Append a secret-free, tamper-evident authentication security event."""

    if severity not in _ALLOWED_SEVERITIES:
        raise ValueError("Severidad de seguridad inválida")
    if not event or len(event) > 64 or not event.replace("_", "").isalnum():
        raise ValueError("Evento de seguridad inválido")
    if reason is not None and (
        len(reason) > 64 or not reason.replace("_", "").isalnum()
    ):
        raise ValueError("Motivo de seguridad inválido")

    subject = (
        pseudonymize(f"security-user:{username.strip().lower()}")
        if username and username.strip()
        else None
    )
    ip_ref, user_agent_ref, request_id = _request_context(request)

    with _transaction() as connection:
        entries = _read_verified(connection)
        previous_hash = entries[-1]["entry_hash"] if entries else "0" * 64
        key_id, key = current_audit_key()
        entry: dict[str, Any] = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event": event,
            "severity": severity,
            "alert": severity in {"warning", "critical"},
            "subject_ref": subject,
            "role": role,
            "reason": reason,
            "client_ip_ref": ip_ref,
            "user_agent_ref": user_agent_ref,
            "request_id": request_id,
            "previous_hash": previous_hash,
            "audit_key_id": key_id,
        }
        entry["entry_hash"] = hmac.new(
            key,
            _canonical(entry),
            hashlib.sha256,
        ).hexdigest()

        serialized = [
            json.dumps(item, ensure_ascii=False, sort_keys=True) for item in entries
        ]
        serialized.append(json.dumps(entry, ensure_ascii=False, sort_keys=True))
        _atomic_write(
            _log_path(),
            ("\n".join(serialized) + "\n").encode("utf-8"),
        )
        _checkpoint_advance(connection, len(entries) + 1, entry["entry_hash"])
