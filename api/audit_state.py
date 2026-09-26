"""Independent audit checkpoint and cross-process serialization.

Keep AUDIT_STATE_DB outside the evidence directory with separate backup and
access controls. This detects evidence rollback, not compromise of both stores.
"""

import os
import sqlite3
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path


class EvidenceSecurityError(RuntimeError):
    """Evidence integrity or secure storage cannot be trusted."""


_LOCK = threading.RLock()
_LOCAL = threading.local()


def state_path(evidence: Path) -> Path:
    raw = os.getenv("AUDIT_STATE_DB", "")
    if not raw:
        raise EvidenceSecurityError("AUDIT_STATE_DB no configurado")
    path = Path(raw).resolve()
    if path.is_relative_to(evidence.resolve()):
        raise EvidenceSecurityError("La auditoría requiere un directorio independiente")
    return path


@contextmanager
def transaction(evidence: Path) -> Iterator[sqlite3.Connection]:
    with _LOCK:
        active = getattr(_LOCAL, "connection", None)
        if active is not None:
            yield active
            return
        connection = None
        try:
            path = state_path(evidence)
            path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            connection = sqlite3.connect(path, timeout=30)
            connection.execute("PRAGMA synchronous=FULL")
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(
                "CREATE TABLE IF NOT EXISTS checkpoint "
                "(id INTEGER PRIMARY KEY CHECK(id=1), entries INTEGER, head TEXT)"
            )
            _LOCAL.connection = connection
            yield connection
            connection.commit()
        except (OSError, sqlite3.Error) as exc:
            raise EvidenceSecurityError("Estado de auditoría no disponible") from exc
        finally:
            _LOCAL.connection = None
            if connection is not None:
                connection.close()


def verify(evidence: Path, count: int, head: str) -> None:
    with transaction(evidence) as connection:
        expected = connection.execute(
            "SELECT entries, head FROM checkpoint WHERE id=1"
        ).fetchone()
        if expected is None:
            if count or any(evidence.glob("informe_*")):
                raise EvidenceSecurityError(
                    "Se requiere migración explícita de auditoría"
                )
            connection.execute("INSERT INTO checkpoint VALUES (1, ?, ?)", (count, head))
        elif expected != (count, head):
            raise EvidenceSecurityError("Auditoría truncada, borrada o desactualizada")


def advance(evidence: Path, count: int, head: str) -> None:
    with transaction(evidence) as connection:
        connection.execute(
            "INSERT OR REPLACE INTO checkpoint VALUES (1, ?, ?)", (count, head)
        )
