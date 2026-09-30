"""Optional PostgreSQL evidence repository.

The current default remains the encrypted filesystem store for backwards
compatibility. Production deployments can explicitly construct this repository
with a PostgreSQL SQLAlchemy engine; the application never silently falls back
to an unencrypted database.
"""

from dataclasses import dataclass
from typing import Any

POSTGRES_SCHEMA = """
CREATE TABLE IF NOT EXISTS evidence_reports (
    report_id TEXT PRIMARY KEY,
    owner TEXT NOT NULL,
    status TEXT NOT NULL,
    metadata JSONB NOT NULL,
    ciphertext BYTEA NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
)
"""


@dataclass(frozen=True)
class StoredEvidence:
    report_id: str
    owner: str
    status: str
    metadata: dict[str, Any]
    ciphertext: bytes


def create_postgres_engine(database_url: str) -> Any:
    if not database_url.startswith(("postgresql://", "postgresql+psycopg://")):
        raise ValueError("DATABASE_URL debe usar PostgreSQL")
    try:
        from sqlalchemy import create_engine
    except ImportError as exc:
        raise RuntimeError("SQLAlchemy no está instalado") from exc
    return create_engine(database_url, pool_pre_ping=True, future=True)


class PostgresEvidenceRepository:
    def __init__(self, engine: Any) -> None:
        self.engine = engine

    def initialize(self) -> None:
        from sqlalchemy import text

        with self.engine.begin() as connection:
            connection.execute(text(POSTGRES_SCHEMA))

    def save(self, evidence: StoredEvidence) -> None:
        from sqlalchemy import text

        query = text(
            """INSERT INTO evidence_reports
            (report_id, owner, status, metadata, ciphertext)
            VALUES (:report_id, :owner, :status, CAST(:metadata AS JSONB), :ciphertext)
            ON CONFLICT (report_id) DO UPDATE SET
              owner = EXCLUDED.owner, status = EXCLUDED.status,
              metadata = EXCLUDED.metadata, ciphertext = EXCLUDED.ciphertext,
              updated_at = NOW()"""
        )
        import json

        with self.engine.begin() as connection:
            connection.execute(
                query,
                {
                    "report_id": evidence.report_id,
                    "owner": evidence.owner,
                    "status": evidence.status,
                    "metadata": json.dumps(evidence.metadata, ensure_ascii=False),
                    "ciphertext": evidence.ciphertext,
                },
            )

    def load(self, report_id: str) -> StoredEvidence | None:
        from sqlalchemy import text

        with self.engine.connect() as connection:
            row = (
                connection.execute(
                    text(
                        "SELECT report_id, owner, status, metadata, ciphertext "
                        "FROM evidence_reports WHERE report_id = :report_id"
                    ),
                    {"report_id": report_id},
                )
                .mappings()
                .first()
            )
        if row is None:
            return None
        return StoredEvidence(
            report_id=row["report_id"],
            owner=row["owner"],
            status=row["status"],
            metadata=dict(row["metadata"]),
            ciphertext=bytes(row["ciphertext"]),
        )
