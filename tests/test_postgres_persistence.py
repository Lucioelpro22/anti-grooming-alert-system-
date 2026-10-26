"""Integration checks against a dedicated PostgreSQL test database."""

import os
from uuid import uuid4

import pytest

from api.persistence import (
    PostgresEvidenceRepository,
    StoredEvidence,
    create_postgres_engine,
)


@pytest.fixture()
def repository():
    database_url = os.environ.get("TEST_POSTGRES_URL")
    if not database_url:
        pytest.skip("Set TEST_POSTGRES_URL to a dedicated PostgreSQL test database")

    from sqlalchemy import event, text

    engine = create_postgres_engine(database_url)
    schema = f"persistence_test_{uuid4().hex}"
    with engine.begin() as connection:
        connection.execute(text(f'CREATE SCHEMA "{schema}"'))

    # A random schema isolates these checks from other tests and existing tables.
    # Apply the search path before every transaction, including pooled connections.
    def set_search_path(connection):
        connection.exec_driver_sql(f'SET LOCAL search_path TO "{schema}"')

    event.listen(engine, "begin", set_search_path)
    try:
        result = PostgresEvidenceRepository(engine)
        result.initialize()
        yield result
    finally:
        event.remove(engine, "begin", set_search_path)
        try:
            with engine.begin() as connection:
                connection.execute(text(f'DROP SCHEMA "{schema}" CASCADE'))
        finally:
            engine.dispose()


def test_postgres_round_trip_and_upsert(repository):
    assert repository.load("missing") is None
    original = StoredEvidence(
        report_id="report-1",
        owner="owner-1",
        status="new",
        metadata={"context": "niñez", "nested": {"values": [1, True, None]}},
        ciphertext=b"\x00\xffencrypted\x00",
    )
    repository.save(original)
    assert repository.load(original.report_id) == original

    updated = StoredEvidence(
        report_id=original.report_id,
        owner="owner-2",
        status="reviewed",
        metadata={"updated": True},
        ciphertext=b"\x01\xfeupdated",
    )
    repository.save(updated)
    assert repository.load(original.report_id) == updated

    from sqlalchemy import text

    with repository.engine.connect() as connection:
        assert (
            connection.execute(text("SELECT count(*) FROM evidence_reports")).scalar()
            == 1
        )


def test_postgres_failed_save_rolls_back_and_connection_remains_usable(repository):
    from sqlalchemy.exc import IntegrityError

    original = StoredEvidence("report-1", "owner-1", "new", {}, b"encrypted")
    repository.save(original)

    # PostgreSQL rejects NULL against the schema's NOT NULL constraint.
    invalid = StoredEvidence("report-1", "owner-2", None, {}, b"changed")
    with pytest.raises(IntegrityError):
        repository.save(invalid)

    assert repository.load(original.report_id) == original
    repository.save(StoredEvidence("report-2", "owner-2", "new", {}, b"second"))
    assert repository.load("report-2") is not None
