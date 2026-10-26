# PostgreSQL persistence integration checks

The SQLAlchemy upgrade needs validation against PostgreSQL with the pinned psycopg
driver. The normal test run skips `tests/test_postgres_persistence.py` unless
`TEST_POSTGRES_URL` is set; a skipped test is not evidence of database compatibility.

The `PostgreSQL persistence integration` job in `.github/workflows/security.yml`
runs these tests against a real PostgreSQL 17.11 service on every pull request to
`main` and on the workflow's configured pushes. The container is pinned by digest,
waits for `pg_isready`, and exposes its disposable database only on runner loopback.
It uses Python 3.12 and the API's pinned SQLAlchemy and psycopg dependencies.
`TEST_POSTGRES_URL` is scoped to the integration test step, so the general suite
continues to skip database integration when no test database is provided.
This CI job must pass before treating PostgreSQL compatibility as verified.

Use a dedicated disposable test database. Its role must have permission to create
and drop schemas. Each test creates a random `persistence_test_*` schema and removes
only that schema when finished. Never use production database credentials.

Install `api/requirements.txt` and pytest in a Python 3.12 environment, then run
from the repository root:

```powershell
$env:TEST_POSTGRES_URL = 'postgresql+psycopg://test_user:test_password@localhost:5432/test_database'
python -m pytest -q tests/test_postgres_persistence.py
Remove-Item Env:TEST_POSTGRES_URL
```

The tests exercise schema initialization, missing records, JSONB and BYTEA round
trips, INSERT/ON CONFLICT updates, and rollback after a constraint violation. A
configured but unreachable database fails rather than silently skipping.
