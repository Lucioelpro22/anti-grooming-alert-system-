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

The CI job installs `requirements-postgres-ci.txt` with `--require-hashes` and
`--only-binary=:all:`. This lock includes the API dependencies, pytest, and their
transitive dependencies for Python 3.12 on Linux. The install also includes
`api/requirements.txt`, so stale runtime versions fail resolution rather than
silently testing the old environment, and runs `pip check`. Both files are passed
as requirements because the API pins include extras, which pip does not allow in
constraint files. Regenerate the lock whenever the API
pins or the test runner change; do not edit package hashes by hand:

```sh
uv pip compile requirements-postgres-ci.in --python-version 3.12 --python-platform x86_64-unknown-linux-gnu --generate-hashes --only-binary :all: --output-file requirements-postgres-ci.txt
```

Review the resulting versions and hashes and run the PostgreSQL job after each
update. Scorecard also runs on PRs changing this lock or the integration workflow.

## Required checks after an update

Run Security and quality, Scorecard and GitHub Actions security analysis on the
new head. Inspect workflow conclusions and Code Scanning annotations, and resolve
review threads only after their alerts are confirmed fixed. Prior test results
do not validate subsequent commits.

Scorecard intentionally analyzes local files on pull requests and the complete
repository on main. See [Scorecard analysis modes](scorecard-analysis.md) for the
resulting comparison limitation and the required post-merge verification.

Use a dedicated disposable test database. Its role must have permission to create
and drop schemas. Each test creates a random `persistence_test_*` schema and removes
only that schema when finished. Never use production database credentials.

Install `api/requirements.txt` and pytest in a Python 3.12 environment, then run
from the repository root:

```powershell
$env:TEST_POSTGRES_URL = 'postgresql+psycopg://test_user@localhost:5432/test_database'
python -m pytest -q tests/test_postgres_persistence.py
Remove-Item Env:TEST_POSTGRES_URL
```

The tests exercise schema initialization, missing records, JSONB and BYTEA round
trips, INSERT/ON CONFLICT updates, and rollback after a constraint violation. A
configured but unreachable database fails rather than silently skipping.
