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
transitive dependencies for Python 3.12 on Linux. Regenerate it whenever the API
pins or the test runner change; do not edit package hashes by hand:

```sh
uv pip compile requirements-postgres-ci.in --python-version 3.12 --python-platform x86_64-unknown-linux-gnu --generate-hashes --only-binary :all: --output-file requirements-postgres-ci.txt
```

Review the resulting versions and hashes and run the PostgreSQL job after each
update. Scorecard also runs on PRs changing this lock or the integration workflow.

## Review evidence and remaining checks

On commit `e604440bd060a049bc2fa8cc2dd64d00dcc47fe5`, all 15 workflows passed,
including 303 ordinary tests (2 database tests skipped) and 2 tests in the real
PostgreSQL job. Those results do not validate subsequent commits.

Successful Scorecard execution and SARIF upload do not mean there are no alerts.
The Code Scanning check on that commit was neutral: it reported a medium
Pinned-Dependencies alert and could not compare `supply-chain/branch-protection`
and `supply-chain/online-scm` configurations with main. The two missing
configurations remain a coverage limitation until a new scan establishes their
status; no missing result should be interpreted as a passing check. PR triggers
are experimental upstream. Do not add a privileged token or suppress alerts to
make the comparison green.

After applying CI changes, rerun Security and quality, Scorecard and GitHub Actions
security analysis on the new head. Inspect both workflow conclusions and Code
Scanning annotations, and resolve the existing review threads only after their
alerts are confirmed fixed. No merge is authorized by these changes.

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
