# Educational CI dependency lock

All nine educational workflows install the shared `requirements-education-ci.txt`
lock with `--require-hashes` and `--only-binary=:all:`. The lock includes each
project's requirements, Ruff and pip-audit plus their transitive dependencies for
Python 3.12 on Linux. Each job also passes its own requirements file to pip, so a
stale shared lock fails instead of silently testing older project versions.

Regenerate the lock after changing any educational requirement or CI tool pin:

```sh
uv pip compile requirements-education-ci.in --python-version 3.12 --python-platform x86_64-unknown-linux-gnu --generate-hashes --only-binary :all: --output-file requirements-education-ci.txt
```

Review version and hash changes, then run all nine educational workflows. Changes
to either shared lock file trigger every educational workflow. The jobs verify
`pip check`, Ruff, project tests and the dependency audit. No mutable pip upgrade
is performed; installation uses the pip supplied with the selected Python.
