# API quality and security dependencies

`requirements-security-ci.txt` pins the API, pytest and all quality/security
tools, including their transitive dependencies and SHA-256 hashes, for Linux
x86_64/Python 3.12. The workflow installs binary wheels with required hashes;
it does not run floating pip upgrades or install floating tool versions at run time.

Regenerate the lock from the repository root when API pins or tools change:

```sh
uv pip compile requirements-security-ci.in --python-version 3.12 --python-platform x86_64-unknown-linux-gnu --generate-hashes --only-binary :all: --output-file requirements-security-ci.txt
```

Review the resulting versions and hashes, including changed tool behavior, and
run Security and quality on the updated commit. Regenerate
`requirements-postgres-ci.txt` too when the API requirements change.

The workflow passes both the hashed lock and `api/requirements.txt` to pip as
requirements. This preserves extras, shares the hashes for matching pins, and
fails dependency resolution when a runtime pin and its lock disagree. `pip check`
then verifies the installed dependency metadata. The PostgreSQL job uses the same
alignment check with its smaller integration lock.
