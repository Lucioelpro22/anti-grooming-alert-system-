from pathlib import Path


def test_dockerfile_runs_as_non_root_and_disables_uvicorn_proxy_headers():
    dockerfile = Path("Dockerfile").read_text(encoding="utf-8")

    base_line = next(
        line for line in dockerfile.splitlines() if line.startswith("ARG PYTHON_IMAGE=")
    )
    assert "python:3.12.14-slim-trixie@sha256:" in base_line
    digest = base_line.split("@sha256:", 1)[1].split()[0]
    assert len(digest) == 64
    assert all(character in "0123456789abcdef" for character in digest)
    assert "USER 10001:10001" in dockerfile
    assert "apt-get upgrade" not in dockerfile
    assert "COPY --chown=0:0 api /app/api" in dockerfile
    assert "COPY --chown=0:0 scripts /app/scripts" in dockerfile
    assert "chmod -R a-w /app/api /app/scripts /opt/venv" in dockerfile
    assert "STOPSIGNAL SIGTERM" in dockerfile
    assert "--no-proxy-headers" in Path("scripts/container-entrypoint.sh").read_text(
        encoding="utf-8"
    )
    assert "--no-server-header" in Path("scripts/container-entrypoint.sh").read_text(
        encoding="utf-8"
    )
    assert "HEALTHCHECK" in dockerfile


def test_production_compose_enforces_runtime_isolation():
    compose = Path("compose.production.yml").read_text(encoding="utf-8")

    assert "read_only: true" in compose
    assert "cap_drop:" in compose
    assert "- ALL" in compose
    assert "no-new-privileges:true" in compose
    assert "pids_limit:" in compose
    assert "mem_limit:" in compose
    assert "cpus:" in compose
    assert 'user: "10001:10001"' in compose
    assert "/run/secrets/" in compose
    assert "/var/run/docker.sock" not in compose
    assert "privileged: true" not in compose


def test_docker_context_excludes_sensitive_material():
    dockerignore = Path(".dockerignore").read_text(encoding="utf-8")

    for pattern in (
        ".env",
        ".env.*",
        "secrets/",
        "*.pem",
        "*.key",
        "*.crt",
        "*.p12",
        "*.pfx",
        "*.sqlite",
        "*.sqlite3",
        "tests/",
        "docs/",
    ):
        assert pattern in dockerignore


def test_container_security_workflow_verifies_runtime_and_scans_image():
    workflow = Path(".github/workflows/container-security.yml").read_text(
        encoding="utf-8"
    )

    assert "Verify runtime hardening" in workflow
    assert "org.opencontainers.image.revision" in workflow
    assert "aquasecurity/trivy-action@" in workflow
    assert "severity: CRITICAL,HIGH" in workflow
    assert "Generate image SBOM" in workflow


def test_container_release_is_scanned_main_only_and_tag_immutable():
    workflow = Path(".github/workflows/container-release.yml").read_text(
        encoding="utf-8"
    )

    assert "Require main branch" in workflow
    assert 'test "${GITHUB_REF}" = "refs/heads/main"' in workflow
    assert "Build and scan before publish" in workflow
    assert "Scan release candidate" in workflow
    assert "Refuse mutable tag overwrite" in workflow
    assert "Container tag already exists; releases are immutable." in workflow
    assert "provenance: mode=max" in workflow
    assert "sbom: true" in workflow
    assert "Attest build provenance" in workflow
    assert "org.opencontainers.image.revision" in workflow


def test_dockerfile_avoids_mutable_package_manager_upgrade():
    dockerfile = Path("Dockerfile").read_text(encoding="utf-8")

    assert "pip install --upgrade pip" not in dockerfile
    assert "apt-get upgrade" not in dockerfile
    assert "PIP_ONLY_BINARY=:all:" in dockerfile
