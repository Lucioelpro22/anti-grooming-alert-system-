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
