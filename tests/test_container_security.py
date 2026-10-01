from pathlib import Path


def test_dockerfile_runs_as_non_root_and_disables_uvicorn_proxy_headers():
    dockerfile = Path("Dockerfile").read_text(encoding="utf-8")

    assert (
        "python:3.12.14-slim-trixie@sha256:"
        "f77ac9e44ae96ef2c90b8053ea08c31f8be030f824196b0ae4db6d462c84e51f"
        in dockerfile
    )
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
