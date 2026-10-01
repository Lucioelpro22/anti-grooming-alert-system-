# syntax=docker/dockerfile:1.7

ARG PYTHON_IMAGE=python:3.12.14-slim-trixie@sha256:f77ac9e44ae96ef2c90b8053ea08c31f8be030f824196b0ae4db6d462c84e51f # pragma: allowlist secret

FROM ${PYTHON_IMAGE} AS builder

ENV VIRTUAL_ENV=/opt/venv \
    PATH=/opt/venv/bin:$PATH \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1

RUN python -m venv "${VIRTUAL_ENV}"

COPY api/requirements.txt /tmp/requirements.txt
RUN python -m pip install --upgrade pip \
    && python -m pip install --no-compile -r /tmp/requirements.txt

FROM ${PYTHON_IMAGE} AS runtime

ENV VIRTUAL_ENV=/opt/venv \
    PATH=/opt/venv/bin:$PATH \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    HOME=/nonexistent \
    TMPDIR=/tmp \
    PORT=8000

RUN groupadd --gid 10001 app \
    && useradd --uid 10001 --gid 10001 --no-create-home \
        --home-dir /nonexistent --shell /usr/sbin/nologin app \
    && mkdir -p \
        /app/informes_generados \
        /var/lib/anti-grooming-audit \
        /var/lib/anti-grooming-security \
        /var/log/anti-grooming-security \
    && chown -R 10001:10001 \
        /app/informes_generados \
        /var/lib/anti-grooming-audit \
        /var/lib/anti-grooming-security \
        /var/log/anti-grooming-security

WORKDIR /app

COPY --from=builder /opt/venv /opt/venv
COPY --chown=0:0 api /app/api
COPY --chown=0:0 scripts /app/scripts

# Package-management/build tooling is not needed by the running service.
# Remove it from both the application venv and the base interpreter to reduce
# runtime attack surface and avoid carrying unrelated vulnerable packages.
RUN /opt/venv/bin/python -m pip uninstall -y setuptools urllib3 msgpack \
    && /opt/venv/bin/python -m pip uninstall -y pip \
    && /usr/local/bin/python -m pip uninstall -y setuptools urllib3 msgpack \
    && /usr/local/bin/python -m pip uninstall -y pip \
    && chmod -R a-w /app/api /app/scripts /opt/venv

USER 10001:10001

EXPOSE 8000

STOPSIGNAL SIGTERM

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD python -c "import os,urllib.request; p=os.getenv('PORT','8000'); h=os.getenv('HEALTHCHECK_HOST','localhost'); r=urllib.request.Request(f'http://127.0.0.1:{p}/health/ready',headers={'Host':h}); urllib.request.urlopen(r,timeout=3).read()" || exit 1

ENTRYPOINT ["/bin/sh", "/app/scripts/container-entrypoint.sh"]
