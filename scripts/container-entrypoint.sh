#!/bin/sh
set -eu

umask 077

if [ "${APP_ENV:-development}" = "production" ]; then
  python -m scripts.check_production_config
fi

exec uvicorn api.main:app \
  --host 0.0.0.0 \
  --port "${PORT:-8000}" \
  --workers 1 \
  --no-proxy-headers \
  --no-server-header \
  --limit-concurrency "${UVICORN_LIMIT_CONCURRENCY:-200}" \
  --timeout-keep-alive "${UVICORN_KEEP_ALIVE_SECONDS:-5}"
