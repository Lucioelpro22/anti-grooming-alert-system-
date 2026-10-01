# Production Security Profile

This document defines the minimum deployment posture for the API when
`APP_ENV=production`. The application refuses to start when these invariants are
not satisfied.

## Required distributed controls

All security state that must survive multiple workers is required to use Redis:

- `RATE_LIMIT_BACKEND=redis`
- `LOGIN_RATE_LIMIT_BACKEND=redis`
- `TOKEN_REVOCATION_BACKEND=redis`
- `SESSION_BACKEND=redis`
- `MFA_STATE_BACKEND=redis`

Memory backends remain available only for development, tests, or a deliberately
single-process non-production deployment.

## Redis transport and authentication

Production requires `REDIS_URL` to use `rediss://`. Plaintext `redis://`,
loopback endpoints, disabled certificate verification, and disabled hostname
verification are rejected.

The connection must authenticate either with a password/token in the URL or with
both a client certificate and client key for mTLS. Server certificate validation
must remain enabled. Example:

```text
rediss://redis.example.org:6380/0?ssl_cert_reqs=required&ssl_check_hostname=true&ssl_certfile=/run/secrets/redis-client.crt&ssl_keyfile=/run/secrets/redis-client.key
```

For private PKI, add the appropriate CA path supported by redis-py. Never set
`ssl_cert_reqs=none` or disable hostname verification.

## HTTP perimeter

`ALLOWED_HOSTS_JSON` must contain exact production hosts. Wildcards, localhost,
and loopback hosts are rejected.

Browser origins, when used, must be exact HTTPS origins in
`ALLOWED_ORIGINS_JSON`. Empty origins are valid for non-browser API clients.
HTTP origins, embedded credentials, query strings, fragments, and loopback
origins are rejected.

Terminate public TLS at a hardened reverse proxy/load balancer and forward only
from explicitly trusted proxy addresses. Do not expose the Uvicorn worker
directly to the public internet.

## Authentication and MFA

Production requires MFA policy coverage for `admin`, `supervisor`, and
`auditor`. JWT signing keys, audit keys, evidence-encryption keys, MFA secrets,
database credentials, Redis credentials, and recovery material should be
injected by the deployment platform's secret manager rather than committed files.

Use the existing key-ring mechanisms for rotation. Do not remove historical keys
until every artifact/token that references them has expired or been migrated.

## Audit and storage paths

The evidence audit checkpoint and authentication-security checkpoint must use
separate absolute paths. The authentication checkpoint must remain outside the
security-event log directory. Existing parent directories that are
world-writable are rejected.

Back up the log and checkpoint independently. Restoring one without the matching
trusted checkpoint should be treated as an integrity incident.

## PostgreSQL

If `DATABASE_URL` is configured in production, only PostgreSQL is accepted and
`sslmode=verify-full` is required. Loopback database targets are rejected.

## Preflight

Run this in the exact production container/VM after secrets and mounted storage
are injected, before routing traffic:

```bash
python -m scripts.check_production_config
```

The command performs the same configuration validation used at startup and
verifies the evidence and security audit checkpoints. It prints only a success
marker and never prints secret values.

## Deployment checklist

1. Set `APP_ENV=production`.
2. Configure all five critical backends to Redis.
3. Use authenticated `rediss://` with certificate and hostname verification.
4. Use exact production hosts and HTTPS browser origins.
5. Keep MFA mandatory for all sensitive roles.
6. Inject secrets through a secret manager and restrict who can read them.
7. Mount audit/checkpoint storage with independent backups and restrictive
   filesystem permissions.
8. Use PostgreSQL `sslmode=verify-full` when database persistence is enabled.
9. Run the production preflight.
10. Start the service only after the preflight succeeds.
11. Monitor security-event entries where `alert=true` and forward them to a
    protected central logging/SIEM destination.
12. Rotate credentials and cryptographic keys on a documented schedule and after
    any suspected exposure.
