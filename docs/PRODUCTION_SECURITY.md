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

## Trusted reverse proxies and client IP

The API does not trust `Forwarded`, `X-Forwarded-For`, or
`CF-Connecting-IP` just because the header exists. Forwarding data is consumed
only when the immediate TCP peer belongs to an explicit CIDR in
`TRUSTED_PROXY_CIDRS_JSON`.

Select exactly one source with `CLIENT_IP_HEADER`:

- `none`: ignore all forwarding headers and use the direct peer;
- `x-forwarded-for`: for Nginx, ingress controllers, and load balancers that
  maintain a sanitized XFF chain;
- `forwarded`: for proxies using the standardized `Forwarded: for=` chain;
- `cf-connecting-ip`: for a Cloudflare-only edge where the origin or trusted
  internal proxy accepts traffic only from the expected Cloudflare path.

Example for an internal reverse proxy:

```text
CLIENT_IP_HEADER=x-forwarded-for
TRUSTED_PROXY_CIDRS_JSON=["10.20.0.0/16","2001:db8:100::/48"]
MAX_FORWARDED_HOPS=10
```

The resolver walks XFF/Forwarded from the nearest hop toward the client and stops
at the first untrusted address. This prevents an attacker-supplied leftmost XFF
value from becoming the rate-limit identity merely because a trusted proxy
appended its own hop.

Never configure `0.0.0.0/0` or `::/0` as a trusted proxy. For a cloud/CDN
provider, maintain only the provider's published proxy ranges and update them
through a controlled deployment process.

The reverse proxy must overwrite/sanitize the selected header and the application
origin must not be directly reachable from arbitrary internet clients. Otherwise
an attacker can bypass the proxy policy entirely.

### Nginx pattern

Configure Nginx to replace the client-IP header from its own trusted network
context rather than forwarding an arbitrary inbound value unchanged. Point
`TRUSTED_PROXY_CIDRS_JSON` at the Nginx/ingress subnet visible to Uvicorn and
select the header Nginx writes.

### Cloudflare pattern

When using `CLIENT_IP_HEADER=cf-connecting-ip`, restrict origin ingress to the
expected Cloudflare/proxy path and list only those immediate trusted proxy
networks. The API rejects duplicate `CF-Connecting-IP` values from a trusted
peer.

Malformed forwarding data from a trusted proxy is rejected with HTTP 400.
Invalid proxy configuration fails closed. The resolved address is used
consistently by global rate limiting, login/password-spraying detection, and the
pseudonymized authentication security audit.

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
