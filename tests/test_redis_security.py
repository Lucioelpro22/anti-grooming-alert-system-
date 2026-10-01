import pytest

from api.redis_security import (
    RedisSecurityConfigurationError,
    validate_redis_url,
)


def test_plain_redis_remains_available_outside_production():
    validate_redis_url("redis://localhost:6379/0", production=False)


def test_production_requires_rediss():
    with pytest.raises(RedisSecurityConfigurationError, match="rediss"):
        validate_redis_url(
            "redis://default:secret@redis.example.org:6379/0",
            production=True,
        )


def test_production_accepts_authenticated_verified_tls():
    validate_redis_url(
        "rediss://default:secret@redis.example.org:6380/0"
        "?ssl_cert_reqs=required&ssl_check_hostname=true",
        production=True,
    )


def test_production_accepts_mtls_authentication():
    validate_redis_url(
        "rediss://redis.example.org:6380/0"
        "?ssl_cert_reqs=required"
        "&ssl_certfile=/run/secrets/redis-client.crt"
        "&ssl_keyfile=/run/secrets/redis-client.key",
        production=True,
    )


@pytest.mark.parametrize(
    "url",
    [
        "rediss://default:secret@redis.example.org:6380/0?ssl_cert_reqs=none",
        (
            "rediss://default:secret@redis.example.org:6380/0"
            "?ssl_check_hostname=false"
        ),
        "rediss://default:secret@localhost:6380/0",
        "rediss://default:secret@127.0.0.1:6380/0",
        "rediss://redis.example.org:6380/0",
    ],
)
def test_production_rejects_unsafe_redis_urls(url):
    with pytest.raises(RedisSecurityConfigurationError):
        validate_redis_url(url, production=True)


def test_mtls_requires_certificate_and_key_together():
    with pytest.raises(RedisSecurityConfigurationError, match="mTLS"):
        validate_redis_url(
            "rediss://redis.example.org:6380/0"
            "?ssl_certfile=/run/secrets/redis-client.crt",
            production=True,
        )
