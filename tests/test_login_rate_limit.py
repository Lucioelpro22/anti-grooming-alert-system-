import pytest

from api import login_rate_limit
from api.login_rate_limit import (
    LoginRateLimitBackendUnavailable,
    LoginRateLimitCapacityExceeded,
    LoginRateLimitPolicy,
    LoginRateLimitStore,
    MemoryLoginRateLimitBackend,
    RedisLoginRateLimitBackend,
    opaque_login_key,
    opaque_scope_key,
)


def policy(
    attempts=2,
    window_seconds=300,
    backoff_base_seconds=10,
    backoff_max_seconds=40,
):
    return LoginRateLimitPolicy(
        attempts=attempts,
        window_seconds=window_seconds,
        backoff_base_seconds=backoff_base_seconds,
        backoff_max_seconds=backoff_max_seconds,
    )


class FakeRedis:
    def __init__(self):
        self.states = {}
        self.now = 100

    def eval(self, script, key_count, key, *args):
        assert key_count == 1
        state = self.states.setdefault(
            key,
            {"count": 0, "level": 0, "block_until": 0},
        )
        if "HINCRBY" not in script:
            if state["block_until"] > self.now:
                return [0, state["block_until"] - self.now]
            return [1, 0]

        attempts, _, base, maximum = (int(value) for value in args)
        state["count"] += 1
        if state["count"] >= attempts:
            state["level"] += 1
            delay = min(maximum, base * (2 ** (state["level"] - 1)))
            state["block_until"] = self.now + delay
        return state["count"]

    def delete(self, key):
        self.states.pop(key, None)
        return 1


class FailingRedis:
    def eval(self, *args, **kwargs):
        raise RuntimeError("redis unavailable")

    def delete(self, key):
        raise RuntimeError("redis unavailable")


def test_memory_backend_progressively_increases_backoff(monkeypatch):
    now = {"value": 100.0}
    monkeypatch.setattr(login_rate_limit.time, "monotonic", lambda: now["value"])
    backend = MemoryLoginRateLimitBackend()
    key = opaque_login_key("127.0.0.1", "alice")
    limits = policy()

    backend.failure(key, limits)
    assert backend.check(key, limits).allowed is True

    backend.failure(key, limits)
    first = backend.check(key, limits)
    assert first.allowed is False
    assert first.retry_after == 10

    now["value"] = 111.0
    assert backend.check(key, limits).allowed is True

    backend.failure(key, limits)
    second = backend.check(key, limits)
    assert second.allowed is False
    assert second.retry_after == 20

    now["value"] = 132.0
    assert backend.check(key, limits).allowed is True

    backend.failure(key, limits)
    third = backend.check(key, limits)
    assert third.allowed is False
    assert third.retry_after == 40


def test_memory_backend_never_evicts_live_scope_at_capacity(monkeypatch):
    now = {"value": 100.0}
    monkeypatch.setattr(login_rate_limit.time, "monotonic", lambda: now["value"])
    backend = MemoryLoginRateLimitBackend(max_keys=1)
    first = opaque_login_key("127.0.0.1", "alice")
    second = opaque_login_key("127.0.0.2", "bob")
    limits = policy(attempts=5)

    backend.failure(first, limits)
    with pytest.raises(LoginRateLimitCapacityExceeded):
        backend.failure(second, limits)

    assert backend.check(first, limits).allowed is True


def test_memory_backend_keeps_independent_scope_expiry(monkeypatch):
    now = {"value": 100.0}
    monkeypatch.setattr(login_rate_limit.time, "monotonic", lambda: now["value"])
    backend = MemoryLoginRateLimitBackend(max_keys=2)
    short = policy(attempts=5, window_seconds=30)
    long = policy(attempts=5, window_seconds=900)
    short_key = opaque_scope_key("pair", "short")
    long_key = opaque_scope_key("account", "long")

    backend.failure(short_key, short)
    backend.failure(long_key, long)
    now["value"] = 140.0

    backend.failure(opaque_scope_key("pair", "replacement"), short)
    assert backend.check(long_key, long).allowed is True


def test_scope_keys_detect_rotating_ips_and_rotating_usernames():
    account_a = opaque_scope_key("account", "alice")
    account_b = opaque_scope_key("account", "alice")
    client_a = opaque_scope_key("client", "203.0.113.10")
    client_b = opaque_scope_key("client", "203.0.113.10")
    pair_a = opaque_login_key("203.0.113.10", "alice")
    pair_b = opaque_login_key("203.0.113.11", "alice")

    assert account_a == account_b
    assert client_a == client_b
    assert pair_a != pair_b


def test_two_redis_workers_share_progressive_state():
    redis = FakeRedis()
    worker_a = RedisLoginRateLimitBackend(redis)
    worker_b = RedisLoginRateLimitBackend(redis)
    key = opaque_scope_key("account", "alice")
    limits = policy()

    worker_a.failure(key, limits)
    worker_b.failure(key, limits)
    first = worker_b.check(key, limits)
    assert first.allowed is False
    assert first.retry_after == 10

    redis.now = 111
    assert worker_a.check(key, limits).allowed is True
    worker_b.failure(key, limits)

    second = worker_a.check(key, limits)
    assert second.allowed is False
    assert second.retry_after == 20


def test_redis_key_does_not_expose_username_or_ip():
    redis = FakeRedis()
    backend = RedisLoginRateLimitBackend(redis)
    raw_user = "Sensitive.User"
    raw_ip = "203.0.113.10"
    key = opaque_login_key(raw_ip, raw_user)
    backend.failure(key, policy())

    stored_key = next(iter(redis.states))
    assert raw_user not in stored_key
    assert raw_user.lower() not in stored_key
    assert raw_ip not in stored_key


def test_store_fails_closed_when_redis_is_unavailable(monkeypatch):
    store = LoginRateLimitStore()
    monkeypatch.setenv("LOGIN_RATE_LIMIT_BACKEND", "redis")
    monkeypatch.setenv("REDIS_URL", "redis://example")
    store._redis_backend = RedisLoginRateLimitBackend(FailingRedis())
    store._redis_url = "redis://example"

    with pytest.raises(LoginRateLimitBackendUnavailable):
        store.check("opaque", policy())


def test_pair_policy_keeps_legacy_environment_compatibility(monkeypatch):
    monkeypatch.setenv("LOGIN_RATE_LIMIT_ATTEMPTS", "7")
    monkeypatch.setenv("LOGIN_RATE_LIMIT_WINDOW_SECONDS", "420")
    monkeypatch.delenv("LOGIN_PAIR_ATTEMPTS", raising=False)
    monkeypatch.delenv("LOGIN_PAIR_WINDOW_SECONDS", raising=False)

    limits = LoginRateLimitStore().policy("pair")
    assert limits.attempts == 7
    assert limits.window_seconds == 420


@pytest.mark.parametrize(
    ("name", "value"),
    [
        ("LOGIN_PAIR_ATTEMPTS", "0"),
        ("LOGIN_ACCOUNT_ATTEMPTS", "invalid"),
        ("LOGIN_CLIENT_WINDOW_SECONDS", "-1"),
        ("LOGIN_BACKOFF_BASE_SECONDS", "0"),
    ],
)
def test_invalid_login_rate_limit_configuration_is_rejected(monkeypatch, name, value):
    monkeypatch.setenv(name, value)

    with pytest.raises(RuntimeError):
        LoginRateLimitStore().validate_configuration()


def test_backoff_maximum_cannot_be_lower_than_base(monkeypatch):
    monkeypatch.setenv("LOGIN_BACKOFF_BASE_SECONDS", "60")
    monkeypatch.setenv("LOGIN_BACKOFF_MAX_SECONDS", "30")

    with pytest.raises(RuntimeError):
        LoginRateLimitStore().validate_configuration()


def test_redis_mode_requires_redis_url(monkeypatch):
    monkeypatch.setenv("LOGIN_RATE_LIMIT_BACKEND", "redis")
    monkeypatch.delenv("REDIS_URL", raising=False)

    with pytest.raises(RuntimeError):
        LoginRateLimitStore().validate_configuration()
