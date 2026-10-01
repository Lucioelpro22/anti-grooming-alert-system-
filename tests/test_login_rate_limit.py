import pytest

from api.login_rate_limit import (
    LoginRateLimitBackendUnavailable,
    LoginRateLimitCapacityExceeded,
    LoginRateLimitStore,
    MemoryLoginRateLimitBackend,
    RedisLoginRateLimitBackend,
    opaque_login_key,
)


class FakePipeline:
    def __init__(self, client):
        self.client = client
        self.operations = []

    def get(self, key):
        self.operations.append(("get", key))
        return self

    def ttl(self, key):
        self.operations.append(("ttl", key))
        return self

    def execute(self):
        results = []
        for operation, key in self.operations:
            if operation == "get":
                results.append(self.client.counts.get(key))
            else:
                results.append(self.client.ttls.get(key, -2))
        return results


class FakeRedis:
    def __init__(self):
        self.counts = {}
        self.ttls = {}

    def pipeline(self, transaction=True):
        assert transaction is True
        return FakePipeline(self)

    def eval(self, script, key_count, key, window_seconds):
        assert "INCR" in script
        assert key_count == 1
        self.counts[key] = self.counts.get(key, 0) + 1
        if self.counts[key] == 1:
            self.ttls[key] = int(window_seconds)
        return self.counts[key]

    def delete(self, key):
        self.counts.pop(key, None)
        self.ttls.pop(key, None)
        return 1


class FailingRedis:
    def pipeline(self, transaction=True):
        raise RuntimeError("redis unavailable")


def test_memory_backend_counts_failures_only_and_success_resets():
    backend = MemoryLoginRateLimitBackend()
    key = opaque_login_key("127.0.0.1", "Alice")

    assert backend.check(key, 2, 300).allowed is True
    backend.failure(key, 2, 300)
    assert backend.check(key, 2, 300).allowed is True
    backend.failure(key, 2, 300)

    blocked = backend.check(key, 2, 300)
    assert blocked.allowed is False
    assert blocked.retry_after >= 1

    backend.success(key)
    assert backend.check(key, 2, 300).allowed is True


def test_memory_backend_never_evicts_live_failure_state_at_capacity():
    backend = MemoryLoginRateLimitBackend(max_keys=1)
    first = opaque_login_key("127.0.0.1", "alice")
    second = opaque_login_key("127.0.0.2", "bob")

    backend.failure(first, 5, 300)
    with pytest.raises(LoginRateLimitCapacityExceeded):
        backend.failure(second, 5, 300)

    assert backend.check(first, 1, 300).allowed is False


def test_two_redis_workers_share_failed_login_counter():
    redis = FakeRedis()
    worker_a = RedisLoginRateLimitBackend(redis)
    worker_b = RedisLoginRateLimitBackend(redis)
    key = opaque_login_key("203.0.113.10", "admin")

    for index in range(5):
        worker = worker_a if index % 2 == 0 else worker_b
        worker.failure(key, 5, 300)

    decision = worker_b.check(key, 5, 300)
    assert decision.allowed is False
    assert decision.retry_after == 300

    worker_a.success(key)
    assert worker_b.check(key, 5, 300).allowed is True


def test_redis_key_does_not_expose_username_or_ip():
    redis = FakeRedis()
    backend = RedisLoginRateLimitBackend(redis)
    key = opaque_login_key("203.0.113.10", "Sensitive.User")
    backend.failure(key, 5, 300)

    stored_key = next(iter(redis.counts))
    assert "Sensitive.User" not in stored_key
    assert "sensitive.user" not in stored_key
    assert "203.0.113.10" not in stored_key


def test_store_fails_closed_when_redis_is_unavailable(monkeypatch):
    store = LoginRateLimitStore()
    monkeypatch.setenv("LOGIN_RATE_LIMIT_BACKEND", "redis")
    monkeypatch.setenv("REDIS_URL", "redis://example")
    store._redis_backend = RedisLoginRateLimitBackend(FailingRedis())
    store._redis_url = "redis://example"

    with pytest.raises(LoginRateLimitBackendUnavailable):
        store.check("opaque")


@pytest.mark.parametrize(
    ("name", "value"),
    [
        ("LOGIN_RATE_LIMIT_ATTEMPTS", "0"),
        ("LOGIN_RATE_LIMIT_ATTEMPTS", "invalid"),
        ("LOGIN_RATE_LIMIT_WINDOW_SECONDS", "-1"),
    ],
)
def test_invalid_login_rate_limit_configuration_is_rejected(
    monkeypatch, name, value
):
    monkeypatch.setenv(name, value)

    with pytest.raises(RuntimeError):
        LoginRateLimitStore().validate_configuration()
