import pytest

from api import token_revocation
from api.token_revocation import (
    MemoryTokenRevocationBackend,
    RedisTokenRevocationBackend,
    RevocationBackendUnavailable,
    RevocationCapacityExceeded,
    TokenRevocationStore,
)


def test_memory_backend_never_evicts_active_revocation(monkeypatch):
    monkeypatch.setattr(token_revocation.time, "time", lambda: 100.0)
    backend = MemoryTokenRevocationBackend(max_entries=1)
    backend.revoke("first-token", 200.0)

    with pytest.raises(RevocationCapacityExceeded):
        backend.revoke("second-token", 200.0)

    assert backend.is_revoked("first-token") is True
    assert backend.is_revoked("second-token") is False


def test_memory_backend_prunes_only_expired_entries(monkeypatch):
    now = {"value": 100.0}
    monkeypatch.setattr(token_revocation.time, "time", lambda: now["value"])
    backend = MemoryTokenRevocationBackend(max_entries=1)
    backend.revoke("first-token", 105.0)

    now["value"] = 106.0
    backend.revoke("second-token", 120.0)

    assert backend.is_revoked("first-token") is False
    assert backend.is_revoked("second-token") is True


def test_redis_backend_uses_hashed_key_and_token_ttl(monkeypatch):
    class FakeRedis:
        def __init__(self):
            self.values = {}

        def set(self, key, value, ex):
            self.values[key] = (value, ex)

        def exists(self, key):
            return int(key in self.values)

    monkeypatch.setattr(token_revocation.time, "time", lambda: 100.0)
    client = FakeRedis()
    backend = RedisTokenRevocationBackend(client)

    backend.revoke("sensitive-jti", 115.2)

    assert len(client.values) == 1
    key, (value, ttl) = next(iter(client.values.items()))
    assert "sensitive-jti" not in key
    assert value == "1"
    assert ttl == 16
    assert backend.is_revoked("sensitive-jti") is True


def test_store_fails_closed_when_redis_is_selected_without_url(monkeypatch):
    monkeypatch.setenv("TOKEN_REVOCATION_BACKEND", "redis")
    monkeypatch.delenv("REDIS_URL", raising=False)
    store = TokenRevocationStore()

    with pytest.raises(RuntimeError):
        store.validate_configuration()
    with pytest.raises(RevocationBackendUnavailable):
        store.is_revoked("token")
