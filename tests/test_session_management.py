import pytest

from api import session_management
from api.session_management import (
    InvalidRefreshToken,
    MemorySessionBackend,
    RefreshReuseDetected,
    SessionCapacityExceeded,
    SessionStore,
)


def test_memory_refresh_rotation_is_single_use(monkeypatch):
    now = {"value": 100.0}
    monkeypatch.setattr(session_management.time, "time", lambda: now["value"])
    backend = MemorySessionBackend(max_entries=10)

    first = backend.issue("alice", "analyst", 600)
    second = backend.rotate(first.refresh_token, 600)

    assert second.username == "alice"
    assert second.role == "analyst"
    assert second.refresh_token != first.refresh_token
    assert backend.current_version("alice") == 0

    with pytest.raises(RefreshReuseDetected):
        backend.rotate(first.refresh_token, 600)

    assert backend.current_version("alice") == 1
    with pytest.raises(InvalidRefreshToken):
        backend.rotate(second.refresh_token, 600)


def test_logout_all_invalidates_existing_refresh_tokens():
    backend = MemorySessionBackend(max_entries=10)
    first = backend.issue("alice", "analyst", 600)
    second = backend.issue("alice", "analyst", 600)

    assert backend.logout_all("alice") == 1

    for token in (first.refresh_token, second.refresh_token):
        with pytest.raises(RefreshReuseDetected):
            backend.rotate(token, 600)

    assert backend.current_version("alice") >= 2


def test_capacity_fails_closed_without_evicting_live_session():
    backend = MemorySessionBackend(max_entries=1)
    first = backend.issue("alice", "analyst", 600)

    with pytest.raises(SessionCapacityExceeded):
        backend.issue("bob", "analyst", 600)

    assert backend.current_version("alice") == 0
    with pytest.raises(SessionCapacityExceeded):
        backend.rotate(first.refresh_token, 600)


@pytest.mark.parametrize("days", ["0", "31", "invalid"])
def test_refresh_ttl_configuration_is_bounded(monkeypatch, days):
    monkeypatch.setenv("REFRESH_TOKEN_DAYS", days)
    store = SessionStore()

    with pytest.raises(RuntimeError):
        store.refresh_ttl_seconds()
