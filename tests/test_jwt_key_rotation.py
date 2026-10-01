import json

import pytest

from api.jwt_key_management import (
    JWTKeyConfigurationError,
    JWTKeyNotFound,
    current_jwt_key,
    jwt_key_for,
    load_jwt_keyring,
)


LEGACY = "legacy-secret-that-is-longer-than-thirty-two-bytes"
ROTATED = "rotated-secret-that-is-longer-than-thirty-two-bytes"


def test_legacy_single_secret_configuration(monkeypatch):
    monkeypatch.setenv("JWT_SECRET", LEGACY)
    monkeypatch.delenv("JWT_SECRETS_JSON", raising=False)
    monkeypatch.delenv("JWT_CURRENT_KEY_ID", raising=False)

    assert load_jwt_keyring() == {"legacy": LEGACY}
    assert current_jwt_key() == ("legacy", LEGACY)


def test_versioned_keyring_selects_current_key(monkeypatch):
    monkeypatch.setenv(
        "JWT_SECRETS_JSON",
        json.dumps({"legacy": LEGACY, "v2": ROTATED}),
    )
    monkeypatch.setenv("JWT_CURRENT_KEY_ID", "v2")
    monkeypatch.delenv("JWT_SECRET", raising=False)

    assert current_jwt_key() == ("v2", ROTATED)
    assert jwt_key_for("legacy") == LEGACY


def test_unknown_historical_key_is_rejected(monkeypatch):
    monkeypatch.setenv("JWT_SECRETS_JSON", json.dumps({"v2": ROTATED}))
    monkeypatch.setenv("JWT_CURRENT_KEY_ID", "v2")

    with pytest.raises(JWTKeyNotFound):
        jwt_key_for("legacy")


@pytest.mark.parametrize(
    "raw",
    [
        "{}",
        "[]",
        "not-json",
        json.dumps({"v2": "short"}),
        json.dumps({"": ROTATED}),
        json.dumps({"x" * 65: ROTATED}),
    ],
)
def test_invalid_jwt_keyring_is_rejected(monkeypatch, raw):
    monkeypatch.setenv("JWT_SECRETS_JSON", raw)

    with pytest.raises(JWTKeyConfigurationError):
        load_jwt_keyring()


def test_duplicate_secrets_under_multiple_ids_are_rejected(monkeypatch):
    monkeypatch.setenv(
        "JWT_SECRETS_JSON",
        json.dumps({"v1": ROTATED, "v2": ROTATED}),
    )

    with pytest.raises(JWTKeyConfigurationError, match="distinto"):
        load_jwt_keyring()


def test_current_key_id_must_exist(monkeypatch):
    monkeypatch.setenv("JWT_SECRETS_JSON", json.dumps({"v2": ROTATED}))
    monkeypatch.setenv("JWT_CURRENT_KEY_ID", "missing")

    with pytest.raises(JWTKeyConfigurationError, match="CURRENT_KEY_ID"):
        current_jwt_key()
