from datetime import datetime, timezone

import pytest

from api.jurisdictions import (
    JurisdictionNotConfiguredError,
    get_policy,
    retention_deadline,
)


def test_supported_jurisdiction_is_normalized():
    policy = get_policy(" ar ")
    assert policy.code == "AR"
    assert "es" in policy.languages
    assert policy.cross_border_review_required is True


def test_unknown_jurisdiction_fails_closed():
    with pytest.raises(JurisdictionNotConfiguredError):
        get_policy("ZZ")


def test_retention_deadline_is_utc_and_configured():
    policy = get_policy("US")
    created = datetime(2026, 1, 1, tzinfo=timezone.utc)
    assert (
        retention_deadline(created, policy).isoformat() == "2026-01-31T00:00:00+00:00"
    )
