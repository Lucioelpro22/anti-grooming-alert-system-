"""Evidence lifecycle rules; legal hold always wins over deletion."""

from datetime import datetime, timedelta, timezone
from enum import Enum


class EvidenceStatus(str, Enum):
    ACTIVE = "ACTIVE"
    ARCHIVED = "ARCHIVED"
    LEGAL_HOLD = "LEGAL_HOLD"
    DELETION_PENDING = "DELETION_PENDING"


def retention_deadline(created_at: datetime, retention_days: int) -> datetime:
    if retention_days <= 0:
        raise ValueError("retention_days debe ser positivo")
    timestamp = created_at.astimezone(timezone.utc)
    return timestamp + timedelta(days=retention_days)


def can_transition(current: EvidenceStatus, target: EvidenceStatus) -> bool:
    if current == EvidenceStatus.LEGAL_HOLD and target != EvidenceStatus.LEGAL_HOLD:
        return False
    if target == EvidenceStatus.DELETION_PENDING:
        return current in {EvidenceStatus.ACTIVE, EvidenceStatus.ARCHIVED}
    if current == EvidenceStatus.ACTIVE:
        return target in {EvidenceStatus.ARCHIVED, EvidenceStatus.LEGAL_HOLD}
    if current == EvidenceStatus.ARCHIVED:
        return target in {EvidenceStatus.ACTIVE, EvidenceStatus.LEGAL_HOLD}
    return current == target
