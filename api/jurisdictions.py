import json
import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import MappingProxyType
from typing import Mapping


class JurisdictionNotConfiguredError(ValueError):
    """The requested country has no reviewed operational policy."""


@dataclass(frozen=True)
class JurisdictionPolicy:
    code: str
    name: str
    languages: tuple[str, ...]
    recommended_retention_days: int
    reporting_channels: tuple[str, ...]
    cross_border_review_required: bool


_CODE_PATTERN = re.compile(r"^[A-Z]{2}$")
_CONFIG_PATH = Path(__file__).with_name("jurisdictions.json")


def _load_policies() -> Mapping[str, JurisdictionPolicy]:
    try:
        raw = json.loads(_CONFIG_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeError("Configuración de jurisdicciones inválida") from exc
    if not isinstance(raw, dict):
        raise RuntimeError("Configuración de jurisdicciones inválida")
    policies: dict[str, JurisdictionPolicy] = {}
    for code, item in raw.items():
        if not isinstance(code, str) or not _CODE_PATTERN.fullmatch(code):
            raise RuntimeError("Código de jurisdicción inválido")
        if not isinstance(item, dict):
            raise RuntimeError("Política de jurisdicción inválida")
        try:
            languages = tuple(item["languages"])
            channels = tuple(item["reporting_channels"])
            retention = int(item["recommended_retention_days"])
            policy = JurisdictionPolicy(
                code=code,
                name=str(item["name"]),
                languages=languages,
                recommended_retention_days=retention,
                reporting_channels=channels,
                cross_border_review_required=bool(item["cross_border_review_required"]),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise RuntimeError("Política de jurisdicción inválida") from exc
        if (
            not policy.name
            or not policy.languages
            or not all(isinstance(value, str) and value for value in policy.languages)
            or not policy.reporting_channels
            or not all(
                isinstance(value, str) and value for value in policy.reporting_channels
            )
            or policy.recommended_retention_days <= 0
        ):
            raise RuntimeError("Política de jurisdicción inválida")
        policies[code] = policy
    return MappingProxyType(policies)


POLICIES = _load_policies()


def get_policy(country_code: str) -> JurisdictionPolicy:
    normalized = country_code.strip().upper()
    if not _CODE_PATTERN.fullmatch(normalized) or normalized not in POLICIES:
        raise JurisdictionNotConfiguredError(
            "No hay una política revisada para esa jurisdicción"
        )
    return POLICIES[normalized]


def retention_deadline(created_at: datetime, policy: JurisdictionPolicy) -> datetime:
    if created_at.tzinfo is None:
        created_at = created_at.replace(tzinfo=timezone.utc)
    return created_at.astimezone(timezone.utc) + timedelta(
        days=policy.recommended_retention_days
    )
