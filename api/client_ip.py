"""Trusted-proxy client IP resolution.

Forwarding headers are never trusted merely because they are present. They are
only considered when the immediate network peer belongs to an explicitly
configured trusted proxy CIDR.
"""

from __future__ import annotations

import ipaddress
import json
import os
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from typing import Any

_SUPPORTED_HEADERS = {
    "none",
    "x-forwarded-for",
    "forwarded",
    "cf-connecting-ip",
}
_MAX_HOPS_LIMIT = 50


class ClientIPConfigurationError(RuntimeError):
    """Trusted-proxy configuration is missing or unsafe."""


class ClientIPResolutionError(RuntimeError):
    """A trusted proxy supplied a malformed or ambiguous client-IP header."""


@dataclass(frozen=True)
class ClientIPResult:
    address: str
    source: str
    trusted_proxy: bool


def _positive_hops() -> int:
    raw = os.getenv("MAX_FORWARDED_HOPS", "10")
    try:
        value = int(raw)
    except ValueError as exc:
        raise ClientIPConfigurationError("MAX_FORWARDED_HOPS inválido") from exc
    if value <= 0 or value > _MAX_HOPS_LIMIT:
        raise ClientIPConfigurationError(
            f"MAX_FORWARDED_HOPS debe estar entre 1 y {_MAX_HOPS_LIMIT}"
        )
    return value


def client_ip_header_mode() -> str:
    value = os.getenv("CLIENT_IP_HEADER", "none").strip().lower()
    if value not in _SUPPORTED_HEADERS:
        raise ClientIPConfigurationError(
            "CLIENT_IP_HEADER debe ser none, x-forwarded-for, forwarded "
            "o cf-connecting-ip"
        )
    return value


def load_trusted_proxy_networks() -> tuple[
    ipaddress.IPv4Network | ipaddress.IPv6Network, ...
]:
    raw = os.getenv("TRUSTED_PROXY_CIDRS_JSON", "[]")
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ClientIPConfigurationError(
            "TRUSTED_PROXY_CIDRS_JSON debe ser una lista JSON"
        ) from exc
    if not isinstance(parsed, list) or not all(
        isinstance(value, str) and value.strip() for value in parsed
    ):
        raise ClientIPConfigurationError(
            "TRUSTED_PROXY_CIDRS_JSON debe ser una lista JSON de CIDRs"
        )

    networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
    for value in parsed:
        try:
            network = ipaddress.ip_network(value.strip(), strict=True)
        except ValueError as exc:
            raise ClientIPConfigurationError(
                "TRUSTED_PROXY_CIDRS_JSON contiene una CIDR inválida"
            ) from exc
        if network.prefixlen == 0:
            raise ClientIPConfigurationError(
                "No se permite confiar en todo Internet como proxy"
            )
        networks.append(network)
    return tuple(networks)


def validate_client_ip_configuration(*, production: bool = False) -> None:
    mode = client_ip_header_mode()
    networks = load_trusted_proxy_networks()
    _positive_hops()

    if mode == "none" and networks:
        raise ClientIPConfigurationError(
            "TRUSTED_PROXY_CIDRS_JSON requiere CLIENT_IP_HEADER explícito"
        )
    if mode != "none" and not networks:
        raise ClientIPConfigurationError(
            "CLIENT_IP_HEADER requiere TRUSTED_PROXY_CIDRS_JSON"
        )
    if production and mode != "none":
        for network in networks:
            if network.is_unspecified or network.is_multicast:
                raise ClientIPConfigurationError(
                    "Producción contiene una red de proxy no enrutable/insegura"
                )


def _canonical_address(value: str) -> str:
    parsed = ipaddress.ip_address(value)
    if isinstance(parsed, ipaddress.IPv6Address) and parsed.ipv4_mapped:
        return str(parsed.ipv4_mapped)
    return str(parsed)


def _parse_ip(value: str) -> str:
    raw = value.strip()
    if not raw:
        raise ClientIPResolutionError("Dirección de cliente vacía")

    if len(raw) >= 2 and raw[0] == '"' and raw[-1] == '"':
        raw = raw[1:-1].strip()
    if not raw or raw.lower() == "unknown" or raw.startswith("_"):
        raise ClientIPResolutionError("Dirección de cliente no verificable")

    host = raw
    if raw.startswith("["):
        closing = raw.find("]")
        if closing <= 1:
            raise ClientIPResolutionError("IPv6 de proxy inválida")
        host = raw[1:closing]
        suffix = raw[closing + 1 :]
        if suffix and (not suffix.startswith(":") or not suffix[1:].isdigit()):
            raise ClientIPResolutionError("Puerto de proxy inválido")
    else:
        try:
            return _canonical_address(raw)
        except ValueError:
            if raw.count(":") == 1:
                candidate, port = raw.rsplit(":", 1)
                if port.isdigit():
                    host = candidate
                else:
                    raise ClientIPResolutionError(
                        "Dirección de proxy inválida"
                    ) from None

    try:
        return _canonical_address(host)
    except ValueError as exc:
        raise ClientIPResolutionError("Dirección de proxy inválida") from exc


def _header_values(
    raw_headers: Sequence[tuple[bytes, bytes]],
    name: bytes,
) -> list[str]:
    values: list[str] = []
    for key, value in raw_headers:
        if key.lower() == name:
            try:
                values.append(value.decode("latin-1"))
            except UnicodeDecodeError as exc:
                raise ClientIPResolutionError(
                    "Encabezado de proxy no decodificable"
                ) from exc
    return values


def _parse_x_forwarded_for(values: Sequence[str]) -> list[str]:
    tokens: list[str] = []
    for value in values:
        tokens.extend(piece.strip() for piece in value.split(","))
    if not tokens or any(not token for token in tokens):
        raise ClientIPResolutionError("X-Forwarded-For inválido")
    return [_parse_ip(token) for token in tokens]


def _parse_forwarded(values: Sequence[str]) -> list[str]:
    elements: list[str] = []
    for value in values:
        elements.extend(piece.strip() for piece in value.split(","))
    if not elements or any(not element for element in elements):
        raise ClientIPResolutionError("Forwarded inválido")

    addresses: list[str] = []
    for element in elements:
        found: list[str] = []
        for parameter in element.split(";"):
            name, separator, raw_value = parameter.strip().partition("=")
            if separator and name.strip().lower() == "for":
                found.append(raw_value.strip())
        if len(found) != 1:
            raise ClientIPResolutionError(
                "Cada elemento Forwarded debe tener un único parámetro for"
            )
        addresses.append(_parse_ip(found[0]))
    return addresses


def _is_trusted(
    address: str,
    networks: Iterable[ipaddress.IPv4Network | ipaddress.IPv6Network],
) -> bool:
    try:
        parsed = ipaddress.ip_address(_canonical_address(address))
    except ValueError:
        return False
    return any(parsed.version == network.version and parsed in network for network in networks)


def _resolve_chain(
    forwarded: Sequence[str],
    peer: str,
    networks: tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...],
) -> str:
    if len(forwarded) > _positive_hops():
        raise ClientIPResolutionError("Cadena de proxies demasiado larga")

    current = peer
    for candidate in reversed(forwarded):
        if not _is_trusted(current, networks):
            break
        current = candidate
    return current


def resolve_client_ip(
    peer_host: str | None,
    raw_headers: Sequence[tuple[bytes, bytes]],
) -> ClientIPResult:
    mode = client_ip_header_mode()
    networks = load_trusted_proxy_networks()
    _positive_hops()

    if not peer_host:
        return ClientIPResult("unknown", "peer", False)

    try:
        peer_ip = _canonical_address(peer_host)
    except ValueError:
        if mode == "none":
            return ClientIPResult(peer_host, "peer", False)
        raise ClientIPResolutionError(
            "El peer inmediato no es una dirección IP válida"
        ) from None

    if mode == "none" or not _is_trusted(peer_ip, networks):
        return ClientIPResult(peer_ip, "peer", False)

    if mode == "x-forwarded-for":
        values = _header_values(raw_headers, b"x-forwarded-for")
        if not values:
            raise ClientIPResolutionError(
                "Proxy confiable sin X-Forwarded-For"
            )
        address = _resolve_chain(
            _parse_x_forwarded_for(values),
            peer_ip,
            networks,
        )
    elif mode == "forwarded":
        values = _header_values(raw_headers, b"forwarded")
        if not values:
            raise ClientIPResolutionError("Proxy confiable sin Forwarded")
        address = _resolve_chain(
            _parse_forwarded(values),
            peer_ip,
            networks,
        )
    else:
        values = _header_values(raw_headers, b"cf-connecting-ip")
        if len(values) != 1:
            raise ClientIPResolutionError(
                "Proxy confiable requiere un único CF-Connecting-IP"
            )
        address = _parse_ip(values[0])

    return ClientIPResult(address, mode, True)


def request_client_ip(request: Any) -> str:
    state = getattr(request, "state", None)
    resolved = getattr(state, "client_ip", None) if state is not None else None
    if isinstance(resolved, str) and resolved:
        return resolved
    client = getattr(request, "client", None)
    host = getattr(client, "host", None)
    return host if isinstance(host, str) and host else "unknown"
