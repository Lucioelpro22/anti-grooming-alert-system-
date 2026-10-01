import asyncio
from types import SimpleNamespace

import pytest

from api.client_ip import (
    ClientIPConfigurationError,
    ClientIPResolutionError,
    request_client_ip,
    resolve_client_ip,
    validate_client_ip_configuration,
)
from api.security import API_LIMITER, ApiShieldMiddleware


def _headers(**values):
    return [
        (name.replace("_", "-").encode("ascii"), value.encode("ascii"))
        for name, value in values.items()
    ]


def test_ipv4_mapped_proxy_address_matches_ipv4_trusted_cidr(monkeypatch):
    monkeypatch.setenv("CLIENT_IP_HEADER", "x-forwarded-for")
    monkeypatch.setenv("TRUSTED_PROXY_CIDRS_JSON", '["10.0.0.0/8"]')

    result = resolve_client_ip(
        "::ffff:10.0.0.5",
        _headers(x_forwarded_for="198.51.100.12"),
    )

    assert result.address == "198.51.100.12"
    assert result.trusted_proxy is True


def test_forwarding_headers_are_ignored_from_untrusted_peer(monkeypatch):
    monkeypatch.setenv("CLIENT_IP_HEADER", "x-forwarded-for")
    monkeypatch.setenv("TRUSTED_PROXY_CIDRS_JSON", '["10.0.0.0/8"]')

    result = resolve_client_ip(
        "198.51.100.40",
        _headers(x_forwarded_for="203.0.113.77"),
    )

    assert result.address == "198.51.100.40"
    assert result.source == "peer"
    assert result.trusted_proxy is False


def test_xff_resolves_client_through_trusted_proxy(monkeypatch):
    monkeypatch.setenv("CLIENT_IP_HEADER", "x-forwarded-for")
    monkeypatch.setenv(
        "TRUSTED_PROXY_CIDRS_JSON",
        '["10.0.0.0/8","192.0.2.0/24"]',
    )

    result = resolve_client_ip(
        "10.0.0.5",
        _headers(x_forwarded_for="198.51.100.22, 192.0.2.10"),
    )

    assert result.address == "198.51.100.22"
    assert result.source == "x-forwarded-for"
    assert result.trusted_proxy is True


def test_xff_stops_at_first_untrusted_hop_and_ignores_spoofed_left_side(
    monkeypatch,
):
    monkeypatch.setenv("CLIENT_IP_HEADER", "x-forwarded-for")
    monkeypatch.setenv("TRUSTED_PROXY_CIDRS_JSON", '["10.0.0.0/8"]')

    result = resolve_client_ip(
        "10.0.0.5",
        _headers(x_forwarded_for="198.51.100.99, 203.0.113.44"),
    )

    assert result.address == "203.0.113.44"


def test_multiple_xff_header_lines_are_combined_safely(monkeypatch):
    monkeypatch.setenv("CLIENT_IP_HEADER", "x-forwarded-for")
    monkeypatch.setenv(
        "TRUSTED_PROXY_CIDRS_JSON",
        '["10.0.0.0/8","192.0.2.0/24"]',
    )
    headers = [
        (b"x-forwarded-for", b"198.51.100.7"),
        (b"x-forwarded-for", b"192.0.2.9"),
    ]

    result = resolve_client_ip("10.0.0.4", headers)
    assert result.address == "198.51.100.7"


def test_forwarded_header_supports_quoted_ipv6_with_port(monkeypatch):
    monkeypatch.setenv("CLIENT_IP_HEADER", "forwarded")
    monkeypatch.setenv("TRUSTED_PROXY_CIDRS_JSON", '["10.0.0.0/8"]')

    result = resolve_client_ip(
        "10.0.0.9",
        _headers(forwarded='for="[2001:db8::5]:443";proto=https'),
    )

    assert result.address == "2001:db8::5"


def test_cf_connecting_ip_requires_exactly_one_value(monkeypatch):
    monkeypatch.setenv("CLIENT_IP_HEADER", "cf-connecting-ip")
    monkeypatch.setenv("TRUSTED_PROXY_CIDRS_JSON", '["10.0.0.0/8"]')
    headers = [
        (b"cf-connecting-ip", b"198.51.100.5"),
        (b"cf-connecting-ip", b"198.51.100.6"),
    ]

    with pytest.raises(ClientIPResolutionError):
        resolve_client_ip("10.0.0.5", headers)


def test_cf_connecting_ip_is_ignored_from_untrusted_peer(monkeypatch):
    monkeypatch.setenv("CLIENT_IP_HEADER", "cf-connecting-ip")
    monkeypatch.setenv("TRUSTED_PROXY_CIDRS_JSON", '["10.0.0.0/8"]')

    result = resolve_client_ip(
        "198.51.100.40",
        _headers(cf_connecting_ip="203.0.113.8"),
    )

    assert result.address == "198.51.100.40"


def test_trusted_proxy_missing_selected_header_is_rejected(monkeypatch):
    monkeypatch.setenv("CLIENT_IP_HEADER", "x-forwarded-for")
    monkeypatch.setenv("TRUSTED_PROXY_CIDRS_JSON", '["10.0.0.0/8"]')

    with pytest.raises(ClientIPResolutionError):
        resolve_client_ip("10.0.0.5", [])


def test_forwarded_chain_has_a_hard_hop_limit(monkeypatch):
    monkeypatch.setenv("CLIENT_IP_HEADER", "x-forwarded-for")
    monkeypatch.setenv("TRUSTED_PROXY_CIDRS_JSON", '["10.0.0.0/8"]')
    monkeypatch.setenv("MAX_FORWARDED_HOPS", "2")

    with pytest.raises(ClientIPResolutionError):
        resolve_client_ip(
            "10.0.0.5",
            _headers(
                x_forwarded_for=(
                    "198.51.100.1, 198.51.100.2, 198.51.100.3"
                )
            ),
        )


def test_proxy_mode_requires_explicit_trusted_cidrs(monkeypatch):
    monkeypatch.setenv("CLIENT_IP_HEADER", "x-forwarded-for")
    monkeypatch.setenv("TRUSTED_PROXY_CIDRS_JSON", "[]")

    with pytest.raises(ClientIPConfigurationError):
        validate_client_ip_configuration()


def test_catch_all_proxy_cidr_is_rejected(monkeypatch):
    monkeypatch.setenv("CLIENT_IP_HEADER", "x-forwarded-for")
    monkeypatch.setenv("TRUSTED_PROXY_CIDRS_JSON", '["0.0.0.0/0"]')

    with pytest.raises(ClientIPConfigurationError):
        validate_client_ip_configuration(production=True)


def test_cidrs_are_rejected_when_proxy_headers_are_disabled(monkeypatch):
    monkeypatch.setenv("CLIENT_IP_HEADER", "none")
    monkeypatch.setenv("TRUSTED_PROXY_CIDRS_JSON", '["10.0.0.0/8"]')

    with pytest.raises(ClientIPConfigurationError):
        validate_client_ip_configuration()


def test_request_client_ip_prefers_middleware_resolved_state():
    request = SimpleNamespace(
        state=SimpleNamespace(client_ip="198.51.100.20"),
        client=SimpleNamespace(host="10.0.0.5"),
    )

    assert request_client_ip(request) == "198.51.100.20"


def test_api_shield_exposes_only_resolved_client_ip(monkeypatch):
    monkeypatch.setenv("CLIENT_IP_HEADER", "x-forwarded-for")
    monkeypatch.setenv("TRUSTED_PROXY_CIDRS_JSON", '["10.0.0.0/8"]')
    monkeypatch.setenv("ALLOWED_HOSTS_JSON", '["testserver"]')
    monkeypatch.setenv("RATE_LIMIT_BACKEND", "memory")
    monkeypatch.setenv("API_RATE_LIMIT", "120")
    API_LIMITER.clear()

    captured = {}
    sent = []

    async def app(scope, receive, send):
        captured.update(scope["state"])
        await send(
            {
                "type": "http.response.start",
                "status": 200,
                "headers": [],
            }
        )
        await send({"type": "http.response.body", "body": b"ok"})

    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message):
        sent.append(message)

    scope = {
        "type": "http",
        "method": "GET",
        "scheme": "https",
        "path": "/estado",
        "raw_path": b"/estado",
        "query_string": b"",
        "headers": [
            (b"host", b"testserver"),
            (b"x-forwarded-for", b"198.51.100.25"),
        ],
        "client": ("10.0.0.5", 12345),
        "server": ("testserver", 443),
    }

    asyncio.run(ApiShieldMiddleware(app)(scope, receive, send))

    assert captured["client_ip"] == "198.51.100.25"
    assert captured["client_ip_source"] == "x-forwarded-for"
    assert captured["trusted_proxy"] is True
    assert sent[0]["status"] == 200
