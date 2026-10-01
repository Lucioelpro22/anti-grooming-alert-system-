import json
import os
import re
import secrets
import threading
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass

from starlette.types import Message, Receive, Scope, Send

from api.rate_limit_backend import RedisRateLimitBackend

ASGIApp = Callable[[Scope, Receive, Send], Awaitable[None]]
REQUEST_ID_PATTERN = re.compile(r"^[A-Za-z0-9._-]{8,64}$")


def env_list(name: str, default: list[str]) -> list[str]:
    raw = os.getenv(name)
    if raw is None:
        return default
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"{name} debe ser una lista JSON") from exc
    if not isinstance(value, list) or not all(
        isinstance(item, str) and item.strip() for item in value
    ):
        raise RuntimeError(f"{name} debe ser una lista JSON de textos")
    return [item.strip() for item in value]


def env_positive_int(name: str, default: int) -> int:
    raw = os.getenv(name, str(default))
    try:
        value = int(raw)
    except ValueError as exc:
        raise RuntimeError(f"{name} debe ser un entero") from exc
    if value <= 0:
        raise RuntimeError(f"{name} debe ser mayor que cero")
    return value


@dataclass(frozen=True)
class RateLimitResult:
    allowed: bool
    retry_after: int


class SlidingWindowRateLimiter:
    def __init__(
        self, attempts: int = 120, window_seconds: int = 60, max_keys: int = 10_000
    ) -> None:
        self.attempts = attempts
        self.window_seconds = window_seconds
        self.max_keys = max_keys
        self._requests: dict[str, list[float]] = {}
        self._lock = threading.Lock()
        self._distributed_backend: RedisRateLimitBackend | None = None

    def _redis_backend(self) -> RedisRateLimitBackend | None:
        if os.getenv("RATE_LIMIT_BACKEND", "memory").lower() != "redis":
            return None
        if self._distributed_backend is None:
            url = os.getenv("REDIS_URL")
            if not url:
                return None
            try:
                import redis  # type: ignore[import-not-found]

                client = redis.Redis.from_url(url, decode_responses=True)
                self._distributed_backend = RedisRateLimitBackend(client)
            except (ImportError, ValueError):
                return None
        return self._distributed_backend

    def check(self, key: str) -> RateLimitResult:
        backend = self._redis_backend()
        if backend is not None:
            try:
                result = backend.check(key, self.attempts, self.window_seconds)
                return RateLimitResult(result.allowed, result.retry_after)
            except Exception:  # noqa: BLE001
                return RateLimitResult(False, self.window_seconds)
        now = time.monotonic()
        cutoff = now - self.window_seconds
        with self._lock:
            if len(self._requests) >= self.max_keys and key not in self._requests:
                stale = [
                    name
                    for name, values in self._requests.items()
                    if not values or values[-1] <= cutoff
                ]
                for name in stale[: max(1, len(stale) // 2)]:
                    self._requests.pop(name, None)
                if len(self._requests) >= self.max_keys:
                    return RateLimitResult(False, self.window_seconds)
            recent = [value for value in self._requests.get(key, []) if value > cutoff]
            if len(recent) >= self.attempts:
                retry_after = max(1, int(self.window_seconds - (now - recent[0])))
                self._requests[key] = recent
                return RateLimitResult(False, retry_after)
            recent.append(now)
            self._requests[key] = recent
        return RateLimitResult(True, 0)

    def clear(self) -> None:
        with self._lock:
            self._requests.clear()


API_LIMITER = SlidingWindowRateLimiter()
REPORT_LIMITER = SlidingWindowRateLimiter(attempts=10, window_seconds=60)


class ApiShieldMiddleware:
    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        headers = {key.lower(): value for key, value in scope.get("headers", [])}
        request_id_value = headers.get(b"x-request-id", b"").decode(
            "ascii", errors="ignore"
        )
        request_id = (
            request_id_value
            if REQUEST_ID_PATTERN.fullmatch(request_id_value)
            else secrets.token_hex(16)
        )
        scope.setdefault("state", {})["request_id"] = request_id

        async def secure_send(message: Message) -> None:
            if message["type"] == "http.response.start":
                response_headers = list(message.get("headers", []))
                response_headers.extend(
                    [
                        (b"x-content-type-options", b"nosniff"),
                        (b"x-frame-options", b"DENY"),
                        (b"referrer-policy", b"no-referrer"),
                        (
                            b"permissions-policy",
                            b"camera=(), microphone=(), geolocation=()",
                        ),
                        (
                            b"content-security-policy",
                            b"default-src 'none'; frame-ancestors 'none'",
                        ),
                        (b"cross-origin-resource-policy", b"same-origin"),
                        (b"cache-control", b"no-store"),
                        (
                            b"strict-transport-security",
                            b"max-age=31536000; includeSubDomains",
                        ),
                        (b"x-request-id", request_id.encode("ascii")),
                    ]
                )
                message["headers"] = response_headers
            await send(message)

        allowed_hosts = {
            value.lower()
            for value in env_list(
                "ALLOWED_HOSTS_JSON", ["localhost", "127.0.0.1", "testserver"]
            )
        }
        host = (
            headers.get(b"host", b"")
            .split(b":", 1)[0]
            .decode("ascii", errors="ignore")
            .lower()
        )
        if host not in allowed_hosts:
            await self._reject(400, "Host no permitido", secure_send)
            return

        client = scope.get("client")
        client_host = client[0] if client else "unknown"
        API_LIMITER.attempts = env_positive_int("API_RATE_LIMIT", 120)
        API_LIMITER.window_seconds = env_positive_int("API_RATE_WINDOW_SECONDS", 60)
        rate = API_LIMITER.check(client_host)
        if not rate.allowed:
            await self._reject(
                429,
                "Demasiadas solicitudes",
                secure_send,
                [(b"retry-after", str(rate.retry_after).encode("ascii"))],
            )
            return

        max_body = env_positive_int("MAX_REQUEST_BODY_BYTES", 65_536)
        content_length = headers.get(b"content-length")
        if content_length is not None:
            try:
                if int(content_length) > max_body:
                    await self._reject(413, "Solicitud demasiado grande", secure_send)
                    return
            except ValueError:
                await self._reject(400, "Content-Length inválido", secure_send)
                return

        if scope.get("method") in {"POST", "PUT", "PATCH"}:
            body = bytearray()
            more_body = True
            while more_body:
                message = await receive()
                if message["type"] == "http.disconnect":
                    return
                chunk = message.get("body", b"")
                body.extend(chunk)
                if len(body) > max_body:
                    await self._reject(413, "Solicitud demasiado grande", secure_send)
                    return
                more_body = message.get("more_body", False)
            consumed = False

            async def replay_receive() -> Message:
                nonlocal consumed
                if consumed:
                    return {"type": "http.request", "body": b"", "more_body": False}
                consumed = True
                return {"type": "http.request", "body": bytes(body), "more_body": False}

            await self.app(scope, replay_receive, secure_send)
            return

        await self.app(scope, receive, secure_send)

    @staticmethod
    async def _reject(
        status_code: int,
        detail: str,
        send: Send,
        headers: list[tuple[bytes, bytes]] | None = None,
    ) -> None:
        payload = json.dumps({"detail": detail}, ensure_ascii=False).encode("utf-8")
        response_headers = [
            (b"content-type", b"application/json; charset=utf-8"),
            (b"content-length", str(len(payload)).encode("ascii")),
        ]
        if headers:
            response_headers.extend(headers)
        await send(
            {
                "type": "http.response.start",
                "status": status_code,
                "headers": response_headers,
            }
        )
        await send({"type": "http.response.body", "body": payload})
