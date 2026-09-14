from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from .payloads import SerializedPayload
from .settings import PluginSettings
from .token_file import read_token
from .transport import HttpResponse, TransportFailure


class RequestTransport(Protocol):
    def request(self, url: str, token: str, body: bytes, timeout: float) -> HttpResponse: ...


@dataclass(frozen=True, slots=True)
class BridgeResult:
    status: int
    body: bytes


def post_json(
    transport: RequestTransport, settings: PluginSettings, path: str,
    payload: SerializedPayload,
) -> BridgeResult | None:
    """Perform one bounded authenticated request, returning only status/body."""
    if settings.token_file is None:
        return None
    try:
        token = read_token(settings.token_file)
        body = payload
        if len(body) > settings.max_request_bytes:
            return None
        response = transport.request(
            f"{settings.base_url}{path}", token, body, settings.timeout_seconds
        )
    except (OSError, UnicodeError, TypeError, ValueError, TransportFailure):
        return None
    return BridgeResult(response.status, response.body)
