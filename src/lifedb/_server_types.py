from __future__ import annotations

from http.server import BaseHTTPRequestHandler
from typing import TYPE_CHECKING, Protocol, runtime_checkable

from ._json_types import JSONMapping, JSONValue

JSONResponse = JSONValue | dict[str, list[JSONMapping]]


@runtime_checkable
class ServerProfile(Protocol):
    vault: "Vault"
    api_token: str | None
    sensitivity_ceiling: str
    principal: str
    destination: str
    purpose: str
    ingest_sensitivity_floor: str
    if TYPE_CHECKING:
        context_budget_maxima: dict[str, int]


class InvalidServerProfileError(TypeError):
    """Raised when an HTTP handler has an incompatible server profile."""


def server_profile(handler: BaseHTTPRequestHandler) -> ServerProfile:
    profile = handler.server
    if not isinstance(profile, ServerProfile):
        raise InvalidServerProfileError("handler server does not implement the LifeDB server profile")
    return profile


if TYPE_CHECKING:
    from .vault import Vault
