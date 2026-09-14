from __future__ import annotations

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from . import __version__
from .auth import validate_api_token, validate_sensitivity
from .index import search
from .policies import context_budget_profile, load_context_policy
from .vault import Vault
from ._server_get import GetRoutesMixin
from ._server_methods import MethodMixin
from ._server_post import PostRoutesMixin
from ._server_transport import BadRequest, MAX_BODY_BYTES, MAX_RESULTS, TransportMixin
from ._json_types import JSONMapping
from ._server_types import ServerProfile, server_profile

__all__ = ["BadRequest", "LifeDBHandler", "LifeDBServer", "MAX_BODY_BYTES", "MAX_RESULTS", "ServerConfigurationError", "ServerProfile", "serve"]


class ServerConfigurationError(ValueError):
    """Raised when a server profile cannot be used safely."""


class LifeDBHandler(TransportMixin, GetRoutesMixin, PostRoutesMixin, MethodMixin, BaseHTTPRequestHandler):
    @property
    def vault(self) -> Vault:
        return server_profile(self).vault

    @property
    def api_token(self) -> str | None:
        return server_profile(self).api_token

    @property
    def server_sensitivity_ceiling(self) -> str:
        return server_profile(self).sensitivity_ceiling

    @property
    def principal(self) -> str:
        return server_profile(self).principal

    @property
    def destination(self) -> str:
        return server_profile(self).destination

    @property
    def purpose(self) -> str:
        return server_profile(self).purpose

    @property
    def ingest_sensitivity_floor(self) -> str:
        return server_profile(self).ingest_sensitivity_floor

    @property
    def context_budget_maxima(self) -> dict[str, int]:
        return server_profile(self).context_budget_maxima

    def _search_results(self, query: str, limit: int, ceiling: str) -> list[JSONMapping]:
        results: list[JSONMapping] = search(self.vault, query, limit=limit, sensitivity_ceiling=ceiling)
        return results


class LifeDBServer(ThreadingHTTPServer):
    vault: Vault
    api_token: str | None
    sensitivity_ceiling: str
    principal: str
    destination: str
    purpose: str
    ingest_sensitivity_floor: str
    context_policy: JSONMapping
    context_budget_maxima: dict[str, int]
    context_budgets: dict[str, int]

    def __init__(self, address: tuple[str, int], vault: Vault, api_token: str | None = None, sensitivity_ceiling: str = "personal", principal: str = "http-token", destination: str = "local-http", purpose: str = "assistant", ingest_sensitivity_floor: str = "personal"):
        api_token = validate_api_token(api_token)
        try:
            validated_ceiling = validate_sensitivity(sensitivity_ceiling, field="server sensitivity ceiling")
        except ValueError as exc:
            raise ServerConfigurationError("invalid server sensitivity ceiling") from exc
        try:
            validated_floor = validate_sensitivity(ingest_sensitivity_floor, field="ingestion sensitivity floor")
        except ValueError as exc:
            raise ServerConfigurationError("invalid ingestion sensitivity floor") from exc
        if type(principal) is not str or not principal.strip():
            raise ServerConfigurationError("principal must be a non-empty string")
        if type(destination) is not str or not destination.strip():
            raise ServerConfigurationError("destination must be a non-empty string")
        if type(purpose) is not str or not purpose.strip():
            raise ServerConfigurationError("purpose must be a non-empty string")
        context_policy = load_context_policy(vault)
        context_budget_maxima = context_budget_profile(context_policy)
        super().__init__(address, LifeDBHandler)
        self.vault = vault
        self.api_token = api_token
        self.sensitivity_ceiling = validated_ceiling
        self.principal = principal
        self.destination = destination
        self.purpose = purpose
        self.ingest_sensitivity_floor = validated_floor
        self.context_policy = context_policy
        self.context_budget_maxima = context_budget_maxima
        self.context_budgets = context_budget_maxima


def serve(vault: Vault, bind: str, port: int, *, api_token: str | None = None, sensitivity_ceiling: str = "personal", principal: str = "http-token", destination: str = "local-http", purpose: str = "assistant", ingest_sensitivity_floor: str = "personal") -> None:
    server = LifeDBServer((bind, port), vault, api_token=api_token, sensitivity_ceiling=sensitivity_ceiling, principal=principal, destination=destination, purpose=purpose, ingest_sensitivity_floor=ingest_sensitivity_floor)
    print(f"LifeDB {__version__} listening on http://{bind}:{port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        return
    finally:
        server.server_close()
