from __future__ import annotations

from http import HTTPStatus
from typing import TYPE_CHECKING, Protocol
from . import __version__
from .auth import SENSITIVITY_ORDER
from .expansion import ExpansionError, expand_evidence
from .index import effective_evidence_sensitivity
from .storage import file_lock
from ._server_transport import BadRequest, TransportCollaborator
from ._json_types import JSONMapping, JSONValue


class GetCollaborator(TransportCollaborator, Protocol):
    vault: "Vault"
    context_budget_maxima: dict[str, int]
    def _search_results(self, query: str, limit: int, ceiling: str) -> list[JSONMapping]: ...
    def _handle_get(self, *, write_body: bool = True) -> None: ...


class GetRoutesMixin:
    def _handle_get(self: GetCollaborator, *, write_body: bool = True) -> None:
        parsed = self._request_url()
        if parsed.path == "/health":
            self._validate_get_framing()
            self._json(HTTPStatus.OK, {"status": "ok", "version": __version__}, write_body=write_body)
            return
        if not self._authorize(write_body=write_body):
            return
        self._validate_get_framing()
        if parsed.path == "/v1/search":
            params = self._query_parameters(parsed.query, allowed={"q", "limit", "sensitivity_ceiling"})
            query = self._query(self._one_query_parameter(params, "q", ""))
            limit = self._limit(self._one_query_parameter(params, "limit"), default=10)
            ceiling = self._effective_ceiling(self._one_query_parameter(params, "sensitivity_ceiling"))
            self._json(HTTPStatus.OK, {"results": self._search_results(query, limit, ceiling)}, write_body=write_body)
            return
        if parsed.path.startswith("/v1/evidence/"):
            suffix = parsed.path.removeprefix("/v1/evidence/")
            content_route = suffix.endswith("/content")
            encoded_id = suffix[:-len("/content")] if content_route else suffix
            evidence_id = self._decode_evidence_id(encoded_id)
            if content_route:
                params = self._query_parameters(parsed.query, allowed={"material", "max_chars", "sensitivity_ceiling"})
                material = self._one_query_parameter(params, "material")
                if material is None or not material:
                    raise BadRequest("material must be supplied exactly once")
                ceiling = self._effective_ceiling(self._one_query_parameter(params, "sensitivity_ceiling"))
                max_chars = self._expansion_max_chars(self._one_query_parameter(params, "max_chars"), default=self.context_budget_maxima["budget_chars"])
                try:
                    expanded = expand_evidence(self.vault, evidence_id, material=material, max_chars=max_chars, sensitivity_ceiling=ceiling)
                except ValueError as exc:
                    raise BadRequest(str(exc)) from exc
                except ExpansionError as exc:
                    self._json(exc.status, exc.as_dict(), write_body=write_body)
                    return
                self._json(HTTPStatus.OK, expanded, write_body=write_body)
                return
            params = self._query_parameters(parsed.query, allowed={"sensitivity_ceiling"})
            ceiling = self._effective_ceiling(self._one_query_parameter(params, "sensitivity_ceiling"))
            with file_lock(self.vault.root / "runtime" / "locks" / "writer.lock"):
                capture = self.vault.load_evidence(evidence_id, verify=True)
                response_status: int = HTTPStatus.NOT_FOUND
                response_value: JSONValue = {"error": "evidence not found"}
                if capture is not None:
                    record = self.vault.effective_evidence(evidence_id, verify=True)
                    if record is not None:
                        sensitivity = effective_evidence_sensitivity(self.vault, record)
                        if sensitivity in SENSITIVITY_ORDER and SENSITIVITY_ORDER[sensitivity] <= SENSITIVITY_ORDER[ceiling]:
                            response_status = HTTPStatus.OK
                            response_value = record
                prepared_status, prepared_payload = self._render_json(response_status, response_value)
            self._send_json_payload(prepared_status, prepared_payload, write_body=write_body)
            return
        if parsed.path in {"/v1/ingest", "/v1/turns", "/v1/context", "/v1/rebuild", "/v1/validate"}:
            self._json(HTTPStatus.METHOD_NOT_ALLOWED, {"error": "method not allowed"}, headers={"Allow": "POST"}, write_body=write_body)
            return
        self._json(HTTPStatus.NOT_FOUND, {"error": "not found"}, write_body=write_body)


if TYPE_CHECKING:
    from .vault import Vault
