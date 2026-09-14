from __future__ import annotations

from http import HTTPStatus
from typing import TYPE_CHECKING, Protocol
from .auth import effective_ingest_sensitivity
from .context import build_context
from .index import rebuild_index
from .secrets import SecretDetectedError
from .turns import MAX_TURN_REQUEST_BYTES, TurnValidationError, parse_turn_bytes
from .validation import validate_vault
from .vault import ExternalIDConflictError
from ._server_transport import BadRequest, CONTENT_LENGTH_RE, MAX_BODY_BYTES, TransportCollaborator
from ._json_types import JSONMapping


class PostCollaborator(TransportCollaborator, Protocol):
    vault: "Vault"
    principal: str
    destination: str
    purpose: str
    ingest_sensitivity_floor: str
    context_budget_maxima: dict[str, int]
    def _handle_turns_post(self) -> None: ...


class PostRoutesMixin:
    close_connection: bool = False

    def _handle_turns_post(self: PostCollaborator) -> None:
        content_types = self.headers.get_all("Content-Type", failobj=[])
        if len(content_types) > 1:
            self.close_connection = True
            raise BadRequest("Content-Type must be supplied at most once")
        try:
            self._require_json_content_type()
        except BadRequest as exc:
            self._json(HTTPStatus.UNSUPPORTED_MEDIA_TYPE, {"error": str(exc)})
            return
        declared = self.headers.get_all("Content-Length", failobj=[])
        if len(declared) == 1 and CONTENT_LENGTH_RE.fullmatch(declared[0]) is not None:
            normalized = declared[0].lstrip("0") or "0"
            if len(normalized) > len(str(MAX_BODY_BYTES)) or int(normalized) > MAX_BODY_BYTES:
                self.close_connection = True
                self._json(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, {"error": "request body exceeds the 64 MiB API limit"})
                return
        body = self._read_body()
        if len(body) > MAX_TURN_REQUEST_BYTES:
            self.close_connection = True
            self._json(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, {"error": "turn request body exceeds the 2 MiB limit"})
            return
        try:
            turn = parse_turn_bytes(body)
        except TurnValidationError as exc:
            raise BadRequest(str(exc)) from exc
        sensitivity = effective_ingest_sensitivity(self.ingest_sensitivity_floor, turn.sensitivity)
        try:
            record = self.vault.ingest(**turn.ingest_kwargs(sensitivity=sensitivity))
        except ExternalIDConflictError:
            self._json(HTTPStatus.CONFLICT, {"error": "turn already exists with different content"})
            return
        except SecretDetectedError:
            self._json(HTTPStatus.UNPROCESSABLE_ENTITY, {"error": "turn contains credential material; ingestion refused"})
            return
        except (TypeError, ValueError) as exc:
            raise BadRequest("invalid turn ingestion") from exc
        self._json(HTTPStatus.CREATED, record)

    def _handle_post(self: PostCollaborator) -> None:
        parsed = self._request_url()
        if not self._authorize():
            return
        if parsed.query:
            _ = self._query_parameters(parsed.query, allowed=set())
        if parsed.path == "/v1/ingest":
            try:
                sensitivity = effective_ingest_sensitivity(self.ingest_sensitivity_floor, self._single_header("X-LifeDB-Sensitivity"))
            except ValueError as exc:
                raise BadRequest("invalid ingestion sensitivity") from exc
            body = self._read_body()
            media_type = (self._single_header("Content-Type", "application/octet-stream") or "").split(";", 1)[0]
            metadata: JSONMapping = {"transport": "http", "authenticated_principal": self.principal}
            asserted_source = self._single_header("X-LifeDB-Source")
            if asserted_source is not None:
                metadata["asserted_kind"] = asserted_source
            try:
                record = self.vault.ingest(body, source_kind="http", source_uri=self._single_header("X-LifeDB-Source-URI"), source_metadata=metadata, external_id=self._single_header("X-LifeDB-External-ID"), media_type=media_type, filename=self._single_header("X-LifeDB-Filename"), retention=self._single_header("X-LifeDB-Retention", "durable") or "", sensitivity=sensitivity, kind=self._single_header("X-LifeDB-Kind", "artifact") or "", captured_at=self._single_header("X-LifeDB-Captured-At"))
            except (TypeError, ValueError) as exc:
                raise BadRequest("invalid ingestion metadata") from exc
            self._json(HTTPStatus.CREATED, record)
            return
        if parsed.path == "/v1/turns":
            self._handle_turns_post()
            return
        if parsed.path == "/v1/context":
            self._require_json_content_type()
            request = self._read_json()
            allowed = {"query", "client", "session", "workspace", "limit", "sensitivity_ceiling", "budget_chars", "core_chars", "continuity_chars", "relevant_chars"}
            if set(request) - allowed:
                raise BadRequest("unknown JSON request field")
            query = self._query(request.get("query", ""), allow_empty=True)
            client = request.get("client", "unknown")
            if not isinstance(client, str):
                raise BadRequest("client must be a string")
            maxima = self.context_budget_maxima
            pack = build_context(self.vault, query, client=client, principal=self.principal, session=self._optional_string(request, "session"), workspace=self._optional_string(request, "workspace"), destination=self.destination, purpose=self.purpose, limit=self._limit(request.get("limit"), default=8), sensitivity_ceiling=self._effective_ceiling(request.get("sensitivity_ceiling")), budget_chars=self._budget(request, "budget_chars", maxima["budget_chars"]), core_chars=self._budget(request, "core_chars", maxima["core_chars"]), continuity_chars=self._budget(request, "continuity_chars", maxima["continuity_chars"]), relevant_chars=self._budget(request, "relevant_chars", maxima["relevant_chars"]))
            self._json(HTTPStatus.OK, pack)
            return
        if parsed.path == "/v1/rebuild":
            if self._read_body():
                raise BadRequest("rebuild requests must have an empty body")
            self._json(HTTPStatus.OK, rebuild_index(self.vault))
            return
        if parsed.path == "/v1/validate":
            if self._read_body():
                raise BadRequest("validate requests must have an empty body")
            self._json(HTTPStatus.OK, validate_vault(self.vault.root).as_dict())
            return
        self._close_if_unread_body()
        if parsed.path == "/v1/search" or parsed.path.startswith("/v1/evidence/"):
            self._json(HTTPStatus.METHOD_NOT_ALLOWED, {"error": "method not allowed"}, headers={"Allow": "GET, HEAD"})
            return
        self._json(HTTPStatus.NOT_FOUND, {"error": "not found"})


if TYPE_CHECKING:
    from .vault import Vault
