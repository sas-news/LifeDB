from __future__ import annotations

import json
import re
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import parse_qs, unquote, urlparse

from . import __version__
from .auth import (
    validate_api_token,
    SENSITIVITY_ORDER,
    bearer_token_matches,
    effective_ingest_sensitivity,
    effective_sensitivity_ceiling,
    validate_sensitivity,
)
from .context import build_context
from .expansion import ExpansionError, MAX_EXPANSION_CHARS, expand_evidence
from .ids import is_uuid7
from .index import MAX_QUERY_CHARS, effective_evidence_sensitivity, rebuild_index, search
from .policies import context_budget_profile, load_context_policy
from .validation import validate_vault
from .storage import file_lock, strict_json_loads
from .vault import Vault


MAX_BODY_BYTES = 64 * 1024 * 1024
MAX_RESULTS = 100
_CONTENT_LENGTH_RE = re.compile(r"^[0-9]+$")


class BadRequest(ValueError):
    """An error caused entirely by the HTTP request boundary."""


class LifeDBHandler(BaseHTTPRequestHandler):
    server_version = f"LifeDB/{__version__}"

    @property
    def vault(self) -> Vault:
        return self.server.vault  # type: ignore[attr-defined]

    @property
    def api_token(self) -> str | None:
        return self.server.api_token  # type: ignore[attr-defined]

    @property
    def server_sensitivity_ceiling(self) -> str:
        return self.server.sensitivity_ceiling  # type: ignore[attr-defined]

    @property
    def principal(self) -> str:
        return self.server.principal  # type: ignore[attr-defined]

    @property
    def destination(self) -> str:
        return self.server.destination  # type: ignore[attr-defined]

    @property
    def purpose(self) -> str:
        return self.server.purpose  # type: ignore[attr-defined]

    @property
    def ingest_sensitivity_floor(self) -> str:
        return self.server.ingest_sensitivity_floor  # type: ignore[attr-defined]

    def _json(
        self,
        status: int,
        value: Any,
        *,
        headers: dict[str, str] | None = None,
        write_body: bool = True,
    ) -> None:
        status, payload = self._render_json(status, value)
        self._send_json_payload(status, payload, headers=headers, write_body=write_body)

    @staticmethod
    def _render_json(status: int, value: Any) -> tuple[int, bytes]:
        try:
            rendered = json.dumps(
                value, ensure_ascii=False, indent=2, allow_nan=False
            )
        except (TypeError, ValueError, OverflowError, RecursionError):
            # Never serialize a malformed/internal value (or echo it) into a
            # protocol error.  This also makes all normal responses strict
            # JSON, including error paths and HEAD framing.
            value = {"error": "internal server error"}
            rendered = json.dumps(value, ensure_ascii=False, allow_nan=False)
            status = HTTPStatus.INTERNAL_SERVER_ERROR
        return int(status), (rendered + "\n").encode("utf-8")

    def _send_json_payload(
        self,
        status: int,
        payload: bytes,
        *,
        headers: dict[str, str] | None = None,
        write_body: bool = True,
    ) -> None:
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        for name, header_value in (headers or {}).items():
            self.send_header(name, header_value)
        self.end_headers()
        if write_body:
            self.wfile.write(payload)

    def _authorization_value(self) -> str | None:
        values = self.headers.get_all("Authorization", failobj=[])
        if len(values) != 1:
            return None
        return values[0]

    def _single_header(self, name: str, default: str | None = None) -> str | None:
        """Read one header and reject ambiguous repeated control headers."""

        values = self.headers.get_all(name, failobj=[])
        if len(values) > 1:
            self.close_connection = True
            raise BadRequest(f"{name} must be supplied at most once")
        return values[0] if values else default

    def _request_url(self):
        try:
            return urlparse(self.path)
        except ValueError as exc:
            self.close_connection = True
            raise BadRequest("invalid request target") from exc

    def _authorize(self, *, write_body: bool = True) -> bool:
        if self.api_token is None:
            self.close_connection = True
            self._json(
                HTTPStatus.SERVICE_UNAVAILABLE,
                {"error": "API authentication is not configured"},
                write_body=write_body,
            )
            return False
        if not bearer_token_matches(self._authorization_value(), self.api_token):
            self.close_connection = True
            self._json(
                HTTPStatus.UNAUTHORIZED,
                {"error": "authentication required"},
                headers={"WWW-Authenticate": 'Bearer realm="LifeDB"'},
                write_body=write_body,
            )
            return False
        return True

    def _content_length(self) -> int:
        transfer_encoding = self.headers.get_all("Transfer-Encoding", failobj=[])
        if transfer_encoding:
            self.close_connection = True
            raise BadRequest("Transfer-Encoding is not supported")
        values = self.headers.get_all("Content-Length", failobj=[])
        if not values:
            return 0
        if len(values) != 1 or _CONTENT_LENGTH_RE.fullmatch(values[0]) is None:
            self.close_connection = True
            raise BadRequest("invalid Content-Length")
        normalized = values[0].lstrip("0") or "0"
        if len(normalized) > len(str(MAX_BODY_BYTES)):
            self.close_connection = True
            raise BadRequest("request body exceeds the 64 MiB API limit")
        try:
            length = int(normalized)
        except ValueError:
            self.close_connection = True
            raise BadRequest("invalid Content-Length") from None
        if length > MAX_BODY_BYTES:
            self.close_connection = True
            raise BadRequest("request body exceeds the 64 MiB API limit")
        return length

    def _validate_get_framing(self) -> None:
        """Reject GET/HEAD bodies and close after any invalid framing signal."""

        try:
            length = self._content_length()
        except BadRequest:
            self.close_connection = True
            raise
        if length:
            self.close_connection = True
            raise BadRequest("GET and HEAD requests must not contain a body")

    def _close_if_unread_body(self) -> None:
        """Validate framing and close when a handler will not consume a body."""

        length = self._content_length()
        if length:
            # Sending the response is safe, but this connection must never be
            # reused while bytes belonging to the rejected request remain.
            self.close_connection = True

    def _read_body(self) -> bytes:
        length = self._content_length()
        body = self.rfile.read(length)
        if len(body) != length:
            self.close_connection = True
            raise BadRequest("request body is shorter than Content-Length")
        return body

    def _read_json(self) -> dict[str, Any]:
        body = self._read_body()
        if not body:
            return {}
        try:
            value = strict_json_loads(body, max_bytes=MAX_BODY_BYTES)
        except ValueError as exc:
            raise BadRequest("invalid JSON request body") from exc
        if not isinstance(value, dict):
            raise BadRequest("JSON request body must be an object")
        return value

    def _require_json_content_type(self) -> None:
        value = self._single_header("Content-Type")
        parts = [part.strip() for part in value.split(";")] if value is not None else []
        valid = bool(parts) and parts[0].casefold() == "application/json"
        if valid and len(parts) > 1:
            valid = len(parts) == 2 and re.fullmatch(
                r'charset\s*=\s*(?:utf-8|"utf-8")', parts[1], re.IGNORECASE
            ) is not None
        if not valid:
            # The body remains unread when the media type is rejected.
            self.close_connection = True
            raise BadRequest("Content-Type must be application/json")

    @staticmethod
    def _limit(value: object, *, default: int) -> int:
        if value is None:
            return default
        if isinstance(value, bool):
            raise BadRequest("limit must be an integer from 1 through 100")
        if isinstance(value, int):
            parsed = value
        elif isinstance(value, str) and re.fullmatch(r"[0-9]+", value):
            parsed = int(value)
        else:
            raise BadRequest("limit must be an integer from 1 through 100")
        if parsed < 1 or parsed > MAX_RESULTS:
            raise BadRequest("limit must be an integer from 1 through 100")
        return parsed

    @staticmethod
    def _query(value: object, *, allow_empty: bool = False) -> str:
        if not isinstance(value, str) or (not allow_empty and not value.strip()):
            raise BadRequest("query must be a non-empty string")
        if len(value.strip()) > MAX_QUERY_CHARS or "\x00" in value:
            raise BadRequest(f"query must be at most {MAX_QUERY_CHARS} characters without NUL")
        return value

    @staticmethod
    def _optional_string(request: dict[str, Any], name: str) -> str | None:
        value = request.get(name)
        if value is None:
            return None
        if not isinstance(value, str):
            raise BadRequest(f"{name} must be a string")
        return value

    @staticmethod
    def _budget(request: dict[str, Any], name: str, default: int) -> int:
        value = request.get(name, default)
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise BadRequest(f"{name} must be a non-negative integer")
        # HTTP request fields may narrow, never raise, the server profile.
        return min(value, default)

    def _effective_ceiling(self, requested: object | None) -> str:
        try:
            return effective_sensitivity_ceiling(
                self.server_sensitivity_ceiling, requested
            )
        except ValueError as exc:
            raise BadRequest(str(exc)) from exc

    @staticmethod
    def _one_query_parameter(
        params: dict[str, list[str]], name: str, default: str | None = None
    ) -> str | None:
        values = params.get(name)
        if values is None:
            return default
        if len(values) != 1:
            raise BadRequest(f"{name} must be supplied at most once")
        return values[0]

    @staticmethod
    def _query_parameters(
        query: str, *, allowed: set[str] | None = None
    ) -> dict[str, list[str]]:
        try:
            params = parse_qs(query, keep_blank_values=True, max_num_fields=32)
        except ValueError as exc:
            raise BadRequest("invalid query parameters") from exc
        if allowed is not None:
            unknown = sorted(set(params) - allowed)
            if unknown:
                raise BadRequest("unknown query parameter")
        return params

    @staticmethod
    def _expansion_max_chars(value: str | None, *, default: int) -> int:
        if value is None:
            return min(default, MAX_EXPANSION_CHARS)
        if _CONTENT_LENGTH_RE.fullmatch(value) is None:
            raise BadRequest("max_chars must be a non-negative integer")
        # Avoid feeding an adversarially long decimal string to int(). Values
        # above the absolute implementation ceiling cannot narrow authority.
        normalized = value.lstrip("0") or "0"
        if len(normalized) > len(str(MAX_EXPANSION_CHARS)):
            return min(default, MAX_EXPANSION_CHARS)
        parsed = int(normalized)
        return min(parsed, default, MAX_EXPANSION_CHARS)

    @staticmethod
    def _decode_evidence_id(encoded_id: str) -> str:
        try:
            evidence_id = unquote(encoded_id, errors="strict")
        except UnicodeDecodeError as exc:
            raise BadRequest("evidence ID is not valid UTF-8") from exc
        if not is_uuid7(evidence_id):
            raise BadRequest("evidence ID must be a UUIDv7")
        return evidence_id

    def _handle_get(self, *, write_body: bool = True) -> None:
        parsed = self._request_url()
        if parsed.path == "/health":
            self._validate_get_framing()
            self._json(
                HTTPStatus.OK,
                {"status": "ok", "version": __version__},
                write_body=write_body,
            )
            return
        if not self._authorize(write_body=write_body):
            return
        # Validate even unusual GET bodies to reject ambiguous framing.
        self._validate_get_framing()
        if parsed.path == "/v1/search":
            params = self._query_parameters(
                parsed.query, allowed={"q", "limit", "sensitivity_ceiling"}
            )
            query = self._query(self._one_query_parameter(params, "q", ""))
            raw_limit = self._one_query_parameter(params, "limit", None)
            requested_ceiling = self._one_query_parameter(
                params, "sensitivity_ceiling", None
            )
            limit = self._limit(raw_limit, default=10)
            ceiling = self._effective_ceiling(requested_ceiling)
            self._json(
                HTTPStatus.OK,
                {
                    "results": search(
                        self.vault,
                        query,
                        limit=limit,
                        sensitivity_ceiling=ceiling,
                    )
                },
                write_body=write_body,
            )
            return
        if parsed.path.startswith("/v1/evidence/"):
            suffix = parsed.path.removeprefix("/v1/evidence/")
            content_route = suffix.endswith("/content")
            encoded_id = suffix[: -len("/content")] if content_route else suffix
            evidence_id = self._decode_evidence_id(encoded_id)

            if content_route:
                params = self._query_parameters(
                    parsed.query,
                    allowed={"material", "max_chars", "sensitivity_ceiling"},
                )
                material = self._one_query_parameter(params, "material")
                if material is None or not material:
                    raise BadRequest("material must be supplied exactly once")
                requested_max = self._one_query_parameter(params, "max_chars")
                requested_ceiling = self._one_query_parameter(
                    params, "sensitivity_ceiling", None
                )
                ceiling = self._effective_ceiling(requested_ceiling)
                server_max = self.server.context_budget_maxima["budget_chars"]  # type: ignore[attr-defined]
                max_chars = self._expansion_max_chars(requested_max, default=server_max)
                try:
                    expanded = expand_evidence(
                        self.vault,
                        evidence_id,
                        material=material,
                        max_chars=max_chars,
                        sensitivity_ceiling=ceiling,
                    )
                except ValueError as exc:
                    raise BadRequest(str(exc)) from exc
                except ExpansionError as exc:
                    self._json(exc.status, exc.as_dict(), write_body=write_body)
                    return
                self._json(HTTPStatus.OK, expanded, write_body=write_body)
                return

            params = self._query_parameters(parsed.query, allowed={"sensitivity_ceiling"})
            requested_ceiling = self._one_query_parameter(
                params, "sensitivity_ceiling", None
            )
            ceiling = self._effective_ceiling(requested_ceiling)
            # Keep authorization, projection, and the response snapshot under
            # the same writer boundary so a newly raised event cannot race the
            # final label check.
            with file_lock(self.vault.root / "runtime" / "locks" / "writer.lock"):
                capture = self.vault.load_evidence(evidence_id, verify=True)
                response_status: int = HTTPStatus.NOT_FOUND
                response_value: Any = {"error": "evidence not found"}
                if capture is not None:
                    record = self.vault.effective_evidence(evidence_id, verify=True)
                    if record is not None:  # A concurrent erasure is hidden as absent.
                        effective_sensitivity = effective_evidence_sensitivity(self.vault, record)
                        if (
                            effective_sensitivity in SENSITIVITY_ORDER
                            and SENSITIVITY_ORDER[effective_sensitivity] <= SENSITIVITY_ORDER[ceiling]
                        ):
                            response_status = HTTPStatus.OK
                            response_value = record
                # Strict serialization is part of the snapshot; network I/O is
                # deliberately deferred until after the writer lock is released.
                prepared_status, prepared_payload = self._render_json(
                    response_status, response_value
                )
            self._send_json_payload(
                prepared_status,
                prepared_payload,
                write_body=write_body,
            )
            return
        if parsed.path in {"/v1/ingest", "/v1/context", "/v1/rebuild", "/v1/validate"}:
            self._json(
                HTTPStatus.METHOD_NOT_ALLOWED,
                {"error": "method not allowed"},
                headers={"Allow": "POST"},
                write_body=write_body,
            )
            return
        self._json(HTTPStatus.NOT_FOUND, {"error": "not found"}, write_body=write_body)

    def _handle_post(self) -> None:
        parsed = self._request_url()
        if not self._authorize():
            return
        # No POST route currently has query parameters.  Silently ignoring a
        # query creates two representations of a request and complicates audit
        # and signature/proxy policy; reject it explicitly.
        if parsed.query:
            self._query_parameters(parsed.query, allowed=set())
        if parsed.path == "/v1/ingest":
            try:
                ingestion_sensitivity = effective_ingest_sensitivity(
                    self.ingest_sensitivity_floor,
                    self._single_header("X-LifeDB-Sensitivity"),
                )
            except ValueError as exc:
                raise BadRequest("invalid ingestion sensitivity") from exc
            body = self._read_body()
            media_type = (
                self._single_header("Content-Type", "application/octet-stream") or ""
            ).split(";", 1)[0]
            asserted_source = self._single_header("X-LifeDB-Source")
            source_metadata: dict[str, Any] = {
                "transport": "http",
                "authenticated_principal": self.principal,
            }
            if asserted_source is not None:
                source_metadata["asserted_kind"] = asserted_source
            try:
                record = self.vault.ingest(
                    body,
                    # Acquisition authority is assigned by this authenticated
                    # boundary; a client header remains an untrusted assertion.
                    source_kind="http",
                    source_uri=self._single_header("X-LifeDB-Source-URI"),
                    source_metadata=source_metadata,
                    external_id=self._single_header("X-LifeDB-External-ID"),
                    media_type=media_type,
                    filename=self._single_header("X-LifeDB-Filename"),
                    retention=self._single_header("X-LifeDB-Retention", "durable")
                    or "",
                    sensitivity=ingestion_sensitivity,
                    kind=self._single_header("X-LifeDB-Kind", "artifact") or "",
                    captured_at=self._single_header("X-LifeDB-Captured-At"),
                )
            except (TypeError, ValueError) as exc:
                raise BadRequest("invalid ingestion metadata") from exc
            self._json(HTTPStatus.CREATED, record)
            return
        if parsed.path == "/v1/context":
            self._require_json_content_type()
            request = self._read_json()
            allowed_fields = {
                "query", "client", "session", "workspace", "limit",
                "sensitivity_ceiling", "budget_chars", "core_chars",
                "continuity_chars", "relevant_chars",
            }
            if set(request) - allowed_fields:
                raise BadRequest("unknown JSON request field")
            query = self._query(request.get("query", ""), allow_empty=True)
            client = request.get("client", "unknown")
            if not isinstance(client, str):
                raise BadRequest("client must be a string")
            limit = self._limit(request.get("limit"), default=8)
            ceiling = self._effective_ceiling(request.get("sensitivity_ceiling"))
            budget_maxima = self.server.context_budget_maxima  # type: ignore[attr-defined]
            pack = build_context(
                self.vault,
                query,
                client=client,
                principal=self.principal,
                session=self._optional_string(request, "session"),
                workspace=self._optional_string(request, "workspace"),
                destination=self.destination,
                purpose=self.purpose,
                limit=limit,
                sensitivity_ceiling=ceiling,
                budget_chars=self._budget(
                    request, "budget_chars", budget_maxima["budget_chars"]
                ),
                core_chars=self._budget(
                    request, "core_chars", budget_maxima["core_chars"]
                ),
                continuity_chars=self._budget(
                    request, "continuity_chars", budget_maxima["continuity_chars"]
                ),
                relevant_chars=self._budget(
                    request, "relevant_chars", budget_maxima["relevant_chars"]
                ),
            )
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
            self._json(
                HTTPStatus.METHOD_NOT_ALLOWED,
                {"error": "method not allowed"},
                headers={"Allow": "GET, HEAD"},
            )
            return
        self._json(HTTPStatus.NOT_FOUND, {"error": "not found"})

    def do_GET(self) -> None:
        try:
            self._handle_get(write_body=True)
        except BadRequest as exc:
            self._json(HTTPStatus.BAD_REQUEST, {"error": str(exc)})
        except Exception as exc:
            self.log_error("internal request failure (%s)", type(exc).__name__)
            self._json(
                HTTPStatus.INTERNAL_SERVER_ERROR,
                {"error": "internal server error"},
            )

    def do_POST(self) -> None:
        try:
            self._handle_post()
        except BadRequest as exc:
            self._json(HTTPStatus.BAD_REQUEST, {"error": str(exc)})
        except Exception as exc:
            self.log_error("internal request failure (%s)", type(exc).__name__)
            self._json(
                HTTPStatus.INTERNAL_SERVER_ERROR,
                {"error": "internal server error"},
            )

    def do_HEAD(self) -> None:
        try:
            self._handle_get(write_body=False)
        except BadRequest as exc:
            self._json(HTTPStatus.BAD_REQUEST, {"error": str(exc)}, write_body=False)
        except Exception as exc:
            self.log_error("internal request failure (%s)", type(exc).__name__)
            self._json(
                HTTPStatus.INTERNAL_SERVER_ERROR,
                {"error": "internal server error"},
                write_body=False,
            )

    @staticmethod
    def _allowed_methods(path: str) -> str:
        if path == "/health":
            return "GET, HEAD"
        if path == "/v1/search" or path.startswith("/v1/evidence/"):
            return "GET, HEAD"
        if path in {"/v1/ingest", "/v1/context", "/v1/rebuild", "/v1/validate"}:
            return "POST"
        return "GET, POST, HEAD"

    def _unsupported_method(self) -> None:
        try:
            parsed = self._request_url()
            if parsed.path != "/health" and not self._authorize():
                return
            # Unsupported methods never consume request bodies. Close after
            # validating framing so leftover bytes cannot become a second
            # request on a persistent connection.
            self._close_if_unread_body()
            self.close_connection = True
            self._json(
                HTTPStatus.METHOD_NOT_ALLOWED,
                {"error": "method not allowed"},
                headers={"Allow": self._allowed_methods(parsed.path)},
            )
        except BadRequest as exc:
            self._json(HTTPStatus.BAD_REQUEST, {"error": str(exc)})
        except Exception as exc:
            self.log_error("internal request failure (%s)", type(exc).__name__)
            self._json(
                HTTPStatus.INTERNAL_SERVER_ERROR,
                {"error": "internal server error"},
            )

    do_DELETE = _unsupported_method
    do_CONNECT = _unsupported_method
    do_OPTIONS = _unsupported_method
    do_PATCH = _unsupported_method
    do_PUT = _unsupported_method
    do_TRACE = _unsupported_method

    def _request_log_path(self) -> str:
        """Return only the path component for access logs, never the query."""

        try:
            path = urlparse(self.path).path
        except ValueError:
            path = ""
        return path or "/"

    def log_request(self, code: int | str = "-", size: int | str = "-") -> None:
        # BaseHTTPRequestHandler's default includes requestline, which can
        # contain sensitive query text. Keep access logs deliberately narrow.
        self.log_message("%s %s %s", self.command or "-", self._request_log_path(), code)

    def log_message(self, fmt: str, *args: Any) -> None:
        print(f"{self.address_string()} - {fmt % args}")


class LifeDBServer(ThreadingHTTPServer):
    def __init__(
        self,
        address: tuple[str, int],
        vault: Vault,
        api_token: str | None = None,
        sensitivity_ceiling: str = "personal",
        principal: str = "http-token",
        destination: str = "local-http",
        purpose: str = "assistant",
        ingest_sensitivity_floor: str = "personal",
    ):
        api_token = validate_api_token(api_token)
        try:
            validated_ceiling = validate_sensitivity(
                sensitivity_ceiling, field="server sensitivity ceiling"
            )
        except ValueError as exc:
            raise ValueError("invalid server sensitivity ceiling") from exc
        try:
            validated_ingest_floor = validate_sensitivity(
                ingest_sensitivity_floor, field="ingestion sensitivity floor"
            )
        except ValueError as exc:
            raise ValueError("invalid ingestion sensitivity floor") from exc
        if not isinstance(principal, str) or not principal.strip():
            raise ValueError("principal must be a non-empty string")
        if not isinstance(destination, str) or not destination.strip():
            raise ValueError("destination must be a non-empty string")
        if not isinstance(purpose, str) or not purpose.strip():
            raise ValueError("purpose must be a non-empty string")
        # Load policy before opening the listening socket.  The resulting
        # profile is intentionally fixed for this server instance; a restarted
        # server is required to adopt a changed HTTP authority policy.
        context_policy = load_context_policy(vault)
        context_budget_maxima = context_budget_profile(context_policy)
        super().__init__(address, LifeDBHandler)
        self.vault = vault
        self.api_token = api_token
        self.sensitivity_ceiling = validated_ceiling
        self.principal = principal
        self.destination = destination
        self.purpose = purpose
        self.ingest_sensitivity_floor = validated_ingest_floor
        self.context_policy = context_policy
        self.context_budget_maxima = context_budget_maxima
        # Public profile spelling retained for callers that treat the server
        # as an authorization profile rather than an HTTP implementation.
        self.context_budgets = context_budget_maxima


def serve(
    vault: Vault,
    bind: str,
    port: int,
    *,
    api_token: str | None = None,
    sensitivity_ceiling: str = "personal",
    principal: str = "http-token",
    destination: str = "local-http",
    purpose: str = "assistant",
    ingest_sensitivity_floor: str = "personal",
) -> None:
    server = LifeDBServer(
        (bind, port),
        vault,
        api_token=api_token,
        sensitivity_ceiling=sensitivity_ceiling,
        principal=principal,
        destination=destination,
        purpose=purpose,
        ingest_sensitivity_floor=ingest_sensitivity_floor,
    )
    print(f"LifeDB {__version__} listening on http://{bind}:{port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
