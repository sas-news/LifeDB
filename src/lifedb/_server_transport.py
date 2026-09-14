from __future__ import annotations

import json
import re
from email.message import Message
from http import HTTPStatus
from io import BufferedIOBase
from typing import Protocol
from urllib.parse import ParseResult, parse_qs, unquote, urlparse

from . import __version__
from .auth import bearer_token_matches, effective_sensitivity_ceiling
from .expansion import MAX_EXPANSION_CHARS
from .ids import is_uuid7
from .index import MAX_QUERY_CHARS
from .storage import strict_json_loads
from ._json_types import JSONMapping, JSONValue
from ._server_types import JSONResponse

MAX_BODY_BYTES = 64 * 1024 * 1024
MAX_RESULTS = 100
CONTENT_LENGTH_RE = re.compile(r"^[0-9]+$")


class BadRequest(ValueError):
    """An error caused entirely by the HTTP request boundary."""


class TransportCollaborator(Protocol):
    headers: Message
    path: str
    rfile: BufferedIOBase
    wfile: BufferedIOBase
    api_token: str | None
    server_sensitivity_ceiling: str
    close_connection: bool
    def send_response(self, code: int, message: str | None = None) -> None: ...
    def send_header(self, keyword: str, value: str) -> None: ...
    def end_headers(self) -> None: ...
    def _json(self, status: int, value: JSONResponse, *, headers: dict[str, str] | None = None, write_body: bool = True) -> None: ...
    def _render_json(self, status: int, value: JSONResponse) -> tuple[int, bytes]: ...
    def _send_json_payload(self, status: int, payload: bytes, *, headers: dict[str, str] | None = None, write_body: bool = True) -> None: ...
    def _authorization_value(self) -> str | None: ...
    def _single_header(self, name: str, default: str | None = None) -> str | None: ...
    def _request_url(self) -> ParseResult: ...
    def _authorize(self, *, write_body: bool = True) -> bool: ...
    def _content_length(self) -> int: ...
    def _validate_get_framing(self) -> None: ...
    def _close_if_unread_body(self) -> None: ...
    def _read_body(self) -> bytes: ...
    def _read_json(self) -> JSONMapping: ...
    def _require_json_content_type(self) -> None: ...
    def _effective_ceiling(self, requested: JSONValue | None) -> str: ...
    @staticmethod
    def _limit(value: JSONValue, *, default: int) -> int: ...
    @staticmethod
    def _query(value: JSONValue, *, allow_empty: bool = False) -> str: ...
    @staticmethod
    def _optional_string(request: JSONMapping, name: str) -> str | None: ...
    @staticmethod
    def _budget(request: JSONMapping, name: str, default: int) -> int: ...
    @staticmethod
    def _one_query_parameter(params: dict[str, list[str]], name: str, default: str | None = None) -> str | None: ...
    @staticmethod
    def _query_parameters(query: str, *, allowed: set[str] | None = None) -> dict[str, list[str]]: ...
    @staticmethod
    def _expansion_max_chars(value: str | None, *, default: int) -> int: ...
    @staticmethod
    def _decode_evidence_id(encoded_id: str) -> str: ...


class TransportMixin:
    close_connection: bool = False
    server_version: str = f"LifeDB/{__version__}"

    def _json(self: TransportCollaborator, status: int, value: JSONResponse, *, headers: dict[str, str] | None = None, write_body: bool = True) -> None:
        status, payload = self._render_json(status, value)
        self._send_json_payload(status, payload, headers=headers, write_body=write_body)

    @staticmethod
    def _render_json(status: int, value: JSONResponse) -> tuple[int, bytes]:
        try:
            rendered = json.dumps(value, ensure_ascii=False, indent=2, allow_nan=False)
        except (TypeError, ValueError, OverflowError, RecursionError):
            value = {"error": "internal server error"}
            rendered = json.dumps(value, ensure_ascii=False, allow_nan=False)
            status = HTTPStatus.INTERNAL_SERVER_ERROR
        return int(status), (rendered + "\n").encode("utf-8")

    def _send_json_payload(self: TransportCollaborator, status: int, payload: bytes, *, headers: dict[str, str] | None = None, write_body: bool = True) -> None:
        _ = self.send_response(status)
        for name, header_value in (("Content-Type", "application/json; charset=utf-8"), ("Content-Length", str(len(payload))), ("Cache-Control", "no-store"), ("X-Content-Type-Options", "nosniff")):
            _ = self.send_header(name, header_value)
        for name, header_value in (headers or {}).items():
            _ = self.send_header(name, header_value)
        self.end_headers()
        if write_body:
            _ = self.wfile.write(payload)

    def _authorization_value(self: TransportCollaborator) -> str | None:
        values = self.headers.get_all("Authorization", failobj=[])
        return values[0] if len(values) == 1 else None

    def _single_header(self: TransportCollaborator, name: str, default: str | None = None) -> str | None:
        values = self.headers.get_all(name, failobj=[])
        if len(values) > 1:
            self.close_connection = True
            raise BadRequest(f"{name} must be supplied at most once")
        return values[0] if values else default

    def _request_url(self: TransportCollaborator) -> ParseResult:
        try:
            return urlparse(self.path)
        except ValueError as exc:
            self.close_connection = True
            raise BadRequest("invalid request target") from exc

    def _authorize(self: TransportCollaborator, *, write_body: bool = True) -> bool:
        if self.api_token is None:
            self.close_connection = True
            self._json(HTTPStatus.SERVICE_UNAVAILABLE, {"error": "API authentication is not configured"}, write_body=write_body)
            return False
        if not bearer_token_matches(self._authorization_value(), self.api_token):
            self.close_connection = True
            self._json(HTTPStatus.UNAUTHORIZED, {"error": "authentication required"}, headers={"WWW-Authenticate": 'Bearer realm="LifeDB"'}, write_body=write_body)
            return False
        return True

    def _content_length(self: TransportCollaborator) -> int:
        if self.headers.get_all("Transfer-Encoding", failobj=[]):
            self.close_connection = True
            raise BadRequest("Transfer-Encoding is not supported")
        values = self.headers.get_all("Content-Length", failobj=[])
        if not values:
            return 0
        if len(values) != 1 or CONTENT_LENGTH_RE.fullmatch(values[0]) is None:
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

    def _validate_get_framing(self: TransportCollaborator) -> None:
        try:
            length = self._content_length()
        except BadRequest:
            self.close_connection = True
            raise
        if length:
            self.close_connection = True
            raise BadRequest("GET and HEAD requests must not contain a body")

    def _close_if_unread_body(self: TransportCollaborator) -> None:
        if self._content_length():
            self.close_connection = True

    def _read_body(self: TransportCollaborator) -> bytes:
        length = self._content_length()
        body = self.rfile.read(length)
        if len(body) != length:
            self.close_connection = True
            raise BadRequest("request body is shorter than Content-Length")
        return body

    def _read_json(self: TransportCollaborator) -> JSONMapping:
        body = self._read_body()
        if not body:
            return {}
        try:
            value: JSONValue = strict_json_loads(body, max_bytes=MAX_BODY_BYTES)
        except ValueError as exc:
            raise BadRequest("invalid JSON request body") from exc
        if not isinstance(value, dict):
            raise BadRequest("JSON request body must be an object")
        return value

    def _require_json_content_type(self: TransportCollaborator) -> None:
        value = self._single_header("Content-Type")
        parts = [part.strip() for part in value.split(";")] if value is not None else []
        valid = bool(parts) and parts[0].casefold() == "application/json"
        if valid and len(parts) > 1:
            valid = len(parts) == 2 and re.fullmatch(r'charset\s*=\s*(?:utf-8|"utf-8")', parts[1], re.IGNORECASE) is not None
        if not valid:
            self.close_connection = True
            raise BadRequest("Content-Type must be application/json")

    @staticmethod
    def _limit(value: JSONValue, *, default: int) -> int:
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
    def _query(value: JSONValue, *, allow_empty: bool = False) -> str:
        if not isinstance(value, str) or (not allow_empty and not value.strip()):
            raise BadRequest("query must be a non-empty string")
        if len(value.strip()) > MAX_QUERY_CHARS or "\x00" in value:
            raise BadRequest(f"query must be at most {MAX_QUERY_CHARS} characters without NUL")
        return value

    @staticmethod
    def _optional_string(request: JSONMapping, name: str) -> str | None:
        value = request.get(name)
        if value is None:
            return None
        if not isinstance(value, str):
            raise BadRequest(f"{name} must be a string")
        return value

    @staticmethod
    def _budget(request: JSONMapping, name: str, default: int) -> int:
        value = request.get(name, default)
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise BadRequest(f"{name} must be a non-negative integer")
        return min(value, default)

    def _effective_ceiling(self: TransportCollaborator, requested: JSONValue | None) -> str:
        try:
            return effective_sensitivity_ceiling(self.server_sensitivity_ceiling, requested)
        except ValueError as exc:
            raise BadRequest(str(exc)) from exc

    @staticmethod
    def _one_query_parameter(params: dict[str, list[str]], name: str, default: str | None = None) -> str | None:
        values = params.get(name)
        if values is None:
            return default
        if len(values) != 1:
            raise BadRequest(f"{name} must be supplied at most once")
        return values[0]

    @staticmethod
    def _query_parameters(query: str, *, allowed: set[str] | None = None) -> dict[str, list[str]]:
        try:
            params = parse_qs(query, keep_blank_values=True, max_num_fields=32)
        except ValueError as exc:
            raise BadRequest("invalid query parameters") from exc
        if allowed is not None and set(params) - allowed:
            raise BadRequest("unknown query parameter")
        return params

    @staticmethod
    def _expansion_max_chars(value: str | None, *, default: int) -> int:
        if value is None:
            return min(default, MAX_EXPANSION_CHARS)
        if CONTENT_LENGTH_RE.fullmatch(value) is None:
            raise BadRequest("max_chars must be a non-negative integer")
        normalized = value.lstrip("0") or "0"
        if len(normalized) > len(str(MAX_EXPANSION_CHARS)):
            return min(default, MAX_EXPANSION_CHARS)
        return min(int(normalized), default, MAX_EXPANSION_CHARS)

    @staticmethod
    def _decode_evidence_id(encoded_id: str) -> str:
        try:
            evidence_id = unquote(encoded_id, errors="strict")
        except UnicodeDecodeError as exc:
            raise BadRequest("evidence ID is not valid UTF-8") from exc
        if not is_uuid7(evidence_id):
            raise BadRequest("evidence ID must be a UUIDv7")
        return evidence_id
