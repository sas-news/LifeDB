from __future__ import annotations

from urllib.parse import urlparse
from typing import Callable, ClassVar, Protocol

from ._server_transport import BadRequest, TransportCollaborator


class MethodCollaborator(TransportCollaborator, Protocol):
    path: str
    command: str
    def _handle_get(self, *, write_body: bool = True) -> None: ...
    def _handle_post(self) -> None: ...
    def log_error(self, format: str, *args: str | int) -> None: ...
    def address_string(self) -> str: ...
    @staticmethod
    def _allowed_methods(path: str) -> str: ...
    def _request_log_path(self) -> str: ...
    def log_message(self, format: str, *args: str | int) -> None: ...


class MethodMixin:
    close_connection: bool = False

    def do_GET(self: MethodCollaborator) -> None:
        try:
            self._handle_get(write_body=True)
        except BadRequest as exc:
            self._json(400, {"error": str(exc)})
        except Exception as exc:  # noqa: BROAD_EXCEPT_OK
            self.log_error("internal request failure (%s)", type(exc).__name__)
            self._json(500, {"error": "internal server error"})

    def do_POST(self: MethodCollaborator) -> None:
        try:
            self._handle_post()
        except BadRequest as exc:
            self._json(400, {"error": str(exc)})
        except Exception as exc:  # noqa: BROAD_EXCEPT_OK
            self.log_error("internal request failure (%s)", type(exc).__name__)
            self._json(500, {"error": "internal server error"})

    def do_HEAD(self: MethodCollaborator) -> None:
        try:
            self._handle_get(write_body=False)
        except BadRequest as exc:
            self._json(400, {"error": str(exc)}, write_body=False)
        except Exception as exc:  # noqa: BROAD_EXCEPT_OK
            self.log_error("internal request failure (%s)", type(exc).__name__)
            self._json(500, {"error": "internal server error"}, write_body=False)

    @staticmethod
    def _allowed_methods(path: str) -> str:
        if path == "/health" or path == "/v1/search" or path.startswith("/v1/evidence/"):
            return "GET, HEAD"
        if path in {"/v1/ingest", "/v1/turns", "/v1/context", "/v1/rebuild", "/v1/validate"}:
            return "POST"
        return "GET, POST, HEAD"

    def _unsupported_method(self: MethodCollaborator) -> None:
        try:
            parsed = self._request_url()
            if parsed.path != "/health" and not self._authorize():
                return
            self._close_if_unread_body()
            self.close_connection = True
            self._json(405, {"error": "method not allowed"}, headers={"Allow": self._allowed_methods(parsed.path)})
        except BadRequest as exc:
            self._json(400, {"error": str(exc)})
        except Exception as exc:  # noqa: BROAD_EXCEPT_OK
            self.log_error("internal request failure (%s)", type(exc).__name__)
            self._json(500, {"error": "internal server error"})

    do_DELETE: ClassVar[Callable[[MethodCollaborator], None]] = _unsupported_method
    do_CONNECT: ClassVar[Callable[[MethodCollaborator], None]] = _unsupported_method
    do_OPTIONS: ClassVar[Callable[[MethodCollaborator], None]] = _unsupported_method
    do_PATCH: ClassVar[Callable[[MethodCollaborator], None]] = _unsupported_method
    do_PUT: ClassVar[Callable[[MethodCollaborator], None]] = _unsupported_method
    do_TRACE: ClassVar[Callable[[MethodCollaborator], None]] = _unsupported_method

    def _request_log_path(self: MethodCollaborator) -> str:
        try:
            path = urlparse(self.path).path
        except ValueError:
            path = ""
        return path or "/"

    def log_request(self: MethodCollaborator, code: int | str = "-", size: int | str = "-") -> None:
        _ = size
        self.log_message("%s %s %s", self.command or "-", self._request_log_path(), code)

    def log_message(self: MethodCollaborator, format: str, *args: str | int) -> None:
        print(f"{self.address_string()} - {format % args}")
