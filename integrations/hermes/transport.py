from __future__ import annotations

from dataclasses import dataclass
import json
import math
import socket
import ssl
from time import monotonic
from typing import Final, NoReturn

from .http_parser import (
    ResponseMetadata,
    TransportFailure,
    parse_response_metadata,
    read_response_body,
)
from .url_validation import Endpoint, parse_endpoint

CONTENT_TYPE: Final = "application/json"
_READ_CHUNK_BYTES: Final = 65_536
_MAX_HEADER_BYTES: Final = 65_536
_MAX_RESPONSE_BYTES: Final = 16_777_216
_MAX_PROVISIONAL_RESPONSES: Final = 1_000


@dataclass(frozen=True, slots=True)
class HttpResponse:
    status: int
    body: bytes


def _endpoint(url: str) -> Endpoint:
    if not isinstance(url, str):
        raise TransportFailure("bridge request unavailable")
    if any(ord(character) < 0x20 or ord(character) == 0x7F for character in url):
        raise TransportFailure("bridge request unavailable")
    try:
        return parse_endpoint(url)
    except ValueError as error:
        raise TransportFailure("bridge request unavailable") from error


def _remaining(deadline: float) -> float:
    remaining = deadline - monotonic()
    if remaining <= 0:
        raise TransportFailure("bridge request deadline exceeded")
    return remaining


def _socket_failure(
    error: OSError | TimeoutError | OverflowError, deadline: float
) -> TransportFailure:
    if monotonic() >= deadline or isinstance(error, TimeoutError):
        return TransportFailure("bridge request deadline exceeded")
    return TransportFailure("bridge request unavailable")


def _connect(endpoint: Endpoint, deadline: float) -> socket.socket:
    connection: socket.socket | None = None
    try:
        connection = socket.create_connection(
            (endpoint.host, endpoint.port or (443 if endpoint.scheme == "https" else 80)),
            timeout=_remaining(deadline),
        )
        if endpoint.scheme == "https":
            context = ssl.create_default_context()
            connection.settimeout(_remaining(deadline))
            wrapped = context.wrap_socket(connection, server_hostname=endpoint.host)
            connection = None
            return wrapped
        return connection
    except TimeoutError as error:
        if connection is not None:
            connection.close()
        raise _socket_failure(error, deadline) from error
    except (OSError, OverflowError) as error:
        if connection is not None:
            connection.close()
        raise _socket_failure(error, deadline) from error


def _send_request(
    connection: socket.socket,
    endpoint: Endpoint,
    token: str,
    body: bytes,
    deadline: float,
) -> None:
    connection.settimeout(_remaining(deadline))
    host = endpoint.host
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    default_port = 443 if endpoint.scheme == "https" else 80
    if endpoint.port is not None and endpoint.port != default_port:
        host += f":{endpoint.port}"
    headers = (
        f"POST {endpoint.target} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Authorization: Bearer {token}\r\n"
        f"Content-Type: {CONTENT_TYPE}\r\n"
        f"Accept: {CONTENT_TYPE}\r\n"
        f"Content-Length: {len(body)}\r\n"
        "Connection: close\r\n\r\n"
    ).encode("utf-8")
    try:
        connection.sendall(headers + body)
    except TimeoutError as error:
        raise _socket_failure(error, deadline) from error
    except OSError as error:
        raise _socket_failure(error, deadline) from error


class _DeadlineReader:
    """Read a response from one owned socket under one monotonic deadline."""

    def __init__(self, connection: socket.socket, deadline: float) -> None:
        self._connection = connection
        self._deadline = deadline
        self._buffer = bytearray()

    def _receive(self, maximum: int) -> bytes:
        try:
            self._connection.settimeout(_remaining(self._deadline))
            chunk = self._connection.recv(maximum)
        except TimeoutError as error:
            raise _socket_failure(error, self._deadline) from error
        except OSError as error:
            raise _socket_failure(error, self._deadline) from error
        if not chunk:
            raise TransportFailure("bridge response ended unexpectedly")
        return chunk

    def read_until(self, delimiter: bytes, maximum: int) -> bytes:
        while True:
            position = self._buffer.find(delimiter)
            if position >= 0:
                end = position + len(delimiter)
                result = bytes(self._buffer[:end])
                del self._buffer[:end]
                return result
            if len(self._buffer) >= maximum:
                raise TransportFailure("bridge response headers exceed limit")
            self._buffer.extend(
                self._receive(min(_READ_CHUNK_BYTES, maximum - len(self._buffer)))
            )

    def read_exact(self, size: int) -> bytes:
        while len(self._buffer) < size:
            self._buffer.extend(self._receive(_READ_CHUNK_BYTES))
        result = bytes(self._buffer[:size])
        del self._buffer[:size]
        return result

    def read_available(self) -> bytes:
        if self._buffer:
            result = bytes(self._buffer[:_READ_CHUNK_BYTES])
            del self._buffer[:_READ_CHUNK_BYTES]
            return result
        try:
            self._connection.settimeout(_remaining(self._deadline))
            return self._connection.recv(_READ_CHUNK_BYTES)
        except TimeoutError as error:
            raise _socket_failure(error, self._deadline) from error
        except OSError as error:
            raise _socket_failure(error, self._deadline) from error


class StdlibTransport:
    """Owned synchronous HTTP transport with no redirect or retry behavior."""

    def __init__(self, max_response_bytes: int) -> None:
        if isinstance(max_response_bytes, bool) or not isinstance(max_response_bytes, int) or not 1 <= max_response_bytes <= _MAX_RESPONSE_BYTES:
            raise TransportFailure("invalid response limit")
        self._max_response_bytes = max_response_bytes

    def request(self, url: str, token: str, body: bytes, timeout: float) -> HttpResponse:
        connection: socket.socket | None = None
        try:
            if (
                isinstance(timeout, bool)
                or not isinstance(timeout, (int, float))
                or (isinstance(timeout, float) and not math.isfinite(timeout))
                or not 0.1 <= timeout <= 30.0
            ):
                raise TransportFailure("bridge request deadline exceeded")
            deadline = monotonic() + float(timeout)
            if any(ord(character) < 0x20 or ord(character) == 0x7F for character in token):
                raise TransportFailure("bridge request unavailable")
            try:
                token_bytes = token.encode("utf-8")
            except UnicodeEncodeError as error:
                raise TransportFailure("bridge request unavailable") from error
            if not 32 <= len(token_bytes) <= 4096 or any(
                character.isspace()
                or ord(character) < 0x20
                or ord(character) == 0x7F
                for character in token
            ):
                raise TransportFailure("bridge request unavailable")
            endpoint = _endpoint(url)
            connection = _connect(endpoint, deadline)
            _send_request(connection, endpoint, token, body, deadline)
            reader = _DeadlineReader(connection, deadline)
            metadata: ResponseMetadata = parse_response_metadata(
                reader.read_until(b"\r\n\r\n", _MAX_HEADER_BYTES)
            )
            provisional_count = 0
            while 100 <= metadata.status < 200 and metadata.status != 101:
                provisional_count += 1
                if provisional_count > _MAX_PROVISIONAL_RESPONSES:
                    raise TransportFailure("too many provisional responses")
                metadata = parse_response_metadata(
                    reader.read_until(b"\r\n\r\n", _MAX_HEADER_BYTES)
                )
            return HttpResponse(
                metadata.status,
                read_response_body(reader, metadata, self._max_response_bytes),
            )
        except TransportFailure:
            raise
        except TimeoutError as error:
            raise _socket_failure(error, deadline) from error
        except (OSError, OverflowError) as error:
            raise _socket_failure(error, deadline) from error
        except ValueError as error:
            raise TransportFailure("bridge request unavailable") from error
        finally:
            if connection is not None:
                connection.close()


def require_json_response(response: HttpResponse, maximum: int) -> bytes:
    """Accept only a bounded successful JSON response body."""
    if response.status < 200 or response.status >= 300 or len(response.body) > maximum:
        raise TransportFailure("unexpected bridge response")
    def reject_constant(value: str) -> NoReturn:
        del value
        raise TransportFailure("unexpected bridge response")

    try:
        decoded = json.loads(response.body, parse_constant=reject_constant)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise TransportFailure("unexpected bridge response") from error
    if not isinstance(decoded, dict):
        raise TransportFailure("unexpected bridge response")
    return response.body
