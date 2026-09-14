from __future__ import annotations

from dataclasses import dataclass
from typing import Final, Protocol


_MAX_HEADER_BYTES: Final = 65_536
_HEX_DIGITS: Final = frozenset(b"0123456789abcdefABCDEF")
_TOKEN_BYTES: Final = frozenset(
    b"!#$%&'*+-.^_`|~0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
)


class TransportFailure(RuntimeError):
    """A bounded bridge request could not produce a usable response."""


class ResponseReader(Protocol):
    def read_until(self, delimiter: bytes, maximum: int) -> bytes: ...

    def read_exact(self, size: int) -> bytes: ...

    def read_available(self) -> bytes: ...


@dataclass(frozen=True, slots=True)
class ResponseMetadata:
    status: int
    content_length: int | None
    chunked: bool


def _malformed() -> TransportFailure:
    return TransportFailure("bridge response is malformed")


def _validate_field_value(value: bytes) -> None:
    if any((byte < 0x20 and byte != 0x09) or byte == 0x7F for byte in value):
        raise _malformed()


def _validate_header_line(line: bytes) -> None:
    name, separator, value = line.partition(b":")
    if (
        not separator
        or not name
        or any(byte not in _TOKEN_BYTES for byte in name)
    ):
        raise _malformed()
    _validate_field_value(value)


def _status(line: bytes) -> int:
    parts = line.split(b" ", 2)
    if len(parts) != 3 or parts[0] not in {b"HTTP/1.0", b"HTTP/1.1"}:
        raise _malformed()
    code = parts[1]
    if len(code) != 3 or any(byte < 0x30 or byte > 0x39 for byte in code):
        raise _malformed()
    _validate_field_value(parts[2])
    parsed = int(code)
    if not 100 <= parsed <= 599:
        raise _malformed()
    return parsed


def parse_response_metadata(header_block: bytes) -> ResponseMetadata:
    """Parse one strict HTTP/1.1 response header block."""
    if len(header_block) < 4 or not header_block.endswith(b"\r\n\r\n"):
        raise _malformed()
    lines = header_block[:-4].split(b"\r\n")
    if not lines:
        raise _malformed()
    status = _status(lines[0])
    content_length: int | None = None
    transfer_encoding_seen = False
    chunked = False
    for line in lines[1:]:
        _validate_header_line(line)
        name, _, raw_value = line.partition(b":")
        value = raw_value.strip(b" \t")
        lowered = name.lower()
        if lowered == b"content-length":
            if content_length is not None or not value:
                raise _malformed()
            if any(byte < 0x30 or byte > 0x39 for byte in value):
                raise _malformed()
            try:
                content_length = int(value)
            except ValueError as error:
                raise _malformed() from error
        elif lowered == b"transfer-encoding":
            if transfer_encoding_seen or value.lower() != b"chunked":
                raise _malformed()
            transfer_encoding_seen = True
            chunked = True
    if chunked and content_length is not None:
        raise _malformed()
    if 100 <= status < 200 or status == 204:
        if content_length is not None or chunked:
            raise _malformed()
    return ResponseMetadata(status, content_length, chunked)


def _chunk_size(line: bytes) -> int:
    value = line[:-2].split(b";", 1)[0].strip(b" \t")
    if not value or any(byte not in _HEX_DIGITS for byte in value):
        raise _malformed()
    try:
        return int(value, 16)
    except ValueError as error:
        raise _malformed() from error


def _chunked_body(reader: ResponseReader, maximum: int) -> bytes:
    body = bytearray()
    trailer_bytes = 0
    while True:
        line = reader.read_until(b"\r\n", _MAX_HEADER_BYTES)
        _validate_field_value(line[:-2])
        size = _chunk_size(line)
        if size == 0:
            while True:
                trailer = reader.read_until(b"\r\n", _MAX_HEADER_BYTES)
                trailer_bytes += len(trailer)
                if trailer_bytes > _MAX_HEADER_BYTES:
                    raise TransportFailure("bridge response headers exceed limit")
                if trailer == b"\r\n":
                    return bytes(body)
                trailer_line = trailer[:-2]
                _validate_header_line(trailer_line)
                name, _, _ = trailer_line.partition(b":")
                if name.lower() in {b"content-length", b"transfer-encoding"}:
                    raise _malformed()
        if len(body) + size > maximum:
            raise TransportFailure("response exceeds configured limit")
        body.extend(reader.read_exact(size))
        if reader.read_exact(2) != b"\r\n":
            raise _malformed()


def read_response_body(
    reader: ResponseReader, metadata: ResponseMetadata, maximum: int
) -> bytes:
    """Read only the body allowed by strict response framing semantics."""
    if 100 <= metadata.status < 200 or metadata.status in {204, 304}:
        return b""
    if metadata.chunked:
        return _chunked_body(reader, maximum)
    if metadata.content_length is not None:
        if metadata.content_length > maximum:
            raise TransportFailure("response exceeds configured limit")
        return reader.read_exact(metadata.content_length)
    body = bytearray()
    while True:
        chunk = reader.read_available()
        if not chunk:
            return bytes(body)
        body.extend(chunk)
        if len(body) > maximum:
            raise TransportFailure("response exceeds configured limit")
