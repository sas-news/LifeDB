from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import SplitResult, urlsplit


_UNRESERVED = frozenset(
    b"0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ-._~"
)
_SUB_DELIMS = frozenset(b"!$&'()*+,;=")


class UrlValidationError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class Endpoint:
    scheme: str
    host: str
    port: int | None
    target: str


def _valid_component(value: str, *, query: bool) -> bool:
    try:
        encoded = value.encode("ascii")
    except UnicodeEncodeError:
        return False
    allowed = _UNRESERVED | _SUB_DELIMS | frozenset(b":@")
    if query:
        allowed |= frozenset(b"/?")
    else:
        allowed |= frozenset(b"/")
    index = 0
    while index < len(encoded):
        byte = encoded[index]
        if byte == ord("%"):
            if index + 2 >= len(encoded):
                return False
            if encoded[index + 1] not in b"0123456789abcdefABCDEF":
                return False
            if encoded[index + 2] not in b"0123456789abcdefABCDEF":
                return False
            index += 3
            continue
        if byte not in allowed:
            return False
        index += 1
    return True


def _target(parsed: SplitResult) -> str:
    path = parsed.path or "/"
    if not _valid_component(path, query=False) or not _valid_component(
        parsed.query, query=True
    ):
        raise UrlValidationError("invalid origin-form target")
    return path if not parsed.query else f"{path}?{parsed.query}"


def _raw_authority(url: str) -> str:
    scheme_end = url.find("://")
    if scheme_end < 0:
        return ""
    start = scheme_end + 3
    end = len(url)
    for delimiter in "/?#":
        position = url.find(delimiter, start)
        if position >= 0:
            end = min(end, position)
    return url[start:end]


def parse_endpoint(url: str) -> Endpoint:
    if not url or url != url.strip():
        raise UrlValidationError("invalid URL authority")
    if "#" in url:
        raise UrlValidationError("invalid URL target")
    if any(ord(character) < 0x20 or ord(character) == 0x7F for character in url):
        raise UrlValidationError("invalid URL authority")
    authority = _raw_authority(url)
    if any(character.isspace() for character in authority) or "@" in authority:
        raise UrlValidationError("invalid URL authority")
    for index, character in enumerate(authority):
        if character == "%" and (
            index + 2 >= len(authority)
            or authority[index + 1] not in "0123456789abcdefABCDEF"
            or authority[index + 2] not in "0123456789abcdefABCDEF"
        ):
            raise UrlValidationError("invalid URL authority")
    try:
        parsed = urlsplit(url)
        hostname = parsed.hostname
        port = parsed.port
    except ValueError as error:
        raise UrlValidationError("invalid URL authority") from error
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise UrlValidationError("invalid URL authority")
    if hostname is None or parsed.username or parsed.password:
        raise UrlValidationError("invalid URL authority")
    if parsed.netloc.endswith(":") or port == 0:
        raise UrlValidationError("invalid URL authority")
    try:
        hostname.encode("ascii")
    except UnicodeEncodeError as error:
        raise UrlValidationError("invalid URL authority") from error
    if parsed.fragment:
        raise UrlValidationError("invalid URL target")
    return Endpoint(parsed.scheme, hostname, port, _target(parsed))
