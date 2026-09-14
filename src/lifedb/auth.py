from __future__ import annotations

import hmac
import os
import re
import stat
import sys
from collections.abc import Mapping


SENSITIVITY_ORDER = {
    "public": 0,
    "personal": 1,
    "sensitive": 2,
    "restricted": 3,
}
SENSITIVITIES = frozenset(SENSITIVITY_ORDER)

# Bearer credentials are supplied through an environment variable and are
# intentionally bounded before a listening socket is opened.  The lower
# bound prevents accidental demo/default credentials; the upper bound keeps
# malformed configuration from consuming disproportionate header/comparison
# resources.  Bounds are measured after UTF-8 encoding, not in code points.
MIN_API_TOKEN_BYTES = 32
MAX_API_TOKEN_BYTES = 4096

_BEARER_RE = re.compile(r"^Bearer ([^\s]+)$", re.IGNORECASE)


def validate_sensitivity(value: object, *, field: str = "sensitivity") -> str:
    """Return a known sensitivity label, rejecting unknown values closed."""

    if not isinstance(value, str) or value not in SENSITIVITY_ORDER:
        raise ValueError(f"invalid {field}")
    return value


def validate_api_token(value: object) -> str | None:
    """Validate an HTTP API token without exposing its value.

    ``None`` and the empty string both mean that HTTP authentication is not
    configured; the handler then keeps health available but fails protected
    requests closed.  Any configured token must be non-whitespace and fall
    within the UTF-8 byte limits above.
    """

    if value is None:
        return None
    if not isinstance(value, str):
        raise TypeError("api_token must be a string or None")
    if not value:
        return None
    if any(character.isspace() for character in value):
        raise ValueError("api_token must not contain whitespace")
    try:
        byte_length = len(value.encode("utf-8"))
    except UnicodeEncodeError:
        # Do not include the offending credential in the exception text.
        raise ValueError("api_token must be valid UTF-8") from None
    if byte_length < MIN_API_TOKEN_BYTES:
        raise ValueError(
            f"api_token must be at least {MIN_API_TOKEN_BYTES} UTF-8 bytes"
        )
    if byte_length > MAX_API_TOKEN_BYTES:
        raise ValueError(
            f"api_token must be at most {MAX_API_TOKEN_BYTES} UTF-8 bytes"
        )
    return value


def effective_sensitivity_ceiling(
    server_ceiling: str, requested_ceiling: object | None = None
) -> str:
    """Intersect a request ceiling with the server-managed maximum.

    A caller may reduce what is returned, but can never use a request field to
    raise its server-side authorization. Unknown labels are rejected rather
    than silently receiving the default level.
    """

    configured = validate_sensitivity(server_ceiling, field="server sensitivity ceiling")
    if requested_ceiling is None:
        return configured
    requested = validate_sensitivity(
        requested_ceiling, field="requested sensitivity ceiling"
    )
    if SENSITIVITY_ORDER[requested] < SENSITIVITY_ORDER[configured]:
        return requested
    return configured


def effective_ingest_sensitivity(
    server_floor: str, requested_sensitivity: object | None = None
) -> str:
    """Apply a server-managed minimum label to HTTP ingestion.

    A caller may conservatively raise a capture's label, but cannot classify it
    below the server profile's floor.
    """

    configured = validate_sensitivity(server_floor, field="ingestion sensitivity floor")
    if requested_sensitivity is None:
        return configured
    requested = validate_sensitivity(
        requested_sensitivity, field="requested ingestion sensitivity"
    )
    if SENSITIVITY_ORDER[requested] > SENSITIVITY_ORDER[configured]:
        return requested
    return configured


def bearer_token_matches(authorization: object, api_token: str) -> bool:
    """Validate one strict Bearer credential with a constant-time comparison."""

    if not isinstance(authorization, str) or not isinstance(api_token, str):
        return False
    match = _BEARER_RE.fullmatch(authorization)
    if match is None:
        return False
    try:
        supplied = match.group(1).encode("utf-8")
        configured = api_token.encode("utf-8")
    except UnicodeEncodeError:
        # The HTTP boundary should fail closed even when called directly with
        # a Python string containing an unpaired surrogate.  Never echo the
        # credential or let its encoding error escape to logs.
        return False
    return hmac.compare_digest(supplied, configured)


# Descriptive aliases kept for callers that prefer operation-oriented names.
authenticate_bearer = bearer_token_matches
resolve_sensitivity_ceiling = effective_sensitivity_ceiling


# Protected token-file contract (Task 4: consumed by CLI startup, Compose
# service bootstrap, and both host adapters).  The file holds the exact token
# bytes: no trimming, no newline tolerance.  Every failure message below is
# deliberately stable and never interpolates the configured value or path.
DIRECT_TOKEN_ENV = "LIFEDB_API_TOKEN"
FILE_TOKEN_ENV = "LIFEDB_API_TOKEN_FILE"
MAX_TOKEN_FILE_BYTES = MAX_API_TOKEN_BYTES


def _normalize_token_source(value: object, *, kind: str) -> str | None:
    """Treat empty env values as unset; reject non-string sources closed."""

    if value is None:
        return None
    if not isinstance(value, str):
        raise TypeError(f"api token {kind} must be a string or None")
    if not value:
        return None
    return value


def _current_owner() -> int:
    try:
        return os.geteuid()
    except AttributeError:
        raise ValueError("api token file owner cannot be verified") from None


def read_token_file(path_value: object) -> str:
    """Read exact token bytes from a protected regular file.

    Absolute path; current-user-owned regular non-symlink final file with
    no group/other bits; at most 4096 bytes; strict UTF-8; no trimming.
    Descriptor identity, timestamps, mode, and owner are verified before
    and after the read, and the final path is re-inspected for the same
    security state. Errors never carry the value or the path.
    """

    if not isinstance(path_value, str):
        raise TypeError("api token file must be an absolute path")
    if not os.path.isabs(path_value):
        raise ValueError("api token file must be an absolute path")
    try:
        before = os.lstat(path_value)
    except OSError:
        raise ValueError("api token file cannot be read safely") from None
    if not stat.S_ISREG(before.st_mode):
        raise ValueError("api token file must be a regular non-symlink file")
    if before.st_size > MAX_TOKEN_FILE_BYTES:
        raise ValueError("api token file exceeds the maximum size")
    flags = (
        os.O_RDONLY
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NONBLOCK", 0)
    )
    try:
        descriptor = os.open(path_value, flags)
    except OSError:
        raise ValueError("api token file cannot be opened safely") from None
    try:
        owner = _current_owner()
        try:
            opened = os.fstat(descriptor)
        except OSError:
            raise ValueError("api token file cannot be read safely") from None
        if not stat.S_ISREG(opened.st_mode):
            raise ValueError("api token file must be a regular non-symlink file")
        if opened.st_mode & 0o077:
            raise ValueError("api token file permissions are too open")
        if opened.st_uid != owner:
            raise ValueError("api token file must be owned by the current user")
        if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
            raise ValueError("api token file changed during safe open")
        if (
            opened.st_size != before.st_size
            or opened.st_mtime_ns != before.st_mtime_ns
            or opened.st_ctime_ns != before.st_ctime_ns
        ):
            raise ValueError("api token file changed during safe open")
        if opened.st_size > MAX_TOKEN_FILE_BYTES:
            raise ValueError("api token file exceeds the maximum size")
        chunks: list[bytes] = []
        remaining = MAX_TOKEN_FILE_BYTES + 1
        while remaining:
            try:
                chunk = os.read(descriptor, min(64 * 1024, remaining))
            except OSError:
                raise ValueError("api token file cannot be read safely") from None
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        payload = b"".join(chunks)
        if len(payload) > MAX_TOKEN_FILE_BYTES:
            raise ValueError("api token file exceeds the maximum size")
        try:
            finished = os.fstat(descriptor)
        except OSError:
            raise ValueError("api token file changed during safe read") from None
        if (
            (finished.st_dev, finished.st_ino, finished.st_size)
            != (opened.st_dev, opened.st_ino, opened.st_size)
            or (finished.st_mtime_ns, finished.st_ctime_ns)
            != (opened.st_mtime_ns, opened.st_ctime_ns)
            or (finished.st_mode, finished.st_uid)
            != (opened.st_mode, opened.st_uid)
            or len(payload) != finished.st_size
        ):
            raise ValueError("api token file changed during safe read")
        try:
            after = os.lstat(path_value)
        except OSError:
            raise ValueError("api token file changed during safe read") from None
        if (
            not stat.S_ISREG(after.st_mode)
            or (after.st_dev, after.st_ino)
            != (finished.st_dev, finished.st_ino)
            or after.st_mode & 0o077
            or after.st_uid != owner
        ):
            raise ValueError("api token file changed during safe read")
        try:
            return payload.decode("utf-8")
        except UnicodeDecodeError:
            raise ValueError("api token file must be valid UTF-8") from None
    finally:
        pending = sys.exception()
        try:
            os.close(descriptor)
        except OSError:
            if pending is None:
                raise ValueError("api token file cannot be read safely") from None


def resolve_api_token(
    direct: object = None, file_path: object = None
) -> str | None:
    """Resolve one token from a direct value or a protected file.

    Empty env strings are unset; two live sources are an error; a
    configured-but-empty file is an error, never silent unconfigure.
    Bytes pass through untrimmed into ``validate_api_token``.
    """

    direct_value = _normalize_token_source(direct, kind="value")
    file_value = _normalize_token_source(file_path, kind="file")
    if direct_value is not None and file_value is not None:
        raise ValueError("api token is configured from two sources")
    if direct_value is not None:
        return validate_api_token(direct_value)
    if file_value is not None:
        content = read_token_file(file_value)
        if not content:
            raise ValueError("api token file must not be empty")
        return validate_api_token(content)
    return None


def resolve_api_token_from_env(
    env: Mapping[str, str] | None = None,
) -> str | None:
    """Resolve the token from process-env sources with empty-means-unset."""

    source = os.environ if env is None else env
    try:
        direct = source.get(DIRECT_TOKEN_ENV)
        file_path = source.get(FILE_TOKEN_ENV)
    except AttributeError:
        raise TypeError("api token env source must be a mapping") from None
    return resolve_api_token(direct, file_path)
