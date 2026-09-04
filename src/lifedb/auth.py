from __future__ import annotations

import hmac
import re


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
