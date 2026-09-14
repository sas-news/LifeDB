from __future__ import annotations

from datetime import datetime, timezone

from .vault_constants import RFC3339_RE
from ._vault_errors import VaultTypeError, VaultValueError


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def parse_time(value: str | None) -> datetime:
    if value is not None and not isinstance(value, str):
        raise VaultTypeError("timestamp must be a string or None")
    if value is None:
        return datetime.now(timezone.utc)
    if not RFC3339_RE.fullmatch(value):
        raise VaultValueError("timestamp must be RFC3339 with T and an explicit UTC offset")
    normalized = value.replace("Z", "+00:00")
    parsed = datetime.fromisoformat(normalized)
    if parsed.tzinfo is None:
        raise VaultValueError("timestamp must include an explicit UTC offset")
    return parsed
