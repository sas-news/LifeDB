from __future__ import annotations

import os
import re
import time
import uuid


UUID7_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
)


def uuid7() -> uuid.UUID:
    """Generate an RFC 9562 UUIDv7 without relying on interpreter version."""
    timestamp_ms = time.time_ns() // 1_000_000
    if timestamp_ms >= 1 << 48:
        raise OverflowError("current time does not fit UUIDv7 timestamp")
    random_bits = int.from_bytes(os.urandom(10), "big")
    rand_a = (random_bits >> 68) & 0xFFF
    rand_b = random_bits & ((1 << 62) - 1)
    value = (
        (timestamp_ms << 80)
        | (0x7 << 76)
        | (rand_a << 64)
        | (0b10 << 62)
        | rand_b
    )
    return uuid.UUID(int=value)


def new_id() -> str:
    return str(uuid7())


def is_uuid7(value: object) -> bool:
    if not isinstance(value, str) or UUID7_RE.fullmatch(value) is None:
        return False
    try:
        parsed = uuid.UUID(value)
    except ValueError:
        return False
    return parsed.version == 7 and parsed.variant == uuid.RFC_4122
