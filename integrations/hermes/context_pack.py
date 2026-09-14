from __future__ import annotations

from datetime import datetime
import json
import math
import re
from typing import Final, NoReturn, TypeAlias


JsonValue: TypeAlias = (
    dict[str, "JsonValue"] | list["JsonValue"] | str | int | float | bool | None
)
ContextPack: TypeAlias = dict[str, JsonValue]


class ContextPackError(ValueError):
    pass

_MAX_BUDGET: Final = 1_000_000
_MAX_ARRAY: Final = 1_000
_MAX_TEXT: Final = 1_000_000
_MAX_QUERY: Final = 4_096
_UUID7: Final = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
)
_RFC3339: Final = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$"
)
_REQUIRED: Final = frozenset(
    {
        "schema", "id", "generated_at", "query", "core", "continuity",
        "relevant", "evidence_handles", "rendered_markdown", "authorization",
        "budget", "watermark", "truncated", "degraded",
    }
)
_BUDGET_FIELDS: Final = frozenset(
    {"budget_chars", "core_chars", "continuity_chars", "relevant_chars", "used_chars"}
)
_WATERMARK_FIELDS: Final = frozenset({"durable_sequence", "indexed_sequence", "dirty"})
_SENSITIVITIES: Final = frozenset({"public", "personal", "sensitive", "restricted"})
_ITEM_REQUIRED: Final = frozenset({"source_kind", "source_id", "title", "snippet"})


def _reject_constant(_value: str) -> NoReturn:
    raise ContextPackError("non-finite JSON number")


def _finite_float(value: str) -> float:
    parsed = float(value)
    if not math.isfinite(parsed):
        raise ContextPackError("non-finite JSON number")
    return parsed


def _unique_object(pairs: list[tuple[str, JsonValue]]) -> dict[str, JsonValue]:
    result: dict[str, JsonValue] = {}
    for key, value in pairs:
        if key in result:
            raise ContextPackError("duplicate JSON object key")
        result[key] = value
    return result


def _strict_load(payload: bytes, maximum: int) -> JsonValue:
    if isinstance(maximum, bool) or not isinstance(maximum, int) or maximum < 1:
        raise ContextPackError("invalid response limit")
    if len(payload) > maximum:
        raise ContextPackError("response exceeds limit")
    try:
        text = payload.decode("utf-8", errors="strict")
        decoded = json.loads(
            text,
            object_pairs_hook=_unique_object,
            parse_constant=_reject_constant,
            parse_float=_finite_float,
        )
        json.dumps(decoded, ensure_ascii=False, allow_nan=False).encode("utf-8")
    except (UnicodeError, ValueError, OverflowError, RecursionError, MemoryError):
        raise ContextPackError("invalid strict JSON") from None
    return decoded


def _mapping(value: JsonValue) -> dict[str, JsonValue] | None:
    return value if isinstance(value, dict) else None


def _text(value: JsonValue, maximum: int, *, nonempty: bool = False) -> bool:
    if not isinstance(value, str) or len(value) > maximum or (nonempty and not value):
        return False
    return all(
        character not in {"\x7f"}
        and (ord(character) >= 0x20 or character in {"\t", "\n", "\r"})
        and not 0xD800 <= ord(character) <= 0xDFFF
        for character in value
    )


def _uuid7(value: JsonValue) -> bool:
    return isinstance(value, str) and _UUID7.fullmatch(value) is not None


def _timestamp(value: JsonValue) -> bool:
    if not isinstance(value, str) or _RFC3339.fullmatch(value) is None:
        return False
    try:
        datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (OverflowError, ValueError):
        return False
    return True


def _nonnegative_integer(value: JsonValue, maximum: int = _MAX_BUDGET) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and 0 <= value <= maximum


def _finite_number(value: JsonValue) -> bool:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return False
    try:
        return math.isfinite(float(value))
    except OverflowError:
        return False


def _valid_item(value: JsonValue) -> bool:
    item = _mapping(value)
    if item is None or not _ITEM_REQUIRED <= item.keys():
        return False
    if item["source_kind"] not in {"canon", "evidence"}:
        return False
    if not _text(item["source_id"], _MAX_TEXT, nonempty=True):
        return False
    if not _text(item["title"], _MAX_TEXT) or not _text(item["snippet"], _MAX_TEXT):
        return False
    optional_strings = ("path",)
    if any(not _text(item[name], _MAX_TEXT) for name in optional_strings if name in item):
        return False
    if "score" in item and not _finite_number(item["score"]):
        return False
    if "sensitivity" in item and item["sensitivity"] not in _SENSITIVITIES:
        return False
    return all(
        isinstance(item[name], bool) for name in ("truncated", "untrusted") if name in item
    )


def _valid_items(pack: ContextPack, name: str) -> bool:
    value = pack.get(name)
    return isinstance(value, list) and len(value) <= _MAX_ARRAY and all(
        _valid_item(item) for item in value
    )


def _valid_authorization(value: JsonValue) -> bool:
    authorization = _mapping(value)
    if authorization is None:
        return False
    required = {"principal", "sensitivity_ceiling"}
    if not required <= authorization.keys():
        return False
    if not _text(authorization["principal"], _MAX_TEXT, nonempty=True):
        return False
    if authorization["sensitivity_ceiling"] not in _SENSITIVITIES:
        return False
    return all(
        _text(authorization[name], _MAX_TEXT)
        for name in ("destination", "purpose")
        if name in authorization
    )


def _valid_budget(value: JsonValue) -> bool:
    budget = _mapping(value)
    if budget is None or set(budget) != _BUDGET_FIELDS:
        return False
    return all(_nonnegative_integer(budget[name]) for name in _BUDGET_FIELDS)


def _valid_watermark(value: JsonValue) -> bool:
    watermark = _mapping(value)
    if watermark is None or set(watermark) != _WATERMARK_FIELDS:
        return False
    return (
        _nonnegative_integer(watermark["durable_sequence"])
        and _nonnegative_integer(watermark["indexed_sequence"])
        and isinstance(watermark["dirty"], bool)
        and watermark["indexed_sequence"] <= watermark["durable_sequence"]
    )


def _valid_text_array(value: JsonValue) -> bool:
    return isinstance(value, list) and len(value) <= _MAX_ARRAY and all(
        _text(item, _MAX_TEXT) for item in value
    )


def _valid_pack(value: JsonValue) -> bool:
    pack = _mapping(value)
    if pack is None or not _REQUIRED <= pack.keys():
        return False
    if pack["schema"] != "0.2" or not _uuid7(pack["id"]):
        return False
    if not _timestamp(pack["generated_at"]) or not _text(pack["query"], _MAX_QUERY):
        return False
    if "client" in pack and not _text(pack["client"], _MAX_TEXT):
        return False
    if not _text(pack["rendered_markdown"], _MAX_TEXT, nonempty=True):
        return False
    handles = pack["evidence_handles"]
    if not isinstance(handles, list) or len(handles) > _MAX_ARRAY:
        return False
    if not all(_uuid7(handle) for handle in handles) or len(set(handles)) != len(handles):
        return False
    if not all(_valid_items(pack, name) for name in ("core", "continuity", "relevant")):
        return False
    if not _valid_authorization(pack["authorization"]):
        return False
    if not _valid_budget(pack["budget"]) or not _valid_watermark(pack["watermark"]):
        return False
    budget = pack["budget"]
    if not isinstance(budget, dict):
        return False
    layer_sum = sum(budget[name] for name in ("core_chars", "continuity_chars", "relevant_chars"))
    if layer_sum > budget["budget_chars"] or budget["used_chars"] > budget["budget_chars"]:
        return False
    if not isinstance(pack["truncated"], bool) or not _valid_text_array(pack["degraded"]):
        return False
    if "truncation" in pack and not _valid_text_array(pack["truncation"]):
        return False
    return True


def parse_context_pack(payload: bytes, *, max_bytes: int) -> ContextPack | None:
    """Parse one bounded Hermes response as a strict schema-valid Context Pack."""
    try:
        decoded = _strict_load(payload, max_bytes)
    except ValueError:
        return None
    return decoded if _valid_pack(decoded) else None
