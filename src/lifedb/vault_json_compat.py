from __future__ import annotations

from typing import NoReturn

from ._json_types import JSONMapping, JSONValue
from ._vault_errors import VaultValueError


def _reject_json_constant(value: str) -> NoReturn:
    raise VaultValueError(f"non-finite JSON value {value!r} is not permitted")


def _reject_duplicate_json_keys(pairs: list[tuple[str, JSONValue]]) -> JSONMapping:
    result: JSONMapping = {}
    for key, value in pairs:
        if key in result:
            raise VaultValueError(f"duplicate JSON object key: {key}")
        result[key] = value
    return result
