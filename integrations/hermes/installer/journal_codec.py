from __future__ import annotations

import json
from typing import TypeAlias

from .journal_schema import identity_data, identity_or_none
from .models import Identity, InstallerError

Json: TypeAlias = str | int | float | bool | None | list["Json"] | dict[str, "Json"]


def fail() -> InstallerError:
    return InstallerError("Hermes installer operation failed")


def pairs(items: list[tuple[str, Json]]) -> dict[str, Json]:
    result: dict[str, Json] = {}
    for key, value in items:
        if key in result:
            raise fail()
        result[key] = value
    return result


def envelope(slot: int, identity: Identity) -> bytes:
    value = {"schema": 1, "state": "active", "slot": slot, "identity": identity_data(identity)}
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def decode(raw: bytes) -> tuple[int, Identity]:
    if len(raw) > 16_384:
        raise fail()
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=pairs)
    except (UnicodeDecodeError, json.JSONDecodeError, InstallerError) as error:
        raise fail() from error
    if raw != json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8"):
        raise fail()
    if not isinstance(value, dict) or set(value) != {"schema", "state", "slot", "identity"}:
        raise fail()
    if type(value["schema"]) is not int or value["schema"] != 1 or value["state"] != "active":
        raise fail()
    if type(value["slot"]) is not int or value["slot"] not in (0, 1):
        raise fail()
    identity = identity_or_none(value["identity"])
    if identity is None:
        raise fail()
    return value["slot"], identity
