from __future__ import annotations

from collections.abc import Mapping

JSONValue = str | int | float | bool | None | list["JSONValue"] | Mapping[str, "JSONValue"]
JSONMapping = dict[str, JSONValue]
