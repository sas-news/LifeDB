from __future__ import annotations

from dataclasses import dataclass
import math
import os
from typing import Protocol
from urllib.parse import urlsplit

from .url_validation import parse_endpoint


SettingValue = str | int | float | bool | None


class ConfigReader(Protocol):
    def get_config(self, key: str, default: SettingValue = None) -> SettingValue: ...


class SettingsError(ValueError):
    """Plugin configuration is invalid without exposing its value."""


@dataclass(frozen=True, slots=True)
class PluginSettings:
    base_url: str
    token_file: str | None
    timeout_seconds: float
    max_response_bytes: int
    max_request_bytes: int = 4_194_304
    workspace: str | None = None
    sensitivity: str | None = None
    budget_chars: int = 12_000
    core_chars: int = 4_000
    continuity_chars: int = 2_000
    relevant_chars: int = 6_000
    limit: int = 8


def _text(value: SettingValue, field: str) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or not value:
        raise SettingsError(f"invalid {field} setting")
    return value


def _base_url(value: SettingValue) -> str:
    candidate = _text(value, "url") or "http://127.0.0.1:7331"
    if any(ord(character) < 0x20 or ord(character) == 0x7F for character in candidate):
        raise SettingsError("invalid url setting")
    try:
        parse_endpoint(candidate)
        parsed = urlsplit(candidate)
    except ValueError as error:
        raise SettingsError("invalid url setting") from error
    if parsed.query or parsed.fragment:
        raise SettingsError("invalid url setting")
    return candidate.rstrip("/")


def _timeout(value: SettingValue) -> float:
    if value is None:
        return 2.0
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise SettingsError("invalid timeout_seconds setting")
    if (isinstance(value, float) and not math.isfinite(value)) or not 0.1 <= value <= 30.0:
        raise SettingsError("invalid timeout_seconds setting")
    return float(value)


def _response_limit(value: SettingValue) -> int:
    if value is None:
        return 1_048_576
    if isinstance(value, bool) or not isinstance(value, int):
        raise SettingsError("invalid max_response_bytes setting")
    if not 1 <= value <= 16_777_216:
        raise SettingsError("invalid max_response_bytes setting")
    return value


def _request_limit(value: SettingValue) -> int:
    if value is None:
        return 4_194_304
    if isinstance(value, bool) or not isinstance(value, int):
        raise SettingsError("invalid max_request_bytes setting")
    if not 1 <= value <= 16_777_216:
        raise SettingsError("invalid max_request_bytes setting")
    return value


def _bounded_budget(value: SettingValue, field: str, default: int) -> int:
    if value is None:
        return default
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= 1_000_000:
        raise SettingsError(f"invalid {field} setting")
    return value


def _result_limit(value: SettingValue) -> int:
    if value is None:
        return 8
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= 100:
        raise SettingsError("invalid limit setting")
    return value


def _optional_label(value: SettingValue, field: str, *, absolute: bool = False) -> str | None:
    if value == "":
        return None
    parsed = _text(value, field)
    if parsed is None:
        return None
    if any(ord(character) < 0x20 or ord(character) == 0x7F for character in parsed):
        raise SettingsError(f"invalid {field} setting")
    if len(parsed.strip()) > 512 or (absolute and not os.path.isabs(parsed)):
        raise SettingsError(f"invalid {field} setting")
    if field == "sensitivity_ceiling" and parsed not in {"public", "personal", "sensitive", "restricted"}:
        raise SettingsError(f"invalid {field} setting")
    return parsed


def load_settings(context: ConfigReader, *, include_context: bool = False) -> PluginSettings:
    """Read and parse only the plugin-owned Hermes settings namespace."""
    loaded = PluginSettings(
        base_url=_base_url(context.get_config("url", "http://127.0.0.1:7331")),
        token_file=_text(context.get_config("token_file"), "token_file"),
        timeout_seconds=_timeout(context.get_config("timeout_seconds", 2.0)),
        max_response_bytes=_response_limit(
            context.get_config("max_response_bytes", 1_048_576)
        ),
        max_request_bytes=_request_limit(
            context.get_config("max_request_bytes", 4_194_304)
        ),
    )
    if not include_context:
        return loaded
    return PluginSettings(
        base_url=loaded.base_url, token_file=loaded.token_file,
        timeout_seconds=loaded.timeout_seconds, max_response_bytes=loaded.max_response_bytes,
        max_request_bytes=loaded.max_request_bytes,
        workspace=_optional_label(context.get_config("workspace"), "workspace", absolute=True),
        sensitivity=_optional_label(context.get_config("sensitivity_ceiling"), "sensitivity_ceiling"),
        budget_chars=_bounded_budget(context.get_config("budget_chars", 12_000), "budget_chars", 12_000),
        core_chars=_bounded_budget(context.get_config("core_chars", 4_000), "core_chars", 4_000),
        continuity_chars=_bounded_budget(context.get_config("continuity_chars", 2_000), "continuity_chars", 2_000),
        relevant_chars=_bounded_budget(context.get_config("relevant_chars", 6_000), "relevant_chars", 6_000),
        limit=_result_limit(context.get_config("limit", 8)),
    )
