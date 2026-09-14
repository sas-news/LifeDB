from __future__ import annotations

from pathlib import Path
from typing import TypeAlias

import yaml
from yaml.events import AliasEvent

ConfigValue: TypeAlias = str | int | float | bool | None | list["ConfigValue"] | dict[str, "ConfigValue"]
Config = dict[str, ConfigValue]


class ConfigError(ValueError):
    pass


class Loader(yaml.SafeLoader):
    def compose_node(self, parent: yaml.Node | None, index: int) -> yaml.Node:
        if self.check_event(AliasEvent):
            raise ConfigError("invalid Hermes configuration")
        return super().compose_node(parent, index)


def _value(value: ConfigValue) -> ConfigValue:
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, list):
        return [_value(item) for item in value]
    if isinstance(value, dict):
        if not all(isinstance(key, str) for key in value):
            raise ConfigError("invalid Hermes configuration")
        return {key: _value(item) for key, item in value.items()}
    raise ConfigError("invalid Hermes configuration")


def _mapping(loader: Loader, node: yaml.MappingNode, deep: bool = False) -> dict[str, ConfigValue]:
    result: dict[str, ConfigValue] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=True)
        if not isinstance(key, str) or key in result:
            raise ConfigError("invalid Hermes configuration")
        result[key] = _value(loader.construct_object(value_node, deep=True))
    return result


Loader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _mapping)


def load_config(path: Path) -> tuple[Config, bytes]:
    try:
        raw = path.read_bytes()
        return load_config_bytes(raw)
    except (OSError, ConfigError) as error:
        raise ConfigError("invalid Hermes configuration") from error


def load_config_bytes(raw: bytes) -> tuple[Config, bytes]:
    if len(raw) > 1_048_576:
        raise ConfigError("invalid Hermes configuration")
    try:
        loaded = yaml.load(raw.decode("utf-8"), Loader=Loader)
    except (UnicodeDecodeError, yaml.YAMLError, ConfigError) as error:
        raise ConfigError("invalid Hermes configuration") from error
    if loaded is None:
        return {}, raw
    if not isinstance(loaded, dict):
        raise ConfigError("invalid Hermes configuration")
    return loaded, raw


def _plugins(config: Config) -> dict[str, ConfigValue]:
    if "plugins" not in config:
        config["plugins"] = {}
    plugins = config.get("plugins", {})
    if not isinstance(plugins, dict):
        raise ConfigError("invalid Hermes configuration")
    return plugins


def projection(config: Config) -> Config:
    plugins = _plugins(config)
    enabled = plugins.get("enabled", [])
    disabled = plugins.get("disabled", [])
    entries = plugins.get("entries", {})
    if not isinstance(enabled, list) or not all(isinstance(item, str) for item in enabled):
        raise ConfigError("invalid Hermes configuration")
    if not isinstance(disabled, list) or not all(isinstance(item, str) for item in disabled):
        raise ConfigError("invalid Hermes configuration")
    if len(set(enabled)) != len(enabled) or len(set(disabled)) != len(disabled):
        raise ConfigError("invalid Hermes configuration")
    if set(enabled) & set(disabled):
        raise ConfigError("invalid Hermes configuration")
    if not isinstance(entries, dict):
        raise ConfigError("invalid Hermes configuration")
    entry = entries.get("lifedb-bridge", {})
    if not isinstance(entry, dict):
        raise ConfigError("invalid Hermes configuration")
    settings = entry.get("settings", {})
    if not isinstance(settings, dict):
        raise ConfigError("invalid Hermes configuration")
    return {"enabled": list(enabled), "disabled": list(disabled), "settings": dict(settings)}


def owned_projection(config: Config) -> Config:
    state = projection(config)
    enabled = "enabled" if "lifedb-bridge" in state["enabled"] else "disabled" if "lifedb-bridge" in state["disabled"] else "absent"
    return {"lifecycle": enabled, "settings": dict(state["settings"])}


def update(config: Config, desired: str, settings: Config | None) -> Config:
    state = projection(config)
    if settings is not None:
        allowed = {"url", "token_file", "workspace", "timeout_seconds", "max_response_bytes", "max_request_bytes", "sensitivity_ceiling", "budget_chars", "core_chars", "continuity_chars", "relevant_chars", "limit"}
        if set(state["settings"]) - allowed:
            raise ConfigError("invalid Hermes configuration")
        state["settings"] = dict(settings)
    state["enabled"] = [item for item in state["enabled"] if item != "lifedb-bridge"]
    state["disabled"] = [item for item in state["disabled"] if item != "lifedb-bridge"]
    (state["enabled"] if desired == "enabled" else state["disabled"]).append("lifedb-bridge")
    plugins = _plugins(config)
    plugins["enabled"] = state["enabled"]
    plugins["disabled"] = state["disabled"]
    entries = plugins.setdefault("entries", {})
    if not isinstance(entries, dict):
        raise ConfigError("invalid Hermes configuration")
    entries["lifedb-bridge"] = {"settings": state["settings"]}
    return config


def remove(config: Config) -> Config:
    state = projection(config)
    plugins = _plugins(config)
    plugins["enabled"] = [item for item in state["enabled"] if item != "lifedb-bridge"]
    plugins["disabled"] = [item for item in state["disabled"] if item != "lifedb-bridge"]
    entries = plugins.get("entries")
    if isinstance(entries, dict):
        entries.pop("lifedb-bridge", None)
    return config


def dump_config(config: Config) -> bytes:
    return yaml.safe_dump(config, sort_keys=False, allow_unicode=False).encode("utf-8")
