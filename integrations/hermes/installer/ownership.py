from __future__ import annotations

import hashlib
import json
import os
import stat
from pathlib import Path
from typing import TypeAlias

from .config import Config
from .cache import validate_cache
from .models import InstallerError
from .source import OWNED_FILES, PLUGIN_ID, RUNTIME
from ..settings import SettingsError, load_settings

JsonValue: TypeAlias = str | int | float | bool | None | list["JsonValue"] | dict[str, "JsonValue"]


def validate_marker(value: JsonValue) -> dict[str, JsonValue]:
    if not isinstance(value, dict):
        raise InstallerError("Hermes installer operation failed")
    required = {"schema", "plugin", "version", "runtime", "files", "manifest_sha256", "managed_config", "lifecycle"}
    if set(value) != required or value["schema"] != 1 or value["plugin"] != PLUGIN_ID or value["version"] != "0.1.0" or value["runtime"] != RUNTIME or value["lifecycle"] not in {"enabled", "disabled"}:
        raise InstallerError("Hermes installer operation failed")
    files = value["files"]
    if not isinstance(files, dict) or set(files) != set(OWNED_FILES) or not all(isinstance(item, str) and len(item) == 64 and all(char in "0123456789abcdef" for char in item) for item in files.values()):
        raise InstallerError("Hermes installer operation failed")
    manifest = value["manifest_sha256"]
    if not isinstance(manifest, str) or len(manifest) != 64 or not all(char in "0123456789abcdef" for char in manifest) or not isinstance(value["managed_config"], dict):
        raise InstallerError("Hermes installer operation failed")
    managed = value["managed_config"]
    if set(managed) != {"lifecycle", "settings"} or managed["lifecycle"] not in {"enabled", "disabled", "absent"} or managed["lifecycle"] != value["lifecycle"] or not isinstance(managed["settings"], dict):
        raise InstallerError("Hermes installer operation failed")
    allowed = {"url", "token_file", "workspace", "timeout_seconds", "max_response_bytes", "max_request_bytes", "sensitivity_ceiling", "budget_chars", "core_chars", "continuity_chars", "relevant_chars", "limit"}
    if set(managed["settings"]) - allowed:
        raise InstallerError("Hermes installer operation failed")
    _config_value(managed)
    class _Reader:
        def get_config(self, key: str, default: str | int | float | bool | None = None) -> str | int | float | bool | None:
            value = managed["settings"].get(key)
            return default if value is None else value
    try:
        load_settings(_Reader(), include_context=True)
    except SettingsError as error:
        raise InstallerError("Hermes installer operation failed") from error
    return value


def _config_value(value: JsonValue) -> None:
    if value is None or isinstance(value, (str, int, float, bool)):
        return
    if isinstance(value, list):
        for item in value:
            _config_value(item)
        return
    if isinstance(value, dict):
        if not all(isinstance(key, str) for key in value):
            raise InstallerError("Hermes installer operation failed")
        for item in value.values():
            _config_value(item)
        return
    raise InstallerError("Hermes installer operation failed")


def marker(root: Path, state: str, config: Config, files: dict[str, str]) -> bytes:
    manifest = _digest(root / "plugin.yaml")
    return marker_for(state, config, files, manifest)


def marker_for(state: str, config: Config, files: dict[str, str], manifest: str) -> bytes:
    return json.dumps({"schema": 1, "plugin": PLUGIN_ID, "version": "0.1.0", "runtime": RUNTIME, "files": files, "manifest_sha256": manifest, "managed_config": config, "lifecycle": state}, sort_keys=True, separators=(",", ":")).encode()


def validate_tree(root: Path) -> dict[str, JsonValue]:
    if root.is_symlink() or not root.is_dir() or root.stat().st_uid != os.geteuid() or stat.S_IMODE(root.stat().st_mode) & 0o077:
        raise InstallerError("Hermes installer operation failed")
    entries = {item.name for item in root.iterdir()}
    if not entries <= set(OWNED_FILES) | {".lifedb-owner.json", "__pycache__"}:
        raise InstallerError("Hermes installer operation failed")
    if "__pycache__" in entries:
        validate_cache(root)
    if entries - {"__pycache__"} != set(OWNED_FILES) | {".lifedb-owner.json"}:
        raise InstallerError("Hermes installer operation failed")
    try:
        marker_path = root / ".lifedb-owner.json"
        descriptor = os.open(marker_path, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            info = os.fstat(descriptor)
            if not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o600 or info.st_size > 1_048_576:
                raise InstallerError("Hermes installer operation failed")
            raw = os.read(descriptor, 1_048_577)
        finally:
            os.close(descriptor)
        if len(raw) != info.st_size:
            raise InstallerError("Hermes installer operation failed")
        if not raw or raw[-1:] != b"}":
            raise InstallerError("Hermes installer operation failed")
        loaded = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_pairs)
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise InstallerError("Hermes installer operation failed") from error
    owner = validate_marker(loaded)
    files = owner["files"]
    if not isinstance(files, dict):
        raise InstallerError("Hermes installer operation failed")
    for name in OWNED_FILES:
        path = root / name
        if path.is_symlink() or not path.is_file() or path.stat().st_uid != os.geteuid() or (path.stat().st_mode & 0o777) != 0o600 or _digest(path) != files[name]:
            raise InstallerError("Hermes installer operation failed")
    if _digest(root / "plugin.yaml") != owner["manifest_sha256"]:
        raise InstallerError("Hermes installer operation failed")
    return owner


def _digest(path: Path) -> str:
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o600 or info.st_size > 16_777_216:
            raise InstallerError("Hermes installer operation failed")
        digest = hashlib.sha256()
        remaining = info.st_size
        while remaining:
            chunk = os.read(descriptor, min(65_536, remaining))
            if not chunk:
                raise InstallerError("Hermes installer operation failed")
            digest.update(chunk)
            remaining -= len(chunk)
        return digest.hexdigest()
    finally:
        os.close(descriptor)


def _unique_pairs(pairs: list[tuple[str, JsonValue]]) -> dict[str, JsonValue]:
    result: dict[str, JsonValue] = {}
    for key, value in pairs:
        if key in result:
            raise InstallerError("Hermes installer operation failed")
        result[key] = value
    return result
