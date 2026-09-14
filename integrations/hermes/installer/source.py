from __future__ import annotations

import hashlib
import os
import stat
from pathlib import Path
from typing import TypeAlias

import yaml
from yaml.events import AliasEvent

from .models import InstallerError

PLUGIN_ID = "lifedb-bridge"
RUNTIME = "hermes-0.21.0"
OWNED_FILES = ("plugin.yaml", "__init__.py", "hooks.py", "preflight.py", "postflight.py", "context_pack.py", "settings.py", "token_file.py", "transport.py", "url_validation.py", "http_parser.py", "bridge.py", "payloads.py", "logging_utils.py")
YamlValue: TypeAlias = str | int | float | bool | None | list["YamlValue"] | dict[str, "YamlValue"]


class _Loader(yaml.SafeLoader):
    def compose_node(self, parent: yaml.Node | None, index: int) -> yaml.Node:
        if self.check_event(AliasEvent):
            raise InstallerError("Hermes installer operation failed")
        return super().compose_node(parent, index)


def _mapping(loader: _Loader, node: yaml.MappingNode, deep: bool = False) -> dict[str, YamlValue]:
    result: dict[str, YamlValue] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=True)
        if not isinstance(key, str) or key in result:
            raise InstallerError("Hermes installer operation failed")
        result[key] = loader.construct_object(value_node, deep=True)
    return result


_Loader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _mapping)


def source_root() -> Path:
    root = Path(__file__).parents[1]
    for name in OWNED_FILES:
        path = root / name
        if path.is_symlink() or not path.is_file():
            raise InstallerError("Hermes installer operation failed")
    try:
        descriptor = os.open(root / "plugin.yaml", os.O_RDONLY | os.O_NOFOLLOW)
        try:
            info = os.fstat(descriptor)
            if not stat.S_ISREG(info.st_mode) or info.st_size > 1_048_576:
                raise InstallerError("Hermes installer operation failed")
            raw = os.read(descriptor, 1_048_577)
            if len(raw) != info.st_size:
                raise InstallerError("Hermes installer operation failed")
        finally:
            os.close(descriptor)
        manifest = yaml.load(raw.decode("utf-8"), Loader=_Loader)
    except (OSError, UnicodeError, yaml.YAMLError) as error:
        raise InstallerError("Hermes installer operation failed") from error
    if not isinstance(manifest, dict):
        raise InstallerError("Hermes installer operation failed")
    if manifest.get("name") != PLUGIN_ID or manifest.get("hooks") != ["pre_llm_call", "post_llm_call", "on_session_end"] or manifest.get("provides_hooks") != manifest.get("hooks"):
        raise InstallerError("Hermes installer operation failed")
    return root


def hashes(root: Path) -> dict[str, str]:
    return {name: _digest(root / name) for name in OWNED_FILES}


def _digest(path: Path) -> str:
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    except OSError as error:
        raise InstallerError("Hermes installer operation failed") from error
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_size > 16_777_216:
            raise InstallerError("Hermes installer operation failed")
        digest = hashlib.sha256(); remaining = info.st_size
        while remaining:
            chunk = os.read(descriptor, min(65_536, remaining))
            if not chunk: raise InstallerError("Hermes installer operation failed")
            digest.update(chunk); remaining -= len(chunk)
        return digest.hexdigest()
    finally:
        os.close(descriptor)
