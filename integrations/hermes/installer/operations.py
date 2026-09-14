from __future__ import annotations

import copy
import base64
import hashlib
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys

from ..settings import PluginSettings, SettingsError, load_settings
from .config import Config, ConfigError, dump_config, load_config_bytes, owned_projection, update
from .environment import backup, fsync_path, write_atomic
from .journal_limits import MAX_CONFIG_BYTES
from .models import ConfigPreimage, Identity, InstallOptions, InstallerError
from .ownership import marker, validate_tree
from .process import child_env, run_host_checks
from .source import OWNED_FILES, hashes, source_root


class _Context:
    def __init__(self, options: InstallOptions) -> None:
        self.values = options.settings()

    def get_config(self, key: str, default: str | int | float | bool | None = None) -> str | int | float | bool | None:
        value = self.values.get(key)
        return default if value is None else value


def validate_options(options: InstallOptions) -> PluginSettings:
    try:
        return load_settings(_Context(options), include_context=True)
    except SettingsError as error:
        raise InstallerError("Hermes installer operation failed") from error


def config_path(home: Path) -> Path:
    path = home / "config.yaml"
    if path.is_symlink() or (path.exists() and not path.is_file()):
        raise InstallerError("Hermes installer operation failed")
    return path


def target_state(root: Path) -> bool:
    try:
        info = root.lstat()
    except FileNotFoundError:
        return False
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        raise InstallerError("Hermes installer operation failed")
    return True


def read_config(home: Path, *, create: bool) -> ConfigPreimage:
    path = config_path(home)
    try:
        before = path.lstat()
    except FileNotFoundError:
        if not create:
            raise InstallerError("Hermes installer operation failed")
        return ConfigPreimage(False, {}, b"", 0o600, 0, None)
    try:
        if before.st_uid != os.geteuid() or not stat.S_ISREG(before.st_mode) or before.st_mode & 0o022 or before.st_size > MAX_CONFIG_BYTES:
            raise InstallerError("Hermes installer operation failed")
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            opened = os.fstat(descriptor)
            if (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns, stat.S_IMODE(opened.st_mode), opened.st_uid) != (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, stat.S_IMODE(before.st_mode), before.st_uid):
                raise InstallerError("Hermes installer operation failed")
            raw = _read_fd(descriptor, opened.st_size)
            identity = Identity(
                opened.st_dev,
                opened.st_ino,
                opened.st_uid,
                "file",
                stat.S_IMODE(opened.st_mode),
                opened.st_size,
                opened.st_mtime_ns,
                hashlib.sha256(raw).hexdigest(),
            )
        finally:
            os.close(descriptor)
        config, _ = load_config_bytes(raw)
        after = path.lstat()
        if (identity.device, identity.inode, identity.size, identity.mtime_ns, identity.mode, identity.owner_uid) != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, stat.S_IMODE(after.st_mode), after.st_uid):
            raise InstallerError("Hermes installer operation failed")
        return ConfigPreimage(True, config, raw, identity.mode, identity.mtime_ns, identity)
    except ConfigError as error:
        raise InstallerError("Hermes installer operation failed") from error


def _read_fd(descriptor: int, size: int) -> bytes:
    chunks: list[bytes] = []
    remaining = size
    while remaining:
        chunk = os.read(descriptor, min(65_536, remaining))
        if not chunk:
            raise InstallerError("Hermes installer operation failed")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def settings_projection(options: InstallOptions, config: Config) -> Config:
    desired = copy.deepcopy(config)
    update(desired, "enabled", options.settings())
    return owned_projection(desired)


def build_tree(staging: Path, source: Path, state: str, managed: Config) -> None:
    for name in OWNED_FILES:
        destination = staging / name
        shutil.copyfile(source / name, destination, follow_symlinks=False)
        destination.chmod(0o600)
    write_atomic(staging / ".lifedb-owner.json", marker(staging, state, managed, hashes(source)), 0o600)


def validate_candidate(staging: Path, binary: str, home: Path) -> None:
    files = [str(staging / name) for name in OWNED_FILES if name.endswith(".py")]
    code = "import pathlib,sys; [compile(pathlib.Path(p).read_text(encoding='utf-8'), p, 'exec') for p in sys.argv[1:]]"
    env = child_env(home)
    try:
        result = subprocess.run([sys.executable, "-c", code, *files], capture_output=True, check=False, timeout=10, env=env)
    except (OSError, subprocess.TimeoutExpired) as error:
        raise InstallerError("Hermes installer operation failed") from error
    if result.returncode != 0 or result.stderr:
        raise InstallerError("Hermes installer operation failed")
    run_host_checks(binary, str(staging), home)


def mutate_config(home: Path, config: Config, old: bytes, mode: int, desired: str, options: InstallOptions | None, uninstall: bool = False, exists: bool = True) -> bytes:
    try:
        changed = config if uninstall else copy.deepcopy(config)
        if uninstall:
            from .config import remove
            remove(changed)
        else:
            update(changed, desired, None if options is None else options.settings())
        new = dump_config(changed)
    except ConfigError as error:
        raise InstallerError("Hermes installer operation failed") from error
    if old != new:
        if exists:
            backup(home / "config.yaml", old)
        write_atomic(home / "config.yaml", new, mode)
    return new
