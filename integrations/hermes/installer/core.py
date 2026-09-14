from __future__ import annotations

import copy
from pathlib import Path
import time

from .config import Config, ConfigError, dump_config, owned_projection, remove, update
from .environment import acquire_lock, fsync_path, release_lock, safe_home, safe_token, write_atomic
from .identity import path_identity
from .lifecycle_state import TransactionSession, capture_snapshot, planned_marker
from .models import ConfigPreimage, Identity, InstallOptions, InstallerError
from .operations import build_tree, read_config, settings_projection, target_state, validate_candidate, validate_options
from .ownership import marker, validate_tree
from .process import resolved_identity, run_host_checks
from .recovery import recover
from .source import hashes, source_root
from .transaction import read_journal

__all__ = ["InstallOptions", "InstallerError", "lifecycle"]

_validate_candidate = validate_candidate
_read_config = read_config


def _desired_config(config: Config, state: str, options: InstallOptions | None) -> bytes:
    changed = copy.deepcopy(config)
    update(changed, state, None if options is None else options.settings())
    return dump_config(changed)


def _removed_config(config: Config) -> bytes:
    changed = copy.deepcopy(config)
    remove(changed)
    return dump_config(changed)


def _session(home: Path, operation: str, config: ConfigPreimage, root: Path, lock_path: Path, binary_identity: Identity, desired_config: bytes | None, desired_marker: bytes | None) -> TransactionSession:
    snapshot = capture_snapshot(home, operation, config, root, path_identity(lock_path), binary_identity)
    return TransactionSession(snapshot, desired_config, desired_marker)


def _install(home: Path, options: InstallOptions, hermes_binary: str, config: Config, config_preimage: ConfigPreimage, lock_path: Path) -> None:
    source = source_root()
    root = home / "plugins" / "lifedb-bridge"
    root_exists = target_state(root)
    source_hashes = hashes(source)
    desired = settings_projection(options, config)
    owner = validate_tree(root) if root_exists else None
    if owner is not None and owner.get("managed_config") == desired and owner.get("lifecycle") == "enabled" and owner.get("files") == source_hashes:
        return
    if not root_exists:
        projection = config.get("plugins", {}) if isinstance(config.get("plugins"), dict) else {}
        if isinstance(projection, dict) and "lifedb-bridge" in set(projection.get("enabled", [])) | set(projection.get("disabled", [])):
            raise InstallerError("Hermes installer operation failed")
    changed = copy.deepcopy(config)
    update(changed, "enabled", options.settings())
    desired_config = dump_config(changed)
    desired_marker = planned_marker("enabled", owned_projection(changed), source_hashes, source_hashes["plugin.yaml"])
    session = _session(home, "install", config_preimage, root, lock_path, resolved_identity(hermes_binary), desired_config, desired_marker)
    plugins = home / "plugins"
    plugins.mkdir(mode=0o700, exist_ok=True)
    staging = plugins / f".lifedb-staging-{time.time_ns()}"
    staging.mkdir(mode=0o700)
    quarantine: Path | None = None
    try:
        session.record("prepared", staging=staging.relative_to(home).as_posix(), quarantine=None, live_identity=path_identity(root, directory=True) if root_exists else None)
        build_tree(staging, source, "enabled", owned_projection(changed))
        validate_tree(staging)
        _validate_candidate(staging, hermes_binary, home)
        session.record("staged", staging=staging.relative_to(home).as_posix(), quarantine=None, staging_identity=path_identity(staging, directory=True), observed_marker=path_identity(staging / ".lifedb-owner.json"), live_identity=path_identity(root, directory=True) if root_exists else None)
        if root_exists:
            quarantine = plugins / f".lifedb-quarantine-{time.time_ns()}"
            session.record("old_root_rename_intent", staging=staging.relative_to(home).as_posix(), quarantine=quarantine.relative_to(home).as_posix(), staging_identity=path_identity(staging, directory=True), observed_marker=path_identity(staging / ".lifedb-owner.json"), live_identity=path_identity(root, directory=True))
            root.rename(quarantine)
            fsync_path(plugins)
            session.record("quarantined", staging=staging.relative_to(home).as_posix(), quarantine=quarantine.relative_to(home).as_posix(), staging_identity=path_identity(staging, directory=True), quarantine_identity=path_identity(quarantine, directory=True), observed_marker=path_identity(staging / ".lifedb-owner.json"))
        session.record("staging_to_live_intent", staging=staging.relative_to(home).as_posix(), quarantine=None if quarantine is None else quarantine.relative_to(home).as_posix(), staging_identity=path_identity(staging, directory=True), quarantine_identity=None if quarantine is None else path_identity(quarantine, directory=True), observed_marker=path_identity(staging / ".lifedb-owner.json"))
        staging.rename(root)
        fsync_path(plugins)
        quarantine_identity = None if quarantine is None else path_identity(quarantine, directory=True)
        session.record("published", staging=None, quarantine=None if quarantine is None else quarantine.relative_to(home).as_posix(), quarantine_identity=quarantine_identity, live_identity=path_identity(root, directory=True), observed_marker=path_identity(root / ".lifedb-owner.json"))
        session.record("config_intent", staging=None, quarantine=None if quarantine is None else quarantine.relative_to(home).as_posix(), quarantine_identity=quarantine_identity, live_identity=path_identity(root, directory=True), observed_marker=path_identity(root / ".lifedb-owner.json"))
        from .operations import mutate_config
        mutate_config(home, config, config_preimage.raw, config_preimage.mode, "enabled", options, exists=config_preimage.exists)
        session.record("config_published", staging=None, quarantine=None if quarantine is None else quarantine.relative_to(home).as_posix(), quarantine_identity=quarantine_identity, live_identity=path_identity(root, directory=True), observed_config=path_identity(home / "config.yaml"), observed_marker=path_identity(root / ".lifedb-owner.json"))
        run_host_checks(hermes_binary, str(root), home)
        session.record("commit_intent", staging=None, quarantine=None if quarantine is None else quarantine.relative_to(home).as_posix(), quarantine_identity=quarantine_identity, live_identity=path_identity(root, directory=True), observed_config=path_identity(home / "config.yaml"), observed_marker=path_identity(root / ".lifedb-owner.json"))
        session.record("committed", staging=None, quarantine=None if quarantine is None else quarantine.relative_to(home).as_posix(), quarantine_identity=quarantine_identity, live_identity=path_identity(root, directory=True), observed_config=path_identity(home / "config.yaml"), observed_marker=path_identity(root / ".lifedb-owner.json"))
        recover(home)
    except (OSError, ConfigError, InstallerError) as error:
        raise InstallerError("Hermes installer operation failed") from error


def _toggle(home: Path, command: str, options: InstallOptions, hermes_binary: str, config: Config, config_preimage: ConfigPreimage, lock_path: Path) -> None:
    root = home / "plugins" / "lifedb-bridge"
    owner = validate_tree(root)
    run_host_checks(hermes_binary, str(root), home)
    state = "disabled" if command == "disable" else "enabled"
    changed = copy.deepcopy(config)
    update(changed, state, options.settings())
    desired_config = dump_config(changed)
    desired_marker = marker(root, state, owned_projection(changed), owner["files"])
    session = _session(home, command, config_preimage, root, lock_path, resolved_identity(hermes_binary), desired_config, desired_marker)
    session.record("prepared", staging=None, quarantine=None, live_identity=path_identity(root, directory=True))
    session.record("config_intent", staging=None, quarantine=None, live_identity=path_identity(root, directory=True))
    from .operations import mutate_config
    mutate_config(home, config, config_preimage.raw, config_preimage.mode, state, options, exists=config_preimage.exists)
    session.record("config_published", staging=None, quarantine=None, live_identity=path_identity(root, directory=True), observed_config=path_identity(home / "config.yaml"))
    session.record("marker_intent", staging=None, quarantine=None, live_identity=path_identity(root, directory=True), observed_config=path_identity(home / "config.yaml"))
    write_atomic(root / ".lifedb-owner.json", desired_marker, 0o600)
    session.record("marker_published", staging=None, quarantine=None, live_identity=path_identity(root, directory=True), observed_config=path_identity(home / "config.yaml"), observed_marker=path_identity(root / ".lifedb-owner.json"))
    session.record("commit_intent", staging=None, quarantine=None, live_identity=path_identity(root, directory=True), observed_config=path_identity(home / "config.yaml"), observed_marker=path_identity(root / ".lifedb-owner.json"))
    session.record("committed", staging=None, quarantine=None, live_identity=path_identity(root, directory=True), observed_config=path_identity(home / "config.yaml"), observed_marker=path_identity(root / ".lifedb-owner.json"))
    session.clear()


def _uninstall(home: Path, hermes_binary: str, config: Config, config_preimage: ConfigPreimage, lock_path: Path) -> None:
    root = home / "plugins" / "lifedb-bridge"
    validate_tree(root)
    run_host_checks(hermes_binary, str(root), home)
    desired_config = _removed_config(config)
    session = _session(home, "uninstall", config_preimage, root, lock_path, resolved_identity(hermes_binary), desired_config, None)
    quarantine = root.parent / f".lifedb-quarantine-{time.time_ns()}"
    session.record("prepared", staging=None, quarantine=None, live_identity=path_identity(root, directory=True))
    session.record("old_root_rename_intent", staging=None, quarantine=quarantine.relative_to(home).as_posix(), live_identity=path_identity(root, directory=True))
    root.rename(quarantine)
    fsync_path(root.parent)
    session.record("quarantined", staging=None, quarantine=quarantine.relative_to(home).as_posix(), quarantine_identity=path_identity(quarantine, directory=True))
    session.record("config_intent", staging=None, quarantine=quarantine.relative_to(home).as_posix(), quarantine_identity=path_identity(quarantine, directory=True))
    from .operations import mutate_config
    mutate_config(home, config, config_preimage.raw, config_preimage.mode, "enabled", None, uninstall=True, exists=config_preimage.exists)
    session.record("config_published", staging=None, quarantine=quarantine.relative_to(home).as_posix(), quarantine_identity=path_identity(quarantine, directory=True), observed_config=path_identity(home / "config.yaml") if home.joinpath("config.yaml").exists() else None)
    session.record("commit_intent", staging=None, quarantine=quarantine.relative_to(home).as_posix(), quarantine_identity=path_identity(quarantine, directory=True), observed_config=path_identity(home / "config.yaml") if home.joinpath("config.yaml").exists() else None)
    session.record("committed", staging=None, quarantine=quarantine.relative_to(home).as_posix(), quarantine_identity=path_identity(quarantine, directory=True), observed_config=path_identity(home / "config.yaml") if home.joinpath("config.yaml").exists() else None)
    recover(home)


def lifecycle(home: Path, command: str, options: InstallOptions, *, hermes_binary: str = "hermes") -> None:
    safe_home(home)
    if command == "check":
        if read_journal(home) is not None:
            raise InstallerError("Hermes installer operation failed")
        read_config(home, create=False)
        source_root()
        run_host_checks(hermes_binary, str(source_root()), home)
        return
    if command not in {"install", "disable", "enable", "uninstall"}:
        raise InstallerError("Hermes installer operation failed")
    if command == "install":
        safe_token(options.token_file)
        validate_options(options)
    lock = acquire_lock(home)
    try:
        recover(home)
        config_preimage = read_config(home, create=command == "install")
        config = config_preimage.config
        root = home / "plugins" / "lifedb-bridge"
        if command == "install":
            _install(home, options, hermes_binary, config, config_preimage, lock.path)
        elif not target_state(root):
            if command == "uninstall" and not config.get("plugins"):
                return
            raise InstallerError("Hermes installer operation failed")
        elif command in {"disable", "enable"}:
            _toggle(home, command, options, hermes_binary, config, config_preimage, lock.path)
        else:
            _uninstall(home, hermes_binary, config, config_preimage, lock.path)
    finally:
        release_lock(lock)
