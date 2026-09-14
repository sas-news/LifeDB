from __future__ import annotations

import base64
from dataclasses import dataclass
import hashlib
from pathlib import Path
from typing import Mapping

from .config import Config
from .identity import path_identity
from .models import ConfigPreimage, Identity, Journal
from .ownership import marker_for
from .source import OWNED_FILES
from .transaction import write_journal


def tree_manifest(root: Path) -> dict[str, Identity]:
    return {name: path_identity(root / name) for name in (*OWNED_FILES, ".lifedb-owner.json")}


@dataclass(frozen=True, slots=True)
class Snapshot:
    home: Path
    operation: str
    config: ConfigPreimage
    old_root_exists: bool
    old_live_identity: Identity | None
    old_tree_manifest: Mapping[str, Identity]
    old_marker_exists: bool
    old_marker: bytes
    old_marker_identity: Identity | None
    old_marker_mode: int
    old_marker_mtime_ns: int
    lock_identity: Identity
    binary_identity: Identity

    def journal(self, phase: str, *, staging: str | None, quarantine: str | None, desired_config: bytes | None, desired_marker: bytes | None, staging_identity: Identity | None = None, quarantine_identity: Identity | None = None, live_identity: Identity | None = None, observed_config: Identity | None = None, observed_marker: Identity | None = None, cleanup_deleted: tuple[str, ...] = ()) -> Journal:
        return Journal(
            home=self.home,
            operation=self.operation,
            phase=phase,
            staging=staging,
            quarantine=quarantine,
            old_root_exists=self.old_root_exists,
            config_exists=self.config.exists,
            old_config_b64=base64.b64encode(self.config.raw).decode("ascii"),
            old_config_mode=self.config.mode,
            old_config_mtime_ns=self.config.mtime_ns,
            old_marker_b64=base64.b64encode(self.old_marker).decode("ascii"),
            old_marker_mode=self.old_marker_mode,
            old_marker_mtime_ns=self.old_marker_mtime_ns,
            config_identity=self.config.identity,
            staging_identity=staging_identity,
            quarantine_identity=quarantine_identity,
            live_identity=live_identity,
            lock_identity=self.lock_identity,
            old_tree_manifest=self.old_tree_manifest,
            desired_config_b64=None if desired_config is None else base64.b64encode(desired_config).decode("ascii"),
            desired_config_hash=None if desired_config is None else hashlib.sha256(desired_config).hexdigest(),
            desired_marker_b64=None if desired_marker is None else base64.b64encode(desired_marker).decode("ascii"),
            desired_marker_hash=None if desired_marker is None else hashlib.sha256(desired_marker).hexdigest(),
            cleanup_manifest=self.old_tree_manifest if self.operation in {"install", "uninstall"} and self.old_root_exists else {},
            cleanup_deleted=cleanup_deleted,
            binary_identity=self.binary_identity,
            old_marker_exists=self.old_marker_exists,
            old_marker_identity=self.old_marker_identity,
            old_live_identity=self.old_live_identity,
            observed_config_identity=observed_config,
            observed_marker_identity=observed_marker,
        )


class TransactionSession:
    def __init__(self, snapshot: Snapshot, desired_config: bytes | None, desired_marker: bytes | None) -> None:
        self.snapshot = snapshot
        self.desired_config = desired_config
        self.desired_marker = desired_marker
        self.token: Identity | None = None

    def record(self, phase: str, **changes: Identity | str | None | tuple[str, ...]) -> Journal:
        journal = self.snapshot.journal(phase, staging=changes.pop("staging", None), quarantine=changes.pop("quarantine", None), desired_config=self.desired_config, desired_marker=self.desired_marker, **changes)
        self.token = write_journal(self.snapshot.home, journal, expected=self.token)
        return journal

    def clear(self) -> None:
        from .transaction import clear_journal

        if self.token is not None:
            clear_journal(self.snapshot.home, self.token)


def capture_snapshot(home: Path, operation: str, config: ConfigPreimage, root: Path, lock_identity: Identity, binary_identity: Identity) -> Snapshot:
    root_exists = root.exists()
    old_live = path_identity(root, directory=True) if root_exists else None
    manifest = tree_manifest(root) if root_exists else {}
    marker_path = root / ".lifedb-owner.json"
    marker_exists = marker_path.exists()
    marker_identity = path_identity(marker_path) if marker_exists else None
    marker_bytes = marker_path.read_bytes() if marker_exists else b""
    marker_stat = marker_path.stat() if marker_exists else None
    return Snapshot(home, operation, config, root_exists, old_live, manifest, marker_exists, marker_bytes, marker_identity, 0 if marker_stat is None else marker_stat.st_mode & 0o777, 0 if marker_stat is None else marker_stat.st_mtime_ns, lock_identity, binary_identity)


def planned_marker(state: str, managed_config: Config, files: dict[str, str], plugin_hash: str) -> bytes:
    return marker_for(state, managed_config, files, plugin_hash)
