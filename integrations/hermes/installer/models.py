from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
import re
from types import MappingProxyType
from typing import Mapping, NamedTuple

from .config import Config


class InstallerError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class Identity:
    device: int
    inode: int
    owner_uid: int
    kind: str
    mode: int
    size: int
    mtime_ns: int
    sha256: str

    def __post_init__(self) -> None:
        if (
            any(type(value) is not int for value in (self.device, self.inode, self.owner_uid, self.mode, self.size, self.mtime_ns))
            or
            self.device <= 0
            or self.inode <= 0
            or self.owner_uid < 0
            or self.kind not in {"file", "directory"}
            or self.mode < 0
            or self.mode > 0o777
            or self.size < 0
            or self.mtime_ns < 0
            or re.fullmatch(r"[0-9a-f]{64}", self.sha256) is None
        ):
            raise InstallerError("Hermes installer operation failed")


class JournalDurabilityUncertain(InstallerError):
    def __init__(self, identity: Identity) -> None:
        self.identity = identity
        super().__init__("Hermes installer journal durability is uncertain")

    def __str__(self) -> str:
        return "Hermes installer journal durability is uncertain"


class ConfigPreimage(NamedTuple):
    exists: bool
    config: Config
    raw: bytes
    mode: int
    mtime_ns: int
    identity: Identity | None


@dataclass(frozen=True, slots=True)
class Journal:
    home: Path
    operation: str
    phase: str
    staging: str | None
    quarantine: str | None
    old_root_exists: bool = False
    config_exists: bool = False
    old_config_b64: str = ""
    old_config_mode: int = 0
    old_marker_b64: str = ""
    old_marker_mode: int = 0
    old_marker_mtime_ns: int = 0
    config_identity: Identity | None = None
    staging_identity: Identity | None = None
    quarantine_identity: Identity | None = None
    live_identity: Identity | None = None
    lock_identity: Identity | None = None
    old_tree_manifest: Mapping[str, Identity] = field(default_factory=dict)
    desired_config_hash: str | None = None
    desired_marker_hash: str | None = None
    old_config_mtime_ns: int = 0
    cleanup_manifest: Mapping[str, Identity] = field(default_factory=dict)
    cleanup_deleted: tuple[str, ...] = ()
    binary_identity: Identity | None = None
    journal_identity: Identity | None = None
    old_marker_exists: bool = False
    old_marker_identity: Identity | None = None
    old_live_identity: Identity | None = None
    desired_config_b64: str | None = None
    desired_marker_b64: str | None = None
    observed_config_identity: Identity | None = None
    observed_marker_identity: Identity | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "old_tree_manifest", MappingProxyType(dict(self.old_tree_manifest)))
        object.__setattr__(self, "cleanup_manifest", MappingProxyType(dict(self.cleanup_manifest)))



@dataclass(frozen=True, slots=True)
class InstallOptions:
    url: str
    token_file: Path
    workspace: Path | None
    timeout_seconds: float
    max_response_bytes: int
    max_request_bytes: int
    sensitivity_ceiling: str | None
    budget_chars: int
    core_chars: int
    continuity_chars: int
    relevant_chars: int
    limit: int

    def settings(self) -> Config:
        return {"url": self.url, "token_file": str(self.token_file), "workspace": None if self.workspace is None else str(self.workspace), "timeout_seconds": self.timeout_seconds, "max_response_bytes": self.max_response_bytes, "max_request_bytes": self.max_request_bytes, "sensitivity_ceiling": self.sensitivity_ceiling, "budget_chars": self.budget_chars, "core_chars": self.core_chars, "continuity_chars": self.continuity_chars, "relevant_chars": self.relevant_chars, "limit": self.limit}
