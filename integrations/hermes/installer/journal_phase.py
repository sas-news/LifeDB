from __future__ import annotations

import os
from typing import Final

from .models import Identity, InstallerError, Journal
from .source import OWNED_FILES

PHASES: Final[frozenset[str]] = frozenset({
    "prepared", "staged", "old_root_rename_intent", "quarantined",
    "staging_to_live_intent", "published", "config_intent", "config_published",
    "marker_intent", "marker_published", "commit_intent", "committed",
    "cleanup_intent", "cleanup_pending",
})
OPERATIONS: Final[frozenset[str]] = frozenset({"install", "disable", "enable", "uninstall"})
OPERATION_PHASES: Final[dict[str, frozenset[str]]] = {
    "install": frozenset(("prepared", "staged", "old_root_rename_intent", "quarantined", "staging_to_live_intent", "published", "config_intent", "config_published", "commit_intent", "committed", "cleanup_intent", "cleanup_pending")),
    "disable": frozenset(("prepared", "config_intent", "config_published", "marker_intent", "marker_published", "commit_intent", "committed")),
    "enable": frozenset(("prepared", "config_intent", "config_published", "marker_intent", "marker_published", "commit_intent", "committed")),
    "uninstall": frozenset(("prepared", "old_root_rename_intent", "quarantined", "config_intent", "config_published", "commit_intent", "committed", "cleanup_intent", "cleanup_pending")),
}
TREE_NAMES: Final[frozenset[str]] = frozenset((*OWNED_FILES, ".lifedb-owner.json"))
CONFIG_INTENT: Final[frozenset[str]] = frozenset(("config_intent", "config_published", "marker_intent", "marker_published", "commit_intent", "committed", "cleanup_intent", "cleanup_pending"))
MARKER_INTENT: Final[frozenset[str]] = frozenset(("marker_intent", "marker_published", "commit_intent", "committed", "cleanup_intent", "cleanup_pending"))
OBSERVED_CONFIG: Final[frozenset[str]] = frozenset(("config_published", "marker_intent", "marker_published", "commit_intent", "committed", "cleanup_intent", "cleanup_pending"))
OBSERVED_MARKER: Final[frozenset[str]] = frozenset(("marker_published", "commit_intent", "committed", "cleanup_intent", "cleanup_pending"))
CLEANUP: Final[frozenset[str]] = frozenset(("cleanup_intent", "cleanup_pending"))


def _fail() -> InstallerError:
    return InstallerError("Hermes installer operation failed")


def _safe(identity: Identity | None, kind: str) -> None:
    if identity is None:
        return
    if identity.kind != kind or identity.owner_uid != os.geteuid() or identity.mode & 0o022:
        raise _fail()


def _path_identity(path: str | None, identity: Identity | None, kind: str, *, future: bool = False) -> None:
    if path is None:
        if identity is not None:
            raise _fail()
        return
    if future:
        if identity is not None:
            raise _fail()
        return
    if identity is None:
        raise _fail()
    _safe(identity, kind)


def validate_phase(journal: Journal) -> None:
    operation, phase = journal.operation, journal.phase
    if operation not in OPERATIONS or phase not in PHASES or phase not in OPERATION_PHASES[operation]:
        raise _fail()
    if journal.lock_identity is None or journal.binary_identity is None:
        raise _fail()
    _safe(journal.lock_identity, "file")
    _safe(journal.binary_identity, "file")
    if not journal.binary_identity.mode & 0o111:
        raise _fail()
    if operation in {"disable", "enable", "uninstall"} and not journal.old_root_exists:
        raise _fail()
    if operation in {"disable", "enable", "uninstall"} and (not journal.config_exists or not journal.old_marker_exists or journal.old_live_identity is None or not journal.old_tree_manifest):
        raise _fail()
    if operation == "install" and not journal.old_root_exists and (journal.quarantine is not None or journal.quarantine_identity is not None or journal.old_tree_manifest or journal.old_live_identity is not None or journal.old_marker_exists or journal.old_marker_identity is not None or journal.old_marker_b64 or journal.old_marker_mode or journal.old_marker_mtime_ns):
        raise _fail()
    if operation == "install" and journal.old_root_exists and (not journal.config_exists or not journal.old_marker_exists or journal.old_live_identity is None or not journal.old_tree_manifest):
        raise _fail()
    if operation == "install" and not journal.old_root_exists and phase in CLEANUP:
        raise _fail()
    if operation == "install" and not journal.old_root_exists and phase in {"old_root_rename_intent", "quarantined"}:
        raise _fail()
    if operation in {"disable", "enable", "uninstall"} and journal.staging is not None:
        raise _fail()
    if operation in {"disable", "enable"} and journal.quarantine is not None:
        raise _fail()

    if operation == "install":
        if phase == "prepared":
            if journal.staging is None:
                raise _fail()
        elif phase in {"staged", "old_root_rename_intent", "quarantined", "staging_to_live_intent"}:
            _path_identity(journal.staging, journal.staging_identity, "directory", future=False)
        elif journal.staging is not None or journal.staging_identity is not None:
            raise _fail()
        _path_identity(journal.quarantine, journal.quarantine_identity, "directory", future=phase == "old_root_rename_intent")
        if phase == "prepared" and journal.staging is None:
            raise _fail()
        if phase == "old_root_rename_intent" and not journal.old_root_exists:
            raise _fail()
        if journal.old_root_exists and phase in {"old_root_rename_intent", "quarantined", "staging_to_live_intent", "published", "config_intent", "config_published", "marker_intent", "marker_published", "commit_intent", "committed", "cleanup_intent", "cleanup_pending"} and journal.quarantine is None:
            raise _fail()
        if phase in {"prepared", "staged", "old_root_rename_intent"}:
            if journal.old_root_exists and journal.live_identity != journal.old_live_identity:
                raise _fail()
        elif phase in {"quarantined", "staging_to_live_intent"} and journal.live_identity is not None:
            raise _fail()
        elif phase not in {"prepared", "staged", "old_root_rename_intent", "quarantined", "staging_to_live_intent"} and journal.live_identity is None:
            raise _fail()
    elif operation == "uninstall":
        _path_identity(journal.quarantine, journal.quarantine_identity, "directory", future=phase == "old_root_rename_intent")
        if phase == "old_root_rename_intent":
            if journal.quarantine is None or journal.live_identity != journal.old_live_identity:
                raise _fail()
        elif phase == "prepared":
            if journal.live_identity != journal.old_live_identity:
                raise _fail()
        elif phase in {"quarantined", "config_intent", "config_published", "commit_intent", "committed", "cleanup_intent", "cleanup_pending"}:
            if journal.quarantine is None or journal.quarantine_identity is None or journal.live_identity is not None:
                raise _fail()
    else:
        if journal.live_identity is None:
            raise _fail()
        _safe(journal.live_identity, "directory")

    if operation == "install" and phase in {"prepared", "staged", "old_root_rename_intent", "quarantined", "staging_to_live_intent"}:
        if journal.desired_config_b64 is None or journal.desired_config_hash is None or journal.desired_marker_b64 is None or journal.desired_marker_hash is None:
            raise _fail()
    elif phase in CONFIG_INTENT:
        if journal.desired_config_b64 is None or journal.desired_config_hash is None:
            raise _fail()
    if phase in MARKER_INTENT and operation not in {"install", "uninstall"}:
        if journal.desired_marker_b64 is None or journal.desired_marker_hash is None:
            raise _fail()
    if phase == "config_intent" and (journal.observed_config_identity is not None or operation != "install" and journal.observed_marker_identity is not None):
        raise _fail()
    if phase == "marker_intent" and journal.observed_marker_identity is not None:
        raise _fail()
    if phase in OBSERVED_CONFIG and journal.observed_config_identity is None:
        raise _fail()
    if operation == "install" and phase in {"staged", "old_root_rename_intent", "quarantined", "staging_to_live_intent", "published", "config_intent", "config_published", "commit_intent", "committed", "cleanup_intent", "cleanup_pending"} and journal.observed_marker_identity is None:
        raise _fail()
    if phase in OBSERVED_MARKER and operation != "uninstall" and journal.observed_marker_identity is None:
        raise _fail()
    if operation == "uninstall" and journal.desired_marker_b64 is not None:
        raise _fail()
    if operation == "uninstall" and journal.observed_marker_identity is not None:
        raise _fail()

    if operation in {"install", "uninstall"} and journal.old_root_exists and phase in ("committed", *CLEANUP):
        if dict(journal.cleanup_manifest) != dict(journal.old_tree_manifest):
            raise _fail()
    if operation in {"disable", "enable"} and (journal.cleanup_manifest or journal.cleanup_deleted):
        raise _fail()
    if phase not in CLEANUP and journal.cleanup_deleted:
        raise _fail()
