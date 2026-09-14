from __future__ import annotations

import base64
import os
from pathlib import Path
import stat

from .environment import fsync_path, write_atomic
from .identity import path_identity
from .models import Identity, InstallerError, Journal
from .ownership import OWNED_FILES
from .cache import remove_cache
from .source import PLUGIN_ID
from .transaction import clear_journal, read_journal, write_journal


def _owned(home: Path, relative: str | None) -> Path | None:
    if relative is None:
        return None
    path = home / relative
    if path.parent != home / "plugins" or not path.name.startswith(f".{PLUGIN_ID.split('-')[0]}-"):
        raise InstallerError("Hermes installer operation failed")
    return path


def _same(path: Path, expected: Identity | None, *, directory: bool) -> bool:
    if expected is None:
        return False
    try:
        return path_identity(path, directory=directory) == expected
    except (OSError, InstallerError):
        return False


def _remove_owned_tree(path: Path) -> None:
    try:
        info = path.lstat()
    except FileNotFoundError:
        return
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid():
        raise InstallerError("Hermes installer operation failed")
    remove_cache(path)
    allowed = set((*OWNED_FILES, ".lifedb-owner.json"))
    for child in path.iterdir():
        if child.name not in allowed:
            raise InstallerError("Hermes installer operation failed")
        child_info = child.lstat()
        if stat.S_ISLNK(child_info.st_mode) or not stat.S_ISREG(child_info.st_mode) or child_info.st_uid != os.geteuid() or stat.S_IMODE(child_info.st_mode) != 0o600:
            raise InstallerError("Hermes installer operation failed")
        child.unlink()
    path.rmdir()


def _restore_file(path: Path, old_exists: bool, old_raw: bytes, old_mode: int, old_mtime: int, desired_raw: bytes | None, old_identity: Identity | None) -> None:
    try:
        current = path_identity(path)
    except (OSError, InstallerError):
        current = None
    if old_identity is not None and current == old_identity:
        return
    if desired_raw is not None and current is not None and current.sha256 == __import__("hashlib").sha256(desired_raw).hexdigest() and current.size == len(desired_raw):
        if old_exists:
            write_atomic(path, old_raw, old_mode)
            os.utime(path, ns=(old_mtime, old_mtime), follow_symlinks=False)
        else:
            path.unlink()
        return
    if current is None and not old_exists:
        return
    raise InstallerError("Hermes installer operation failed")


def _restore_config(home: Path, journal: Journal) -> None:
    _restore_file(home / "config.yaml", journal.config_exists, base64.b64decode(journal.old_config_b64), journal.old_config_mode, journal.old_config_mtime_ns, None if journal.desired_config_b64 is None else base64.b64decode(journal.desired_config_b64), journal.config_identity)


def _restore_marker(root: Path, journal: Journal) -> None:
    if journal.old_marker_identity is None and not journal.old_marker_exists:
        old_raw, mode, mtime = b"", 0, 0
    else:
        old_raw, mode, mtime = base64.b64decode(journal.old_marker_b64), journal.old_marker_mode, journal.old_marker_mtime_ns
    _restore_file(root / ".lifedb-owner.json", journal.old_marker_exists, old_raw, mode, mtime, None if journal.desired_marker_b64 is None else base64.b64decode(journal.desired_marker_b64), journal.old_marker_identity)


def _rollback_root(home: Path, journal: Journal, live: Path, quarantine: Path | None) -> None:
    if journal.old_root_exists:
        if live.exists() and not _same(live, journal.old_live_identity, directory=True):
            _remove_owned_tree(live)
        if quarantine is not None and quarantine.exists():
            if not _same(quarantine, journal.quarantine_identity, directory=True):
                raise InstallerError("Hermes installer operation failed")
            quarantine.rename(live)
    elif live.exists():
        _remove_owned_tree(live)


def _cleanup(home: Path, journal: Journal, quarantine: Path) -> None:
    remove_cache(quarantine)
    deleted = list(journal.cleanup_deleted)
    for name, expected in journal.cleanup_manifest.items():
        if name in deleted:
            continue
        token = write_journal(home, Journal(**{**{field: getattr(journal, field) for field in Journal.__dataclass_fields__ if field != "journal_identity"}, "phase": "cleanup_intent", "cleanup_deleted": tuple(deleted)}), expected=journal.journal_identity)
        journal = Journal(**{**{field: getattr(journal, field) for field in Journal.__dataclass_fields__ if field != "journal_identity"}, "journal_identity": token, "cleanup_deleted": tuple(deleted)})
        path = quarantine / name
        try:
            info = path.lstat()
        except FileNotFoundError:
            deleted.append(name)
        else:
            if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o600 or not _same(path, expected, directory=False):
                raise InstallerError("Hermes installer operation failed")
            path.unlink()
            fsync_path(quarantine)
            deleted.append(name)
        token = write_journal(home, Journal(**{**{field: getattr(journal, field) for field in Journal.__dataclass_fields__ if field != "journal_identity"}, "phase": "cleanup_pending", "cleanup_deleted": tuple(deleted)}), expected=journal.journal_identity)
        journal = Journal(**{**{field: getattr(journal, field) for field in Journal.__dataclass_fields__ if field != "journal_identity"}, "journal_identity": token, "cleanup_deleted": tuple(deleted)})
    if any(quarantine.iterdir()):
        raise InstallerError("Hermes installer operation failed")
    quarantine.rmdir()
    fsync_path(home / "plugins")
    clear_journal(home, journal.journal_identity)


def recover(home: Path) -> Journal | None:
    journal = read_journal(home)
    if journal is None:
        plugins = home / "plugins"
        if plugins.is_dir():
            for candidate in plugins.iterdir():
                if candidate.name.startswith(f".{PLUGIN_ID.split('-')[0]}-staging-"):
                    if not candidate.is_dir() or candidate.is_symlink() or candidate.stat().st_uid != os.geteuid() or stat.S_IMODE(candidate.stat().st_mode) & 0o077:
                        raise InstallerError("Hermes installer operation failed")
                    if any(candidate.iterdir()):
                        _remove_owned_tree(candidate)
                    else:
                        candidate.rmdir()
        return None
    staging = _owned(home, journal.staging)
    quarantine = _owned(home, journal.quarantine)
    live = home / "plugins" / PLUGIN_ID
    if journal.phase in {"committed", "cleanup_intent", "cleanup_pending"}:
        if quarantine is None:
            clear_journal(home, journal.journal_identity)
        else:
            _cleanup(home, journal, quarantine)
        return journal
    if journal.operation == "install" and journal.phase in {"prepared", "staged"}:
        if staging is not None:
            _remove_owned_tree(staging)
    elif journal.phase in {"old_root_rename_intent", "quarantined"}:
        if quarantine is not None and quarantine.exists():
            if not _same(quarantine, journal.quarantine_identity, directory=True):
                raise InstallerError("Hermes installer operation failed")
            quarantine.rename(live)
        if staging is not None:
            _remove_owned_tree(staging)
    elif journal.phase in {"staging_to_live_intent", "published", "config_intent", "config_published", "marker_intent", "marker_published", "commit_intent"}:
        _rollback_root(home, journal, live, quarantine)
        if journal.operation in {"disable", "enable", "uninstall"} or journal.phase != "published":
            _restore_config(home, journal)
        if journal.operation in {"disable", "enable"} and live.exists():
            _restore_marker(live, journal)
        if staging is not None:
            _remove_owned_tree(staging)
    else:
        raise InstallerError("Hermes installer operation failed")
    fsync_path(home / "plugins")
    clear_journal(home, journal.journal_identity)
    return journal
