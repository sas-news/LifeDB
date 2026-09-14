from __future__ import annotations

import json
import os
import stat
from pathlib import Path

from . import journal_io
from .journal_limits import MAX_JOURNAL_BYTES
from .journal_schema import decode_bytes, identity_from_stat, journal_data, journal_fields
from .models import Identity, InstallerError, Journal, JournalDurabilityUncertain

JOURNAL_NAME = ".lifedb-transaction.json"


def _serialize(journal: Journal) -> bytes:
    try:
        raw = json.dumps(journal_data(journal), sort_keys=True, separators=(",", ":")).encode("utf-8")
        decode_bytes(raw, journal.home)
    except (TypeError, ValueError, UnicodeError, InstallerError) as error:
        if isinstance(error, InstallerError):
            raise
        raise InstallerError("Hermes installer operation failed") from error
    if len(raw) > MAX_JOURNAL_BYTES:
        raise InstallerError("Hermes installer operation failed")
    return raw


def _active(home: Path) -> tuple[Identity, int, Identity] | None:
    return journal_io._pointer(home)


def write_journal(home: Path, journal: Journal, expected: Identity | None = None) -> Identity:
    raw = _serialize(journal)
    with journal_io._lock(home, bootstrap=True):
        active = _active(home)
        if expected is None and active is not None:
            raise InstallerError("Hermes installer operation failed")
        if expected is not None and (active is None or active[0] != expected):
            raise InstallerError("Hermes installer operation failed")
        store = journal_io._store(home)
        slot = 0 if active is None else 1 - active[1]
        slot_path = store / journal_io.SLOTS[slot]
        slot_identity = journal_io._read_identity(slot_path)
        data_identity = journal_io._write_file(slot_path, raw, slot_identity)
        try:
            return journal_io._publish(home, slot, data_identity, expected)
        except JournalDurabilityUncertain:
            raise
        except (OSError, InstallerError) as error:
            if isinstance(error, InstallerError):
                raise
            raise InstallerError("Hermes installer operation failed") from error


def read_journal(home: Path) -> Journal | None:
    active = _active(home)
    if active is None:
        store = home / journal_io.STORE_NAME
        if store.exists() or store.is_symlink():
            journal_io._store(home)
        public = home / JOURNAL_NAME
        if public.exists() or public.is_symlink():
            raise InstallerError("Hermes installer operation failed")
        return None
    store = journal_io._store(home)
    path = store / journal_io.SLOTS[active[1]]
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError as error:
        raise InstallerError("Hermes installer operation failed") from error
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o600 or info.st_size > MAX_JOURNAL_BYTES:
            raise InstallerError("Hermes installer operation failed")
        raw = os.pread(descriptor, MAX_JOURNAL_BYTES + 1, 0)
        identity = journal_io._identity_from_fd(descriptor)
    except OSError as error:
        raise InstallerError("Hermes installer operation failed") from error
    finally:
        os.close(descriptor)
    if len(raw) != info.st_size or identity != active[2] or journal_io._read_identity(path) != active[2] or _active(home) != active:
        raise InstallerError("Hermes installer operation failed")
    journal = decode_bytes(raw, home)
    return Journal(**{**journal_fields(journal), "journal_identity": active[0]})


def clear_journal(home: Path, expected: Identity | None = None) -> None:
    if expected is None:
        raise InstallerError("Hermes installer operation failed")
    with journal_io._lock(home, bootstrap=False):
        path = home / JOURNAL_NAME
        try:
            info = path.lstat()
            if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
                raise InstallerError("Hermes installer operation failed")
            descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        except OSError as error:
            raise InstallerError("Hermes installer operation failed") from error
        try:
            if journal_io._identity_from_fd(descriptor) != expected:
                raise InstallerError("Hermes installer operation failed")
            journal_io._conditional_unlink(descriptor, path)
        finally:
            os.close(descriptor)


def _identity_from_stat(info: os.stat_result, raw: bytes) -> Identity:
    return identity_from_stat(info, raw)
