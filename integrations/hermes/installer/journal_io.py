from __future__ import annotations

import errno
import fcntl
import os
import sys
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

from .environment import fsync_path
from .journal_codec import decode, envelope
from .journal_limits import MAX_JOURNAL_BYTES
from .journal_store import CARRIERS, SLOTS, STORE_NAME, absent_carrier, ensure_store, private_carrier
from .journal_syscalls import RENAME_EXCHANGE, RENAME_NOREPLACE, identity_from_fd, read_identity, renameat2, write_file
from .models import Identity, InstallerError, JournalDurabilityUncertain


def _fail() -> InstallerError:
    return InstallerError("Hermes installer operation failed")


def _uncertain(path: Path, fallback: Identity) -> JournalDurabilityUncertain:
    try:
        return JournalDurabilityUncertain(_read_identity(path))
    except InstallerError:
        return JournalDurabilityUncertain(fallback)


def _read_identity(path: Path) -> Identity:
    return read_identity(path)


def _identity_from_fd(descriptor: int) -> Identity:
    return identity_from_fd(descriptor)


def _write_file(path: Path, raw: bytes, expected: Identity | None) -> Identity:
    return write_file(path, raw, expected)


def _renameat2(source: Path, target: Path, flags: int) -> None:
    renameat2(source, target, flags)


def _present(path: Path) -> bool:
    try:
        path.lstat()
    except FileNotFoundError:
        return False
    except OSError as error:
        raise _fail() from error
    return True


def _verify_renameat2(home: Path) -> None:
    if sys.platform != "linux":
        raise _fail()
    source = home / ".lifedb-rename-probe-source"
    target = home / ".lifedb-rename-probe-target"
    try:
        _renameat2(source, target, RENAME_NOREPLACE)
    except OSError as error:
        if error.errno != errno.ENOENT:
            raise _fail() from error


def _store(home: Path, *, bootstrap: bool = False) -> Path:
    return ensure_store(
        home,
        bootstrap=bootstrap,
        read_identity=_read_identity,
        fsync_path=fsync_path,
        verify_rename=lambda: _verify_renameat2(home),
    )


@contextmanager
def _lock(home: Path, *, bootstrap: bool) -> Iterator[None]:
    store = home / STORE_NAME
    parent = home
    parent_descriptor = os.open(parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        fcntl.flock(parent_descriptor, fcntl.LOCK_EX)
        if not store.exists():
            _store(home, bootstrap=bootstrap)
        try:
            store_descriptor = os.open(store, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        except OSError as error:
            raise _fail() from error
        try:
            fcntl.flock(store_descriptor, fcntl.LOCK_EX)
            _store(home, bootstrap=bootstrap)
            yield
        finally:
            fcntl.flock(store_descriptor, fcntl.LOCK_UN)
            os.close(store_descriptor)
    finally:
        fcntl.flock(parent_descriptor, fcntl.LOCK_UN)
        os.close(parent_descriptor)


def _pointer(home: Path) -> tuple[Identity, int, Identity] | None:
    public = home / ".lifedb-transaction.json"
    if not _present(public):
        return None
    try:
        descriptor = os.open(public, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError as error:
        raise _fail() from error
    try:
        pointer_identity = _identity_from_fd(descriptor)
        raw = os.pread(descriptor, MAX_JOURNAL_BYTES + 1, 0)
    except OSError as error:
        raise _fail() from error
    finally:
        os.close(descriptor)
    if len(raw) != pointer_identity.size:
        raise _fail()
    slot, slot_identity = decode(raw)
    store = _store(home)
    selected = store / SLOTS[slot]
    if _read_identity(selected) != slot_identity:
        raise _fail()
    if _read_identity(public) != pointer_identity:
        raise _fail()
    return pointer_identity, slot, slot_identity


def _publish(home: Path, slot: int, data_identity: Identity, expected: Identity | None) -> Identity:
    store = _store(home)
    public = home / ".lifedb-transaction.json"
    active = _pointer(home)
    actual_expected = None if active is None else active[0]
    if expected != actual_expected:
        raise _fail()
    if active is None:
        source = store / CARRIERS[0]
        source_identity = _read_identity(source)
        flags = RENAME_NOREPLACE
    else:
        source = private_carrier(store)
        source_identity = _read_identity(source)
        flags = RENAME_EXCHANGE
    prepared = _write_file(source, envelope(slot, data_identity), source_identity)
    if _pointer(home) is not None:
        if expected is None or _pointer(home)[0] != expected:
            raise _fail()
    try:
        _renameat2(source, public, flags)
    except (OSError, InstallerError) as error:
        if isinstance(error, InstallerError):
            raise
        raise _fail() from error
    if active is not None and _read_identity(source) != expected:
        try:
            _renameat2(public, source, RENAME_EXCHANGE)
        except (OSError, InstallerError) as error:
            raise _uncertain(public, source_identity) from error
        raise _uncertain(source, source_identity)
    if _read_identity(public) != prepared:
        raise _uncertain(public, prepared)
    for directory in (store, home):
        try:
            fsync_path(directory)
        except OSError as error:
            raise _uncertain(public, prepared) from error
    return _read_identity(public)


def _conditional_unlink(descriptor: int, target: Path) -> None:
    expected = _identity_from_fd(descriptor)
    _before_atomic_move(target)
    state = _pointer(target.parent)
    if state is None or state[0] != expected:
        raise _fail()
    store = _store(target.parent)
    private = absent_carrier(store)
    try:
        _renameat2(target, private, RENAME_NOREPLACE)
    except (OSError, InstallerError) as error:
        if isinstance(error, InstallerError):
            raise
        raise _fail() from error
    moved = _read_identity(private)
    if moved != expected:
        try:
            _renameat2(private, target, RENAME_NOREPLACE)
        except (OSError, InstallerError) as error:
            raise _uncertain(private, expected) from error
        raise _fail()
    _after_atomic_move(target)
    if _present(target):
        raise JournalDurabilityUncertain(expected)
    try:
        fsync_path(store)
        fsync_path(target.parent)
    except OSError as error:
        raise _uncertain(private, expected) from error
    if _present(target):
        raise JournalDurabilityUncertain(expected)


def _before_atomic_move(target: Path) -> None:
    return None


def _after_atomic_move(target: Path) -> None:
    return None
