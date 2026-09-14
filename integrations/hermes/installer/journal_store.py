from __future__ import annotations

import os
import stat
import sys
from pathlib import Path
from typing import Callable

from .models import Identity, InstallerError

STORE_NAME = ".lifedb-journal-store"
SLOTS = ("data-0", "data-1")
CARRIERS = ("pointer-0", "pointer-1")
ReadIdentity = Callable[[Path], Identity]
Fsync = Callable[[Path], None]
VerifyRename = Callable[[], None]


def fail() -> InstallerError:
    return InstallerError("Hermes installer operation failed")


def _present(path: Path) -> bool:
    try:
        path.lstat()
    except FileNotFoundError:
        return False
    except OSError as error:
        raise fail() from error
    return True


def ensure_store(home: Path, *, bootstrap: bool, read_identity: ReadIdentity, fsync_path: Fsync, verify_rename: VerifyRename) -> Path:
    store = home / STORE_NAME
    public = home / ".lifedb-transaction.json"
    public_present = _present(public)
    changed = False
    try:
        info = store.lstat()
    except FileNotFoundError:
        if not bootstrap or public_present or sys.platform != "linux":
            raise fail()
        try:
            verify_rename()
            store.mkdir(mode=0o700)
            info = store.lstat()
            changed = True
        except OSError as error:
            raise fail() from error
    except OSError as error:
        raise fail() from error
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700:
        raise fail()
    allowed = set((*SLOTS, *CARRIERS))
    try:
        if any(item.name not in allowed for item in store.iterdir()):
            raise fail()
    except OSError as error:
        raise fail() from error
    if bootstrap and not public_present:
        verify_rename()
        for name in (*SLOTS, *CARRIERS):
            path = store / name
            if not _present(path):
                try:
                    descriptor = os.open(path, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
                    try:
                        os.fsync(descriptor)
                    finally:
                        os.close(descriptor)
                    changed = True
                except OSError as error:
                    raise fail() from error
        for name in (*SLOTS, *CARRIERS):
            read_identity(store / name)
        try:
            fsync_path(store)
            fsync_path(home)
        except OSError as error:
            raise fail() from error
    for name in SLOTS:
        path = store / name
        if not _present(path):
            raise fail()
        read_identity(path)
    carriers = [store / name for name in CARRIERS if _present(store / name)]
    if public_present:
        if len(carriers) != 1:
            raise fail()
    elif len(carriers) != 2:
        raise fail()
    for path in carriers:
        read_identity(path)
    return store


def private_carrier(store: Path) -> Path:
    paths = [store / name for name in CARRIERS if _present(store / name)]
    if len(paths) != 1:
        raise fail()
    return paths[0]


def absent_carrier(store: Path) -> Path:
    paths = [store / name for name in CARRIERS if not _present(store / name)]
    if len(paths) != 1:
        raise fail()
    return paths[0]
