from __future__ import annotations

import os
import fcntl
from pathlib import Path
import secrets
import stat
from dataclasses import dataclass

from .models import InstallerError


@dataclass(frozen=True, slots=True)
class Lock:
    path: Path
    descriptor: int
    device: int
    inode: int


def safe_home(home: Path) -> None:
    if not home.is_absolute() or home.is_symlink() or not home.is_dir() or not stat.S_ISDIR(home.stat().st_mode):
        raise InstallerError("Hermes installer operation failed")


def safe_token(path: Path) -> None:
    if not path.is_absolute() or path.is_symlink():
        raise InstallerError("Hermes installer operation failed")
    try:
        info = path.lstat()
    except OSError as error:
        raise InstallerError("Hermes installer operation failed") from error
    if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
        raise InstallerError("Hermes installer operation failed")


def acquire_lock(home: Path) -> Lock:
    path = home / ".lifedb-installer.lock"
    descriptor = -1
    try:
        try:
            descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        except FileExistsError:
            descriptor = os.open(path, os.O_WRONLY | os.O_NOFOLLOW)
        info = os.fstat(descriptor)
        if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o600 or not stat.S_ISREG(info.st_mode):
            os.close(descriptor)
            raise InstallerError("Hermes installer operation failed")
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError as error:
        if descriptor >= 0:
            os.close(descriptor)
        raise InstallerError("Hermes installer operation failed") from error
    return Lock(path, descriptor, info.st_dev, info.st_ino)


def release_lock(lock: Lock) -> None:
    fcntl.flock(lock.descriptor, fcntl.LOCK_UN)
    os.close(lock.descriptor)
    try:
        info = os.lstat(lock.path)
        if info.st_dev == lock.device and info.st_ino == lock.inode:
            lock.path.unlink()
    except FileNotFoundError:
        return
    except OSError as error:
        raise InstallerError("Hermes installer operation failed") from error


def fsync_path(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY if path.is_dir() else os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def write_atomic(path: Path, data: bytes, mode: int) -> None:
    temporary = path.parent / f".lifedb-{os.getpid()}-{secrets.token_hex(12)}.tmp"
    descriptor = -1
    created = False
    renamed = False
    try:
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
        created = True
        remaining = memoryview(data)
        while remaining:
            written = os.write(descriptor, remaining)
            if written <= 0:
                raise InstallerError("Hermes installer operation failed")
            remaining = remaining[written:]
        os.fchmod(descriptor, mode)
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = -1
        os.replace(temporary, path)
        renamed = True
        fsync_path(path.parent)
    except (OSError, InstallerError) as error:
        if descriptor >= 0:
            os.close(descriptor)
        if created and not renamed:
            temporary.unlink(missing_ok=True)
        raise InstallerError("Hermes installer operation failed") from error


def backup(path: Path, data: bytes) -> None:
    directory = path.parent / ".lifedb-backups"
    try:
        info = directory.lstat()
    except FileNotFoundError:
        directory.mkdir(mode=0o700)
        info = directory.lstat()
    if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700 or not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode):
        raise InstallerError("Hermes installer operation failed")
    candidate = directory / f"config-{secrets.token_hex(16)}.yaml"
    write_atomic(candidate, data, 0o600)
    fsync_path(directory)
