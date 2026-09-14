from __future__ import annotations

import ctypes
import hashlib
import os
import stat
import sys
from pathlib import Path

from .journal_limits import MAX_JOURNAL_BYTES
from .models import Identity, InstallerError

RENAME_NOREPLACE = 1
RENAME_EXCHANGE = 2
AT_FDCWD = -100
LIBC = ctypes.CDLL(None, use_errno=True)


def fail() -> InstallerError:
    return InstallerError("Hermes installer operation failed")


def identity_from_fd(descriptor: int) -> Identity:
    info = os.fstat(descriptor)
    if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o600 or info.st_size > MAX_JOURNAL_BYTES:
        raise fail()
    initial = (info.st_dev, info.st_ino, info.st_uid, stat.S_IFMT(info.st_mode), stat.S_IMODE(info.st_mode), info.st_size, info.st_mtime_ns, info.st_ctime_ns)
    digest = hashlib.sha256()
    offset = 0
    while offset < info.st_size:
        chunk = os.pread(descriptor, min(65_536, info.st_size - offset), offset)
        if not chunk:
            raise fail()
        digest.update(chunk)
        offset += len(chunk)
    final = os.fstat(descriptor)
    if (final.st_dev, final.st_ino, final.st_uid, stat.S_IFMT(final.st_mode), stat.S_IMODE(final.st_mode), final.st_size, final.st_mtime_ns, final.st_ctime_ns) != initial:
        raise fail()
    return Identity(info.st_dev, info.st_ino, info.st_uid, "file", 0o600, info.st_size, info.st_mtime_ns, digest.hexdigest())


def read_identity(path: Path) -> Identity:
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError as error:
        raise fail() from error
    try:
        return identity_from_fd(descriptor)
    finally:
        os.close(descriptor)


def renameat2(source: Path, target: Path, flags: int) -> None:
    if sys.platform != "linux":
        raise fail()
    try:
        function = LIBC.renameat2
    except AttributeError as error:
        raise fail() from error
    function.argtypes = (ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint)
    function.restype = ctypes.c_int
    result = function(AT_FDCWD, str(source).encode(), AT_FDCWD, str(target).encode(), flags)
    if result:
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error))


def write_file(path: Path, raw: bytes, expected: Identity | None) -> Identity:
    try:
        descriptor = os.open(path, os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError as error:
        raise fail() from error
    try:
        current = identity_from_fd(descriptor)
        if expected is not None and current != expected:
            raise fail()
        os.ftruncate(descriptor, 0)
        offset = 0
        while offset < len(raw):
            written = os.pwrite(descriptor, raw[offset:], offset)
            if written <= 0:
                raise fail()
            offset += written
        os.fchmod(descriptor, 0o600)
        os.fsync(descriptor)
        result = identity_from_fd(descriptor)
    except (OSError, InstallerError) as error:
        raise error if isinstance(error, InstallerError) else fail() from error
    finally:
        os.close(descriptor)
    if read_identity(path) != result:
        raise fail()
    return result
