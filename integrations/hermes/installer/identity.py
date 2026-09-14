from __future__ import annotations

import hashlib
import os
from pathlib import Path
import stat

from .models import Identity, InstallerError


def path_identity(path: Path, *, directory: bool | None = None) -> Identity:
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | (os.O_DIRECTORY if directory else 0))
    try:
        info = os.fstat(descriptor)
        kind = "directory" if stat.S_ISDIR(info.st_mode) else "file" if stat.S_ISREG(info.st_mode) else "other"
        if kind == "other" or directory is True and kind != "directory" or directory is False and kind != "file":
            raise InstallerError("Hermes installer operation failed")
        if info.st_uid != os.geteuid():
            raise InstallerError("Hermes installer operation failed")
        digest = hashlib.sha256()
        if kind == "file":
            if info.st_size > 16_777_216:
                raise InstallerError("Hermes installer operation failed")
            remaining = info.st_size
            while remaining:
                chunk = os.read(descriptor, min(65_536, remaining))
                if not chunk:
                    raise InstallerError("Hermes installer operation failed")
                digest.update(chunk); remaining -= len(chunk)
        else:
            entries = []
            for item in os.scandir(descriptor):
                child = item.stat(follow_symlinks=False)
                entries.append((item.name, child.st_dev, child.st_ino, child.st_uid, stat.S_IFMT(child.st_mode), stat.S_IMODE(child.st_mode), child.st_size, child.st_mtime_ns))
            for entry in sorted(entries):
                digest.update(repr(entry).encode("utf-8"))
        return Identity(info.st_dev, info.st_ino, info.st_uid, kind, stat.S_IMODE(info.st_mode), info.st_size, info.st_mtime_ns, digest.hexdigest())
    finally:
        os.close(descriptor)
