"""Fail-closed reads for content-addressed vault objects."""

from __future__ import annotations

import hashlib
import os
import stat
from pathlib import Path


class ObjectReadError(ValueError):
    """An object cannot be safely read or does not match its address."""


def read_object_prefix(
    root: Path,
    digest: str,
    *,
    retain_bytes: int,
) -> tuple[bytes, int, bool]:
    """Hash an object completely while retaining only a bounded prefix.

    The returned tuple is ``(prefix, total_size, truncated)``.  Every path
    component is checked with lstat, the final open uses O_NOFOLLOW, and the
    descriptor identity/size is checked before and after streaming.
    """
    if not isinstance(digest, str) or len(digest) != 64 or any(
        char not in "0123456789abcdef" for char in digest
    ):
        raise ObjectReadError("invalid object digest")
    if isinstance(retain_bytes, bool) or not isinstance(retain_bytes, int) or retain_bytes < 0:
        raise ObjectReadError("invalid object read limit")
    path = Path(root) / "objects" / "sha256" / digest[:2] / digest[2:4] / digest
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    directory_fds: list[int] = []
    current_fd = -1
    try:
        current_fd = os.open(Path(root), flags)
        directory_fds.append(current_fd)
        for part in ("objects", "sha256", digest[:2], digest[2:4]):
            try:
                child_fd = os.open(part, flags, dir_fd=current_fd)
            except OSError:
                raise ObjectReadError("object path contains an unsafe directory") from None
            current_fd = child_fd
            directory_fds.append(child_fd)
        try:
            before = os.stat(digest, dir_fd=current_fd, follow_symlinks=False)
        except OSError:
            raise ObjectReadError("object is missing or unsafe") from None
        if not stat.S_ISREG(before.st_mode):
            raise ObjectReadError("object must be a regular file")
        open_flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
        if hasattr(os, "O_NOFOLLOW"):
            open_flags |= os.O_NOFOLLOW
        try:
            descriptor = os.open(digest, open_flags, dir_fd=current_fd)
        except OSError:
            raise ObjectReadError("object cannot be opened safely") from None
    except Exception:
        for fd in reversed(directory_fds):
            try:
                os.close(fd)
            except OSError:
                pass
        raise
    try:
        opened = os.fstat(descriptor)
        identity_fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
        if not stat.S_ISREG(opened.st_mode) or any(
            getattr(opened, field) != getattr(before, field) for field in identity_fields
        ):
            raise ObjectReadError("object changed while being opened")
        hasher = hashlib.sha256()
        prefix = bytearray()
        total = 0
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            hasher.update(chunk)
            if len(prefix) < retain_bytes:
                prefix.extend(chunk[: retain_bytes - len(prefix)])
            total += len(chunk)
        after = os.fstat(descriptor)
        try:
            after_path = os.stat(digest, dir_fd=current_fd, follow_symlinks=False)
        except OSError:
            raise ObjectReadError("object path changed during read") from None
        if (
            not stat.S_ISREG(after.st_mode)
            or any(getattr(after, field) != getattr(opened, field) for field in identity_fields)
            or any(getattr(after_path, field) != getattr(after, field) for field in identity_fields)
            or total != opened.st_size
            or hasher.hexdigest() != digest
        ):
            raise ObjectReadError("object integrity or metadata changed")
        return bytes(prefix), total, total > len(prefix)
    except OSError:
        raise ObjectReadError("object cannot be read safely") from None
    finally:
        os.close(descriptor)
        for fd in reversed(directory_fds):
            try:
                os.close(fd)
            except OSError:
                pass
