from __future__ import annotations

import os
import re
import stat
from pathlib import Path

from .models import InstallerError
from .source import OWNED_FILES

_CACHE_NAME = "__pycache__"
_CACHE_FILE = re.compile(r"^(?P<stem>[A-Za-z_][A-Za-z0-9_]*)\.cpython-3\d{2}(?:\.opt-[12])?\.pyc$")


def _error() -> InstallerError:
    return InstallerError("Hermes installer operation failed")


def _allowed_names() -> set[str]:
    return {Path(name).stem for name in OWNED_FILES if name.endswith(".py")}


def _identity(info: os.stat_result) -> tuple[int, int, int, int]:
    return info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns


def _open_root(root: Path) -> int:
    try:
        return os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    except OSError as error:
        raise _error() from error


def _open_cache(root_fd: int) -> tuple[int, tuple[int, int, int, int]] | None:
    try:
        cache_fd = os.open(_CACHE_NAME, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=root_fd)
    except FileNotFoundError:
        return None
    except OSError as error:
        raise _error() from error
    info = os.fstat(cache_fd)
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) & 0o022:
        os.close(cache_fd)
        raise _error()
    return cache_fd, _identity(info)


def _validate_entry(cache_fd: int, name: str, allowed: set[str]) -> None:
    match = _CACHE_FILE.fullmatch(name)
    if match is None or match.group("stem") not in allowed:
        raise _error()
    try:
        descriptor = os.open(name, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW, dir_fd=cache_fd)
    except OSError as error:
        raise _error() from error
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) & 0o022:
            raise _error()
        observed = os.stat(name, dir_fd=cache_fd, follow_symlinks=False)
        if _identity(observed) != _identity(info):
            raise _error()
    finally:
        os.close(descriptor)


def _validate_from_fd(root_fd: int) -> None:
    opened = _open_cache(root_fd)
    if opened is None:
        return
    cache_fd, _ = opened
    try:
        allowed = _allowed_names()
        for name in os.listdir(cache_fd):
            _validate_entry(cache_fd, name, allowed)
    finally:
        os.close(cache_fd)


def validate_cache(root: Path) -> None:
    """Validate the optional mutable CPython cache under an owned root."""
    root_fd = _open_root(root)
    try:
        _validate_from_fd(root_fd)
    finally:
        os.close(root_fd)


def remove_cache(root: Path) -> None:
    """Remove only a validated immediate CPython cache directory."""
    root_fd = _open_root(root)
    try:
        opened = _open_cache(root_fd)
        if opened is None:
            return
        cache_fd, original = opened
        try:
            allowed = _allowed_names()
            for name in os.listdir(cache_fd):
                _validate_entry(cache_fd, name, allowed)
                try:
                    os.unlink(name, dir_fd=cache_fd)
                except FileNotFoundError:
                    continue
                except OSError as error:
                    raise _error() from error
            current = os.fstat(cache_fd)
            observed = os.stat(_CACHE_NAME, dir_fd=root_fd, follow_symlinks=False)
            if (
                (current.st_dev, current.st_ino) != original[:2]
                or (observed.st_dev, observed.st_ino) != original[:2]
                or current.st_uid != os.geteuid()
                or observed.st_uid != os.geteuid()
                or stat.S_IMODE(current.st_mode) & 0o022
                or stat.S_IMODE(observed.st_mode) & 0o022
            ):
                raise _error()
            try:
                os.rmdir(_CACHE_NAME, dir_fd=root_fd)
            except OSError as error:
                raise _error() from error
        finally:
            os.close(cache_fd)
    finally:
        os.close(root_fd)
