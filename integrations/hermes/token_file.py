from __future__ import annotations

import os
import stat


MAX_TOKEN_BYTES = 4096
MIN_TOKEN_BYTES = 32


class TokenFileError(ValueError):
    """A token file failed the protected-file contract."""


def _invalid() -> TokenFileError:
    return TokenFileError("invalid protected token file")


def _validate_token(value: str) -> str:
    encoded = value.encode("utf-8")
    if not MIN_TOKEN_BYTES <= len(encoded) <= MAX_TOKEN_BYTES:
        raise TokenFileError("invalid protected token file")
    if any(
        character.isspace() or ord(character) < 0x20 or ord(character) == 0x7F
        for character in value
    ):
        raise TokenFileError("invalid protected token file")
    return value


def read_token(path: str) -> str:
    """Read one exact, owner-only UTF-8 token without following symlinks."""
    if not os.path.isabs(path):
        raise _invalid()
    try:
        initial = os.lstat(path)
        if not stat.S_ISREG(initial.st_mode) or stat.S_ISLNK(initial.st_mode):
            raise _invalid()
        if initial.st_uid != os.geteuid() or initial.st_mode & 0o077:
            raise _invalid()
        if initial.st_size > MAX_TOKEN_BYTES:
            raise _invalid()
        descriptor = os.open(
            path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK
        )
    except (OSError, TokenFileError):
        raise _invalid() from None
    try:
        opened = os.fstat(descriptor)
        initial_state = (
            initial.st_dev, initial.st_ino, initial.st_size,
            initial.st_mtime_ns, initial.st_ctime_ns, initial.st_mode,
            initial.st_uid,
        )
        opened_state = (
            opened.st_dev, opened.st_ino, opened.st_size,
            opened.st_mtime_ns, opened.st_ctime_ns, opened.st_mode,
            opened.st_uid,
        )
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_uid != os.geteuid()
            or opened.st_mode & 0o077
            or opened_state != initial_state
        ):
            raise _invalid()
        data = b""
        while len(data) <= MAX_TOKEN_BYTES:
            chunk = os.read(descriptor, MAX_TOKEN_BYTES + 1 - len(data))
            if not chunk:
                break
            data += chunk
        finished = os.fstat(descriptor)
        finished_state = (
            finished.st_dev, finished.st_ino, finished.st_size,
            finished.st_mtime_ns, finished.st_ctime_ns, finished.st_mode,
            finished.st_uid,
        )
        if (
            finished_state != opened_state
            or len(data) != opened.st_size
            or len(data) > MAX_TOKEN_BYTES
        ):
            raise _invalid()
        final = os.lstat(path)
        if (
            not stat.S_ISREG(final.st_mode)
            or stat.S_ISLNK(final.st_mode)
            or final.st_uid != os.geteuid()
            or final.st_mode & 0o077
            or (final.st_dev, final.st_ino) != (opened.st_dev, opened.st_ino)
            or final.st_size != opened.st_size
            or final.st_mtime_ns != opened.st_mtime_ns
            or final.st_ctime_ns != opened.st_ctime_ns
        ):
            raise _invalid()
    except (OSError, TokenFileError):
        raise _invalid() from None
    finally:
        os.close(descriptor)
    try:
        return _validate_token(data.decode("utf-8"))
    except (UnicodeDecodeError, TokenFileError):
        raise _invalid() from None
