"""Read the repository dotenv file without following path races."""

from __future__ import annotations

import os
import stat
from pathlib import Path
import re


MAX_DOTENV_BYTES = 1_048_576
ENV_KEY = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


class DotenvError(ValueError):
    """A repository dotenv file is unsafe or malformed."""


def parse_dotenv_value(value: str) -> str:
    """Parse one non-evaluating dotenv value."""

    stripped = value.strip()
    if not stripped:
        return ""
    if stripped[0] not in {"'", '"'}:
        comment = stripped.find(" #")
        return stripped if comment < 0 else stripped[:comment].rstrip()
    quote = stripped[0]
    if len(stripped) < 2 or stripped[-1] != quote:
        raise DotenvError("dotenv file is invalid")
    body = stripped[1:-1]
    if quote == "'":
        return body
    result: list[str] = []
    escaped = False
    for character in body:
        if escaped:
            if character not in {'"', "\\", "n", "r", "t"}:
                raise DotenvError("dotenv file is invalid")
            result.append({"n": "\n", "r": "\r", "t": "\t"}.get(character, character))
            escaped = False
        elif character == "\\":
            escaped = True
        else:
            result.append(character)
    if escaped:
        raise DotenvError("dotenv file is invalid")
    return "".join(result)


def _same_file(left: os.stat_result, right: os.stat_result) -> bool:
    return (
        left.st_dev == right.st_dev
        and left.st_ino == right.st_ino
        and left.st_mode == right.st_mode
        and left.st_size == right.st_size
        and left.st_mtime_ns == right.st_mtime_ns
        and left.st_ctime_ns == right.st_ctime_ns
    )


def read_dotenv(path: Path) -> dict[str, str]:
    """Read bounded UTF-8 assignments from an opened regular file."""

    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK
    try:
        path_before = os.lstat(path)
        if stat.S_ISLNK(path_before.st_mode) or not stat.S_ISREG(path_before.st_mode):
            raise DotenvError("dotenv file cannot be read safely")
        file_descriptor = os.open(path, flags)
    except FileNotFoundError:
        raise
    except OSError:
        raise DotenvError("dotenv file cannot be read safely") from None
    try:
        with os.fdopen(file_descriptor, "rb", closefd=True) as stream:
            descriptor_before = os.fstat(stream.fileno())
            if not _same_file(path_before, descriptor_before):
                raise DotenvError("dotenv file cannot be read safely")
            if descriptor_before.st_size > MAX_DOTENV_BYTES:
                raise DotenvError("dotenv file is too large")
            payload = stream.read(MAX_DOTENV_BYTES + 1)
            descriptor_after = os.fstat(stream.fileno())
        path_after = os.lstat(path)
    except (OSError, UnicodeDecodeError):
        raise DotenvError("dotenv file cannot be read safely") from None
    if len(payload) > MAX_DOTENV_BYTES or not _same_file(descriptor_before, descriptor_after):
        raise DotenvError("dotenv file cannot be read safely")
    if not _same_file(path_before, path_after):
        raise DotenvError("dotenv file cannot be read safely")
    text = payload.decode("utf-8")
    values: dict[str, str] = {}
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        name, separator, raw_value = line.partition("=")
        if not separator or not ENV_KEY.fullmatch(name.strip()):
            raise DotenvError("dotenv file is invalid")
        values[name.strip()] = parse_dotenv_value(raw_value)
    return values
