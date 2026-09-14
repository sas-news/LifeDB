from __future__ import annotations

import json
import math
import os
import stat
import tempfile
import threading
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator

from ._server_types import JSONValue

try:  # pragma: no cover - exercised only on platforms without fcntl
    import fcntl
except ImportError:  # pragma: no cover
    fcntl = None  # type: ignore[assignment]


_LOCKS_GUARD = threading.Lock()
_LOCKS: dict[str, threading.RLock] = {}
_LOCK_DEPTH = threading.local()


class DurablePublicationUncertain(OSError):
    """The final name was published, but its directory fsync was uncertain.

    Callers must treat this as an ambiguous durable mutation: the destination
    may survive a crash and must never be compensated as though publication
    definitely failed.
    """

    def __init__(self, path: Path | str):
        self.path = Path(path)
        self.published = True
        super().__init__("durable publication state is uncertain")


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            # Never include the attacker-controlled key in an error message.
            raise ValueError("JSON object contains a duplicate key")
        value[key] = item
    return value


def _strict_float(value: str) -> float:
    parsed = float(value)
    if not math.isfinite(parsed):
        raise ValueError("JSON number must be finite")
    return parsed


def _reject_json_constant(_value: str) -> None:
    raise ValueError("JSON number must be finite")


def strict_json_loads(payload: bytes, *, max_bytes: int) -> JSONValue:
    """Decode bounded UTF-8 JSON without ambiguous or non-finite data.

    Duplicate object names are rejected at every nesting level. Errors are
    deliberately stable and never interpolate input bytes or decoded values.
    Whether the top-level value must be an object remains a caller decision.
    """

    if isinstance(max_bytes, bool) or not isinstance(max_bytes, int) or max_bytes < 1:
        raise ValueError("JSON byte limit must be a positive integer")
    if not isinstance(payload, (bytes, bytearray, memoryview)):
        raise ValueError("JSON input must be bytes-like")
    if len(payload) > max_bytes:
        raise ValueError("JSON input exceeds the maximum size")
    try:
        text = bytes(payload).decode("utf-8", errors="strict")
        value = json.loads(
            text,
            object_pairs_hook=_strict_object,
            parse_constant=_reject_json_constant,
            parse_float=_strict_float,
        )
        # Escaped lone surrogates and any other value the canonical writer
        # cannot encode are not part of the durable JSON domain.
        canonical_json_bytes(value)
        return value
    except (MemoryError, OverflowError, RecursionError, UnicodeError, ValueError):
        raise ValueError("invalid strict JSON") from None


def _open_bounded_file(path: Path, boundary: Path | None) -> tuple[int, int | None, str | None]:
    """Open a regular file, optionally traversing every component from boundary."""

    if boundary is None:
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        return os.open(path, flags), None, None
    try:
        relative = path.relative_to(boundary)
    except ValueError:
        raise ValueError("record path must remain inside the durable boundary") from None
    if not relative.parts or any(part in {"", ".", ".."} for part in relative.parts):
        raise ValueError("record path contains an unsafe component")
    directory_flags = (
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        parent_fd = os.open(boundary, directory_flags)
    except OSError:
        raise ValueError("record boundary must be a real directory") from None
    try:
        for part in relative.parts[:-1]:
            try:
                child_fd = os.open(part, directory_flags, dir_fd=parent_fd)
            except OSError:
                raise ValueError("record path contains an unsafe directory") from None
            os.close(parent_fd)
            parent_fd = child_fd
        open_flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(relative.parts[-1], open_flags, dir_fd=parent_fd)
        return descriptor, parent_fd, relative.parts[-1]
    except Exception:
        os.close(parent_fd)
        raise


def read_bounded_regular_file(
    path: Path | str, *, max_bytes: int, boundary: Path | str | None = None
) -> bytes:
    """Read a bounded regular file without following its final symlink.

    ``lstat`` avoids blocking on FIFOs before opening, while ``O_NONBLOCK`` and
    descriptor ``fstat`` defend the stated local-process threat model. A host
    administrator racing individual syscalls remains outside that model.
    """

    if isinstance(max_bytes, bool) or not isinstance(max_bytes, int) or max_bytes < 1:
        raise ValueError("file byte limit must be a positive integer")
    location = Path(path)
    safe_boundary = _absolute_path(boundary) if boundary is not None else None
    if safe_boundary is not None:
        location = _absolute_path(location)
    try:
        before = os.lstat(location)
    except OSError:
        raise ValueError("record file cannot be inspected safely") from None
    if not stat.S_ISREG(before.st_mode):
        raise ValueError("record path must be a regular non-symlink file")
    if before.st_size > max_bytes:
        raise ValueError("record file exceeds the maximum size")

    try:
        descriptor, parent_fd, final_name = _open_bounded_file(location, safe_boundary)
    except OSError:
        raise ValueError("record file cannot be opened safely") from None
    try:
        opened = os.fstat(descriptor)
        identity_fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
        if (
            not stat.S_ISREG(opened.st_mode)
            or any(getattr(opened, field) != getattr(before, field) for field in identity_fields)
        ):
            raise ValueError("record path changed during safe open")
        if opened.st_size > max_bytes:
            raise ValueError("record file exceeds the maximum size")
        chunks: list[bytes] = []
        remaining = max_bytes + 1
        while remaining:
            chunk = os.read(descriptor, min(64 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        payload = b"".join(chunks)
        if len(payload) > max_bytes:
            raise ValueError("record file exceeds the maximum size")
        finished = os.fstat(descriptor)
        if any(
            getattr(finished, field) != getattr(opened, field)
            for field in identity_fields
        ) or len(payload) != finished.st_size:
            raise ValueError("record file changed during safe read")
        try:
            after = (
                os.stat(final_name, dir_fd=parent_fd, follow_symlinks=False)
                if parent_fd is not None
                else os.lstat(location)
            )
        except OSError:
            raise ValueError("record path changed during safe read") from None
        if not stat.S_ISREG(after.st_mode) or any(
            getattr(after, field) != getattr(finished, field)
            for field in identity_fields
        ):
            raise ValueError("record path changed during safe read")
        return payload
    except OSError:
        raise ValueError("record file cannot be read safely") from None
    finally:
        os.close(descriptor)
        if parent_fd is not None:
            os.close(parent_fd)


def canonical_json_bytes(value: Any) -> bytes:
    """Return the deterministic UTF-8 representation used for integrity hashes."""

    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def _json_bytes(value: Any) -> bytes:
    return (json.dumps(value, ensure_ascii=False, indent=2, allow_nan=False) + "\n").encode(
        "utf-8"
    )


def fsync_directory(path: Path | str | int) -> None:
    """Persist directory-entry changes where the host supports directory fsync."""

    if isinstance(path, int):
        os.fsync(path)
        return
    directory = Path(path)
    flags = os.O_RDONLY
    if hasattr(os, "O_DIRECTORY"):
        flags |= os.O_DIRECTORY
    descriptor = os.open(directory, flags)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _ensure_private_parent(path: Path) -> None:
    """Create missing durable parent directories owner-only and persist them.

    ``Path.mkdir(parents=True)`` applies its mode only to the final directory
    on some Python/platform combinations.  Build the missing suffix explicitly
    so every newly created parent is mode 0700; existing directories retain
    their administrator-selected permissions.
    """

    missing: list[Path] = []
    current = path
    while not current.exists():
        missing.append(current)
        parent = current.parent
        if parent == current:  # pragma: no cover - filesystem root always exists
            break
        current = parent
    for directory in reversed(missing):
        try:
            directory.mkdir(mode=0o700)
        except FileExistsError:
            # Another writer may have won the race.  Do not chmod a directory
            # that this call did not create.
            if not directory.is_dir():
                raise
            continue
        directory.chmod(0o700)
        fsync_directory(directory.parent)


def _absolute_path(path: Path | str) -> Path:
    return Path(os.path.abspath(os.fspath(Path(path).expanduser())))


def _prepare_bounded_parent(destination: Path, boundary: Path) -> None:
    """Validate/create destination parents without following boundary symlinks."""

    try:
        relative = destination.relative_to(boundary)
    except ValueError:
        raise ValueError("destination must remain inside the durable boundary") from None
    if not relative.parts:
        raise ValueError("destination must be below the durable boundary")

    try:
        boundary_status = os.lstat(boundary)
    except OSError:
        raise ValueError("durable boundary must already exist") from None
    if not stat.S_ISDIR(boundary_status.st_mode):
        raise ValueError("durable boundary must be a real directory")

    current = boundary
    for part in relative.parts[:-1]:
        current = current / part
        try:
            status = os.lstat(current)
        except FileNotFoundError:
            try:
                os.mkdir(current, 0o700)
                os.chmod(current, 0o700)
                fsync_directory(current.parent)
                status = os.lstat(current)
            except OSError:
                raise ValueError("durable parent could not be created safely") from None
        except OSError:
            raise ValueError("durable parent could not be inspected safely") from None
        if not stat.S_ISDIR(status.st_mode):
            raise ValueError("durable parent must be a real directory")

    try:
        final_status = os.lstat(destination)
    except FileNotFoundError:
        return
    except OSError:
        raise ValueError("destination could not be inspected safely") from None
    if not stat.S_ISREG(final_status.st_mode):
        raise ValueError("destination must be a regular non-symlink file")


def _open_bounded_parent(destination: Path, boundary: Path) -> tuple[int, str]:
    """Open/create a destination parent below boundary using directory fds."""

    try:
        relative = destination.relative_to(boundary)
    except ValueError:
        raise ValueError("destination must remain inside the durable boundary") from None
    if not relative.parts:
        raise ValueError("destination must be below the durable boundary")
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        current_fd = os.open(boundary, flags)
    except OSError:
        raise ValueError("durable boundary must be a real directory") from None
    try:
        for component in relative.parts[:-1]:
            if component in {"", ".", ".."}:
                raise ValueError("destination contains an unsafe path component")
            try:
                child_fd = os.open(component, flags, dir_fd=current_fd)
            except FileNotFoundError:
                try:
                    try:
                        os.mkdir(component, 0o700, dir_fd=current_fd)
                    except FileExistsError:
                        pass
                    fsync_directory(current_fd)
                    child_fd = os.open(component, flags, dir_fd=current_fd)
                except OSError:
                    raise ValueError("durable parent could not be created safely") from None
            except OSError:
                raise ValueError("durable parent must be a real directory") from None
            os.close(current_fd)
            current_fd = child_fd
        final_name = relative.parts[-1]
        try:
            existing = os.stat(final_name, dir_fd=current_fd, follow_symlinks=False)
        except FileNotFoundError:
            existing = None
        except OSError:
            raise ValueError("destination could not be inspected safely") from None
        if existing is not None and not stat.S_ISREG(existing.st_mode):
            raise ValueError("destination must be a regular non-symlink file")
        return current_fd, final_name
    except Exception:
        os.close(current_fd)
        raise


def durable_write_bytes(
    path: Path | str,
    payload: bytes,
    *,
    exclusive: bool = False,
    mode: int = 0o600,
    boundary: Path | str | None = None,
) -> None:
    """Durably publish bytes without ever exposing a partially written target.

    The temporary file is created beside the destination so that link/replace is
    atomic on the destination filesystem.  Exclusive publication uses a hard
    link: unlike opening the final path with O_EXCL, a crash during the write can
    leave only an ignorable temporary file, never a truncated final record.
    """

    destination = Path(path)
    durable_boundary: Path | None = None
    if boundary is not None:
        destination = _absolute_path(destination)
        durable_boundary = _absolute_path(boundary)
    else:
        _ensure_private_parent(destination.parent)
    parent_fd: int | None = None
    temporary_name: str
    if durable_boundary is not None:
        parent_fd, destination_name = _open_bounded_parent(destination, durable_boundary)
        try:
            for _ in range(32):
                temporary_name = f".{destination_name}.tmp-{os.urandom(12).hex()}"
                try:
                    descriptor = os.open(
                        temporary_name,
                        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0),
                        0o600,
                        dir_fd=parent_fd,
                    )
                    break
                except FileExistsError:
                    continue
            else:
                raise OSError("could not allocate a durable temporary file")
        except BaseException:
            os.close(parent_fd)
            raise
    else:
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=f".{destination.name}.tmp-", dir=destination.parent
        )
    temporary = Path(temporary_name)
    published = False
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fchmod(stream.fileno(), mode)
            os.fsync(stream.fileno())

        if durable_boundary is not None and parent_fd is None:  # pragma: no cover - defensive
            raise ValueError("durable parent descriptor is unavailable")
        if exclusive:
            if parent_fd is not None:
                os.link(temporary_name, destination_name, src_dir_fd=parent_fd, dst_dir_fd=parent_fd)
            else:
                os.link(temporary, destination)
        else:
            if parent_fd is not None:
                os.replace(temporary_name, destination_name, src_dir_fd=parent_fd, dst_dir_fd=parent_fd)
            else:
                os.replace(temporary, destination)
        published = True
        try:
            fsync_directory(parent_fd if parent_fd is not None else destination.parent)
        except OSError as exc:
            # link/replace already made the final name visible.  The caller
            # must be able to distinguish this from a pre-publication error.
            raise DurablePublicationUncertain(destination) from exc
    finally:
        # For replace, temporary no longer exists.  For link, the final name is
        # already published; the staging name is disposable and its cleanup
        # must not turn a durable operation into a second ambiguous failure.
        try:
            if parent_fd is not None:
                os.unlink(temporary_name, dir_fd=parent_fd)
            elif temporary.exists():
                temporary.unlink()
        except OSError:
            pass
        if parent_fd is not None:
            os.close(parent_fd)


def durable_write_json(
    path: Path | str,
    value: Any,
    *,
    exclusive: bool = False,
    mode: int = 0o600,
    boundary: Path | str | None = None,
) -> None:
    durable_write_bytes(
        path,
        _json_bytes(value),
        exclusive=exclusive,
        mode=mode,
        boundary=boundary,
    )


def durable_touch(
    path: Path | str,
    payload: bytes = b"",
    *,
    boundary: Path | str | None = None,
) -> None:
    """Atomically create or replace a disposable marker and persist its entry."""

    durable_write_bytes(
        path,
        payload,
        exclusive=False,
        mode=0o600,
        boundary=boundary,
    )


def _thread_lock(path: Path) -> threading.RLock:
    key = str(path.absolute())
    with _LOCKS_GUARD:
        lock = _LOCKS.get(key)
        if lock is None:
            lock = threading.RLock()
            _LOCKS[key] = lock
    return lock


def _lock_boundary(lock_path: Path, boundary: Path | str | None) -> Path | None:
    """Choose the vault boundary for a lock, including legacy call sites."""

    if boundary is not None:
        return _absolute_path(boundary)
    # Existing callers all use ``<vault>/runtime/locks/...``.  Inferring this
    # boundary keeps those call sites safe while allowing generic file_lock()
    # users to retain the old unbounded path API.
    parts = lock_path.parts
    try:
        runtime_index = len(parts) - 1 - parts[::-1].index("runtime")
    except ValueError:
        return None
    if runtime_index <= 0 or runtime_index + 1 >= len(parts) or parts[runtime_index + 1] != "locks":
        return None
    return Path(*parts[:runtime_index])


def _open_lock_parent(lock_path: Path, boundary: Path | None) -> tuple[int, str]:
    """Open the lock's parent by descriptor-relative, no-follow traversal."""

    if boundary is None:
        _ensure_private_parent(lock_path.parent)
        return os.open(lock_path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)), lock_path.name

    try:
        relative = lock_path.parent.relative_to(boundary)
    except ValueError:
        raise ValueError("lock path must remain inside the durable boundary") from None
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        root_fd = os.open(boundary, flags)
    except OSError:
        raise ValueError("lock boundary must be a real directory") from None
    current_fd = root_fd
    try:
        for component in relative.parts:
            if component in {"", ".", ".."}:
                raise ValueError("lock path contains an unsafe component")
            try:
                child_fd = os.open(component, flags, dir_fd=current_fd)
            except FileNotFoundError:
                try:
                    try:
                        os.mkdir(component, 0o700, dir_fd=current_fd)
                    except FileExistsError:
                        pass
                    child_fd = os.open(component, flags, dir_fd=current_fd)
                except OSError:
                    raise ValueError("lock parent cannot be created safely") from None
            except OSError:
                raise ValueError("lock parent cannot be traversed safely") from None
            if child_fd != current_fd:
                os.close(current_fd)
            current_fd = child_fd
        return current_fd, lock_path.name
    except Exception:
        os.close(current_fd)
        raise


@contextmanager
def file_lock(path: Path | str, *, boundary: Path | str | None = None) -> Iterator[None]:
    """Serialize a critical section using a stable parent directory descriptor."""

    lock_path = _absolute_path(path)
    durable_boundary = _lock_boundary(lock_path, boundary)
    thread_lock = _thread_lock(lock_path)
    key = str(lock_path.absolute())
    with thread_lock:
        depths = getattr(_LOCK_DEPTH, "values", None)
        if depths is None:
            depths = {}
            _LOCK_DEPTH.values = depths
        if depths.get(key, 0):
            depths[key] += 1
            try:
                yield
            finally:
                depths[key] -= 1
            return
        parent_fd, lock_name = _open_lock_parent(lock_path, durable_boundary)
        descriptor = -1
        try:
            try:
                existing = os.stat(lock_name, dir_fd=parent_fd, follow_symlinks=False)
            except FileNotFoundError:
                existing = None
            except OSError:
                raise ValueError("lock path cannot be inspected safely") from None
            if existing is not None and not stat.S_ISREG(existing.st_mode):
                raise ValueError("lock path must be a regular file")
            flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_CLOEXEC", 0)
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            descriptor = os.open(lock_name, flags, 0o600, dir_fd=parent_fd)
            opened = os.fstat(descriptor)
            if not stat.S_ISREG(opened.st_mode):
                raise ValueError("lock path must be a regular file")
            if existing is not None and (
                opened.st_dev,
                opened.st_ino,
            ) != (existing.st_dev, existing.st_ino):
                raise ValueError("lock path changed during safe open")
            try:
                after_open = os.stat(lock_name, dir_fd=parent_fd, follow_symlinks=False)
            except OSError:
                raise ValueError("lock path changed during safe open") from None
            if (opened.st_dev, opened.st_ino) != (after_open.st_dev, after_open.st_ino):
                raise ValueError("lock path changed during safe open")
            if fcntl is not None:
                fcntl.flock(descriptor, fcntl.LOCK_EX)
            depths[key] = 1
            try:
                yield
            finally:
                depths.pop(key, None)
        finally:
            if descriptor >= 0 and fcntl is not None:
                fcntl.flock(descriptor, fcntl.LOCK_UN)
            if descriptor >= 0:
                os.close(descriptor)
            os.close(parent_fd)
