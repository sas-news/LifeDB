"""Safe lifecycle operations for disposable Runtime projections."""

from __future__ import annotations

import errno
import os
import re
import secrets
import stat
import ctypes
from pathlib import Path
from typing import Any

from .storage import file_lock, read_bounded_regular_file, strict_json_loads
from .schema_validation import schema_errors
from .vault import DURABLE_TOP_LEVEL
from .ids import is_uuid7


CONFIRM_RUNTIME_RESET = "DELETE-RUNTIME"
_RESET_TRANSACTION_RE = re.compile(r"^[0-9a-f]{24}$")
_MAX_RESET_TRANSACTIONS = 4


class RuntimeResetError(RuntimeError):
    """A runtime reset was refused or could not be completed safely."""


def _rename_noreplace(
    source: str, destination: str, *, source_dir_fd: int, destination_dir_fd: int
) -> None:
    """Rename a directory without ever replacing an attacker-created entry."""
    # Linux provides the exact primitive needed for publishing a directory
    # atomically with no replacement.  There is no race-free portable
    # fallback for directory rename; fail closed instead of stat-then-rename,
    # which could replace an empty attacker-created directory.
    try:
        libc = ctypes.CDLL(None, use_errno=True)
        renameat2 = libc.renameat2
    except (AttributeError, OSError) as exc:
        raise RuntimeResetError(
            "atomic no-replace runtime publication is unavailable"
        ) from exc
    renameat2.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
    renameat2.restype = ctypes.c_int
    result = renameat2(
        source_dir_fd,
        os.fsencode(source),
        destination_dir_fd,
        os.fsencode(destination),
        1,  # RENAME_NOREPLACE
    )
    if result == 0:
        return
    error_number = ctypes.get_errno()
    if error_number == errno.EEXIST:
        raise RuntimeResetError("runtime appeared during reset")
    if error_number in {errno.ENOSYS, errno.ENOTSUP, errno.EOPNOTSUPP}:
        raise RuntimeResetError(
            "atomic no-replace runtime publication is unavailable"
        ) from OSError(error_number, os.strerror(error_number))
    raise OSError(error_number, os.strerror(error_number), destination)


def _check_tree_device(path: Path, device: int) -> None:
    status = os.lstat(path)
    if status.st_dev != device:
        raise RuntimeResetError("runtime contains a different-filesystem mount")
    if stat.S_ISDIR(status.st_mode) and not stat.S_ISLNK(status.st_mode):
        with os.scandir(path) as entries:
            for entry in entries:
                _check_tree_device(path / entry.name, device)


def _remove_entry(path: Path, device: int) -> None:
    """Remove one tree without following symlinks."""
    status = os.lstat(path)
    if status.st_dev != device:
        raise RuntimeResetError("runtime contains a different-filesystem mount")
    if stat.S_ISDIR(status.st_mode) and not stat.S_ISLNK(status.st_mode):
        with os.scandir(path) as entries:
            for entry in entries:
                _remove_entry(path / entry.name, device)
        os.rmdir(path)
    else:
        os.unlink(path)


def _remove_dirfd(directory: int, device: int) -> None:
    """Remove a directory tree through descriptors, never path traversal."""
    status = os.fstat(directory)
    if status.st_dev != device or not stat.S_ISDIR(status.st_mode):
        raise RuntimeResetError("runtime replacement is not a same-device directory")
    with os.scandir(directory) as entries:
        for entry in entries:
            try:
                child_status = os.stat(entry.name, dir_fd=directory, follow_symlinks=False)
            except OSError as exc:
                raise RuntimeResetError("runtime changed during reset") from exc
            if child_status.st_dev != device:
                raise RuntimeResetError("runtime contains a different-filesystem mount")
            if stat.S_ISDIR(child_status.st_mode) and not stat.S_ISLNK(child_status.st_mode):
                flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
                child = os.open(entry.name, flags, dir_fd=directory)
                try:
                    opened = os.fstat(child)
                    if (opened.st_dev, opened.st_ino) != (child_status.st_dev, child_status.st_ino):
                        raise RuntimeResetError("runtime changed during reset")
                    _remove_dirfd(child, device)
                finally:
                    os.close(child)
                os.rmdir(entry.name, dir_fd=directory)
            else:
                os.unlink(entry.name, dir_fd=directory)


def _write_reset_marker(directory: int, transaction_name: str) -> None:
    descriptor = os.open(
        "index.dirty",
        os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_CLOEXEC", 0),
        0o600,
        dir_fd=directory,
    )
    try:
        # Include the exact transaction name.  Recovery uses this marker,
        # together with the descriptor identity recorded in the transaction,
        # to distinguish our published runtime from a same-device directory
        # that appeared at the path after a crash.
        os.write(descriptor, f"reset:{transaction_name}\n".encode("ascii"))
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _write_runtime_identity(transaction: int, runtime: int, device: int) -> None:
    """Persist the identity of a newly-created runtime before publication."""
    status = os.fstat(runtime)
    if status.st_dev != device or not stat.S_ISDIR(status.st_mode):
        raise RuntimeResetError("runtime replacement is not a same-device directory")
    descriptor = os.open(
        "new-runtime",
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0),
        0o600,
        dir_fd=transaction,
    )
    try:
        os.write(descriptor, f"{status.st_dev}:{status.st_ino}\n".encode("ascii"))
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    os.fsync(transaction)


def _read_runtime_marker(runtime: int, transaction_name: str) -> bool:
    """Return whether ``runtime`` carries this reset transaction's marker."""
    try:
        descriptor = os.open(
            "index.dirty",
            os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0),
            dir_fd=runtime,
        )
    except OSError:
        return False
    try:
        status = os.fstat(descriptor)
        if not stat.S_ISREG(status.st_mode) or status.st_dev != os.fstat(runtime).st_dev:
            return False
        value = os.read(descriptor, 128)
        return value == f"reset:{transaction_name}\n".encode("ascii")
    finally:
        os.close(descriptor)


def _read_runtime_identity(transaction: int) -> tuple[int, int] | None:
    """Read the descriptor identity recorded for a published runtime."""
    try:
        descriptor = os.open(
            "new-runtime",
            os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0),
            dir_fd=transaction,
        )
    except OSError:
        return None
    try:
        status = os.fstat(descriptor)
        if not stat.S_ISREG(status.st_mode) or status.st_size > 128:
            return None
        value = os.read(descriptor, 128).decode("ascii")
    except (OSError, UnicodeDecodeError):
        return None
    finally:
        os.close(descriptor)
    match = re.fullmatch(r"(\d+):(\d+)\n", value)
    return (int(match.group(1)), int(match.group(2))) if match else None


def _runtime_is_verified_new(
    root: int, transaction: int, transaction_name: str, device: int
) -> bool:
    """Prove that the current top-level runtime is this transaction's new tree."""
    try:
        runtime = _open_directory(root, "runtime")
    except OSError:
        return False
    try:
        status = os.fstat(runtime)
        identity = _read_runtime_identity(transaction)
        return (
            identity is not None
            and (status.st_dev, status.st_ino) == identity
            and status.st_dev == device
            and _read_runtime_marker(runtime, transaction_name)
        )
    finally:
        os.close(runtime)


def _unlink_if_exists(directory: int, name: str) -> None:
    try:
        os.unlink(name, dir_fd=directory)
    except FileNotFoundError:
        pass


def _open_directory(parent: int, name: str | Path) -> int:
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    return os.open(name, flags, dir_fd=parent) if isinstance(parent, int) else os.open(name, flags)


def _reset_stage_entries(stage: int) -> list[str]:
    entries: list[str] = []
    with os.scandir(stage) as values:
        for entry in values:
            if not _RESET_TRANSACTION_RE.fullmatch(entry.name):
                raise RuntimeResetError("runtime reset staging contains an unknown entry")
            if not entry.is_dir(follow_symlinks=False):
                raise RuntimeResetError("runtime reset staging entry is not a directory")
            entries.append(entry.name)
    if len(entries) > _MAX_RESET_TRANSACTIONS:
        raise RuntimeResetError("too many incomplete runtime resets")
    return sorted(entries)


def _recover_reset_staging(root: int, stage: int, device: int) -> None:
    """Reconcile only exact reset transaction directories left by a crash."""
    entries = _reset_stage_entries(stage)
    runtime_exists = True
    try:
        runtime_status = os.stat("runtime", dir_fd=root, follow_symlinks=False)
        if not stat.S_ISDIR(runtime_status.st_mode) or runtime_status.st_dev != device:
            raise RuntimeResetError("runtime must be a same-device real directory")
    except FileNotFoundError:
        runtime_exists = False
    for name in entries:
        tx = _open_directory(stage, name)
        remove_transaction = False
        try:
            try:
                old = _open_directory(tx, "old")
            except FileNotFoundError:
                old = None
            if old is not None:
                try:
                    old_status = os.fstat(old)
                    if old_status.st_dev != device or not stat.S_ISDIR(old_status.st_mode):
                        raise RuntimeResetError("runtime reset staging is unsafe")
                    if not runtime_exists:
                        os.rename("old", "runtime", src_dir_fd=tx, dst_dir_fd=root)
                        runtime_exists = True
                        # The old runtime is restored before publication.  It
                        # is now safe to discard this exact transaction.
                        remove_transaction = True
                    elif _runtime_is_verified_new(root, tx, name, device):
                        # Only a runtime whose inode and transaction marker
                        # were durably recorded by us may permit cleanup of
                        # the staged old tree.  A same-device replacement at
                        # the top-level path is never deleted or overwritten.
                        _remove_dirfd(old, device)
                        os.rmdir("old", dir_fd=tx)
                        _unlink_if_exists(tx, "new-runtime")
                        remove_transaction = True
                    else:
                        raise RuntimeResetError(
                            "runtime reset staging cannot verify the published runtime; "
                            "manual inspection is required"
                        )
                finally:
                    os.close(old)
            elif not runtime_exists:
                raise RuntimeResetError("runtime reset staging has no recoverable old runtime")
            else:
                # The old tree is already gone, so this transaction is only
                # disposable bookkeeping.  Removing the transaction itself
                # never removes the top-level runtime (which may have been
                # replaced while reset was stopped), and is therefore safe
                # even when publication verification is unavailable.
                remove_transaction = True
            if remove_transaction:
                _unlink_if_exists(tx, "new-runtime")
                try:
                    staged_new = _open_directory(tx, "new")
                except FileNotFoundError:
                    staged_new = None
                if staged_new is not None:
                    try:
                        _remove_dirfd(staged_new, device)
                    finally:
                        os.close(staged_new)
                    os.rmdir("new", dir_fd=tx)
        finally:
            os.close(tx)
        if remove_transaction:
            os.rmdir(name, dir_fd=stage)
    if entries:
        os.fsync(stage)
        os.fsync(root)


def reset_runtime(vault: Any, *, confirmation: str) -> dict[str, Any]:
    """Delete and recreate exactly ``<vault>/runtime``.

    Runtime is disposable; all durable stores remain untouched. Callers must
    stop the server before invoking this operation. The explicit confirmation
    and conservative path checks are intentionally kept here, rather than in a
    shell recipe, so every caller gets the same guardrails. The reset lock only
    coordinates cooperating callers that open the current runtime path; a
    process still waiting on a lock file inside the renamed old runtime is not
    observable here and is not made safe by this function.
    """
    if confirmation != CONFIRM_RUNTIME_RESET:
        raise RuntimeResetError("runtime reset requires --confirm DELETE-RUNTIME")
    root = Path(os.path.abspath(os.fspath(Path(getattr(vault, "root", vault)).expanduser())))
    try:
        root_status = os.lstat(root)
    except OSError as exc:
        raise RuntimeResetError("vault root cannot be inspected safely") from exc
    if not stat.S_ISDIR(root_status.st_mode) or stat.S_ISLNK(root_status.st_mode):
        raise RuntimeResetError("vault root must be a real directory")
    if root == Path("/") or root == Path("/home/repo"):
        raise RuntimeResetError("refusing to reset a dangerous vault root")
    home = Path.home()
    if root == home:
        raise RuntimeResetError("refusing to reset a home directory")
    if (root / "pyproject.toml").is_file() and (root / ".git").exists():
        raise RuntimeResetError("refusing to reset a repository root")
    metadata = root / "vault.json"
    try:
        metadata_status = os.lstat(metadata)
    except OSError as exc:
        raise RuntimeResetError("vault is not initialized") from exc
    if not stat.S_ISREG(metadata_status.st_mode) or stat.S_ISLNK(metadata_status.st_mode):
        raise RuntimeResetError("vault metadata must be a regular file")
    # Validate the schema directory before asking schema_validation to load
    # anything; otherwise a swapped parent could redirect that read outside
    # the vault boundary.
    for schema_dir in (root / "schemas", root / "schemas" / "0.2"):
        try:
            schema_status = os.lstat(schema_dir)
        except OSError as exc:
            raise RuntimeResetError("vault schema layout is incomplete") from exc
        if stat.S_ISLNK(schema_status.st_mode) or not stat.S_ISDIR(schema_status.st_mode):
            raise RuntimeResetError("vault schema layout is unsafe")
    try:
        metadata_value = strict_json_loads(
            read_bounded_regular_file(
                metadata, max_bytes=1 * 1024 * 1024, boundary=root
            ),
            max_bytes=1 * 1024 * 1024,
        )
    except ValueError as exc:
        raise RuntimeResetError("vault metadata is not valid strict JSON") from exc
    try:
        metadata_invalid = not isinstance(metadata_value, dict) or bool(
            schema_errors("vault", metadata_value, vault_root=root)
        )
    except (OSError, ValueError) as exc:
        raise RuntimeResetError("vault schema cannot be verified") from exc
    if (
        metadata_invalid
        or metadata_value.get("schema") != "0.2"
        or not is_uuid7(metadata_value.get("vault_id"))
    ):
        raise RuntimeResetError("vault metadata does not match the LifeDB schema")
    required_dirs = (set(DURABLE_TOP_LEVEL) - {"runtime"}) | {
        "canon/core", "canon/self", "evidence/_events", "objects/sha256",
        "schemas/0.2", "quarantine",
    }
    try:
        unknown = [
            entry.name
            for entry in os.scandir(root)
            if entry.name not in set(DURABLE_TOP_LEVEL) | {"vault.json"}
        ]
    except OSError as exc:
        raise RuntimeResetError("vault durable layout cannot be inspected") from exc
    if unknown:
        raise RuntimeResetError("vault root contains unknown entries")
    for relative in required_dirs:
        candidate = root / relative
        try:
            candidate_status = os.lstat(candidate)
        except OSError as exc:
            raise RuntimeResetError("vault durable layout is incomplete") from exc
        if stat.S_ISLNK(candidate_status.st_mode) or not stat.S_ISDIR(candidate_status.st_mode):
            raise RuntimeResetError("vault durable layout is unsafe")

    device = root_status.st_dev
    lock_path = root / "quarantine" / "runtime-reset.lock"
    with file_lock(lock_path, boundary=root):
        runtime = root / "runtime"
        if runtime.exists() and not runtime.is_symlink():
            # Diagnostic preflight; the descriptor walk remains authoritative.
            _check_tree_device(runtime, device)
        # The descriptor-relative calls below are POSIX hardening. On a
        # platform without dir_fd/O_NOFOLLOW support, failure is safer than a
        # path-based recursive fallback. Callers must stop the server first;
        # this lock coordinates cooperating local writers only.
        root_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
        root_descriptor = os.open(root, root_flags)
        stage_descriptor: int | None = None
        transaction_descriptor: int | None = None
        old_descriptor: int | None = None
        transaction_name: str | None = None
        try:
            quarantine_descriptor = os.open("quarantine", root_flags, dir_fd=root_descriptor)
            try:
                try:
                    os.mkdir("runtime-reset", 0o700, dir_fd=quarantine_descriptor)
                except FileExistsError:
                    pass
                stage_descriptor = os.open("runtime-reset", root_flags, dir_fd=quarantine_descriptor)
                _recover_reset_staging(root_descriptor, stage_descriptor, device)
            finally:
                os.close(quarantine_descriptor)

            old_descriptor = os.open("runtime", root_flags, dir_fd=root_descriptor)
            old_stat = os.fstat(old_descriptor)
            if old_stat.st_dev != device:
                raise RuntimeResetError("runtime contains a different-filesystem mount")
            assert stage_descriptor is not None
            for _ in range(32):
                candidate = secrets.token_hex(12)
                try:
                    os.mkdir(candidate, 0o700, dir_fd=stage_descriptor)
                    transaction_name = candidate
                    break
                except FileExistsError:
                    continue
            if transaction_name is None:
                raise RuntimeResetError("cannot create a unique runtime reset name")
            transaction_descriptor = os.open(transaction_name, root_flags, dir_fd=stage_descriptor)
            os.rename("runtime", "old", src_dir_fd=root_descriptor, dst_dir_fd=transaction_descriptor)
            old_parent_sync_error: OSError | None = None
            # Both directory entries are durable before any replacement is
            # attempted.  If a parent fsync is uncertain, continue only far
            # enough to leave a fully recoverable staged transaction; do not
            # discard the old tree or claim reset success.
            try:
                os.fsync(transaction_descriptor)
                os.fsync(root_descriptor)
            except OSError as exc:
                old_parent_sync_error = exc
            staged_old = os.open("old", root_flags, dir_fd=transaction_descriptor)
            try:
                staged_stat = os.fstat(staged_old)
                if (staged_stat.st_dev, staged_stat.st_ino) != (old_stat.st_dev, old_stat.st_ino):
                    os.rename("old", "runtime", src_dir_fd=transaction_descriptor, dst_dir_fd=root_descriptor)
                    raise RuntimeResetError("runtime changed during reset")
            finally:
                os.close(staged_old)

            new_published = False
            try:
                # Build and fsync the replacement entirely inside the exact
                # transaction directory.  A crash anywhere in creation then
                # leaves no partial top-level runtime; publication is one
                # descriptor-relative rename after the identity is recorded.
                os.mkdir("new", 0o700, dir_fd=transaction_descriptor)
                new_descriptor = os.open("new", root_flags, dir_fd=transaction_descriptor)
                try:
                    os.mkdir("locks", 0o700, dir_fd=new_descriptor)
                    _write_reset_marker(new_descriptor, transaction_name)
                    _write_runtime_identity(
                        transaction_descriptor, new_descriptor, device
                    )
                    os.fsync(new_descriptor)
                finally:
                    os.close(new_descriptor)
                # Publish with RENAME_NOREPLACE so an entry created at the
                # top-level path during the kill window is never deleted or
                # overwritten (including an empty attacker directory).
                try:
                    os.stat("runtime", dir_fd=root_descriptor, follow_symlinks=False)
                except FileNotFoundError:
                    pass
                else:
                    raise RuntimeResetError("runtime appeared during reset")
                _rename_noreplace(
                    "new", "runtime",
                    source_dir_fd=transaction_descriptor,
                    destination_dir_fd=root_descriptor,
                )
                os.fsync(transaction_descriptor)
                os.fsync(root_descriptor)
                new_published = True

                if old_parent_sync_error is not None:
                    # The new runtime is already published but staging is
                    # intentionally retained so the next reset can reconcile
                    # the exact old inode.  This is an uncertain publication,
                    # never a successful reset.
                    raise old_parent_sync_error

                staged_old = os.open("old", root_flags, dir_fd=transaction_descriptor)
                try:
                    _remove_dirfd(staged_old, device)
                finally:
                    os.close(staged_old)
                os.rmdir("old", dir_fd=transaction_descriptor)
                _unlink_if_exists(transaction_descriptor, "new-runtime")
                os.close(transaction_descriptor)
                transaction_descriptor = None
                os.rmdir(transaction_name, dir_fd=stage_descriptor)
                transaction_name = None
                os.fsync(stage_descriptor)
                os.fsync(root_descriptor)
            except Exception:
                if not new_published:
                    # Before publication, restore the exact old inode if the
                    # new runtime could not be made usable. If restoration
                    # itself fails, the exact staging directory remains for a
                    # subsequent reset to reconcile; no tree is deleted.
                    try:
                        os.stat("runtime", dir_fd=root_descriptor, follow_symlinks=False)
                    except FileNotFoundError:
                        try:
                            os.rename(
                                "old", "runtime",
                                src_dir_fd=transaction_descriptor,
                                dst_dir_fd=root_descriptor,
                            )
                            # Restoration is complete and the staged tree is
                            # the exact old descriptor.  Close before removing
                            # the now-empty transaction directory; retaining
                            # the name here would make a successful
                            # compensation look like unknown staging.
                            _unlink_if_exists(transaction_descriptor, "new-runtime")
                            try:
                                staged_new = _open_directory(transaction_descriptor, "new")
                            except FileNotFoundError:
                                staged_new = None
                            if staged_new is not None:
                                try:
                                    _remove_dirfd(staged_new, device)
                                finally:
                                    os.close(staged_new)
                                os.rmdir("new", dir_fd=transaction_descriptor)
                            os.close(transaction_descriptor)
                            transaction_descriptor = None
                            os.rmdir(transaction_name, dir_fd=stage_descriptor)
                            transaction_name = None
                            os.fsync(stage_descriptor)
                        except OSError:
                            pass
                raise
        finally:
            if transaction_descriptor is not None:
                os.close(transaction_descriptor)
            if old_descriptor is not None:
                os.close(old_descriptor)
            if stage_descriptor is not None:
                os.close(stage_descriptor)
            os.close(root_descriptor)
    return {
        "schema": "0.2",
        "reset": True,
        "runtime": "runtime",
        "dirty": True,
    }


__all__ = ["CONFIRM_RUNTIME_RESET", "RuntimeResetError", "reset_runtime"]
