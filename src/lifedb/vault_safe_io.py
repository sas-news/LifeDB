from __future__ import annotations

import os
import stat
from collections.abc import Generator
from contextlib import contextmanager

from .ids import new_id
from .vault_constants import DURABLE_TOP_LEVEL
from ._vault_cleanup import discard_temp_at
from ._vault_errors import VaultValueError
from ._vault_protocols import VaultCollaborator


class VaultSafeIOMixin:
    @staticmethod
    def _init_dir_flags() -> int:
        return (os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) |
                getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0))

    @contextmanager
    def _open_init_root(self: VaultCollaborator) -> Generator[tuple[int, int, str], None, None]:
        if self.root == self.root.parent or self.root.name in {"", ".", ".."}:
            raise VaultValueError("vault root must not be the filesystem root")
        parent_fd = -1
        root_fd = -1
        try:
            parent_fd = os.open(self.root.parent, self._init_dir_flags())
            if not stat.S_ISDIR(os.fstat(parent_fd).st_mode):
                raise VaultValueError("vault parent must be a real directory")
            try:
                status = os.stat(self.root.name, dir_fd=parent_fd, follow_symlinks=False)
                if stat.S_ISLNK(status.st_mode) or not stat.S_ISDIR(status.st_mode):
                    raise VaultValueError("vault root must be a real directory")
                root_preexisting = True
            except FileNotFoundError:
                try:
                    os.mkdir(self.root.name, 0o700, dir_fd=parent_fd)
                except FileExistsError:
                    root_preexisting = True
                else:
                    os.fsync(parent_fd)
                    root_preexisting = False
            root_fd = os.open(self.root.name, self._init_dir_flags(), dir_fd=parent_fd)
            root_status = os.fstat(root_fd)
            if not stat.S_ISDIR(root_status.st_mode):
                raise VaultValueError("vault root must be a real directory")
            if not root_preexisting:
                os.fchmod(root_fd, 0o700)
                os.fsync(root_fd)
            yield parent_fd, root_fd, self.root.name
        except OSError as exc:
            raise VaultValueError("vault root cannot be opened safely") from exc
        finally:
            if root_fd >= 0:
                os.close(root_fd)
            if parent_fd >= 0:
                os.close(parent_fd)

    @staticmethod
    def _assert_init_identity(parent_fd: int, root_fd: int, root_name: str) -> None:
        root_status = os.fstat(root_fd)
        if not stat.S_ISDIR(root_status.st_mode):
            raise VaultValueError("vault root changed during initialization")
        try:
            current = os.stat(root_name, dir_fd=parent_fd, follow_symlinks=False)
        except OSError as exc:
            raise VaultValueError("vault root changed during initialization") from exc
        if (current.st_dev, current.st_ino) != (root_status.st_dev, root_status.st_ino):
            raise VaultValueError("vault root changed during initialization")

    @staticmethod
    def _reject_unknown_entries(root_fd: int) -> None:
        allowed = set(DURABLE_TOP_LEVEL) | {"vault.json"}
        unknown = sorted(name for name in os.listdir(root_fd) if name not in allowed)
        if unknown:
            raise VaultValueError(
                "refusing to initialize non-empty non-LifeDB directory; "
                f"unknown entries: {', '.join(unknown[:8])}"
            )

    @classmethod
    def _ensure_directory_at(cls, root_fd: int, components: tuple[str, ...]) -> None:
        current_fd = os.dup(root_fd)
        try:
            for component in components:
                if component in {"", ".", ".."}:
                    raise VaultValueError("vault directory contains an unsafe component")
                try:
                    child_fd = os.open(component, cls._init_dir_flags(), dir_fd=current_fd)
                except FileNotFoundError:
                    try:
                        os.mkdir(component, 0o700, dir_fd=current_fd)
                    except FileExistsError:
                        child_fd = os.open(component, cls._init_dir_flags(), dir_fd=current_fd)
                    else:
                        os.fsync(current_fd)
                        child_fd = os.open(component, cls._init_dir_flags(), dir_fd=current_fd)
                        os.fchmod(child_fd, 0o700)
                os.close(current_fd)
                current_fd = child_fd
            os.fsync(current_fd)
        except OSError as exc:
            raise VaultValueError("vault durable component must be a real directory") from exc
        finally:
            os.close(current_fd)

    @classmethod
    def _open_parent_at(cls, root_fd: int, components: tuple[str, ...]) -> tuple[int, str]:
        if not components:
            raise VaultValueError("vault destination must have a filename")
        current_fd = os.dup(root_fd)
        transferred = False
        try:
            for component in components[:-1]:
                if component in {"", ".", ".."}:
                    raise VaultValueError("vault destination contains an unsafe component")
                child_fd = os.open(component, cls._init_dir_flags(), dir_fd=current_fd)
                os.close(current_fd)
                current_fd = child_fd
            if components[-1] in {"", ".", ".."}:
                raise VaultValueError("vault destination contains an unsafe component")
            transferred = True
            return current_fd, components[-1]
        finally:
            if not transferred:
                os.close(current_fd)

    @classmethod
    def _exists_at(cls, root_fd: int, components: tuple[str, ...]) -> bool:
        parent_fd, name = cls._open_parent_at(root_fd, components)
        try:
            try:
                os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
                return True
            except FileNotFoundError:
                return False
        finally:
            os.close(parent_fd)

    @classmethod
    def _require_regular_at(cls, root_fd: int, components: tuple[str, ...], label: str) -> bool:
        parent_fd, name = cls._open_parent_at(root_fd, components)
        try:
            try:
                status = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
            except FileNotFoundError:
                return False
            if not stat.S_ISREG(status.st_mode):
                raise VaultValueError(f"{label} must be a regular file")
            return True
        finally:
            os.close(parent_fd)

    @classmethod
    def _read_regular_at(
        cls, root_fd: int, components: tuple[str, ...], *, max_bytes: int
    ) -> bytes:
        parent_fd, name = cls._open_parent_at(root_fd, components)
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = -1
        try:
            descriptor = os.open(name, flags, dir_fd=parent_fd)
            before = os.fstat(descriptor)
            if not stat.S_ISREG(before.st_mode) or before.st_size > max_bytes:
                raise VaultValueError("durable file must be a bounded regular file")
            chunks: list[bytes] = []
            remaining = max_bytes + 1
            while remaining:
                chunk = os.read(descriptor, min(64 * 1024, remaining))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            payload = b"".join(chunks)
            after = os.fstat(descriptor)
            if (
                len(payload) > max_bytes
                or not stat.S_ISREG(after.st_mode)
                or (before.st_dev, before.st_ino, before.st_size)
                != (after.st_dev, after.st_ino, after.st_size)
                or len(payload) != after.st_size
            ):
                raise VaultValueError("durable file changed during safe read")
            return payload
        except OSError as exc:
            raise VaultValueError("durable file cannot be read safely") from exc
        finally:
            if descriptor >= 0:
                os.close(descriptor)
            os.close(parent_fd)

    @classmethod
    def _publish_bytes_at(
        cls,
        root_fd: int,
        components: tuple[str, ...],
        payload: bytes,
        *,
        mode: int,
        preserve_existing: bool = False,
        compare_existing: bool = False,
    ) -> None:
        parent_fd, name = cls._open_parent_at(root_fd, components)
        temp_name = f".lifedb-init-{new_id()}.tmp"
        temp_fd = -1
        try:
            try:
                existing = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
            except FileNotFoundError:
                existing = None
            except OSError as exc:
                raise VaultValueError("durable init file cannot be inspected safely") from exc
            if existing is not None:
                if not stat.S_ISREG(existing.st_mode):
                    raise VaultValueError("durable init file must be a regular file")
                if preserve_existing:
                    return
                if compare_existing:
                    if cls._read_regular_at(root_fd, components, max_bytes=max(1, len(payload))) != payload:
                        raise VaultValueError("authoritative schema differs from packaged schema")
                    return
                raise VaultValueError("durable init file already exists")
            flags = (
                os.O_WRONLY | os.O_CREAT | os.O_EXCL
                | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
            )
            try:
                temp_fd = os.open(temp_name, flags, mode, dir_fd=parent_fd)
                os.fchmod(temp_fd, mode)
                view = memoryview(payload)
                while view:
                    written = os.write(temp_fd, view)
                    if written <= 0:
                        raise OSError("short write while publishing init artifact")
                    view = view[written:]
                os.fsync(temp_fd)
                os.close(temp_fd)
                temp_fd = -1
                os.link(temp_name, name, src_dir_fd=parent_fd, dst_dir_fd=parent_fd, follow_symlinks=False)
                os.unlink(temp_name, dir_fd=parent_fd)
                os.fsync(parent_fd)
            except FileExistsError:
                if temp_fd >= 0:
                    os.close(temp_fd)
                    temp_fd = -1
                try:
                    winner = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
                except OSError as exc:
                    raise VaultValueError("durable init file race cannot be validated") from exc
                if not stat.S_ISREG(winner.st_mode):
                    raise VaultValueError("durable init file must be a regular file")
                if not compare_existing or cls._read_regular_at(root_fd, components, max_bytes=max(1, len(payload))) != payload:
                    if not preserve_existing:
                        raise VaultValueError("durable init file race changed its contents")
            except OSError as exc:
                raise VaultValueError("durable init file could not be published safely") from exc
        finally:
            if temp_fd >= 0:
                os.close(temp_fd)
            discard_temp_at(parent_fd, temp_name)
            os.close(parent_fd)
