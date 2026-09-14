from __future__ import annotations

from contextlib import AbstractContextManager
from pathlib import Path
from typing import Protocol

from ._json_types import JSONMapping


class VaultCollaborator(Protocol):
    root: Path

    @staticmethod
    def _init_dir_flags() -> int: ...

    def _open_init_root(self) -> AbstractContextManager[tuple[int, int, str]]: ...

    @classmethod
    def _ensure_directory_at(cls, root_fd: int, components: tuple[str, ...]) -> None: ...

    @classmethod
    def _open_parent_at(cls, root_fd: int, components: tuple[str, ...]) -> tuple[int, str]: ...

    @classmethod
    def _exists_at(cls, root_fd: int, components: tuple[str, ...]) -> bool: ...

    @classmethod
    def _read_regular_at(
        cls, root_fd: int, components: tuple[str, ...], *, max_bytes: int
    ) -> bytes: ...

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
    ) -> None: ...

    def _assert_init_identity(self, parent_fd: int, root_fd: int, root_name: str) -> None: ...

    def _reject_unknown_entries(self, root_fd: int) -> None: ...

    def _read_metadata_at(self, root_fd: int) -> JSONMapping | None: ...

    def _init_descriptor_transaction(self) -> JSONMapping: ...

    def _install_schemas(self, root_fd: int) -> None: ...

    def _install_default_policies(self, root_fd: int) -> None: ...

    def _write_initial_core(self, root_fd: int, self_id: str) -> None: ...

    def _require_current_metadata(self) -> JSONMapping: ...

    def _validate_persistent_string(self, value: str, label: str, *, max_length: int) -> None: ...

    def store_object(self, data: bytes) -> tuple[str, Path]: ...

    def object_path(self, digest: str) -> Path: ...

    def _idempotent_capture(
        self, source: JSONMapping, external_id: str, digest: str
    ) -> JSONMapping | None: ...

    def _write_json_exclusive(self, path: Path, value: JSONMapping) -> None: ...

    def mark_index_dirty(self, *, reason: str = "durable-change", record_id: str | None = None) -> bool: ...
