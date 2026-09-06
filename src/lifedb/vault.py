from __future__ import annotations

import hashlib
import os
import re
import stat
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import urlparse

try:  # pragma: no cover - Windows has no advisory flock
    import fcntl
except ImportError:  # pragma: no cover
    fcntl = None  # type: ignore[assignment]

from . import __version__
from .evidence import (
    append_event as append_evidence_event,
    effective_evidence as project_effective_evidence,
    find_evidence_path,
    iter_captures,
    iter_events,
    load_evidence as read_evidence,
    seal_record,
)
from .ids import is_uuid7, new_id
from .schema_validation import MAX_SCHEMA_BYTES, SCHEMA_FILES, schema_errors, schema_path
from .secrets import assert_no_credentials
from .storage import (
    canonical_json_bytes,
    durable_touch,
    durable_write_bytes,
    durable_write_json,
    file_lock,
    read_bounded_regular_file,
    strict_json_loads,
)


SOURCE_RE = re.compile(r"[^a-z0-9._-]+")
RFC3339_RE = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$"
)
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
MAX_SOURCE_KIND_LENGTH = 128
MAX_URI_LENGTH = 8192
MAX_FILENAME_LENGTH = 255
MAX_EXTERNAL_ID_LENGTH = 512
MAX_SOURCE_METADATA_BYTES = 1 * 1024 * 1024
MAX_VAULT_METADATA_BYTES = 1 * 1024 * 1024
DURABLE_TOP_LEVEL = (
    "canon",
    "evidence",
    "objects",
    "quarantine",
    "policies",
    "schemas",
    "migrations",
    "runtime",
)


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def parse_time(value: str | None) -> datetime:
    if value is not None and not isinstance(value, str):
        raise TypeError("timestamp must be a string or None")
    if value is None:
        return datetime.now(timezone.utc)
    if not RFC3339_RE.fullmatch(value):
        raise ValueError("timestamp must be RFC3339 with T and an explicit UTC offset")
    normalized = value.replace("Z", "+00:00")
    parsed = datetime.fromisoformat(normalized)
    if parsed.tzinfo is None:
        raise ValueError("timestamp must include an explicit UTC offset")
    return parsed


def _reject_json_constant(value: str) -> Any:
    raise ValueError(f"non-finite JSON value {value!r} is not permitted")


def _reject_duplicate_json_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON object key: {key}")
        result[key] = value
    return result


class Vault:
    def __init__(self, root: Path | str):
        # Keep the user-supplied final path component intact so init() can
        # reject a symlink instead of resolving it to an external directory.
        supplied = Path(root).expanduser().absolute()
        if not supplied.name:
            raise ValueError("vault root must have a final path component")
        self.root = supplied.parent.resolve() / supplied.name

    @property
    def metadata_path(self) -> Path:
        return self.root / "vault.json"

    @property
    def index_path(self) -> Path:
        return self.root / "runtime" / "index.sqlite3"

    @property
    def index_dirty_path(self) -> Path:
        return self.root / "runtime" / "index.dirty"

    def init(self) -> dict[str, Any]:
        return self._init_descriptor_transaction()

    @staticmethod
    def _init_dir_flags() -> int:
        return (os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) |
                getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0))

    @contextmanager
    def _open_init_root(self):
        if self.root == self.root.parent or self.root.name in {"", ".", ".."}:
            raise ValueError("vault root must not be the filesystem root")
        parent_fd = -1
        root_fd = -1
        try:
            # The parent is canonicalized once by __init__, then held open.
            # The final component is never resolved through a path lookup.
            parent_fd = os.open(self.root.parent, self._init_dir_flags())
            if not stat.S_ISDIR(os.fstat(parent_fd).st_mode):
                raise ValueError("vault parent must be a real directory")
            try:
                status = os.stat(self.root.name, dir_fd=parent_fd, follow_symlinks=False)
                if stat.S_ISLNK(status.st_mode) or not stat.S_ISDIR(status.st_mode):
                    raise ValueError("vault root must be a real directory")
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
                raise ValueError("vault root must be a real directory")
            if not root_preexisting:
                os.fchmod(root_fd, 0o700)
                os.fsync(root_fd)
            yield parent_fd, root_fd, self.root.name
        except OSError as exc:
            raise ValueError("vault root cannot be opened safely") from exc
        finally:
            if root_fd >= 0:
                os.close(root_fd)
            if parent_fd >= 0:
                os.close(parent_fd)

    @staticmethod
    def _assert_init_identity(parent_fd: int, root_fd: int, root_name: str) -> None:
        root_status = os.fstat(root_fd)
        if not stat.S_ISDIR(root_status.st_mode):
            raise ValueError("vault root changed during initialization")
        try:
            current = os.stat(root_name, dir_fd=parent_fd, follow_symlinks=False)
        except OSError as exc:
            raise ValueError("vault root changed during initialization") from exc
        if (current.st_dev, current.st_ino) != (root_status.st_dev, root_status.st_ino):
            raise ValueError("vault root changed during initialization")

    @staticmethod
    def _reject_unknown_entries(root_fd: int) -> None:
        allowed = set(DURABLE_TOP_LEVEL) | {"vault.json"}
        unknown = sorted(name for name in os.listdir(root_fd) if name not in allowed)
        if unknown:
            raise ValueError(
                "refusing to initialize non-empty non-LifeDB directory; "
                f"unknown entries: {', '.join(unknown[:8])}"
            )

    @classmethod
    def _ensure_directory_at(cls, root_fd: int, components: tuple[str, ...]) -> None:
        current_fd = os.dup(root_fd)
        try:
            for component in components:
                if component in {"", ".", ".."}:
                    raise ValueError("vault directory contains an unsafe component")
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
            raise ValueError("vault durable component must be a real directory") from exc
        finally:
            os.close(current_fd)

    @classmethod
    def _open_parent_at(cls, root_fd: int, components: tuple[str, ...]) -> tuple[int, str]:
        if not components:
            raise ValueError("vault destination must have a filename")
        current_fd = os.dup(root_fd)
        try:
            for component in components[:-1]:
                if component in {"", ".", ".."}:
                    raise ValueError("vault destination contains an unsafe component")
                child_fd = os.open(component, cls._init_dir_flags(), dir_fd=current_fd)
                os.close(current_fd)
                current_fd = child_fd
            return current_fd, components[-1]
        except BaseException:
            os.close(current_fd)
            raise

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
                raise ValueError(f"{label} must be a regular file")
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
                raise ValueError("durable file must be a bounded regular file")
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
                raise ValueError("durable file changed during safe read")
            return payload
        except OSError as exc:
            raise ValueError("durable file cannot be read safely") from exc
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
        """Publish one init artifact below a held root descriptor.

        A hard-link into the destination directory is used as the no-replace
        commit primitive.  Unlike rename, it cannot overwrite an attacker
        supplied symlink or a concurrently-created file.
        """
        parent_fd, name = cls._open_parent_at(root_fd, components)
        temp_name = f".lifedb-init-{new_id()}.tmp"
        temp_fd = -1
        try:
            try:
                existing = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
            except FileNotFoundError:
                existing = None
            except OSError as exc:
                raise ValueError("durable init file cannot be inspected safely") from exc
            if existing is not None:
                if not stat.S_ISREG(existing.st_mode):
                    raise ValueError("durable init file must be a regular file")
                if preserve_existing:
                    return
                if compare_existing:
                    if cls._read_regular_at(root_fd, components, max_bytes=max(1, len(payload))) != payload:
                        raise ValueError("authoritative schema differs from packaged schema")
                    return
                raise ValueError("durable init file already exists")

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
                os.link(
                    temp_name,
                    name,
                    src_dir_fd=parent_fd,
                    dst_dir_fd=parent_fd,
                    follow_symlinks=False,
                )
                os.unlink(temp_name, dir_fd=parent_fd)
                os.fsync(parent_fd)
            except FileExistsError:
                # A concurrent initializer won the destination race.  It is
                # acceptable only if the winner published the same artifact.
                if temp_fd >= 0:
                    os.close(temp_fd)
                    temp_fd = -1
                try:
                    winner = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
                except OSError as exc:
                    raise ValueError("durable init file race cannot be validated") from exc
                if not stat.S_ISREG(winner.st_mode):
                    raise ValueError("durable init file must be a regular file")
                if not compare_existing or cls._read_regular_at(
                    root_fd, components, max_bytes=max(1, len(payload))
                ) != payload:
                    if not preserve_existing:
                        raise ValueError("durable init file race changed its contents")
            except OSError as exc:
                raise ValueError("durable init file could not be published safely") from exc
        finally:
            if temp_fd >= 0:
                os.close(temp_fd)
            try:
                os.unlink(temp_name, dir_fd=parent_fd)
            except FileNotFoundError:
                pass
            os.close(parent_fd)

    def _install_schemas(self, root_fd: int) -> None:
        self._ensure_directory_at(root_fd, ("schemas", "0.2"))
        for kind, filename in SCHEMA_FILES.items():
            source = schema_path(kind)
            source_bytes = read_bounded_regular_file(source, max_bytes=MAX_SCHEMA_BYTES)

            # Versioned schemas are the machine-selected copy.  Publish them
            # exclusively so an existing installation is never clobbered.
            self._publish_bytes_at(
                root_fd, ("schemas", "0.2", filename), source_bytes,
                mode=0o444, compare_existing=True,
            )

            # Keep a flat copy for people browsing a vault.  A pre-existing
            # flat file may be a legacy/stale schema and must remain untouched.
            self._publish_bytes_at(
                root_fd, ("schemas", filename), source_bytes,
                mode=0o444, preserve_existing=True,
            )

    def _install_default_policies(self, root_fd: int) -> None:
        policies = {
            "context.json": {
                "schema": "0.2",
                "budget_chars": 24000,
                "core_chars": 8000,
                "continuity_chars": 4000,
                "relevant_chars": 12000,
                "default_sensitivity_ceiling": "personal",
            },
            "retention.json": {
                "schema": "0.2",
                "grace_days": 30,
                "holds": {"evidence": [], "objects": []},
                "automatic_eviction": False,
            },
        }
        for filename, value in policies.items():
            self._publish_bytes_at(
                root_fd, ("policies", filename),
                canonical_json_bytes(value) + b"\n", mode=0o600,
                preserve_existing=True,
            )

    def _write_initial_core(self, root_fd: int, self_id: str) -> None:
        document_id = new_id()
        text = f"""---
type: Profile
title: LifeDB memory contract
description: Durable rules that every connected agent should receive.
tags: [lifedb, memory, core]
status: stable
generated:
  by: process:lifedb-init
  at: "{utc_now()}"
x-lifedb:
  schema: "0.2"
  id: {document_id}
  kind: memory-contract
  sensitivity: personal
  claims: []
---

# LifeDB memory contract

- Treat LifeDB Canon as the current semantic model, not as infallible fact.
- Preserve contradictions and uncertainty instead of forcing consistency.
- Expand Evidence when an exact historical claim matters.
- New memory must retain provenance and must remain reversible.

Vault identity: `{self_id}`
"""
        self._publish_bytes_at(
            root_fd, ("canon", "core", "lifedb.md"), text.encode("utf-8"),
            mode=0o600, preserve_existing=True,
        )

    def _read_metadata_at(self, root_fd: int) -> dict[str, Any] | None:
        if not self._exists_at(root_fd, ("vault.json",)):
            return None
        try:
            payload = self._read_regular_at(
                root_fd, ("vault.json",), max_bytes=MAX_VAULT_METADATA_BYTES
            )
        except ValueError:
            raise ValueError("vault metadata cannot be read safely") from None
        try:
            value = strict_json_loads(payload, max_bytes=MAX_VAULT_METADATA_BYTES)
        except ValueError:
            raise ValueError("vault metadata must be strict JSON") from None
        if not isinstance(value, dict):
            raise ValueError("vault metadata must be a JSON object")
        if (
            value.get("schema") != "0.2"
            or not is_uuid7(value.get("vault_id"))
            or not isinstance(value.get("created_at"), str)
        ):
            raise ValueError("vault metadata does not identify a v0.2 vault")
        try:
            parse_time(value["created_at"])
        except (TypeError, ValueError):
            raise ValueError("vault metadata created_at is invalid") from None
        return value

    def _init_descriptor_transaction(self) -> dict[str, Any]:
        """Initialize or replay the durable vault layout under held FDs.

        Every creation and publication below the final vault directory is
        descriptor-relative.  The path is checked only as an identity witness
        after the transaction, so replacing the name with a symlink cannot
        redirect writes outside the originally opened directory.
        """
        with self._open_init_root() as (parent_fd, root_fd, root_name):
            self._assert_init_identity(parent_fd, root_fd, root_name)
            self._reject_unknown_entries(root_fd)

            directories: list[tuple[str, ...]] = [
                (name,) for name in DURABLE_TOP_LEVEL
            ]
            directories.extend(
                ("canon", name)
                for name in (
                    "core", "self", "entities", "projects", "topics", "goals",
                    "decisions", "patterns", "procedures", "conflicts",
                )
            )
            directories.extend(
                ("evidence", name)
                for name in ("conversations", "activity", "web", "mail", "calendar", "git", "imports", "_events")
            )
            directories.append(("objects", "sha256"))
            directories.extend(
                ("runtime", name)
                for name in ("postgres", "lexical", "vector", "graph", "embeddings", "cache", "locks")
            )
            for components in directories:
                self._ensure_directory_at(root_fd, components)
                self._assert_init_identity(parent_fd, root_fd, root_name)

            metadata = self._read_metadata_at(root_fd)
            if metadata is None:
                metadata = {
                    "schema": "0.2",
                    "vault_id": new_id(),
                    "created_at": utc_now(),
                    "generator": f"lifedb/{__version__}",
                }
                self._publish_bytes_at(
                    root_fd, ("vault.json",),
                    canonical_json_bytes(metadata) + b"\n", mode=0o400,
                    preserve_existing=True,
                )
                # Re-read the committed bytes so a concurrent initializer and
                # the return value always agree exactly.
                metadata = self._read_metadata_at(root_fd)
                assert metadata is not None

            self._install_schemas(root_fd)
            self._install_default_policies(root_fd)
            self._publish_bytes_at(
                root_fd, ("canon", "index.md"),
                b"---\nokf_version: \"0.2\"\n---\n\n# LifeDB Canon index\n\nThis directory is the durable semantic Canon.\n",
                mode=0o600, preserve_existing=True,
            )
            self._write_initial_core(root_fd, str(metadata["vault_id"]))
            self._publish_bytes_at(
                root_fd, ("runtime", "locks", "writer.lock"),
                b"", mode=0o600, preserve_existing=True,
            )
            self._publish_bytes_at(
                root_fd, ("runtime", "index.dirty"),
                b"", mode=0o600, preserve_existing=True,
            )
            self._assert_init_identity(parent_fd, root_fd, root_name)
            return metadata

    def _require_current_metadata(self) -> dict[str, Any]:
        """Verify the vault identity before a durable ingest/event mutation."""

        try:
            metadata = strict_json_loads(
                read_bounded_regular_file(
                    self.metadata_path,
                    max_bytes=MAX_VAULT_METADATA_BYTES,
                    boundary=self.root,
                ),
                max_bytes=MAX_VAULT_METADATA_BYTES,
            )
        except (OSError, ValueError):
            raise ValueError("vault metadata cannot be validated safely") from None
        if not isinstance(metadata, dict):
            raise ValueError("vault metadata must be a JSON object")
        if metadata.get("schema") != "0.2" or not isinstance(metadata.get("vault_id"), str):
            raise ValueError("vault metadata does not identify a v0.2 vault")
        if schema_errors("vault", metadata, vault_root=self.root):
            raise ValueError("vault metadata does not match the LifeDB schema")
        return metadata

    def object_path(self, digest: str) -> Path:
        if not isinstance(digest, str) or SHA256_RE.fullmatch(digest) is None:
            raise ValueError("object digest must be exactly 64 lowercase hexadecimal characters")
        return self.root / "objects" / "sha256" / digest[:2] / digest[2:4] / digest

    def store_object(self, data: bytes) -> tuple[str, Path]:
        if not isinstance(data, (bytes, bytearray, memoryview)):
            raise TypeError("object data must be bytes-like")
        data = bytes(data)
        assert_no_credentials(data)
        digest = hashlib.sha256(data).hexdigest()
        destination = self.object_path(digest)
        try:
            durable_write_bytes(
                destination,
                data,
                exclusive=True,
                mode=0o400,
                boundary=self.root,
            )
        except FileExistsError:
            # Content-addressing makes a concurrent winner equivalent only if
            # the bytes on disk still match the address.
            try:
                existing_data = read_bounded_regular_file(
                    destination, max_bytes=max(1, len(data)), boundary=self.root
                )
            except ValueError:
                raise IOError(f"existing object does not match its digest: {digest}") from None
            if hashlib.sha256(existing_data).hexdigest() != digest:
                raise IOError(f"existing object does not match its digest: {digest}")
        return digest, destination

    def mark_index_dirty(
        self, *, reason: str = "durable-change", record_id: str | None = None
    ) -> bool:
        """Best-effort runtime invalidation marker.

        The marker is disposable projection state.  Durable capture/event
        publication has already committed by the time callers reach this
        method, so marker I/O failure must never turn a successful operation
        into an ambiguous exception or trigger compensation.
        """
        marker = f"{utc_now()}\t{reason}"
        if record_id is not None:
            marker += f"\t{record_id}"
        try:
            durable_touch(
                self.index_dirty_path,
                (marker + "\n").encode("utf-8"),
                boundary=self.root,
            )
        except Exception:
            return False
        return True

    # Short name used by transaction/event producers.  Runtime state is only a
    # projection hint, so all durable mutations may safely mark it dirty.
    mark_dirty = mark_index_dirty

    def _idempotent_capture(
        self, source: dict[str, Any], external_id: str, digest: str
    ) -> dict[str, Any] | None:
        def identity(value: dict[str, Any], key: str) -> Any:
            direct = value.get(key)
            if direct is not None:
                return direct
            metadata = value.get("metadata")
            if isinstance(metadata, dict):
                return metadata.get(key)
            return None

        for record in iter_captures(self, verify=True):
            existing_source = record.get("source")
            if not isinstance(existing_source, dict):
                continue
            same_source = all(
                (
                    identity(existing_source, key) == identity(source, key)
                    if key in {"account", "device"}
                    else existing_source.get(key) == source.get(key)
                )
                for key in ("kind", "uri", "account", "device")
            )
            if not same_source or existing_source.get("external_id") != external_id:
                continue
            existing_digest = record.get("content", {}).get("sha256")
            if existing_digest != digest:
                raise ValueError(
                    "external_id already exists for this source with different content"
                )
            return record
        return None

    def ingest(
        self,
        data: bytes,
        *,
        source_kind: str = "manual",
        source_uri: str | None = None,
        media_type: str = "application/octet-stream",
        filename: str | None = None,
        retention: str = "durable",
        sensitivity: str = "personal",
        kind: str = "artifact",
        captured_at: str | None = None,
        source_metadata: dict[str, Any] | None = None,
        external_id: str | None = None,
    ) -> dict[str, Any]:
        if not isinstance(data, (bytes, bytearray, memoryview)):
            raise TypeError("ingest data must be bytes-like")
        data = bytes(data)
        self._validate_persistent_string(
            source_kind, "source_kind", max_length=MAX_SOURCE_KIND_LENGTH
        )
        if source_uri is not None:
            self._validate_persistent_string(
                source_uri, "source_uri", max_length=MAX_URI_LENGTH
            )
        if source_metadata is not None and not isinstance(source_metadata, dict):
            raise ValueError("source_metadata must be a mapping when supplied")
        normalized_metadata: dict[str, Any] | None = None
        if source_metadata is not None:
            # Validate before hashing or publishing the raw Object.  Round
            # tripping also gives the sealed record a detached, canonical JSON
            # value and rejects NaN, infinity, cycles, and custom objects.
            try:
                metadata_bytes = canonical_json_bytes(source_metadata)
            except (TypeError, ValueError, OverflowError, RecursionError, UnicodeError):
                raise ValueError("source_metadata must be finite JSON-serializable data") from None
            if len(metadata_bytes) > MAX_SOURCE_METADATA_BYTES:
                raise ValueError(
                    f"source_metadata exceeds {MAX_SOURCE_METADATA_BYTES} UTF-8 bytes"
                )
            # Scan exactly the complete bounded representation which is
            # persisted in the capture envelope.
            assert_no_credentials(metadata_bytes)
            try:
                normalized = strict_json_loads(
                    metadata_bytes, max_bytes=MAX_SOURCE_METADATA_BYTES
                )
            except ValueError:
                raise ValueError("source_metadata must be finite JSON-serializable data") from None
            if not isinstance(normalized, dict):  # defensive; input was a dict
                raise ValueError("source_metadata must be a JSON object")
            normalized_metadata = normalized
            for identity_key in ("account", "device"):
                if identity_key in normalized_metadata:
                    value = normalized_metadata[identity_key]
                    if (
                        not isinstance(value, str)
                        or not value.strip()
                        or len(value) > 256
                        or any(ord(character) < 0x20 for character in value)
                    ):
                        raise ValueError(f"source_metadata.{identity_key} must be a non-empty string")
        self._validate_persistent_string(media_type, "media_type", max_length=255)
        if filename is not None:
            self._validate_persistent_string(
                filename, "filename", max_length=MAX_FILENAME_LENGTH
            )
        if retention not in {"pinned", "durable", "grace", "derivative-only", "reference-only"}:
            raise ValueError("invalid retention class")
        if sensitivity not in {"public", "personal", "sensitive", "restricted"}:
            raise ValueError("invalid sensitivity")
        if kind not in {"artifact", "conversation", "event-batch", "web-capture", "message", "import", "augmentation"}:
            raise ValueError("invalid evidence kind")
        if retention == "reference-only" and not source_uri:
            raise ValueError("reference-only ingestion requires source_uri")
        if source_uri is not None:
            parsed_uri = urlparse(source_uri)
            if (
                not parsed_uri.scheme
                or any(character.isspace() for character in source_uri)
                or (parsed_uri.scheme in {"http", "https"} and not parsed_uri.netloc)
                or parsed_uri.username is not None
                or parsed_uri.password is not None
            ):
                raise ValueError("source_uri must be an absolute URI without userinfo")
        if external_id is None and normalized_metadata is not None:
            candidate_external_id = normalized_metadata.get("external_id")
            if candidate_external_id is not None:
                external_id = candidate_external_id
        if external_id is not None and (
            not isinstance(external_id, str) or not external_id.strip()
        ):
            raise ValueError("external_id must be a non-empty string")
        if external_id is not None:
            self._validate_persistent_string(
                external_id, "external_id", max_length=MAX_EXTERNAL_ID_LENGTH
            )

        digest = hashlib.sha256(data).hexdigest()
        captured = parse_time(captured_at)
        captured_text = captured.isoformat().replace("+00:00", "Z")
        source: dict[str, Any] = {"kind": source_kind}
        if source_uri:
            source["uri"] = source_uri
        if normalized_metadata:
            source["metadata"] = normalized_metadata
            for identity_key in ("account", "device"):
                if identity_key in normalized_metadata:
                    # Promote source identity into the stable source envelope;
                    # _idempotent_capture also understands legacy metadata.
                    source[identity_key] = normalized_metadata[identity_key]
        if external_id is not None:
            source["external_id"] = external_id

        with file_lock(self.root / "runtime" / "locks" / "writer.lock", boundary=self.root):
            self._require_current_metadata()
            if external_id is not None:
                previous = self._idempotent_capture(source, external_id, digest)
                if previous is not None:
                    return previous

            if retention != "reference-only":
                self.store_object(data)
            evidence_id = new_id()
            payload: dict[str, Any] = {
                "state": "external" if retention == "reference-only" else "present",
                "retention": retention,
            }
            if retention != "reference-only":
                payload["object"] = f"sha256:{digest}"
            record = seal_record(
                {
                    "schema": "0.2",
                    "record_type": "capture",
                    "id": evidence_id,
                    "kind": kind,
                    "captured_at": captured_text,
                    "ingested_at": utc_now(),
                    "source": source,
                    "content": {
                        "media_type": media_type,
                        "filename": filename or "unnamed",
                        "size": len(data),
                        "sha256": digest,
                    },
                    "payload": payload,
                    "representations": [],
                    "sensitivity": sensitivity,
                    "producer": {"by": "process:lifedb-ingest", "version": __version__},
                    "sealed": True,
                }
            )
            safe_source = (
                SOURCE_RE.sub("-", source_kind.lower()).strip(".-") or "unknown"
            )
            if safe_source == "_events":
                safe_source = "source-events"
            target = (
                self.root
                / "evidence"
                / safe_source
                / f"{captured.year:04d}"
                / f"{captured.month:02d}"
                / f"{captured.day:02d}"
                / f"{evidence_id}.json"
            )
            self._write_json_exclusive(target, record)
            self.mark_index_dirty(reason="evidence-captured", record_id=evidence_id)
            return record

    def evidence_path(self, evidence_id: str) -> Path | None:
        return find_evidence_path(self, evidence_id)

    def load_evidence(self, evidence_id: str, *, verify: bool = True) -> dict[str, Any] | None:
        return read_evidence(self, evidence_id, verify=verify)

    def append_event(
        self,
        event_type: str,
        *,
        actor: str,
        data: Any | None = None,
        target: str | None = None,
        sensitivity: str = "personal",
        category: str | None = None,
        recorded_at: str | None = None,
    ) -> dict[str, Any]:
        with file_lock(
            self.root / "runtime" / "locks" / "writer.lock", boundary=self.root
        ):
            self._require_current_metadata()
            event = append_evidence_event(
                self,
                event_type,
                actor=actor,
                data=data,
                target=target,
                sensitivity=sensitivity,
                category=category,
                recorded_at=recorded_at,
            )
        self.mark_index_dirty(reason="evidence-event", record_id=event["id"])
        return event

    def events_for(
        self,
        target: str,
        *,
        event_types: Iterable[str] | None = None,
        category: str | None = None,
        verify: bool = True,
    ) -> list[dict[str, Any]]:
        return list(
            iter_events(
                self,
                target=target,
                event_types=event_types,
                category=category,
                verify=verify,
            )
        )

    def effective_evidence(
        self, evidence_id: str, *, verify: bool = True
    ) -> dict[str, Any] | None:
        return project_effective_evidence(self, evidence_id, verify=verify)

    def _write_json_exclusive(self, path: Path, value: Any) -> None:
        durable_write_json(
            path,
            value,
            exclusive=True,
            mode=0o400,
            boundary=self.root,
        )

    @staticmethod
    def _validate_persistent_string(value: Any, label: str, *, max_length: int) -> None:
        if not isinstance(value, str) or not value.strip():
            raise ValueError(f"{label} must be a non-empty string")
        if len(value) > max_length:
            raise ValueError(f"{label} exceeds the maximum length")
        if any(ord(character) < 0x20 for character in value):
            raise ValueError(f"{label} contains control characters")
        # The scanner reports detector names only; it never includes the
        # supplied string in an exception message.
        assert_no_credentials(value.encode("utf-8"))
