from __future__ import annotations

from . import __version__
from ._json_types import JSONMapping
from .ids import is_uuid7, new_id
from .schema_validation import MAX_SCHEMA_BYTES, SCHEMA_FILES, schema_errors, schema_path
from .storage import canonical_json_bytes, read_bounded_regular_file, strict_json_loads
from .vault_constants import DURABLE_TOP_LEVEL, MAX_VAULT_METADATA_BYTES
from .vault_safe_io import VaultSafeIOMixin
from .vault_time import parse_time, utc_now
from ._vault_errors import VaultValueError
from ._vault_protocols import VaultCollaborator


class VaultBootstrapMixin(VaultSafeIOMixin):
    def _install_schemas(self: VaultCollaborator, root_fd: int) -> None:
        self._ensure_directory_at(root_fd, ("schemas", "0.2"))
        for kind, filename in SCHEMA_FILES.items():
            source = schema_path(kind)
            source_bytes = read_bounded_regular_file(source, max_bytes=MAX_SCHEMA_BYTES)
            self._publish_bytes_at(
                root_fd, ("schemas", "0.2", filename), source_bytes,
                mode=0o444, compare_existing=True,
            )
            self._publish_bytes_at(
                root_fd, ("schemas", filename), source_bytes,
                mode=0o444, preserve_existing=True,
            )

    def _install_default_policies(self: VaultCollaborator, root_fd: int) -> None:
        policies = {
            "context.json": {
                "schema": "0.2", "budget_chars": 24000, "core_chars": 8000,
                "continuity_chars": 4000, "relevant_chars": 12000,
                "default_sensitivity_ceiling": "personal",
            },
            "retention.json": {
                "schema": "0.2", "grace_days": 30,
                "holds": {"evidence": [], "objects": []},
                "automatic_eviction": False,
            },
        }
        for filename, value in policies.items():
            self._publish_bytes_at(
                root_fd, ("policies", filename), canonical_json_bytes(value) + b"\n",
                mode=0o600, preserve_existing=True,
            )

    def _write_initial_core(self: VaultCollaborator, root_fd: int, self_id: str) -> None:
        document_id = new_id()
        text = (
            "---\n"
            "type: Profile\n"
            "title: LifeDB memory contract\n"
            "description: Durable rules that every connected agent should receive.\n"
            "tags: [lifedb, memory, core]\n"
            "status: stable\n"
            "generated:\n"
            "  by: process:lifedb-init\n"
            f'  at: "{utc_now()}"\n'
            "x-lifedb:\n"
            "  schema: \"0.2\"\n"
            f"  id: {document_id}\n"
            "  kind: memory-contract\n"
            "  sensitivity: personal\n"
            "  claims: []\n"
            "---\n\n"
            "# LifeDB memory contract\n\n"
            "- Treat LifeDB Canon as the current semantic model, not as infallible fact.\n"
            "- Preserve contradictions and uncertainty instead of forcing consistency.\n"
            "- Expand Evidence when an exact historical claim matters.\n"
            "- New memory must retain provenance and must remain reversible.\n\n"
            f"Vault identity: `{self_id}`\n"
        )
        self._publish_bytes_at(
            root_fd, ("canon", "core", "lifedb.md"), text.encode("utf-8"),
            mode=0o600, preserve_existing=True,
        )

    def _read_metadata_at(self: VaultCollaborator, root_fd: int) -> JSONMapping | None:
        if not self._exists_at(root_fd, ("vault.json",)):
            return None
        try:
            payload = self._read_regular_at(
                root_fd, ("vault.json",), max_bytes=MAX_VAULT_METADATA_BYTES
            )
        except ValueError:
            raise VaultValueError("vault metadata cannot be read safely") from None
        try:
            value = strict_json_loads(payload, max_bytes=MAX_VAULT_METADATA_BYTES)
        except ValueError:
            raise VaultValueError("vault metadata must be strict JSON") from None
        if not isinstance(value, dict):
            raise VaultValueError("vault metadata must be a JSON object")
        if (
            value.get("schema") != "0.2"
            or not is_uuid7(value.get("vault_id"))
            or not isinstance(value.get("created_at"), str)
        ):
            raise VaultValueError("vault metadata does not identify a v0.2 vault")
        created_at = value.get("created_at")
        if not isinstance(created_at, str):
            raise VaultValueError("vault metadata created_at is invalid")
        try:
            parse_time(created_at)
        except (TypeError, ValueError):
            raise VaultValueError("vault metadata created_at is invalid") from None
        return value

    def _init_descriptor_transaction(self: VaultCollaborator) -> JSONMapping:
        with self._open_init_root() as (parent_fd, root_fd, root_name):
            self._assert_init_identity(parent_fd, root_fd, root_name)
            self._reject_unknown_entries(root_fd)
            directories: list[tuple[str, ...]] = [(name,) for name in DURABLE_TOP_LEVEL]
            directories.extend(
                ("canon", name) for name in (
                    "core", "self", "entities", "projects", "topics", "goals",
                    "decisions", "patterns", "procedures", "conflicts",
                )
            )
            directories.extend(
                ("evidence", name) for name in (
                    "conversations", "activity", "web", "mail", "calendar", "git",
                    "imports", "_events",
                )
            )
            directories.append(("objects", "sha256"))
            directories.extend(
                ("runtime", name) for name in (
                    "postgres", "lexical", "vector", "graph", "embeddings", "cache", "locks",
                )
            )
            for components in directories:
                self._ensure_directory_at(root_fd, components)
                self._assert_init_identity(parent_fd, root_fd, root_name)
            metadata = self._read_metadata_at(root_fd)
            if metadata is None:
                metadata = {
                    "schema": "0.2", "vault_id": new_id(), "created_at": utc_now(),
                    "generator": f"lifedb/{__version__}",
                }
                self._publish_bytes_at(
                    root_fd, ("vault.json",), canonical_json_bytes(metadata) + b"\n",
                    mode=0o400, preserve_existing=True,
                )
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
                root_fd, ("runtime", "locks", "writer.lock"), b"",
                mode=0o600, preserve_existing=True,
            )
            self._publish_bytes_at(
                root_fd, ("runtime", "index.dirty"), b"",
                mode=0o600, preserve_existing=True,
            )
            self._assert_init_identity(parent_fd, root_fd, root_name)
            return metadata

    def _require_current_metadata(self: VaultCollaborator) -> JSONMapping:
        try:
            metadata = strict_json_loads(
                read_bounded_regular_file(
                    self.root / "vault.json", max_bytes=MAX_VAULT_METADATA_BYTES, boundary=self.root,
                ), max_bytes=MAX_VAULT_METADATA_BYTES,
            )
        except (OSError, ValueError):
            raise VaultValueError("vault metadata cannot be validated safely") from None
        if not isinstance(metadata, dict):
            raise VaultValueError("vault metadata must be a JSON object")
        if metadata.get("schema") != "0.2" or not isinstance(metadata.get("vault_id"), str):
            raise VaultValueError("vault metadata does not identify a v0.2 vault")
        if schema_errors("vault", metadata, vault_root=self.root):
            raise VaultValueError("vault metadata does not match the LifeDB schema")
        return metadata
