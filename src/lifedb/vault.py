from __future__ import annotations

from pathlib import Path
from ._json_types import JSONMapping

from .storage import durable_touch
from .vault_bootstrap import VaultBootstrapMixin
from .vault_constants import (
    DURABLE_TOP_LEVEL,
    MAX_EXTERNAL_ID_LENGTH,
    MAX_FILENAME_LENGTH,
    MAX_SOURCE_KIND_LENGTH,
    MAX_SOURCE_METADATA_BYTES,
    MAX_URI_LENGTH,
    MAX_VAULT_METADATA_BYTES,
    RFC3339_RE,
    SHA256_RE,
    SOURCE_RE,
)
from .vault_evidence import VaultEvidenceMixin
from .vault_ingest import ExternalIDConflictError, VaultIngestMixin
from .vault_json_compat import _reject_duplicate_json_keys, _reject_json_constant
from .vault_objects import VaultObjectsMixin
from .vault_time import parse_time, utc_now
from ._vault_errors import VaultValueError


class Vault(VaultBootstrapMixin, VaultObjectsMixin, VaultIngestMixin, VaultEvidenceMixin):
    root: Path

    def __init__(self, root: Path | str):
        supplied = Path(root).expanduser().absolute()
        if not supplied.name:
            raise VaultValueError("vault root must have a final path component")
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

    def init(self) -> JSONMapping:
        return self._init_descriptor_transaction()

    def mark_index_dirty(self, *, reason: str = "durable-change", record_id: str | None = None) -> bool:
        marker = f"{utc_now()}\t{reason}"
        if record_id is not None:
            marker += f"\t{record_id}"
        try:
            durable_touch(
                self.index_dirty_path,
                (marker + "\n").encode("utf-8"),
                boundary=self.root,
            )
        except (OSError, ValueError):
            return False
        return True

    mark_dirty = mark_index_dirty


__all__ = [
    "DURABLE_TOP_LEVEL",
    "ExternalIDConflictError",
    "MAX_EXTERNAL_ID_LENGTH",
    "MAX_FILENAME_LENGTH",
    "MAX_SOURCE_KIND_LENGTH",
    "MAX_SOURCE_METADATA_BYTES",
    "MAX_URI_LENGTH",
    "MAX_VAULT_METADATA_BYTES",
    "RFC3339_RE",
    "SHA256_RE",
    "SOURCE_RE",
    "Vault",
    "parse_time",
    "utc_now",
]
