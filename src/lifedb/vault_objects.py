from __future__ import annotations

import hashlib
from pathlib import Path
from .secrets import assert_no_credentials
from .storage import durable_write_bytes, durable_write_json, read_bounded_regular_file
from .vault_constants import SHA256_RE
from ._json_types import JSONMapping
from ._vault_errors import VaultTypeError, VaultValueError
from ._vault_protocols import VaultCollaborator


class VaultObjectsMixin:
    def object_path(self: VaultCollaborator, digest: str) -> Path:
        if not isinstance(digest, str) or SHA256_RE.fullmatch(digest) is None:
            raise VaultValueError("object digest must be exactly 64 lowercase hexadecimal characters")
        return self.root / "objects" / "sha256" / digest[:2] / digest[2:4] / digest

    def store_object(self: VaultCollaborator, data: bytes) -> tuple[str, Path]:
        if not isinstance(data, (bytes, bytearray, memoryview)):
            raise VaultTypeError("object data must be bytes-like")
        data = bytes(data)
        assert_no_credentials(data)
        digest = hashlib.sha256(data).hexdigest()
        destination = self.object_path(digest)
        try:
            durable_write_bytes(destination, data, exclusive=True, mode=0o400, boundary=self.root)
        except FileExistsError:
            try:
                existing_data = read_bounded_regular_file(
                    destination, max_bytes=max(1, len(data)), boundary=self.root
                )
            except ValueError:
                raise IOError(f"existing object does not match its digest: {digest}") from None
            if hashlib.sha256(existing_data).hexdigest() != digest:
                raise IOError(f"existing object does not match its digest: {digest}")
        return digest, destination

    def _write_json_exclusive(self: VaultCollaborator, path: Path, value: JSONMapping) -> None:
        durable_write_json(path, value, exclusive=True, mode=0o400, boundary=self.root)

    @staticmethod
    def _validate_persistent_string(value: str, label: str, *, max_length: int) -> None:
        if not isinstance(value, str) or not value.strip():
            raise VaultValueError(f"{label} must be a non-empty string")
        if len(value) > max_length:
            raise VaultValueError(f"{label} exceeds the maximum length")
        if any(ord(character) < 0x20 for character in value):
            raise VaultValueError(f"{label} contains control characters")
        assert_no_credentials(value.encode("utf-8"))
