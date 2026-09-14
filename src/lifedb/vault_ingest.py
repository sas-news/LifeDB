from __future__ import annotations

import hashlib
from collections.abc import Mapping
from urllib.parse import urlparse

from . import __version__
from .evidence import iter_captures, seal_record
from .ids import new_id
from .secrets import assert_no_credentials
from .storage import canonical_json_bytes, file_lock, strict_json_loads
from .vault_constants import (
    MAX_EXTERNAL_ID_LENGTH, MAX_FILENAME_LENGTH, MAX_SOURCE_KIND_LENGTH,
    MAX_SOURCE_METADATA_BYTES, MAX_URI_LENGTH, SOURCE_RE,
)
from .vault_time import parse_time, utc_now
from ._json_types import JSONMapping, JSONValue
from ._vault_errors import VaultTypeError, VaultValueError
from ._vault_protocols import VaultCollaborator


class ExternalIDConflictError(ValueError):
    """Same source identity already captured different content."""


class VaultIngestMixin:
    def _idempotent_capture(
        self: VaultCollaborator, source: JSONMapping, external_id: str, digest: str
    ) -> JSONMapping | None:
        def identity(value: Mapping[str, JSONValue], key: str) -> JSONValue | None:
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
            existing_content = record.get("content")
            existing_digest = (
                existing_content.get("sha256") if isinstance(existing_content, dict) else None
            )
            if existing_digest != digest:
                raise ExternalIDConflictError(
                    "external_id already exists for this source with different content"
                )
            return record
        return None

    def ingest(
        self: VaultCollaborator,
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
        source_metadata: Mapping[str, JSONValue] | None = None,
        external_id: str | None = None,
    ) -> JSONMapping:
        if not isinstance(data, (bytes, bytearray, memoryview)):
            raise VaultTypeError("ingest data must be bytes-like")
        data = bytes(data)
        self._validate_persistent_string(source_kind, "source_kind", max_length=MAX_SOURCE_KIND_LENGTH)
        if source_uri is not None:
            self._validate_persistent_string(source_uri, "source_uri", max_length=MAX_URI_LENGTH)
        if source_metadata is not None and not isinstance(source_metadata, Mapping):
            raise VaultValueError("source_metadata must be a mapping when supplied")
        normalized_metadata: JSONMapping | None = None
        if source_metadata is not None:
            try:
                metadata_bytes = canonical_json_bytes(source_metadata)
            except (TypeError, ValueError, OverflowError, RecursionError, UnicodeError):
                raise VaultValueError("source_metadata must be finite JSON-serializable data") from None
            if len(metadata_bytes) > MAX_SOURCE_METADATA_BYTES:
                raise VaultValueError(f"source_metadata exceeds {MAX_SOURCE_METADATA_BYTES} UTF-8 bytes")
            assert_no_credentials(metadata_bytes)
            try:
                normalized = strict_json_loads(metadata_bytes, max_bytes=MAX_SOURCE_METADATA_BYTES)
            except ValueError:
                raise VaultValueError("source_metadata must be finite JSON-serializable data") from None
            if not isinstance(normalized, dict):
                raise VaultValueError("source_metadata must be a JSON object")
            normalized_metadata = normalized
            for identity_key in ("account", "device"):
                if identity_key in normalized_metadata:
                    value = normalized_metadata[identity_key]
                    if (
                        not isinstance(value, str) or not value.strip() or len(value) > 256
                        or any(ord(character) < 0x20 for character in value)
                    ):
                        raise VaultValueError(f"source_metadata.{identity_key} must be a non-empty string")
        self._validate_persistent_string(media_type, "media_type", max_length=255)
        if filename is not None:
            self._validate_persistent_string(filename, "filename", max_length=MAX_FILENAME_LENGTH)
        if retention not in {"pinned", "durable", "grace", "derivative-only", "reference-only"}:
            raise VaultValueError("invalid retention class")
        if sensitivity not in {"public", "personal", "sensitive", "restricted"}:
            raise VaultValueError("invalid sensitivity")
        if kind not in {"artifact", "conversation", "event-batch", "web-capture", "message", "import", "augmentation"}:
            raise VaultValueError("invalid evidence kind")
        if retention == "reference-only" and not source_uri:
            raise VaultValueError("reference-only ingestion requires source_uri")
        if source_uri is not None:
            parsed_uri = urlparse(source_uri)
            if (
                not parsed_uri.scheme or any(character.isspace() for character in source_uri)
                or (parsed_uri.scheme in {"http", "https"} and not parsed_uri.netloc)
                or parsed_uri.username is not None or parsed_uri.password is not None
            ):
                raise VaultValueError("source_uri must be an absolute URI without userinfo")
        if external_id is None and normalized_metadata is not None:
            candidate_external_id = normalized_metadata.get("external_id")
            if candidate_external_id is not None:
                if not isinstance(candidate_external_id, str):
                    raise VaultValueError("external_id must be a non-empty string")
                external_id = candidate_external_id
        if external_id is not None and (not isinstance(external_id, str) or not external_id.strip()):
            raise VaultValueError("external_id must be a non-empty string")
        if external_id is not None:
            self._validate_persistent_string(external_id, "external_id", max_length=MAX_EXTERNAL_ID_LENGTH)
        digest = hashlib.sha256(data).hexdigest()
        captured = parse_time(captured_at)
        captured_text = captured.isoformat().replace("+00:00", "Z")
        source: JSONMapping = {"kind": source_kind}
        if source_uri:
            source["uri"] = source_uri
        if normalized_metadata:
            source["metadata"] = normalized_metadata
            for identity_key in ("account", "device"):
                if identity_key in normalized_metadata:
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
            payload: JSONMapping = {
                "state": "external" if retention == "reference-only" else "present",
                "retention": retention,
            }
            if retention != "reference-only":
                payload["object"] = f"sha256:{digest}"
            record = seal_record({
                "schema": "0.2", "record_type": "capture", "id": evidence_id,
                "kind": kind, "captured_at": captured_text, "ingested_at": utc_now(),
                "source": source,
                "content": {"media_type": media_type, "filename": filename or "unnamed", "size": len(data), "sha256": digest},
                "payload": payload, "representations": [], "sensitivity": sensitivity,
                "producer": {"by": "process:lifedb-ingest", "version": __version__}, "sealed": True,
            })
            safe_source = SOURCE_RE.sub("-", source_kind.lower()).strip(".-") or "unknown"
            if safe_source == "_events":
                safe_source = "source-events"
            target = self.root / "evidence" / safe_source / f"{captured.year:04d}" / f"{captured.month:02d}" / f"{captured.day:02d}" / f"{evidence_id}.json"
            self._write_json_exclusive(target, record)
            self.mark_index_dirty(reason="evidence-captured", record_id=evidence_id)
            return record
