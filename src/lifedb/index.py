from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import sqlite3
from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import Any

from .evidence import iter_capture_paths, iter_events, read_capture
from .ids import is_uuid7
from .markdown import MarkdownDocument, canon_documents
from .objectio import ObjectReadError, read_object_prefix
from .storage import file_lock, fsync_directory
from .vault import Vault, utc_now


INDEX_SCHEMA = "0.2"
MAX_QUERY_CHARS = 4096
MAX_SEARCH_LIMIT = 100
# Indexing intentionally caps each retained text object. Structured capture
# metadata is still indexed when a raw object exceeds this bound.
MAX_TEXT_OBJECT_BYTES = 8 * 1024 * 1024
TOKEN_RE = re.compile(r"[\w.-]+", re.UNICODE)
CJK_RE = re.compile(r"[\u3040-\u30ff\u3400-\u4dbf\u4e00-\u9fff\uf900-\ufaff]")
SENSITIVITY_ORDER = {"public": 0, "personal": 1, "sensitive": 2, "restricted": 3}
TEXTUAL_APPLICATION_TYPES = {
    "application/json",
    "application/xml",
    "application/yaml",
    "application/x-yaml",
}
CLAIM_OBJECT_KEYS = ("ref", "text", "boolean", "number", "date", "datetime", "uri", "json")
LIFECYCLE_EVENT_TYPES = {
    "representation-added",
    "representation.added",
    "retention.changed",
    "retention-changed",
    "payload-evicted",
    "payload.evicted",
    "payload-restored",
    "payload.restored",
    "payload-redacted",
    "payload.redacted",
    "payload-missing-observed",
    "payload.missing-observed",
}


def _bigrams(text: str) -> set[str]:
    normalized = "".join(character.casefold() for character in text[:200_000] if character.isalnum())
    if len(normalized) < 2:
        return {normalized} if normalized else set()
    return {normalized[index : index + 2] for index in range(len(normalized) - 1)}


def _plain_title(record: Mapping[str, Any], fallback: str) -> str:
    content = record.get("content")
    filename = content.get("filename") if isinstance(content, Mapping) else None
    return filename if isinstance(filename, str) and filename else fallback


def _textual_media_type(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    media_type = value.partition(";")[0].strip().casefold()
    return (
        media_type.startswith("text/")
        or media_type in TEXTUAL_APPLICATION_TYPES
        or media_type.endswith("+json")
        or media_type.endswith("+xml")
        or media_type.endswith("+yaml")
    )


def _object_digest(reference: Any) -> str | None:
    if not isinstance(reference, str) or not reference.startswith("sha256:"):
        return None
    digest = reference.removeprefix("sha256:")
    return digest if len(digest) == 64 else None


def _read_text_object(vault: Vault, reference: Any) -> str:
    digest = _object_digest(reference)
    if digest is None:
        return ""
    try:
        raw, _, truncated = read_object_prefix(
            vault.root, digest, retain_bytes=MAX_TEXT_OBJECT_BYTES
        )
        try:
            return raw.decode("utf-8", errors="strict")
        except UnicodeDecodeError as exc:
            if (
                not truncated
                or exc.reason != "unexpected end of data"
                or exc.end != len(raw)
                or len(raw) - exc.start > 4
            ):
                return ""
            # The retained prefix may end in an incomplete code point.
            return raw[:exc.start].decode("utf-8", errors="strict")
    except (ObjectReadError, UnicodeDecodeError):
        return ""


def _json_text(value: Any) -> str:
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
    except (TypeError, ValueError):
        # Validation reports unsupported durable values separately. Indexing
        # remains useful for forward-compatible Markdown fields.
        return str(value)


def _normalized_sensitivity(value: Any, *, fallback: str = "personal") -> str:
    if value is None:
        return fallback if isinstance(fallback, str) and fallback in SENSITIVITY_ORDER else "unknown"
    if isinstance(value, str) and value in SENSITIVITY_ORDER:
        return value
    # Fail closed: unknown durable labels are never exposed by any valid
    # sensitivity ceiling.  This sentinel is deliberately outside the policy
    # vocabulary and therefore outside every SQL allow-list.
    return "unknown"


def _maximum_sensitivity(values: Iterable[str]) -> str:
    values = tuple(values)
    if any(not isinstance(value, str) or value not in SENSITIVITY_ORDER for value in values):
        return "unknown"
    return max(values, key=SENSITIVITY_ORDER.__getitem__, default="personal")


def _claim_object_parts(value: Any) -> tuple[str, str, str]:
    if not isinstance(value, Mapping):
        return "unknown", _json_text(value), _json_text(value)
    object_json = _json_text(dict(value))
    object_type = next((key for key in CLAIM_OBJECT_KEYS if key in value), "unknown")
    item = value.get(object_type) if object_type != "unknown" else value
    if object_type == "boolean" and isinstance(item, bool):
        object_value = "true" if item else "false"
    elif object_type == "json":
        object_value = _json_text(item)
    else:
        object_value = str(item)
    if object_type == "number" and isinstance(value.get("unit"), str):
        object_value = f"{object_value} {value['unit']}"
    return object_type, object_value, object_json


def _claims(extension: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    values = extension.get("claims", [])
    if not isinstance(values, list):
        return []
    return [value for value in values if isinstance(value, Mapping)]


def _claim_evidence_sensitivities(vault: Vault, claim: Mapping[str, Any]) -> list[str]:
    references = claim.get("evidence")
    if not isinstance(references, list) or not references:
        return ["unknown"]
    sensitivities: list[str] = []
    for reference in references:
        evidence_id = (
            reference
            if isinstance(reference, str)
            else reference.get("id")
            if isinstance(reference, Mapping)
            else None
        )
        if not isinstance(evidence_id, str) or not evidence_id:
            sensitivities.append("unknown")
            continue
        try:
            record = vault.effective_evidence(evidence_id, verify=True)
        except Exception:
            record = None
        if record is None:
            sensitivities.append("unknown")
        else:
            sensitivities.append(_effective_evidence_sensitivity(vault, record))
    return sensitivities


def _effective_document_sensitivity(
    vault: Vault, extension: Mapping[str, Any]
) -> str:
    values = [_normalized_sensitivity(extension.get("sensitivity"))]
    raw_claims = extension.get("claims")
    if raw_claims is not None and not isinstance(raw_claims, list):
        values.append("unknown")
        raw_claims = []
    for raw_claim in raw_claims or []:
        if not isinstance(raw_claim, Mapping):
            values.append("unknown")
            continue
        claim = raw_claim
        if claim.get("sensitivity") is not None:
            values.append(_normalized_sensitivity(claim.get("sensitivity")))
        values.extend(_claim_evidence_sensitivities(vault, claim))
    return _maximum_sensitivity(values)


def _canon_search_body(document: MarkdownDocument, claims: list[Mapping[str, Any]]) -> str:
    frontmatter = document.frontmatter
    parts = [document.body]
    description = frontmatter.get("description")
    if isinstance(description, str) and description:
        parts.append(description)
    tags = frontmatter.get("tags")
    if isinstance(tags, list):
        parts.append(" ".join(str(tag) for tag in tags))
    for claim in claims:
        # Superseded and retracted Claims remain in the graph for provenance,
        # but are no longer part of the current searchable view.
        state = claim.get("state", "unknown")
        if state not in {"active", "disputed"}:
            continue
        _, object_value, object_json = _claim_object_parts(claim.get("object"))
        parts.append(f"[claim state={state}]")
        parts.extend(
            value
            for value in (
                claim.get("predicate"),
                claim.get("statement"),
                object_value,
                object_json,
            )
            if isinstance(value, str) and value
        )
    return "\n".join(parts)


def _canon_evidence_handles(vault: Vault, path: str, ceiling: str) -> list[str]:
    """Return authorized Evidence IDs cited by active/disputed Canon claims."""
    return _canon_evidence_handles_map(vault, {path}, ceiling).get(path, [])


def _canon_evidence_handles_map(
    vault: Vault, paths: set[str], ceiling: str
) -> dict[str, list[str]]:
    """Build Canon handle lists in one bounded document walk."""
    maximum = SENSITIVITY_ORDER[ceiling]
    result: dict[str, list[str]] = {}
    for document in canon_documents(vault.root / "canon"):
        path = document.path.relative_to(vault.root).as_posix()
        if path not in paths:
            continue
        extension = document.frontmatter.get("x-lifedb")
        claims = extension.get("claims", []) if isinstance(extension, Mapping) else []
        handles: list[str] = []
        for claim in claims if isinstance(claims, list) else []:
            if not isinstance(claim, Mapping) or claim.get("state") not in {"active", "disputed"}:
                continue
            references = claim.get("evidence")
            if not isinstance(references, list):
                continue
            for reference in references:
                evidence_id = reference if isinstance(reference, str) else reference.get("id") if isinstance(reference, Mapping) else None
                if not is_uuid7(evidence_id) or evidence_id in handles:
                    continue
                try:
                    record = vault.effective_evidence(evidence_id, verify=True)
                    sensitivity = _effective_evidence_sensitivity(vault, record) if record is not None else "unknown"
                except Exception:
                    continue
                if sensitivity in SENSITIVITY_ORDER and SENSITIVITY_ORDER[sensitivity] <= maximum:
                    handles.append(evidence_id)
        result[path] = handles
    return result


def _evidence_search_body(vault: Vault, record: Mapping[str, Any]) -> str:
    metadata = {
        key: record.get(key)
        for key in (
            "schema",
            "record_type",
            "id",
            "kind",
            "captured_at",
            "ingested_at",
            "source",
            "content",
            "payload",
            "representations",
            "sensitivity",
            "producer",
        )
        if key in record
    }
    parts: list[str] = []
    payload = record.get("payload")
    content = record.get("content")
    if isinstance(payload, Mapping) and isinstance(content, Mapping):
        if payload.get("state") == "present" and _textual_media_type(content.get("media_type")):
            raw_text = _read_text_object(vault, payload.get("object"))
            if raw_text:
                parts.extend(("[raw]", raw_text))

    representations = record.get("representations")
    if isinstance(representations, list):
        for representation in representations:
            if not isinstance(representation, Mapping) or not _textual_media_type(
                representation.get("media_type")
            ):
                continue
            represented_text = _read_text_object(vault, representation.get("object"))
            if represented_text:
                role = representation.get("role", "text")
                parts.extend((f"[representation:{role}]", represented_text))
    # Metadata remains searchable even when raw bytes were never retained.
    parts.append(_json_text(metadata))
    return "\n".join(parts)


def _capture_object_references(record: Mapping[str, Any]) -> set[str]:
    references: set[str] = set()
    content = record.get("content")
    if isinstance(content, Mapping):
        digest = content.get("sha256")
        if isinstance(digest, str) and re.fullmatch(r"[0-9a-f]{64}", digest):
            references.add(digest)
    payload = record.get("payload")
    if isinstance(payload, Mapping):
        digest = _object_digest(payload.get("object"))
        if digest is not None and re.fullmatch(r"[0-9a-f]{64}", digest):
            references.add(digest)
    representations = record.get("representations")
    if isinstance(representations, list):
        for representation in representations:
            if not isinstance(representation, Mapping):
                continue
            for field in ("object", "derived_from"):
                digest = _object_digest(representation.get(field))
                if digest is not None and re.fullmatch(r"[0-9a-f]{64}", digest):
                    references.add(digest)
    return references


def _event_object_references(event: Mapping[str, Any]) -> set[str]:
    data = event.get("data")
    if not isinstance(data, Mapping):
        return set()
    values: list[Mapping[str, Any]] = []
    payload = data.get("payload")
    if isinstance(payload, Mapping):
        values.append(payload)
    representation = data.get("representation")
    if isinstance(representation, Mapping):
        values.append(representation)
    representations = data.get("representations")
    if isinstance(representations, list):
        values.extend(item for item in representations if isinstance(item, Mapping))
    if "object" in data:
        values.append(data)
    references: set[str] = set()
    for value in values:
        for field in ("object", "derived_from"):
            digest = _object_digest(value.get(field))
            if digest is not None and re.fullmatch(r"[0-9a-f]{64}", digest):
                references.add(digest)
    return references


def _representation_object_references(record: Mapping[str, Any]) -> set[str]:
    references: set[str] = set()
    representations = record.get("representations")
    for representation in representations if isinstance(representations, list) else []:
        if not isinstance(representation, Mapping):
            continue
        for field in ("object", "derived_from"):
            digest = _object_digest(representation.get(field))
            if digest is not None and re.fullmatch(r"[0-9a-f]{64}", digest):
                references.add(digest)
    return references


def _effective_object_sensitivity(vault: Vault, digest: str) -> str:
    """Return the highest label ever attached to an addressed Object."""
    if re.fullmatch(r"[0-9a-f]{64}", digest) is None:
        return "unknown"
    highest = "public"
    try:
        for path in iter_capture_paths(vault):
            capture = read_capture(path, verify=True)
            if digest not in _capture_object_references(capture):
                continue
            label = capture.get("sensitivity")
            if not isinstance(label, str) or label not in SENSITIVITY_ORDER:
                return "unknown"
            if SENSITIVITY_ORDER[label] > SENSITIVITY_ORDER[highest]:
                highest = label
        for event in iter_events(vault, verify=True):
            if digest not in _event_object_references(event):
                continue
            label = event.get("sensitivity")
            if not isinstance(label, str) or label not in SENSITIVITY_ORDER:
                return "unknown"
            if SENSITIVITY_ORDER[label] > SENSITIVITY_ORDER[highest]:
                highest = label
    except Exception:
        return "unknown"
    return highest


def effective_evidence_sensitivity(vault: Vault, record: Mapping[str, Any]) -> str:
    """Resolve all target-event and addressed-Object sensitivity floors."""
    values = [_normalized_sensitivity(record.get("sensitivity"))]
    evidence_id = record.get("id")
    if isinstance(evidence_id, str):
        events = vault.events_for(evidence_id, verify=True)
        values.extend(_normalized_sensitivity(event.get("sensitivity")) for event in events)
        for digest in _representation_object_references(record):
            values.append(_effective_object_sensitivity(vault, digest))
        for event in events:
            for digest in _event_object_references(event):
                values.append(_effective_object_sensitivity(vault, digest))
    return _maximum_sensitivity(values)


_effective_evidence_sensitivity = effective_evidence_sensitivity


def _source_directory_flags() -> int:
    return (
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )


def _open_source_child(parent: int, name: str) -> int:
    """Open a durable source directory relative to a held directory FD."""
    descriptor = -1
    try:
        descriptor = os.open(name, _source_directory_flags(), dir_fd=parent)
        opened = os.fstat(descriptor)
        current = os.stat(name, dir_fd=parent, follow_symlinks=False)
    except OSError as exc:
        if descriptor >= 0:
            os.close(descriptor)
        raise OSError("durable source directory changed while being read") from exc
    if not stat.S_ISDIR(opened.st_mode) or (opened.st_dev, opened.st_ino) != (
        current.st_dev,
        current.st_ino,
    ):
        os.close(descriptor)
        raise OSError("durable source directory changed while being read")
    return descriptor


def _fingerprint_source_tree(
    digest: Any,
    directory: int,
    relative: str,
    *,
    kind: str,
    suffix: str | None,
    excluded_names: frozenset[str] = frozenset(),
) -> None:
    """Hash a source tree while every traversal component remains FD-rooted.

    A pathname walk can be redirected to an unrelated directory between its
    ``lstat`` and ``open`` calls.  This walker holds each directory descriptor,
    uses ``O_NOFOLLOW`` for every child, and compares the opened inode with the
    directory-entry identity observed immediately before opening it.
    """
    try:
        with os.scandir(directory) as iterator:
            entries = sorted(iterator, key=lambda entry: entry.name)
    except OSError as exc:
        raise OSError("durable source tree cannot be inspected safely") from exc
    for entry in entries:
        name = entry.name
        descriptor = -1
        try:
            before = os.stat(name, dir_fd=directory, follow_symlinks=False)
        except OSError as exc:
            raise OSError("durable source tree changed while being read") from exc
        child_relative = f"{relative}/{name}"
        if stat.S_ISDIR(before.st_mode):
            child = _open_source_child(directory, name)
            try:
                _fingerprint_source_tree(
                    digest,
                    child,
                    child_relative,
                    kind=kind,
                    suffix=suffix,
                    excluded_names=excluded_names,
                )
            finally:
                os.close(child)
            continue
        if not stat.S_ISREG(before.st_mode):
            raise OSError("durable source tree contains an unsafe file")
        if name in excluded_names or (suffix is not None and not name.endswith(suffix)):
            continue
        try:
            descriptor = os.open(
                name,
                os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=directory,
            )
            opened = os.fstat(descriptor)
            if (opened.st_dev, opened.st_ino, opened.st_size) != (
                before.st_dev,
                before.st_ino,
                before.st_size,
            ):
                raise OSError("durable source changed while opening")
            digest.update(kind.encode("ascii") + b"\0" + child_relative.encode("utf-8") + b"\0")
            if kind == "content":
                while chunk := os.read(descriptor, 1024 * 1024):
                    digest.update(chunk)
            else:
                digest.update(str(before.st_size).encode("ascii"))
                digest.update(b"\0")
                digest.update(str(before.st_mtime_ns).encode("ascii"))
            after = os.fstat(descriptor)
            if (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns) != (
                opened.st_dev,
                opened.st_ino,
                opened.st_size,
                opened.st_mtime_ns,
                opened.st_ctime_ns,
            ):
                raise OSError("durable source changed while being read")
        except OSError as exc:
            if "durable source" in str(exc):
                raise
            raise OSError("durable source file cannot be read safely") from exc
        finally:
            if descriptor >= 0:
                os.close(descriptor)
        digest.update(b"\0")


def _source_fingerprint(vault: Vault) -> str:
    """Fingerprint durable inputs without pathname-raceable source walks."""

    digest = hashlib.sha256(b"lifedb-index-sources-v0.2\0")
    root_flags = _source_directory_flags()
    try:
        root_fd = os.open(vault.root, root_flags)
    except FileNotFoundError:
        raise OSError("durable vault root cannot be inspected") from None
    try:
        root_status = os.fstat(root_fd)
        path_status = os.lstat(vault.root)
        if not stat.S_ISDIR(root_status.st_mode) or (root_status.st_dev, root_status.st_ino) != (
            path_status.st_dev,
            path_status.st_ino,
        ):
            raise OSError("durable vault root changed while being read")
        for name, relative, suffix, excluded in (
            ("canon", "canon", ".md", frozenset({"index.md", "log.md"})),
            ("evidence", "evidence", ".json", frozenset()),
            ("objects", "objects/sha256", None, frozenset()),
        ):
            try:
                parent = root_fd
                if name == "objects":
                    objects_fd = _open_source_child(root_fd, "objects")
                    try:
                        source_fd = _open_source_child(objects_fd, "sha256")
                    finally:
                        os.close(objects_fd)
                else:
                    source_fd = _open_source_child(parent, name)
            except FileNotFoundError:
                continue
            try:
                _fingerprint_source_tree(
                    digest,
                    source_fd,
                    relative,
                    kind="object" if name == "objects" else "content",
                    suffix=suffix,
                    excluded_names=excluded,
                )
            finally:
                os.close(source_fd)
        final_status = os.lstat(vault.root)
        if (final_status.st_dev, final_status.st_ino) != (root_status.st_dev, root_status.st_ino):
            raise OSError("durable vault root changed while being read")
    finally:
        os.close(root_fd)
    return digest.hexdigest()


def _durable_sequence(vault: Vault) -> int:
    return max((event["sequence"] for event in iter_events(vault, verify=True)), default=0)


# SQLite's public Python API opens a database by pathname.  Passing the
# runtime pathname to sqlite3.connect would re-resolve it after a hostile
# runtime rename/symlink swap.  Pin the database to an already-open descriptor
# through procfs and use descriptor-relative reads/writes for the durable
# runtime boundary.
_RUNTIME_IDENTITY_FIELDS = ("st_dev", "st_ino")
_RUNTIME_ENTRY_IDENTITY_FIELDS = (
    "st_dev",
    "st_ino",
    "st_size",
    "st_mtime_ns",
    "st_ctime_ns",
)


def _directory_flags() -> int:
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    return flags


def _open_runtime(vault: Vault) -> tuple[int, os.stat_result, os.stat_result]:
    """Open vault/runtime without following any path component.

    The returned runtime descriptor is the authority for every runtime entry
    operation.  Path and descriptor identities are compared immediately so a
    parent swap is rejected before any runtime I/O occurs.
    """
    root = Path(os.path.abspath(vault.root))
    root_fd = os.open(root, _directory_flags())
    try:
        root_status = os.fstat(root_fd)
        root_path_status = os.lstat(root)
        if (root_status.st_dev, root_status.st_ino) != (
            root_path_status.st_dev,
            root_path_status.st_ino,
        ) or not stat.S_ISDIR(root_status.st_mode):
            raise OSError("vault root changed during safe open")
        runtime_fd = os.open("runtime", _directory_flags(), dir_fd=root_fd)
    except BaseException:
        os.close(root_fd)
        raise
    os.close(root_fd)
    try:
        runtime_status = os.fstat(runtime_fd)
        runtime_path_status = os.lstat(root / "runtime")
        if not stat.S_ISDIR(runtime_status.st_mode) or stat.S_ISLNK(runtime_path_status.st_mode):
            raise OSError("runtime must be a real directory")
        if (runtime_status.st_dev, runtime_status.st_ino) != (
            runtime_path_status.st_dev,
            runtime_path_status.st_ino,
        ):
            raise OSError("runtime changed during safe open")
        return runtime_fd, runtime_status, runtime_path_status
    except BaseException:
        os.close(runtime_fd)
        raise


def _assert_runtime_identity(vault: Vault, runtime_status: os.stat_result) -> None:
    """Fail closed if the named runtime is no longer our opened directory."""
    try:
        path_status = os.lstat(os.path.abspath(vault.root) + os.sep + "runtime")
    except OSError as exc:
        raise OSError("runtime changed during safe operation") from exc
    if stat.S_ISLNK(path_status.st_mode) or not stat.S_ISDIR(path_status.st_mode):
        raise OSError("runtime must be a real directory")
    if any(
        getattr(path_status, field) != getattr(runtime_status, field)
        for field in _RUNTIME_IDENTITY_FIELDS
    ):
        raise OSError("runtime changed during safe operation")


def _runtime_entry(
    runtime_fd: int, name: str, *, regular: bool = True
) -> os.stat_result | None:
    try:
        status = os.stat(name, dir_fd=runtime_fd, follow_symlinks=False)
    except FileNotFoundError:
        return None
    if regular and (stat.S_ISLNK(status.st_mode) or not stat.S_ISREG(status.st_mode)):
        raise OSError(f"runtime entry {name} must be a regular non-symlink file")
    return status


def _descriptor_sqlite_uri(descriptor: int, *, writable: bool) -> str:
    """Return a descriptor-pinned SQLite URI on supported hosts.

    `/proc/self/fd/N` is a kernel-provided handle to the already-open inode;
    unlike the vault pathname it cannot be redirected by replacing runtime.
    Refuse rather than silently falling back to a path-resolved database on
    platforms without this primitive.
    """
    if os.name != "posix" or not os.path.isdir("/proc/self/fd"):
        raise OSError("descriptor-pinned SQLite is unavailable on this platform")
    mode = "rwc" if writable else "ro"
    immutable = "" if writable else "&immutable=1"
    return f"file:/proc/self/fd/{descriptor}?mode={mode}{immutable}"


def _open_index_connection(
    vault: Vault, *, writable: bool
) -> tuple[sqlite3.Connection, int, int, os.stat_result]:
    """Open index SQLite against an already-verified file descriptor.

    The runtime and index descriptors stay open for the entire SQLite
    connection lifetime.  Callers must close the connection first, then both
    returned descriptors.
    """
    runtime_fd, runtime_status, _ = _open_runtime(vault)
    index_fd = -1
    try:
        index_status = _runtime_entry(runtime_fd, "index.sqlite3")
        if index_status is None:
            raise FileNotFoundError("index.sqlite3")
        index_fd = os.open(
            "index.sqlite3",
            (os.O_RDWR if writable else os.O_RDONLY)
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=runtime_fd,
        )
        opened = os.fstat(index_fd)
        if any(
            getattr(opened, field) != getattr(index_status, field)
            for field in _RUNTIME_ENTRY_IDENTITY_FIELDS
        ):
            raise OSError("runtime index changed during safe open")
        _assert_runtime_identity(vault, runtime_status)
        connection = sqlite3.connect(_descriptor_sqlite_uri(index_fd, writable=writable), uri=True)
        try:
            after = _runtime_entry(runtime_fd, "index.sqlite3")
            if after is None or any(
                getattr(after, field) != getattr(opened, field)
                for field in _RUNTIME_ENTRY_IDENTITY_FIELDS
            ):
                raise OSError("runtime index changed during safe open")
            _assert_runtime_identity(vault, runtime_status)
        except BaseException:
            connection.close()
            raise
        return connection, runtime_fd, index_fd, runtime_status
    except BaseException:
        if index_fd >= 0:
            os.close(index_fd)
        os.close(runtime_fd)
        raise


def _open_index_temp(vault: Vault, runtime_fd: int, runtime_status: os.stat_result) -> tuple[int, str]:
    """Create a private SQLite temp file relative to the verified runtime."""
    _assert_runtime_identity(vault, runtime_status)
    for _ in range(32):
        name = f".index.sqlite3.tmp-{os.urandom(12).hex()}"
        try:
            descriptor = os.open(
                name,
                os.O_RDWR | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0),
                0o600,
                dir_fd=runtime_fd,
            )
            return descriptor, name
        except FileExistsError:
            continue
    raise OSError("could not allocate a private runtime index")


def _publish_runtime_temp(
    vault: Vault,
    runtime_fd: int,
    runtime_status: os.stat_result,
    temporary_name: str,
    name: str,
    *,
    expected: os.stat_result | None,
) -> None:
    """Publish an SQLite temp file using the verified runtime descriptor."""
    _assert_runtime_identity(vault, runtime_status)
    current = _runtime_entry(runtime_fd, name)
    if expected is None:
        if current is not None:
            raise OSError("runtime destination appeared during safe publish")
    elif current is None or any(
        getattr(current, field) != getattr(expected, field)
        for field in _RUNTIME_ENTRY_IDENTITY_FIELDS
    ):
        raise OSError("runtime destination changed during safe publish")
    os.replace(
        temporary_name,
        name,
        src_dir_fd=runtime_fd,
        dst_dir_fd=runtime_fd,
    )
    fsync_directory(runtime_fd)
    published = _runtime_entry(runtime_fd, name)
    if published is None or stat.S_ISLNK(published.st_mode):
        raise OSError("runtime destination is not safely published")
    _assert_runtime_identity(vault, runtime_status)


def _create_schema(connection: sqlite3.Connection) -> None:
    connection.executescript(
        """
        PRAGMA journal_mode=DELETE;
        PRAGMA synchronous=FULL;
        CREATE TABLE metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL);
        CREATE VIRTUAL TABLE documents USING fts5(
            source_kind UNINDEXED,
            source_id UNINDEXED,
            title,
            body,
            path UNINDEXED,
            sensitivity UNINDEXED,
            tokenize='unicode61'
        );
        CREATE TABLE ngrams (
            document_rowid INTEGER NOT NULL,
            gram TEXT NOT NULL,
            PRIMARY KEY(document_rowid, gram)
        ) WITHOUT ROWID;
        CREATE INDEX ngrams_by_gram ON ngrams(gram);
        CREATE TABLE concepts (
            id TEXT PRIMARY KEY,
            path TEXT NOT NULL UNIQUE,
            type TEXT NOT NULL,
            kind TEXT NOT NULL,
            title TEXT NOT NULL,
            description TEXT NOT NULL,
            tags_json TEXT NOT NULL,
            status TEXT NOT NULL,
            sensitivity TEXT NOT NULL
        );
        CREATE TABLE claims (
            id TEXT PRIMARY KEY,
            concept_id TEXT NOT NULL,
            subject TEXT NOT NULL,
            predicate TEXT NOT NULL,
            object_type TEXT NOT NULL,
            object_value TEXT NOT NULL,
            object_json TEXT NOT NULL,
            statement TEXT NOT NULL,
            basis TEXT NOT NULL,
            certainty TEXT NOT NULL,
            state TEXT NOT NULL,
            observed_at TEXT NOT NULL,
            valid_from TEXT,
            valid_until TEXT,
            sensitivity TEXT NOT NULL
        );
        CREATE INDEX claims_by_concept ON claims(concept_id);
        CREATE INDEX claims_by_subject_predicate ON claims(subject, predicate);
        CREATE TABLE claim_evidence (
            claim_id TEXT NOT NULL,
            evidence_id TEXT NOT NULL,
            requirement TEXT NOT NULL,
            PRIMARY KEY(claim_id, evidence_id, requirement)
        ) WITHOUT ROWID;
        CREATE INDEX claim_evidence_by_evidence ON claim_evidence(evidence_id);
        CREATE TABLE claim_edges (
            claim_id TEXT NOT NULL,
            edge_type TEXT NOT NULL,
            target_id TEXT NOT NULL,
            target_kind TEXT NOT NULL,
            PRIMARY KEY(claim_id, edge_type, target_id, target_kind)
        ) WITHOUT ROWID;
        CREATE INDEX claim_edges_by_target ON claim_edges(target_kind, target_id);
        """
    )


def _insert_ngrams(connection: sqlite3.Connection, rowid: int, text: str) -> None:
    connection.executemany(
        "INSERT INTO ngrams(document_rowid, gram) VALUES (?, ?)",
        ((rowid, gram) for gram in _bigrams(text)),
    )


def _insert_claim_graph(
    connection: sqlite3.Connection,
    *,
    vault: Vault,
    concept_id: str,
    document_sensitivity: str,
    claim: Mapping[str, Any],
) -> None:
    claim_id = str(claim.get("id", ""))
    if not claim_id:
        return
    object_type, object_value, object_json = _claim_object_parts(claim.get("object"))
    claim_sensitivity = _maximum_sensitivity(
        (
            document_sensitivity,
            _normalized_sensitivity(claim.get("sensitivity"), fallback=document_sensitivity),
            *_claim_evidence_sensitivities(vault, claim),
        )
    )
    validity = claim.get("valid")
    valid_from = validity.get("from") if isinstance(validity, Mapping) else None
    valid_until = validity.get("until") if isinstance(validity, Mapping) else None
    connection.execute(
        "INSERT INTO claims("
        "id, concept_id, subject, predicate, object_type, object_value, object_json, "
        "statement, basis, certainty, state, observed_at, valid_from, valid_until, sensitivity"
        ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            claim_id,
            concept_id,
            str(claim.get("subject", "")),
            str(claim.get("predicate", "")),
            object_type,
            object_value,
            object_json,
            str(claim.get("statement", "")),
            str(claim.get("basis", "")),
            str(claim.get("certainty", "")),
            str(claim.get("state", "")),
            str(claim.get("observed_at", "")),
            str(valid_from) if valid_from is not None else None,
            str(valid_until) if valid_until is not None else None,
            claim_sensitivity,
        ),
    )
    evidence = claim.get("evidence")
    if isinstance(evidence, list):
        for item in evidence:
            if isinstance(item, str):
                evidence_id, requirement = item, "raw"
            elif isinstance(item, Mapping):
                evidence_id = item.get("id")
                requirement = item.get("requires")
            else:
                continue
            if isinstance(evidence_id, str) and isinstance(requirement, str):
                connection.execute(
                    "INSERT OR IGNORE INTO claim_evidence(claim_id, evidence_id, requirement) "
                    "VALUES (?, ?, ?)",
                    (claim_id, evidence_id, requirement),
                )
    if object_type == "ref":
        connection.execute(
            "INSERT OR IGNORE INTO claim_edges(claim_id, edge_type, target_id, target_kind) "
            "VALUES (?, 'object-ref', ?, 'concept')",
            (claim_id, object_value),
        )
    for field in ("supersedes", "superseded_by"):
        targets = claim.get(field)
        if not isinstance(targets, list):
            continue
        connection.executemany(
            "INSERT OR IGNORE INTO claim_edges(claim_id, edge_type, target_id, target_kind) "
            "VALUES (?, ?, ?, 'claim')",
            ((claim_id, field, target) for target in targets if isinstance(target, str) and target),
        )


def _index_canon(connection: sqlite3.Connection, vault: Vault, counts: dict[str, int]) -> None:
    seen_concept_ids: set[str] = set()
    for document in canon_documents(vault.root / "canon"):
        frontmatter = document.frontmatter
        extension_value = frontmatter.get("x-lifedb")
        extension = extension_value if isinstance(extension_value, Mapping) else {}
        concept_id = extension.get("id")
        # Malformed/manual documents are left for validation but cannot create
        # an invalid or ambiguous searchable row.
        if not is_uuid7(concept_id) or concept_id in seen_concept_ids:
            continue
        seen_concept_ids.add(concept_id)
        claims = _claims(extension)
        document_sensitivity = _normalized_sensitivity(extension.get("sensitivity"))
        effective_sensitivity = _effective_document_sensitivity(vault, extension)
        relative_path = document.path.relative_to(vault.root).as_posix()
        concept_id = str(concept_id)
        title = str(frontmatter.get("title", document.path.stem))
        description = str(frontmatter.get("description", ""))
        tags = frontmatter.get("tags", [])
        tags_json = _json_text(tags if isinstance(tags, list) else [])
        searchable_body = _canon_search_body(document, claims)
        cursor = connection.execute(
            "INSERT INTO documents(source_kind, source_id, title, body, path, sensitivity) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            ("canon", concept_id, title, searchable_body, relative_path, effective_sensitivity),
        )
        _insert_ngrams(connection, int(cursor.lastrowid), f"{title}\n{searchable_body}")
        connection.execute(
            "INSERT INTO concepts(id, path, type, kind, title, description, tags_json, status, sensitivity) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                concept_id,
                relative_path,
                str(frontmatter.get("type", "")),
                str(extension.get("kind", "")),
                title,
                description,
                tags_json,
                str(frontmatter.get("status", "")),
                effective_sensitivity,
            ),
        )
        for claim in claims:
            _insert_claim_graph(
                connection,
                vault=vault,
                concept_id=concept_id,
                document_sensitivity=document_sensitivity,
                claim=claim,
            )
            counts["claims"] += 1
        counts["canon"] += 1


def _index_evidence(connection: sqlite3.Connection, vault: Vault, counts: dict[str, int]) -> None:
    for path in iter_capture_paths(vault):
        capture = read_capture(path, verify=True)
        record = vault.effective_evidence(capture["id"], verify=True)
        if record is None:
            continue
        title = _plain_title(record, path.stem)
        searchable_body = _evidence_search_body(vault, record)
        sensitivity = _effective_evidence_sensitivity(vault, record)
        cursor = connection.execute(
            "INSERT INTO documents(source_kind, source_id, title, body, path, sensitivity) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (
                "evidence",
                str(record.get("id", "")),
                title,
                searchable_body,
                path.relative_to(vault.root).as_posix(),
                sensitivity,
            ),
        )
        _insert_ngrams(connection, int(cursor.lastrowid), f"{title}\n{searchable_body}")
        counts["evidence"] += 1


def rebuild_index(vault: Vault) -> dict[str, Any]:
    runtime = vault.root / "runtime"
    # Runtime is created by Vault.init.  Do not create it through a path here:
    # a missing or swapped runtime is a safety failure, not a new destination.
    with file_lock(runtime / "locks" / "writer.lock", boundary=vault.root):
        runtime_fd, runtime_status, _ = _open_runtime(vault)
        try:
            expected_index = _runtime_entry(runtime_fd, "index.sqlite3")
            _runtime_entry(runtime_fd, "index.dirty")
            counts = {"canon": 0, "evidence": 0, "claims": 0}
            built_at = utc_now()
            source_fingerprint = _source_fingerprint(vault)
            durable_sequence = _durable_sequence(vault)
            temporary_fd, temporary_name = _open_index_temp(vault, runtime_fd, runtime_status)
            try:
                connection = sqlite3.connect(
                    _descriptor_sqlite_uri(temporary_fd, writable=True), uri=True
                )
                try:
                    _assert_runtime_identity(vault, runtime_status)
                    _create_schema(connection)
                    _index_canon(connection, vault, counts)
                    _index_evidence(connection, vault, counts)
                    if _source_fingerprint(vault) != source_fingerprint:
                        raise RuntimeError("durable sources changed during index rebuild")
                    connection.executemany(
                        "INSERT INTO metadata(key, value) VALUES (?, ?)",
                        [
                            ("schema", INDEX_SCHEMA),
                            ("built_at", built_at),
                            ("durable_sequence", str(durable_sequence)),
                            ("indexed_sequence", str(durable_sequence)),
                            ("source_fingerprint", source_fingerprint),
                            ("canon_count", str(counts["canon"])),
                            ("evidence_count", str(counts["evidence"])),
                            ("claim_count", str(counts["claims"])),
                        ],
                    )
                    connection.commit()
                    check = connection.execute("PRAGMA integrity_check").fetchone()[0]
                    if check != "ok":
                        raise RuntimeError(f"SQLite integrity check failed: {check}")
                    _assert_runtime_identity(vault, runtime_status)
                finally:
                    connection.close()
                os.fsync(temporary_fd)
                _publish_runtime_temp(
                    vault,
                    runtime_fd,
                    runtime_status,
                    temporary_name,
                    "index.sqlite3",
                    expected=expected_index,
                )
            finally:
                os.close(temporary_fd)
                try:
                    os.unlink(temporary_name, dir_fd=runtime_fd)
                except FileNotFoundError:
                    pass
            marker = _runtime_entry(runtime_fd, "index.dirty")
            if marker is not None:
                _assert_runtime_identity(vault, runtime_status)
                current_marker = _runtime_entry(runtime_fd, "index.dirty")
                if current_marker is None or any(
                    getattr(current_marker, field) != getattr(marker, field)
                    for field in _RUNTIME_ENTRY_IDENTITY_FIELDS
                ):
                    raise OSError("runtime dirty marker changed during safe publish")
                os.unlink("index.dirty", dir_fd=runtime_fd)
                fsync_directory(runtime_fd)
                _assert_runtime_identity(vault, runtime_status)
        finally:
            os.close(runtime_fd)
    return {
        "built_at": built_at,
        **counts,
        "durable_sequence": durable_sequence,
        "indexed_sequence": durable_sequence,
        "source_fingerprint": source_fingerprint,
        "index": str(vault.index_path),
    }


def _read_index_metadata(vault: Vault) -> dict[str, str]:
    try:
        connection, runtime_fd, index_fd, runtime_status = _open_index_connection(
            vault, writable=False
        )
        try:
            rows = connection.execute("SELECT key, value FROM metadata").fetchall()
        finally:
            connection.close()
            os.close(index_fd)
            os.close(runtime_fd)
    except (OSError, sqlite3.Error, ValueError):
        return {}
    return {str(key): str(value) for key, value in rows if isinstance(key, str)}


def index_watermark(vault: Vault) -> dict[str, Any]:
    durable_sequence = _durable_sequence(vault)
    metadata = _read_index_metadata(vault)
    try:
        indexed_sequence = int(metadata.get("indexed_sequence", "0"))
        if indexed_sequence < 0:
            raise ValueError
    except ValueError:
        indexed_sequence = 0
    try:
        recorded_durable_sequence = int(metadata.get("durable_sequence", "-1"))
    except ValueError:
        recorded_durable_sequence = -1
    runtime_safe = False
    marker_present = False
    index_present = False
    try:
        runtime_fd, runtime_status, _ = _open_runtime(vault)
        try:
            marker_present = _runtime_entry(runtime_fd, "index.dirty") is not None
            index_present = _runtime_entry(runtime_fd, "index.sqlite3") is not None
            _assert_runtime_identity(vault, runtime_status)
            runtime_safe = True
        finally:
            os.close(runtime_fd)
    except OSError:
        # A missing/swapped runtime is itself a dirty projection.  Crucially,
        # no Path.exists()/is_file() call is made here, so an external marker
        # cannot be consulted through a replaced runtime pathname.
        runtime_safe = False
    dirty = (
        not runtime_safe
        or marker_present
        or not index_present
        or metadata.get("schema") != INDEX_SCHEMA
        or recorded_durable_sequence != indexed_sequence
        or indexed_sequence != durable_sequence
    )
    if not dirty:
        try:
            dirty = metadata.get("source_fingerprint") != _source_fingerprint(vault)
        except OSError:
            dirty = True
    return {
        "durable_sequence": durable_sequence,
        "indexed_sequence": indexed_sequence,
        "dirty": bool(dirty),
    }


def _fts_query(query: str) -> str:
    terms = TOKEN_RE.findall(query)
    escaped = [f'"{term.replace(chr(34), chr(34) * 2)}"' for term in terms[:32]]
    return " OR ".join(escaped)


def _validate_search(query: Any, limit: Any, sensitivity_ceiling: Any) -> tuple[str, int, str]:
    if not isinstance(query, str):
        raise ValueError("query must be a string")
    normalized_query = query.strip()
    if not normalized_query:
        raise ValueError("query must be a non-empty string")
    if len(normalized_query) > MAX_QUERY_CHARS:
        raise ValueError(f"query must be at most {MAX_QUERY_CHARS} characters")
    if "\x00" in normalized_query:
        raise ValueError("query must not contain NUL characters")
    if isinstance(limit, bool) or not isinstance(limit, int):
        raise ValueError("limit must be an integer")
    if not 1 <= limit <= MAX_SEARCH_LIMIT:
        raise ValueError(f"limit must be between 1 and {MAX_SEARCH_LIMIT}")
    if not isinstance(sensitivity_ceiling, str) or sensitivity_ceiling not in SENSITIVITY_ORDER:
        raise ValueError("unknown sensitivity ceiling")
    return normalized_query, limit, sensitivity_ceiling


def _search_locked(
    vault: Vault,
    query: str,
    *,
    limit: int = 10,
    sensitivity_ceiling: str = "personal",
) -> list[dict[str, Any]]:
    if index_watermark(vault)["dirty"]:
        rebuild_index(vault)
    ceiling = SENSITIVITY_ORDER[sensitivity_ceiling]
    allowed_sensitivities = tuple(
        label for label, rank in SENSITIVITY_ORDER.items() if rank <= ceiling
    )
    sensitivity_placeholders = ",".join("?" for _ in allowed_sensitivities)
    fetch_limit = min(MAX_SEARCH_LIMIT * 4, max(limit * 4, limit))
    connection, runtime_fd, index_fd, runtime_status = _open_index_connection(
        vault, writable=False
    )
    connection.row_factory = sqlite3.Row
    try:
        rows: list[sqlite3.Row] = []
        fts_query = _fts_query(query)
        if fts_query:
            rows.extend(
                connection.execute(
                    "SELECT source_kind, source_id, title, "
                    "snippet(documents, 3, '[', ']', ' … ', 32) AS snippet, "
                    "path, sensitivity, bm25(documents, 2.0, 1.0) AS rank "
                    f"FROM documents WHERE documents MATCH ? AND sensitivity IN ({sensitivity_placeholders}) "
                    "ORDER BY rank LIMIT ?",
                    (fts_query, *allowed_sensitivities, fetch_limit),
                ).fetchall()
            )
        seen = {(row["source_kind"], row["source_id"], row["path"]) for row in rows}
        if len(rows) < fetch_limit:
            like_query = (
                "%"
                + query.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
                + "%"
            )
            fallback = connection.execute(
                "SELECT source_kind, source_id, title, "
                "substr(body, 1, 320) AS snippet, path, sensitivity, 0.0 AS rank "
                f"FROM documents WHERE sensitivity IN ({sensitivity_placeholders}) "
                "AND (title LIKE ? ESCAPE '\\' OR body LIKE ? ESCAPE '\\') LIMIT ?",
                (*allowed_sensitivities, like_query, like_query, fetch_limit),
            ).fetchall()
            for row in fallback:
                key = (row["source_kind"], row["source_id"], row["path"])
                if key not in seen:
                    rows.append(row)
                    seen.add(key)
        # FTS5 unicode61 does not segment Japanese consistently.  Keep the
        # approximate bigram path scoped to CJK queries; applying it to Latin
        # text creates surprising matches on ordinary metadata field names.
        query_grams = sorted(_bigrams(query)) if CJK_RE.search(query) else []
        if query_grams:
            minimum_gram_matches = max(1, (len(query_grams) + 1) // 2)
            gram_placeholders = ",".join("?" for _ in query_grams)
            ngram_rows = connection.execute(
                "SELECT d.source_kind, d.source_id, d.title, "
                "substr(d.body, 1, 320) AS snippet, d.path, d.sensitivity, "
                "CAST(count(*) AS REAL) / ? AS rank "
                "FROM ngrams n JOIN documents d ON d.rowid = n.document_rowid "
                f"WHERE d.sensitivity IN ({sensitivity_placeholders}) "
                f"AND n.gram IN ({gram_placeholders}) "
                "GROUP BY n.document_rowid HAVING count(*) >= ? "
                "ORDER BY count(*) DESC LIMIT ?",
                (
                    len(query_grams),
                    *allowed_sensitivities,
                    *query_grams,
                    minimum_gram_matches,
                    fetch_limit,
                ),
            ).fetchall()
            for row in ngram_rows:
                key = (row["source_kind"], row["source_id"], row["path"])
                if key not in seen:
                    rows.append(row)
                    seen.add(key)
    finally:
        connection.close()
        os.close(index_fd)
        os.close(runtime_fd)
    canon_paths = {
        str(row["path"]) for row in rows[:limit] if row["source_kind"] == "canon"
    }
    canon_handles = _canon_evidence_handles_map(vault, canon_paths, sensitivity_ceiling)
    results = [
        {
            "source_kind": row["source_kind"],
            "source_id": row["source_id"],
            "title": row["title"],
            "snippet": row["snippet"],
            "path": row["path"],
            "sensitivity": row["sensitivity"],
            "score": abs(float(row["rank"])),
            "untrusted": True,
            "evidence_handles": (
                canon_handles.get(str(row["path"]), [])
                if row["source_kind"] == "canon" else []
            ),
        }
        for row in rows[:limit]
    ]
    return results


def search(
    vault: Vault,
    query: str,
    *,
    limit: int = 10,
    sensitivity_ceiling: str = "personal",
) -> list[dict[str, Any]]:
    """Search one coherent durable snapshot under the writer boundary."""
    query, limit, sensitivity_ceiling = _validate_search(query, limit, sensitivity_ceiling)
    with file_lock(
        vault.root / "runtime" / "locks" / "writer.lock", boundary=vault.root
    ):
        return _search_locked(
            vault,
            query,
            limit=limit,
            sensitivity_ceiling=sensitivity_ceiling,
        )
