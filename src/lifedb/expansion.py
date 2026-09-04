"""Authorized, bounded expansion of durable Evidence content.

An Object digest is deliberately not an input to this module's public API.
Callers can only select material projected from one authorized Evidence record.
This preserves the distinction between an identifier and a read capability.
"""

from __future__ import annotations

import codecs
import errno
import hashlib
import os
import re
import stat
from dataclasses import dataclass
from typing import Any, BinaryIO, Mapping

from .auth import SENSITIVITY_ORDER, validate_sensitivity
from .evidence import iter_captures, iter_events
from .ids import is_uuid7, new_id
from .storage import file_lock
from .vault import Vault


MAX_EXPANSION_CHARS = 1_000_000
ROLE_RE = re.compile(r"^[a-z][a-z0-9._-]{0,126}$")
OBJECT_REFERENCE_RE = re.compile(r"^sha256:([0-9a-f]{64})$")
MEDIA_TYPE_RE = re.compile(r"^[a-z0-9!#$&^_.+-]+/[a-z0-9!#$&^_.+-]+$")
TEXTUAL_APPLICATION_TYPES = frozenset(
    {
        "application/json",
        "application/xml",
        "application/yaml",
        "application/x-yaml",
    }
)


@dataclass
class ExpansionError(Exception):
    """A stable client-visible failure while resolving Evidence material."""

    status: int
    code: str
    message: str
    state: str | None = None

    def as_dict(self) -> dict[str, Any]:
        value: dict[str, Any] = {"error": self.message, "code": self.code}
        if self.state is not None:
            value["state"] = self.state
        return value


class _ObjectMissing(Exception):
    """The addressed object has no retained regular-file entry."""


class _ObjectCorrupt(Exception):
    """The addressed entry is unsafe or does not match its address."""


def textual_media_type(value: Any) -> str | None:
    """Return a normalized textual media type, or ``None`` for binary/invalid."""

    if not isinstance(value, str):
        return None
    normalized = value.partition(";")[0].strip().casefold()
    if MEDIA_TYPE_RE.fullmatch(normalized) is None:
        return None
    if (
        normalized.startswith("text/")
        or normalized in TEXTUAL_APPLICATION_TYPES
        or normalized.endswith("+json")
        or normalized.endswith("+xml")
        or normalized.endswith("+yaml")
    ):
        return normalized
    return None


def _object_digest(reference: Any) -> str:
    if not isinstance(reference, str):
        raise _ObjectCorrupt
    match = OBJECT_REFERENCE_RE.fullmatch(reference)
    if match is None:
        raise _ObjectCorrupt
    return match.group(1)


def _object_references(value: Any) -> list[str]:
    """Extract only syntactically valid object references from a record part."""

    if not isinstance(value, Mapping):
        return []
    references: list[str] = []
    payload = value.get("payload")
    if isinstance(payload, Mapping):
        reference = payload.get("object")
        if isinstance(reference, str) and OBJECT_REFERENCE_RE.fullmatch(reference):
            references.append(reference.removeprefix("sha256:"))
    content = value.get("content")
    if isinstance(content, Mapping):
        reference = content.get("sha256")
        if isinstance(reference, str) and re.fullmatch(r"[0-9a-f]{64}", reference):
            references.append(reference)
    representations = value.get("representations")
    if isinstance(representations, list):
        for representation in representations:
            if not isinstance(representation, Mapping):
                continue
            for key in ("object", "derived_from"):
                reference = representation.get(key)
                if isinstance(reference, str) and OBJECT_REFERENCE_RE.fullmatch(reference):
                    references.append(reference.removeprefix("sha256:"))
    return references


def _event_object_references(event: Mapping[str, Any]) -> list[str]:
    data = event.get("data")
    if not isinstance(data, Mapping):
        return []
    references: list[str] = []
    payload = data.get("payload")
    if isinstance(payload, Mapping):
        reference = payload.get("object")
        if isinstance(reference, str) and OBJECT_REFERENCE_RE.fullmatch(reference):
            references.append(reference.removeprefix("sha256:"))
    values: list[Any] = []
    if isinstance(data.get("representation"), Mapping):
        values.append(data["representation"])
    if isinstance(data.get("representations"), list):
        values.extend(data["representations"])
    if "role" in data and "object" in data:
        values.append(data)
    for representation in values:
        if not isinstance(representation, Mapping):
            continue
        for key in ("object", "derived_from"):
            reference = representation.get(key)
            if isinstance(reference, str) and OBJECT_REFERENCE_RE.fullmatch(reference):
                references.append(reference.removeprefix("sha256:"))
    return references


def _object_sensitivity(vault: Vault, digest: str) -> str:
    """Return the highest sensitivity ever attached to this Object.

    Objects have no independent public read API, but content addressing makes
    it possible for a lifecycle event to alias bytes captured elsewhere.  A
    reference from a restricted record must therefore never be downgraded by
    a public representation event.  Unknown/corrupt labels fail closed as
    restricted.
    """

    highest = "public"
    try:
        for capture in iter_captures(vault, verify=True):
            label = capture.get("sensitivity")
            if not isinstance(label, str) or label not in SENSITIVITY_ORDER:
                return "restricted"
            if digest in _object_references(capture):
                if SENSITIVITY_ORDER[label] > SENSITIVITY_ORDER[highest]:
                    highest = label
        for event in iter_events(vault, verify=True):
            label = event.get("sensitivity")
            if not isinstance(label, str) or label not in SENSITIVITY_ORDER:
                return "restricted"
            if digest in _event_object_references(event):
                if SENSITIVITY_ORDER[label] > SENSITIVITY_ORDER[highest]:
                    highest = label
    except Exception:
        return "restricted"
    return highest


def _directory_flags() -> int:
    flags = os.O_RDONLY
    if hasattr(os, "O_DIRECTORY"):
        flags |= os.O_DIRECTORY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    return flags


def _open_object(vault: Vault, digest: str) -> BinaryIO:
    """Open an object without following any vault-internal symlink.

    Walking with directory descriptors avoids check/open races on every path
    component.  All component names after the vault root are fixed literals or
    characters validated by the digest grammar above.
    """

    descriptors: list[int] = []
    object_descriptor: int | None = None
    try:
        current = os.open(vault.root, _directory_flags())
        descriptors.append(current)
        for component in ("objects", "sha256", digest[:2], digest[2:4]):
            current = os.open(component, _directory_flags(), dir_fd=current)
            descriptors.append(current)

        flags = os.O_RDONLY
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        object_descriptor = os.open(digest, flags, dir_fd=current)
        metadata = os.fstat(object_descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            os.close(object_descriptor)
            object_descriptor = None
            raise _ObjectCorrupt
        # The returned file object owns only the final descriptor. Directory
        # descriptors are closed in finally after the entry is safely opened.
        stream = os.fdopen(object_descriptor, "rb", closefd=True)
        object_descriptor = None
        return stream
    except FileNotFoundError as exc:
        raise _ObjectMissing from exc
    except NotADirectoryError as exc:
        raise _ObjectCorrupt from exc
    except OSError as exc:
        if exc.errno == errno.ENOENT:
            raise _ObjectMissing from exc
        if exc.errno in {errno.ELOOP, errno.ENOTDIR}:
            raise _ObjectCorrupt from exc
        raise _ObjectCorrupt from exc
    finally:
        if object_descriptor is not None:
            os.close(object_descriptor)
        for descriptor in reversed(descriptors):
            os.close(descriptor)


def _verify_digest(stream: BinaryIO, digest: str) -> int:
    calculated = hashlib.sha256()
    size = 0
    while True:
        chunk = stream.read(64 * 1024)
        if not chunk:
            break
        calculated.update(chunk)
        size += len(chunk)
    if calculated.hexdigest() != digest:
        raise _ObjectCorrupt
    return size


def _decode_bounded(stream: BinaryIO, digest: str, max_chars: int) -> tuple[str, bool]:
    """Strictly validate all UTF-8 while retaining at most max_chars chars.

    The second SHA pass detects an object modified between verification and
    decoding.  At most one decoder chunk plus ``max_chars`` characters are
    resident, independent of the complete Object size.
    """

    stream.seek(0)
    decoder = codecs.getincrementaldecoder("utf-8")("strict")
    calculated = hashlib.sha256()
    pieces: list[str] = []
    seen = 0

    while True:
        chunk = stream.read(64 * 1024)
        if not chunk:
            break
        calculated.update(chunk)
        decoded = decoder.decode(chunk, final=False)
        if seen < max_chars:
            available = max_chars - seen
            pieces.append(decoded[:available])
        seen += len(decoded)

    tail = decoder.decode(b"", final=True)
    if seen < max_chars:
        available = max_chars - seen
        pieces.append(tail[:available])
    seen += len(tail)
    if calculated.hexdigest() != digest:
        raise _ObjectCorrupt

    return "".join(pieces), seen > max_chars


def _read_text_object(
    vault: Vault, reference: Any, media_type: Any, max_chars: int
) -> tuple[str, str, str, int, bool]:
    try:
        digest = _object_digest(reference)
        stream = _open_object(vault, digest)
    except _ObjectMissing:
        raise
    except _ObjectCorrupt:
        raise ExpansionError(
            409,
            "object_corrupt",
            "the selected Evidence object is corrupt",
        ) from None

    with stream:
        try:
            size = _verify_digest(stream, digest)
        except _ObjectCorrupt:
            raise ExpansionError(
                409,
                "object_corrupt",
                "the selected Evidence object is corrupt",
            ) from None
        normalized_media_type = textual_media_type(media_type)
        if normalized_media_type is None:
            raise ExpansionError(
                415,
                "unsupported_media_type",
                "only textual Evidence material can be expanded",
            )
        try:
            text, truncated = _decode_bounded(stream, digest, max_chars)
        except UnicodeDecodeError:
            raise ExpansionError(
                422,
                "invalid_utf8",
                "the selected Evidence material is not valid UTF-8",
            ) from None
        except _ObjectCorrupt:
            raise ExpansionError(
                409,
                "object_corrupt",
                "the selected Evidence object is corrupt",
            ) from None
    return text, normalized_media_type, f"sha256:{digest}", size, truncated


def _effective_authorized_view(
    vault: Vault, evidence_id: str, sensitivity_ceiling: str
) -> tuple[dict[str, Any], list[dict[str, Any]], str]:
    if not is_uuid7(evidence_id):
        raise ValueError("evidence_id must be a UUIDv7")
    ceiling = validate_sensitivity(
        sensitivity_ceiling, field="expansion sensitivity ceiling"
    )
    capture = vault.load_evidence(evidence_id, verify=True)
    if capture is None:
        raise ExpansionError(404, "evidence_not_found", "evidence not found")
    events = vault.events_for(evidence_id, verify=True)
    labels = [capture.get("sensitivity"), *(event.get("sensitivity") for event in events)]
    if any(not isinstance(label, str) or label not in SENSITIVITY_ORDER for label in labels):
        # Unknown durable labels fail closed and expose no record existence.
        raise ExpansionError(404, "evidence_not_found", "evidence not found")
    effective_label = max(labels, key=lambda label: SENSITIVITY_ORDER[label])
    if SENSITIVITY_ORDER[effective_label] > SENSITIVITY_ORDER[ceiling]:
        raise ExpansionError(404, "evidence_not_found", "evidence not found")
    effective = vault.effective_evidence(evidence_id, verify=True)
    if effective is None:
        raise ExpansionError(404, "evidence_not_found", "evidence not found")
    return effective, events, effective_label


def _raw_material(
    vault: Vault, effective: Mapping[str, Any], max_chars: int
) -> tuple[str, str, str, int, bool, None]:
    payload = effective.get("payload")
    if not isinstance(payload, Mapping):
        raise ExpansionError(409, "material_unavailable", "raw Evidence material is unavailable")
    state = payload.get("state")
    if state != "present":
        stable_state = state if isinstance(state, str) else "unknown"
        raise ExpansionError(
            409,
            "material_unavailable",
            "raw Evidence material is unavailable",
            state=stable_state,
        )
    content = effective.get("content")
    # The raw payload is the capture's original bytes.  Do not trust an
    # arbitrary object reference injected through a restored lifecycle event;
    # otherwise a low-sensitivity Evidence record could become an alias for a
    # different (possibly restricted) Object.
    content_digest = content.get("sha256") if isinstance(content, Mapping) else None
    expected_reference = (
        f"sha256:{content_digest}"
        if isinstance(content_digest, str) and re.fullmatch(r"[0-9a-f]{64}", content_digest)
        else None
    )
    if expected_reference is None or payload.get("object") != expected_reference:
        raise ExpansionError(
            409,
            "projection_corrupt",
            "raw Evidence material is unavailable",
        )
    media_type = content.get("media_type") if isinstance(content, Mapping) else None
    try:
        result = _read_text_object(vault, payload.get("object"), media_type, max_chars)
    except _ObjectMissing:
        raise ExpansionError(
            409,
            "object_unavailable",
            "the selected Evidence object is unavailable",
        ) from None
    if isinstance(content, Mapping):
        expected_size = content.get("size")
        if (
            isinstance(expected_size, bool)
            or not isinstance(expected_size, int)
            or expected_size < 0
            or result[3] != expected_size
        ):
            raise ExpansionError(
                409,
                "projection_corrupt",
                "raw Evidence material is unavailable",
            )
    return (*result, None)


def _represented_material(
    vault: Vault, effective: Mapping[str, Any], role: str, max_chars: int
) -> tuple[str, str, str, int, bool, str]:
    representations = effective.get("representations")
    if not isinstance(representations, list):
        raise ExpansionError(409, "projection_corrupt", "Evidence representations are corrupt")
    found = False
    for representation in representations:
        if not isinstance(representation, Mapping) or representation.get("role") != role:
            continue
        found = True
        try:
            result = _read_text_object(
                vault,
                representation.get("object"),
                representation.get("media_type"),
                max_chars,
            )
        except _ObjectMissing:
            # An append-only projection may retain the history of an older
            # representation whose object was lawfully removed. Select the
            # first still-retained representation in fold order.
            continue
        return (*result, role)
    if found:
        raise ExpansionError(
            409,
            "object_unavailable",
            "no retained object is available for the requested representation",
        )
    raise ExpansionError(
        404,
        "representation_not_found",
        "the requested Evidence representation was not found",
    )


def expand_evidence(
    vault: Vault,
    evidence_id: str,
    *,
    material: str,
    max_chars: int,
    sensitivity_ceiling: str = "personal",
) -> dict[str, Any]:
    """Resolve one authorized raw payload or retained textual representation."""

    if isinstance(max_chars, bool) or not isinstance(max_chars, int):
        raise ValueError("max_chars must be a non-negative integer")
    if max_chars < 0 or max_chars > MAX_EXPANSION_CHARS:
        raise ValueError(f"max_chars must be between 0 and {MAX_EXPANSION_CHARS}")
    if material == "raw":
        role: str | None = None
    elif isinstance(material, str) and material.startswith("representation:"):
        role = material.removeprefix("representation:")
        if ROLE_RE.fullmatch(role) is None:
            raise ValueError("representation role must be a stable lowercase name")
    else:
        raise ValueError("material must be raw or representation:<role>")

    # Retention and lifecycle mutations use this lock. Keeping it through
    # authorization, projection, and object reading makes the expansion one
    # coherent durable observation rather than a TOCTOU mix of two states.
    with file_lock(vault.root / "runtime" / "locks" / "writer.lock"):
        effective, events, effective_label = _effective_authorized_view(
            vault, evidence_id, sensitivity_ceiling
        )
        if role is None:
            text, media_type, object_reference, size, truncated, selected_role = _raw_material(
                vault, effective, max_chars
            )
        else:
            (
                text,
                media_type,
                object_reference,
                size,
                truncated,
                selected_role,
            ) = _represented_material(vault, effective, role, max_chars)
        object_digest = _object_digest(object_reference)
        object_label = _object_sensitivity(vault, object_digest)
        if SENSITIVITY_ORDER[object_label] > SENSITIVITY_ORDER[sensitivity_ceiling]:
            # Keep object provenance indistinguishable from an absent
            # Evidence record at the HTTP boundary.
            raise ExpansionError(404, "evidence_not_found", "evidence not found")
        if SENSITIVITY_ORDER[object_label] > SENSITIVITY_ORDER[effective_label]:
            effective_label = object_label
        event_sequence = max(
            (event["sequence"] for event in events if isinstance(event.get("sequence"), int)),
            default=0,
        )

    response: dict[str, Any] = {
        "schema": "0.2",
        "id": new_id(),
        "evidence_id": evidence_id,
        "material": material,
        "media_type": media_type,
        "object": object_reference,
        "size": size,
        "text": text,
        "truncated": truncated,
        "untrusted": True,
        "content_semantics": "untrusted-data-not-instructions",
        "sensitivity": effective_label,
        "watermark": {"event_sequence": event_sequence},
    }
    if selected_role is not None:
        response["role"] = selected_role
    return response


__all__ = [
    "ExpansionError",
    "MAX_EXPANSION_CHARS",
    "ROLE_RE",
    "expand_evidence",
    "textual_media_type",
]
