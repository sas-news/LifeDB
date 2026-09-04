from __future__ import annotations

import copy
import hashlib
import os
import re
import stat
import unicodedata
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Iterator

from .ids import is_uuid7, new_id
from .secrets import assert_no_credentials
from .storage import (
    canonical_json_bytes,
    durable_write_bytes,
    file_lock,
    read_bounded_regular_file,
    strict_json_loads,
)


SCHEMA_VERSION = "0.2"
INTEGRITY_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
CATEGORY_RE = re.compile(r"^[a-z0-9](?:[a-z0-9._-]{0,126}[a-z0-9])?$")
EVENT_TYPE_RE = re.compile(r"^[a-z][a-z0-9]*(?:[._-][a-z0-9]+)+$")
RFC3339_RE = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$"
)
SENSITIVITIES = {"public", "personal", "sensitive", "restricted"}

# Event data is intentionally capped by its canonical UTF-8 representation.
# Four MiB is large enough for lifecycle snapshots while bounding both the
# durable record and the credential scan performed before publication.
EVENT_DATA_MAX_BYTES = 4 * 1024 * 1024
# Pretty-printed durable records need headroom over the canonical Event data
# cap. This also bounds legacy Capture reads and all integrity work.
DURABLE_RECORD_MAX_BYTES = 16 * 1024 * 1024
MAX_EVENT_ACTOR_LENGTH = 256


def _root(value: Any) -> Path:
    # pathlib.Path itself has a ``root`` attribute (normally "/"), so only
    # inspect an object's Vault-style root after ruling out path-like inputs.
    root = value if isinstance(value, (str, os.PathLike)) else getattr(value, "root", value)
    # Preserve the final component so callers cannot hide a symlink by having
    # it resolved before the safe walkers or bounded writer inspect it.
    return Path(root).expanduser().absolute()


def _is_real_directory(path: Path) -> bool:
    try:
        return stat.S_ISDIR(os.lstat(path).st_mode)
    except OSError:
        return False


def _is_regular_file(path: Path) -> bool:
    try:
        return stat.S_ISREG(os.lstat(path).st_mode)
    except OSError:
        return False


def _capture_directory_chain(root: Path, *parts: str) -> Path | None:
    """Resolve an existing Capture tree prefix, rejecting unsafe components."""

    current = root
    for part in (None, *parts):
        if part is not None:
            current = current / part
        try:
            status = os.lstat(current)
        except FileNotFoundError:
            return None
        except OSError:
            raise ValueError("Evidence directory cannot be inspected safely") from None
        if not stat.S_ISDIR(status.st_mode):
            raise ValueError("Evidence directory chain must contain only real directories")
    return current


def _event_directory_chain(root: Path, *parts: str) -> Path | None:
    """Resolve an existing Event tree prefix, rejecting unsafe components."""

    current = root
    for part in (None, *parts):
        if part is not None:
            current = current / part
        try:
            status = os.lstat(current)
        except FileNotFoundError:
            return None
        except OSError:
            raise ValueError("Event directory cannot be inspected safely") from None
        if not stat.S_ISDIR(status.st_mode):
            raise ValueError("Event directory chain must contain only real directories")
    return current


def _raise_event_walk_error(_error: OSError) -> None:
    raise ValueError("Event tree cannot be traversed safely") from None


def _raise_capture_walk_error(_error: OSError) -> None:
    raise ValueError("Evidence tree cannot be traversed safely") from None


def _timestamp(value: str | None) -> tuple[datetime, str]:
    if value is None:
        parsed = datetime.now(timezone.utc)
    else:
        if not isinstance(value, str):
            raise TypeError("timestamp must be a string")
        if not RFC3339_RE.fullmatch(value):
            raise ValueError("timestamp must be RFC3339 with T and an explicit UTC offset")
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            raise ValueError("timestamp must include an explicit UTC offset")
    rendered = parsed.isoformat().replace("+00:00", "Z")
    return parsed, rendered


def integrity_for(record: dict[str, Any]) -> str:
    """Compute a record's SHA-256 over canonical JSON, excluding integrity itself."""

    unsigned = {key: value for key, value in record.items() if key != "integrity"}
    digest = hashlib.sha256(canonical_json_bytes(unsigned)).hexdigest()
    return f"sha256:{digest}"


def seal_record(record: dict[str, Any]) -> dict[str, Any]:
    """Return a sealed, integrity-bearing copy of a capture or event."""

    sealed = copy.deepcopy(record)
    sealed.pop("integrity", None)
    sealed["sealed"] = True
    sealed["integrity"] = integrity_for(sealed)
    return sealed


def verify_integrity(record: dict[str, Any]) -> bool:
    integrity = record.get("integrity")
    return (
        isinstance(integrity, str)
        and INTEGRITY_RE.fullmatch(integrity) is not None
        and integrity == integrity_for(record)
    )


def require_valid_integrity(record: dict[str, Any], *, location: str = "record") -> None:
    if not verify_integrity(record):
        raise ValueError(f"{location}: integrity verification failed")


def _capture_path_is_candidate(evidence_root: Path, path: Path) -> bool:
    try:
        relative = path.relative_to(evidence_root)
    except ValueError:
        return False
    return bool(relative.parts) and relative.parts[0] != "_events" and path.suffix == ".json"


def iter_capture_paths(root_or_vault: Any) -> Iterator[Path]:
    """Walk capture files with a static pattern; user input is never used as a glob."""

    evidence_root = _capture_directory_chain(_root(root_or_vault), "evidence")
    if evidence_root is None:
        return
    for directory, directory_names, file_names in os.walk(
        evidence_root, followlinks=False, onerror=_raise_capture_walk_error
    ):
        base = Path(directory)
        safe_directories: list[str] = []
        for name in sorted(directory_names):
            if name == "_events":
                continue
            if not _is_real_directory(base / name):
                raise ValueError("Evidence tree contains an unsafe directory entry")
            safe_directories.append(name)
        directory_names[:] = safe_directories
        for name in sorted(file_names):
            path = base / name
            if not _capture_path_is_candidate(evidence_root, path):
                continue
            if not _is_regular_file(path):
                raise ValueError("Capture record path must be a regular non-symlink file")
            yield path


def find_evidence_path(root_or_vault: Any, evidence_id: str) -> Path | None:
    """Resolve an Evidence UUID without interpolating it into a glob expression."""

    if not is_uuid7(evidence_id):
        raise ValueError("evidence_id must be a UUIDv7")
    expected_name = f"{evidence_id}.json"
    matches = [path for path in iter_capture_paths(root_or_vault) if path.name == expected_name]
    if len(matches) > 1:
        raise ValueError(f"duplicate Evidence ID: {evidence_id}")
    return matches[0] if matches else None


def read_capture(
    path: Path | str, *, verify: bool = True, boundary: Path | str | None = None
) -> dict[str, Any]:
    location = Path(path)
    try:
        payload = read_bounded_regular_file(
            location, max_bytes=DURABLE_RECORD_MAX_BYTES, boundary=boundary
        )
        value = strict_json_loads(payload, max_bytes=DURABLE_RECORD_MAX_BYTES)
    except ValueError as exc:
        raise ValueError(f"{location}: invalid capture JSON ({exc})") from None
    if not isinstance(value, dict):
        raise ValueError(f"{location}: capture must be a JSON object")
    schema = value.get("schema")
    if value.get("sealed") is not True:
        raise ValueError(f"{location}: capture is not sealed")
    if schema == "0.1":
        # v0.1 records predate record_type and mandatory integrity.  If a record
        # happens to carry an integrity field, verify it rather than ignoring it.
        if value.get("record_type") not in {None, "capture"}:
            raise ValueError(f"{location}: invalid v0.1 record_type")
        if verify and "integrity" in value:
            require_valid_integrity(value, location=str(location))
    elif schema == SCHEMA_VERSION:
        if value.get("record_type") != "capture":
            raise ValueError(f"{location}: expected a capture record")
        if verify:
            require_valid_integrity(value, location=str(location))
    else:
        raise ValueError(f"{location}: unsupported capture schema")
    if not is_uuid7(value.get("id")):
        raise ValueError(f"{location}: invalid Evidence UUIDv7")
    if schema == SCHEMA_VERSION:
        for field in ("captured_at", "ingested_at"):
            if not isinstance(value.get(field), str):
                raise ValueError(f"{location}: {field} is missing")
            try:
                _timestamp(value[field])
            except (TypeError, ValueError):
                raise ValueError(f"{location}: {field} is not strict RFC3339") from None
        representations = value.get("representations")
        if not isinstance(representations, list):
            raise ValueError(f"{location}: representations must be a list")
        for index, representation in enumerate(representations):
            if not isinstance(representation, dict):
                raise ValueError(f"{location}: invalid representation")
            if not isinstance(representation.get("created_at"), str):
                raise ValueError(f"{location}: invalid representation timestamp")
            try:
                _timestamp(representation["created_at"])
            except (TypeError, ValueError):
                raise ValueError(
                    f"{location}: representations[{index}].created_at is not strict RFC3339"
                ) from None
    return value


def load_evidence(
    root_or_vault: Any, evidence_id: str, *, verify: bool = True
) -> dict[str, Any] | None:
    path = find_evidence_path(root_or_vault, evidence_id)
    if path is None:
        return None
    record = read_capture(path, verify=verify, boundary=_root(root_or_vault))
    if record["id"] != evidence_id:
        raise ValueError(f"{path}: filename and Evidence ID do not match")
    return record


def iter_captures(root_or_vault: Any, *, verify: bool = True) -> Iterator[dict[str, Any]]:
    for path in iter_capture_paths(root_or_vault):
        yield read_capture(path, verify=verify, boundary=_root(root_or_vault))


def _category_for(event_type: str) -> str:
    candidate = event_type.split("-", 1)[0].lower()
    candidate = re.sub(r"[^a-z0-9._-]+", "-", candidate).strip("-.")
    return candidate or "general"


def _validate_category(category: str) -> str:
    if not isinstance(category, str) or CATEGORY_RE.fullmatch(category) is None:
        raise ValueError("event category must be a safe lowercase path component")
    return category


def _validate_actor(actor: Any, *, location: str = "actor") -> str:
    if not isinstance(actor, str) or not actor.strip():
        raise ValueError(f"{location} must be a non-empty string")
    if len(actor) > MAX_EVENT_ACTOR_LENGTH:
        raise ValueError(f"{location} exceeds the maximum length")
    # Reject all Unicode control/format characters, including line separators
    # and invisible formatting controls that could confuse audit consumers.
    if any(unicodedata.category(character).startswith("C") for character in actor):
        raise ValueError(f"{location} contains control characters")
    # Actors are written into the durable audit trail too; use the same
    # detector as event data without ever including matched bytes in errors.
    assert_no_credentials(actor.encode("utf-8"))
    return actor


def _normalize_event_data(data: Any) -> Any:
    """Validate and detach event data before any sequence is allocated.

    The normalized value is parsed back from canonical JSON so custom objects,
    non-finite numbers, cycles, and non-string object keys cannot survive into
    a sealed Event.  The byte cap applies to exactly the representation used by
    the integrity hash and by the credential scanner.
    """

    try:
        encoded = canonical_json_bytes({} if data is None else data)
    except (TypeError, ValueError, OverflowError, RecursionError, UnicodeError) as exc:
        raise ValueError("event data must be finite canonical-JSON serializable data") from None
    if len(encoded) > EVENT_DATA_MAX_BYTES:
        raise ValueError(f"event data exceeds the maximum size of {EVENT_DATA_MAX_BYTES} bytes")
    # Scan the complete bounded canonical representation.  SecretDetectedError
    # intentionally exposes detector names only, never matched material.
    assert_no_credentials(encoded)
    try:
        return strict_json_loads(encoded, max_bytes=EVENT_DATA_MAX_BYTES)
    except ValueError:  # pragma: no cover - canonical output is strict JSON
        raise ValueError("event data must be finite canonical-JSON serializable data") from None


def _validated_event_chain(
    events: list[dict[str, Any]],
) -> tuple[int, str | None, set[str]]:
    """Validate the complete global sequence and return its append position."""

    identifiers: set[str] = set()
    for event in events:
        event_id = event["id"]
        if event_id in identifiers:
            raise ValueError("existing Event log contains a duplicate Event ID")
        identifiers.add(event_id)

    ordered = sorted(events, key=lambda item: item["sequence"])
    previous_event: str | None = None
    for expected_sequence, event in enumerate(ordered, start=1):
        if event["sequence"] != expected_sequence:
            raise ValueError("existing Event log sequence is not contiguous")
        if event.get("previous_event") != previous_event:
            raise ValueError("existing Event log previous_event chain is broken")
        previous_event = event["id"]
    return len(ordered), previous_event, identifiers


def append_event(
    root_or_vault: Any,
    event_type: str,
    *,
    actor: str,
    data: Any | None = None,
    target: str | None = None,
    sensitivity: str = "personal",
    category: str | None = None,
    recorded_at: str | None = None,
) -> dict[str, Any]:
    """Append a generic immutable event and return its sealed representation."""

    root = _root(root_or_vault)
    if not isinstance(event_type, str) or EVENT_TYPE_RE.fullmatch(event_type) is None:
        raise ValueError("event_type must be a lowercase dotted, dashed, or underscored name")
    _validate_actor(actor)
    if target is not None and not is_uuid7(target):
        raise ValueError("target must be a stable UUIDv7 when supplied")
    if sensitivity not in SENSITIVITIES:
        raise ValueError("invalid sensitivity")
    safe_category = _validate_category(category or _category_for(event_type))
    recorded, rendered_time = _timestamp(recorded_at)
    normalized_data = _normalize_event_data(data)
    lock_path = root / "runtime" / "locks" / "writer.lock"
    with file_lock(lock_path, boundary=root):
        # The global scan remains authoritative.  A crash-safe HEAD would need
        # to prove its metadata is published atomically with every Event at all
        # kill boundaries; until then correctness takes precedence over speed.
        existing_events = [
            read_event(path, verify=True, boundary=root) for path in iter_event_paths(root)
        ]
        previous_sequence, previous_event, existing_ids = _validated_event_chain(existing_events)

        # UUID collisions are extraordinarily unlikely, but exclusive publication
        # is the authority.  Retry without ever overwriting an existing event.
        for _ in range(8):
            event_id = new_id()
            if event_id in existing_ids:
                continue
            event: dict[str, Any] = {
                "schema": SCHEMA_VERSION,
                "record_type": "event",
                "id": event_id,
                "event_type": event_type,
                "sequence": previous_sequence + 1,
                "previous_event": previous_event,
                "recorded_at": rendered_time,
                "actor": actor,
                "data": normalized_data,
                "sensitivity": sensitivity,
                "sealed": True,
            }
            if target is not None:
                event["target"] = target
            event = seal_record(event)
            destination = (
                root
                / "evidence"
                / "_events"
                / safe_category
                / f"{recorded.year:04d}"
                / f"{recorded.month:02d}"
                / f"{recorded.day:02d}"
                / f"{event['id']}.json"
            )
            try:
                record_payload = canonical_json_bytes(event) + b"\n"
                if len(record_payload) > DURABLE_RECORD_MAX_BYTES:
                    raise ValueError("Event record exceeds the maximum durable size")
                durable_write_bytes(
                    destination,
                    record_payload,
                    exclusive=True,
                    mode=0o400,
                    boundary=root,
                )
            except FileExistsError:
                continue
            return event
    raise RuntimeError("could not allocate a unique event ID")


def read_event(
    path: Path | str, *, verify: bool = True, boundary: Path | str | None = None
) -> dict[str, Any]:
    location = Path(path)
    try:
        payload = read_bounded_regular_file(
            location, max_bytes=DURABLE_RECORD_MAX_BYTES, boundary=boundary
        )
        value = strict_json_loads(payload, max_bytes=DURABLE_RECORD_MAX_BYTES)
    except ValueError as exc:
        raise ValueError(f"{location}: invalid event JSON ({exc})") from None
    if not isinstance(value, dict):
        raise ValueError(f"{location}: event must be a JSON object")
    if value.get("schema") != SCHEMA_VERSION or value.get("record_type") != "event":
        raise ValueError(f"{location}: unsupported event record")
    if value.get("sealed") is not True:
        raise ValueError(f"{location}: event is not sealed")
    if not is_uuid7(value.get("id")):
        raise ValueError(f"{location}: invalid Event UUIDv7")
    if (
        not isinstance(value.get("event_type"), str)
        or EVENT_TYPE_RE.fullmatch(value["event_type"]) is None
    ):
        raise ValueError(f"{location}: invalid event_type")
    if not isinstance(value.get("recorded_at"), str):
        raise ValueError(f"{location}: recorded_at is missing")
    _timestamp(value["recorded_at"])
    _validate_actor(value.get("actor"), location=f"{location}: actor")
    if "data" not in value:
        raise ValueError(f"{location}: event data is missing")
    _normalize_event_data(value["data"])
    sequence = value.get("sequence")
    if isinstance(sequence, bool) or not isinstance(sequence, int) or sequence < 1:
        raise ValueError(f"{location}: invalid event sequence")
    previous_event = value.get("previous_event")
    if previous_event is not None and not is_uuid7(previous_event):
        raise ValueError(f"{location}: invalid previous_event UUIDv7")
    if value.get("sensitivity") not in SENSITIVITIES:
        raise ValueError(f"{location}: invalid sensitivity")
    if "target" in value and not is_uuid7(value["target"]):
        raise ValueError(f"{location}: invalid target UUIDv7")
    if verify:
        require_valid_integrity(value, location=str(location))
    return value


def iter_event_paths(root_or_vault: Any, *, category: str | None = None) -> Iterator[Path]:
    root = _root(root_or_vault)
    directory_parts = ["evidence", "_events"]
    if category is not None:
        directory_parts.append(_validate_category(category))
    events_root = _event_directory_chain(root, *directory_parts)
    if events_root is None:
        return
    for directory, directory_names, file_names in os.walk(
        events_root, followlinks=False, onerror=_raise_event_walk_error
    ):
        base = Path(directory)
        safe_directories: list[str] = []
        for name in sorted(directory_names):
            if not _is_real_directory(base / name):
                raise ValueError("Event tree contains an unsafe directory entry")
            safe_directories.append(name)
        directory_names[:] = safe_directories
        for name in sorted(file_names):
            path = base / name
            if not name.endswith(".json"):
                continue
            if not _is_regular_file(path):
                raise ValueError("Event record path must be a regular non-symlink file")
            yield path


def iter_events(
    root_or_vault: Any,
    *,
    target: str | None = None,
    event_types: Iterable[str] | None = None,
    category: str | None = None,
    verify: bool = True,
) -> Iterator[dict[str, Any]]:
    if target is not None and not is_uuid7(target):
        raise ValueError("target must be a stable UUIDv7")
    allowed_types = (
        {event_types}
        if isinstance(event_types, str)
        else set(event_types)
        if event_types is not None
        else None
    )
    # Read the complete log even when the caller asks for one category.  The
    # sequence/previous_event chain is global, so validating a category-only
    # subset would incorrectly report ordinary cross-category appends as gaps.
    requested_category = _validate_category(category) if category is not None else None
    events: list[dict[str, Any]] = []
    paths: list[Path] = []
    for path in iter_event_paths(root_or_vault):
        event = read_event(path, verify=verify, boundary=_root(root_or_vault))
        events.append(event)
        paths.append(path)

    # A filtered projection must not hide a missing or reordered event.  The
    # global chain is the durable append contract; verify it before applying
    # target/type filters so callers cannot obtain a seemingly valid partial
    # history from a damaged log.
    if verify:
        _validated_event_chain(events)

    filtered: list[dict[str, Any]] = []
    events_root = _root(root_or_vault) / "evidence" / "_events"
    for path, event in zip(paths, events):
        if requested_category is not None:
            try:
                relative = path.relative_to(events_root)
            except ValueError:
                raise ValueError("Event path escaped the durable event tree") from None
            if not relative.parts or relative.parts[0] != requested_category:
                continue
        if target is not None and event.get("target") != target:
            continue
        if allowed_types is not None and event.get("event_type") not in allowed_types:
            continue
        filtered.append(event)
    filtered.sort(key=lambda item: (item["sequence"], str(item.get("id", ""))))
    yield from filtered


def _event_payload_data(event: dict[str, Any]) -> dict[str, Any]:
    data = event.get("data")
    if not isinstance(data, dict):
        return {}
    nested = data.get("payload")
    return copy.deepcopy(nested if isinstance(nested, dict) else data)


def _representations_from_event(event: dict[str, Any]) -> list[dict[str, Any]]:
    data = event.get("data")
    if not isinstance(data, dict):
        return []
    if isinstance(data.get("representation"), dict):
        return [copy.deepcopy(data["representation"])]
    if isinstance(data.get("representations"), list):
        return [copy.deepcopy(item) for item in data["representations"] if isinstance(item, dict)]
    # A bare representation object is convenient for event producers and keeps
    # event.data extensible without prescribing one universal nested envelope.
    if "role" in data and "object" in data:
        return [copy.deepcopy(data)]
    return []


def effective_evidence(
    root_or_vault: Any, evidence_id: str, *, verify: bool = True
) -> dict[str, Any] | None:
    """Project a capture through its append-only representation/payload events."""

    capture = load_evidence(root_or_vault, evidence_id, verify=verify)
    if capture is None:
        return None
    effective = copy.deepcopy(capture)
    effective.setdefault("representations", [])
    effective.setdefault("payload", {})
    lifecycle_types = {
        "representation-added",
        "representation.added",
        "retention.changed",
        "retention-changed",
        "payload-evicted",
        "payload.evicted",
        "payload-missing-observed",
        "payload.missing-observed",
        "payload-restored",
        "payload.restored",
        "payload-redacted",
        "payload.redacted",
    }
    for event in iter_events(
        root_or_vault,
        target=evidence_id,
        event_types=lifecycle_types,
        verify=verify,
    ):
        event_type = {
            "representation.added": "representation-added",
            "retention-changed": "retention.changed",
            "payload.evicted": "payload-evicted",
            "payload.missing-observed": "payload-missing-observed",
            "payload.restored": "payload-restored",
            "payload.redacted": "payload-redacted",
        }.get(event["event_type"], event["event_type"])
        if event_type == "representation-added":
            effective["representations"].extend(_representations_from_event(event))
            continue

        if event_type == "retention.changed":
            # Retention is metadata on the immutable capture.  A transition is
            # projected in sequence order and its event time is the origin for
            # a subsequent grace period.
            data = event.get("data")
            if isinstance(data, dict):
                target_class = data.get("to")
                if isinstance(target_class, str):
                    effective["payload"]["retention"] = target_class
                effective["payload"]["changed_at"] = event["recorded_at"]
            continue

        payload = effective["payload"]
        changes = _event_payload_data(event)
        changes.pop("state", None)
        if event_type == "payload-missing-observed":
            payload.pop("object", None)
            changes.pop("object", None)
            payload.pop("evicted_at", None)
            payload.pop("eviction_reason", None)
            payload.pop("redacted_at", None)
            payload.pop("redaction_reason", None)
            payload["state"] = "missing"
            if "reason" in changes and "missing_reason" not in changes:
                changes["missing_reason"] = changes.pop("reason")
            payload.setdefault("missing_at", event["recorded_at"])
        elif event_type == "payload-evicted":
            payload.pop("object", None)
            changes.pop("object", None)
            payload["state"] = "evicted"
            if "reason" in changes and "eviction_reason" not in changes:
                changes["eviction_reason"] = changes.pop("reason")
            payload.setdefault("evicted_at", event["recorded_at"])
        elif event_type == "payload-restored":
            payload["state"] = "present"
            if "object" not in changes:
                digest = effective.get("content", {}).get("sha256")
                if isinstance(digest, str):
                    changes["object"] = f"sha256:{digest}"
            payload.pop("evicted_at", None)
            payload.pop("eviction_reason", None)
            payload.pop("missing_at", None)
            payload.pop("missing_reason", None)
            payload.pop("redacted_at", None)
            payload.pop("redaction_reason", None)
        elif event_type == "payload-redacted":
            payload.pop("object", None)
            changes.pop("object", None)
            payload["state"] = "redacted"
            if "reason" in changes and "redaction_reason" not in changes:
                changes["redaction_reason"] = changes.pop("reason")
            payload.setdefault("redacted_at", event["recorded_at"])
        payload.update(changes)
        # Event type controls state; arbitrary event data cannot accidentally
        # claim a contradictory state in the effective projection.
        payload["state"] = {
            "payload-evicted": "evicted",
            "payload-missing-observed": "missing",
            "payload-restored": "present",
            "payload-redacted": "redacted",
        }[event_type]
    return effective


# Explicit aliases make the read API discoverable while retaining the vocabulary
# used by callers of the original Vault implementation.
load_capture = load_evidence
events_for = iter_events
