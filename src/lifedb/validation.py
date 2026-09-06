from __future__ import annotations

import hashlib
import json
import math
import os
import re
import stat
from dataclasses import dataclass, field
from datetime import date, datetime
from pathlib import Path
from typing import Any, Iterable, Mapping
from urllib.parse import urlparse

from .evidence import (
    iter_capture_paths,
    iter_event_paths,
    read_capture,
    read_event,
)
from .ids import is_uuid7
from .markdown import MAX_MARKDOWN_BYTES, canon_documents
from .policies import PolicyError, load_context_policy, load_retention_policy
from .secrets import detect_credentials
from .storage import file_lock, read_bounded_regular_file, strict_json_loads
from .schema_validation import schema_errors


SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
OBJECT_REF_RE = re.compile(r"^sha256:([0-9a-f]{64})$")
DATETIME_RE = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$"
)
PREDICATE_RE = re.compile(r"^[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*$")
REQUIREMENT_RE = re.compile(r"^(?:raw|record-only|representation:[a-z][a-z0-9._-]*)$")
SENSITIVITIES = {"public", "personal", "sensitive", "restricted"}
SENSITIVITY_RANK = {"public": 0, "personal": 1, "sensitive": 2, "restricted": 3}
BASES = {"declared", "observed", "inferred", "imported", "computed"}
CERTAINTIES = {"confirmed", "probable", "tentative", "unknown"}
CLAIM_STATES = {"active", "superseded", "retracted", "disputed"}
RETENTIONS = {"pinned", "durable", "grace", "derivative-only", "reference-only"}
OBJECT_KEYS = {"ref", "text", "boolean", "number", "date", "datetime", "uri", "json"}
LIFECYCLE_EVENTS = {
    "representation-added",
    "representation.added",
    "retention.changed",
    "retention-changed",
    "payload-evicted",
    "payload.evicted",
    "payload-restored",
    "payload.restored",
    "payload-missing-observed",
    "payload.missing-observed",
    "payload-redacted",
    "payload.redacted",
}
RETENTION_CLASSES = {"pinned", "durable", "grace", "derivative-only", "reference-only"}
CHANGEABLE_RETENTION_CLASSES = RETENTION_CLASSES - {"reference-only"}
VALID_OBJECT_COMPONENT_RE = re.compile(r"^[0-9a-f]{2}$")
DURABLE_JSON_MAX_BYTES = 16 * 1024 * 1024


@dataclass
class ValidationReport:
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    canon_documents: int = 0
    claims: int = 0
    evidence_records: int = 0
    evidence_events: int = 0
    objects_checked: int = 0

    @property
    def valid(self) -> bool:
        return not self.errors

    def as_dict(self) -> dict[str, Any]:
        return {
            "valid": self.valid,
            "errors": self.errors,
            "warnings": self.warnings,
            "counts": {
                "canon_documents": self.canon_documents,
                "claims": self.claims,
                "evidence_records": self.evidence_records,
                "evidence_events": self.evidence_events,
                "objects_checked": self.objects_checked,
            },
        }


def _error(report: ValidationReport, location: str, message: str) -> None:
    report.errors.append(f"{location}: {message}")


def _warn(report: ValidationReport, location: str, message: str) -> None:
    report.warnings.append(f"{location}: {message}")


def _parse_datetime(value: Any) -> datetime | None:
    if not isinstance(value, str) or DATETIME_RE.fullmatch(value) is None:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo is not None and parsed.utcoffset() is not None else None


def _parse_temporal(value: Any) -> date | datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        if re.fullmatch(r"\d{4}-\d{2}-\d{2}", value):
            return date.fromisoformat(value)
        return _parse_datetime(value)
    except ValueError:
        return None


def _temporal_precision(value: Any) -> str | None:
    if not isinstance(value, str) or not value:
        return None
    if re.fullmatch(r"\d{4}-\d{2}-\d{2}", value):
        try:
            date.fromisoformat(value)
        except ValueError:
            return None
        return "date"
    return "datetime" if _parse_datetime(value) is not None else None


def _object_path(root: Path, digest: str) -> Path:
    return root / "objects" / "sha256" / digest[:2] / digest[2:4] / digest


def _digest_from_ref(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    match = OBJECT_REF_RE.fullmatch(value)
    return match.group(1) if match else None


def _validate_canon_manifest(
    data: Any, *, operation: str, location: str, transaction_id: str, report: ValidationReport
) -> None:
    """Validate the stable shape of a Canon transaction manifest."""
    if not isinstance(data, Mapping):
        _error(report, location, "Canon transaction data must be a mapping")
        return
    if data.get("transaction_id") != transaction_id:
        _error(report, location, "transaction_id does not match event target")
    if data.get("operation") != operation:
        _error(report, location, f"operation must be {operation}")
    if not isinstance(data.get("actor"), str) or not data["actor"].strip():
        _error(report, f"{location}.actor", "must be a non-empty string")
    path_value = data.get("path")
    if not isinstance(path_value, str) or not path_value.startswith("canon/") or Path(path_value).is_absolute():
        _error(report, f"{location}.path", "must be a relative path under canon/")
    else:
        normalized = Path(path_value).as_posix()
        if normalized != path_value or ".." in Path(path_value).parts:
            _error(report, f"{location}.path", "must be normalized and remain under canon/")
    if not is_uuid7(data.get("document")):
        _error(report, f"{location}.document", "must be a semantic UUIDv7")
    for field in ("before", "after"):
        if _digest_from_ref(data.get(field)) is None:
            _error(report, f"{location}.{field}", "must be a sha256 snapshot reference")
    if operation == "promotion":
        for field in ("candidate", "claim"):
            if not is_uuid7(data.get(field)):
                _error(report, f"{location}.{field}", "must be a UUIDv7")
    elif not is_uuid7(data.get("rollback_of")):
        _error(report, f"{location}.rollback_of", "must be a source transaction UUIDv7")


def _retention_manifest(
    data: Any, *, location: str, report: ValidationReport, committed: bool = False
) -> tuple[str | None, str | None, list[tuple[str, int, tuple[str, ...]]]]:
    """Validate the durable part of a retention transaction event."""
    if not isinstance(data, Mapping):
        _error(report, location, "retention transaction data must be a mapping")
        return None, None, []
    plan = data.get("plan")
    if not is_uuid7(plan):
        _error(report, f"{location}.plan", "must be a UUIDv7")
        plan_text = None
    else:
        plan_text = str(plan)
    confirmation = _digest_from_ref(data.get("confirmation"))
    if confirmation is None:
        _error(report, f"{location}.confirmation", "must be a sha256 reference")
    candidates = data.get("candidates")
    if not isinstance(candidates, list):
        _error(report, f"{location}.candidates", "must be a list")
        candidates = []
    normalized: list[tuple[str, int, tuple[str, ...]]] = []
    seen_objects: set[str] = set()
    for index, candidate in enumerate(candidates):
        candidate_location = f"{location}.candidates[{index}]"
        if not isinstance(candidate, Mapping):
            _error(report, candidate_location, "must be a mapping")
            continue
        digest = _digest_from_ref(candidate.get("object"))
        size = candidate.get("size")
        evidence = candidate.get("evidence")
        if digest is None:
            _error(report, f"{candidate_location}.object", "must be a sha256 object reference")
            continue
        if isinstance(size, bool) or not isinstance(size, int) or size < 0:
            _error(report, f"{candidate_location}.size", "must be a non-negative integer")
            continue
        if (
            not isinstance(evidence, list)
            or not evidence
            or any(not is_uuid7(item) for item in evidence)
            or len(evidence) != len(set(evidence))
        ):
            _error(report, f"{candidate_location}.evidence", "must be a unique non-empty UUIDv7 list")
            continue
        if digest in seen_objects:
            _error(report, candidate_location, "object must occur only once in a transaction")
        seen_objects.add(digest)
        normalized.append((digest, size, tuple(str(item) for item in evidence)))
    if committed:
        freed = data.get("freed_bytes")
        if isinstance(freed, bool) or not isinstance(freed, int) or freed < 0:
            _error(report, f"{location}.freed_bytes", "must be a non-negative integer")
        elif freed != sum(item[1] for item in normalized):
            _error(report, f"{location}.freed_bytes", "does not match candidate sizes")
    return plan_text, confirmation, normalized


def _validate_candidate_proposal(
    claim: Any, *, location: str, report: ValidationReport, document_id: str | None,
    document_sensitivity: str,
) -> str | None:
    """Validate the proposal shape before it is projected into a Candidate."""
    if not isinstance(claim, Mapping):
        _error(report, location, "Candidate Claim proposal must be a mapping")
        return None
    required = {"predicate", "object", "statement", "basis", "certainty", "observed_at", "evidence"}
    for field in sorted(required.difference(claim)):
        _error(report, location, f"Candidate Claim missing {field}")
    predicate = claim.get("predicate")
    if not isinstance(predicate, str) or PREDICATE_RE.fullmatch(predicate) is None:
        _error(report, f"{location}.predicate", "invalid predicate name")
        predicate = None
    _validate_claim_object(claim.get("object"), f"{location}.object", report)
    if not isinstance(claim.get("statement"), str) or not claim.get("statement", "").strip():
        _error(report, f"{location}.statement", "must be a non-empty string")
    if not isinstance(claim.get("basis"), str) or claim.get("basis") not in BASES:
        _error(report, f"{location}.basis", "invalid basis")
    if not isinstance(claim.get("certainty"), str) or claim.get("certainty") not in CERTAINTIES:
        _error(report, f"{location}.certainty", "invalid certainty")
    if _parse_datetime(claim.get("observed_at")) is None:
        _error(report, f"{location}.observed_at", "must be a date-time with explicit offset")
    evidence = claim.get("evidence")
    if not isinstance(evidence, list) or not evidence:
        _error(report, f"{location}.evidence", "must be a non-empty list")
    else:
        edges = [
            _evidence_edge(item, legacy_allowed=False, location=f"{location}.evidence[{i}]", report=report)
            for i, item in enumerate(evidence)
        ]
        ids = [edge[0] for edge in edges if edge]
        if len(ids) != len(set(ids)):
            _error(report, f"{location}.evidence", "contains duplicate Evidence IDs")
    sensitivity = claim.get("sensitivity", document_sensitivity)
    if not isinstance(sensitivity, str) or sensitivity not in SENSITIVITIES:
        _error(report, f"{location}.sensitivity", "invalid sensitivity")
    elif document_sensitivity in SENSITIVITY_RANK and SENSITIVITY_RANK[sensitivity] < SENSITIVITY_RANK[document_sensitivity]:
        _error(report, f"{location}.sensitivity", "cannot lower target document sensitivity")
    for field in ("supersedes",):
        values = claim.get(field, [])
        if not isinstance(values, list) or any(not is_uuid7(value) for value in values):
            _error(report, f"{location}.{field}", "must be a list of UUIDv7 values")
        elif len(values) != len(set(values)):
            _error(report, f"{location}.{field}", "must not contain duplicates")
    return predicate


def _absolute_uri(value: Any) -> bool:
    if not isinstance(value, str) or not value or any(character.isspace() for character in value):
        return False
    try:
        parsed = urlparse(value)
        if parsed.username is not None or parsed.password is not None:
            return False
    except ValueError:
        return False
    if not parsed.scheme:
        return False
    return parsed.scheme not in {"http", "https"} or bool(parsed.netloc)


def _validate_claim_object(value: Any, location: str, report: ValidationReport) -> None:
    if not isinstance(value, Mapping):
        _error(report, location, "object must be a mapping")
        return
    keys = OBJECT_KEYS.intersection(value)
    if len(keys) != 1:
        _error(report, location, "object must contain exactly one typed value")
        return
    kind = next(iter(keys))
    allowed = {kind, "unit"} if kind == "number" else {kind}
    if set(value).difference(allowed):
        _error(report, location, "object contains fields not allowed for its value type")
    item = value[kind]
    valid = True
    if kind == "ref":
        valid = is_uuid7(item)
    elif kind == "text":
        valid = isinstance(item, str)
    elif kind == "boolean":
        valid = isinstance(item, bool)
    elif kind == "number":
        valid = (
            not isinstance(item, bool)
            and isinstance(item, (int, float))
            and (not isinstance(item, float) or math.isfinite(item))
        )
    elif kind == "date":
        valid = isinstance(item, str) and isinstance(_parse_temporal(item), date) and "T" not in item
    elif kind == "datetime":
        valid = _parse_datetime(item) is not None
    elif kind == "uri":
        valid = _absolute_uri(item)
    else:
        try:
            json.dumps(item, ensure_ascii=False, allow_nan=False)
        except (TypeError, ValueError):
            valid = False
    if not valid:
        _error(report, location, f"invalid {kind} value")


def _evidence_edge(
    item: Any,
    *,
    legacy_allowed: bool,
    location: str,
    report: ValidationReport,
) -> tuple[str, str] | None:
    if is_uuid7(item):
        if not legacy_allowed:
            _error(report, location, "v0.2 Claims must use {id, requires}; bare UUID is legacy-only")
        return str(item), "raw"
    if not isinstance(item, Mapping) or set(item) != {"id", "requires"}:
        _error(report, location, "must be a UUIDv7 or an exact {id, requires} mapping")
        return None
    evidence_id = item.get("id")
    requirement = item.get("requires")
    if not is_uuid7(evidence_id):
        _error(report, f"{location}.id", "must be a UUIDv7")
        return None
    if not isinstance(requirement, str) or REQUIREMENT_RE.fullmatch(requirement) is None:
        _error(report, f"{location}.requires", "must be raw, record-only, or representation:<role>")
        return None
    return str(evidence_id), requirement


def _validate_claim(
    claim: Any,
    *,
    location: str,
    document_id: str | None,
    document_schema: str,
    document_sensitivity: str,
    report: ValidationReport,
) -> tuple[str | None, list[tuple[str, str]], str | None]:
    if not isinstance(claim, Mapping):
        _error(report, location, "Claim must be a mapping")
        return None, [], None
    if "confidence" in claim:
        _error(report, f"{location}.confidence", "numeric model confidence must not be stored in Canon")
    required = {
        "id", "subject", "predicate", "object", "statement", "basis",
        "certainty", "state", "observed_at", "evidence",
    }
    for key in sorted(required.difference(claim)):
        _error(report, location, f"Claim missing {key}")
    claim_id = claim.get("id")
    if not is_uuid7(claim_id):
        _error(report, f"{location}.id", "invalid Claim UUIDv7")
        claim_id = None
    subject = claim.get("subject")
    if not is_uuid7(subject):
        _error(report, f"{location}.subject", "invalid subject UUIDv7")
    elif document_id is not None and subject != document_id:
        _error(report, f"{location}.subject", "must equal the containing document ID")
    predicate = claim.get("predicate")
    if not isinstance(predicate, str) or PREDICATE_RE.fullmatch(predicate) is None:
        _error(report, f"{location}.predicate", "invalid predicate name")
        predicate = None
    _validate_claim_object(claim.get("object"), f"{location}.object", report)
    if not isinstance(claim.get("statement"), str) or not claim.get("statement", "").strip():
        _error(report, f"{location}.statement", "must be a non-empty string")
    if claim.get("basis") not in BASES:
        _error(report, f"{location}.basis", "invalid basis")
    if claim.get("certainty") not in CERTAINTIES:
        _error(report, f"{location}.certainty", "invalid certainty")
    if claim.get("state") not in CLAIM_STATES:
        _error(report, f"{location}.state", "invalid Claim state")
    if _parse_datetime(claim.get("observed_at")) is None:
        _error(report, f"{location}.observed_at", "must be a date-time with explicit offset")

    sensitivity = claim.get("sensitivity", document_sensitivity)
    if sensitivity not in SENSITIVITIES:
        _error(report, f"{location}.sensitivity", "invalid sensitivity")
    elif document_sensitivity in SENSITIVITY_RANK and (
        SENSITIVITY_RANK[sensitivity] < SENSITIVITY_RANK[document_sensitivity]
    ):
        _error(report, f"{location}.sensitivity", "a Claim cannot lower document sensitivity")

    validity = claim.get("valid")
    if validity is not None:
        if not isinstance(validity, Mapping) or not validity or set(validity).difference({"from", "until"}):
            _error(report, f"{location}.valid", "must contain only from and/or until")
        else:
            parsed: dict[str, date | datetime] = {}
            for bound in ("from", "until"):
                if bound in validity:
                    converted = _parse_temporal(validity[bound])
                    if converted is None:
                        _error(report, f"{location}.valid.{bound}", "invalid date or date-time")
                    else:
                        parsed[bound] = converted
            if "from" in parsed and "until" in parsed:
                left, right = parsed["from"], parsed["until"]
                left_precision = _temporal_precision(validity.get("from"))
                right_precision = _temporal_precision(validity.get("until"))
                if left_precision != right_precision:
                    _error(report, f"{location}.valid", "from and until must use the same date/date-time precision")
                elif type(left) is type(right) and left >= right:
                    _error(report, f"{location}.valid", "until must be later than from")

    edges: list[tuple[str, str]] = []
    evidence = claim.get("evidence")
    if not isinstance(evidence, list) or not evidence:
        _error(report, f"{location}.evidence", "must be a non-empty list")
    else:
        for index, item in enumerate(evidence):
            edge = _evidence_edge(
                item,
                legacy_allowed=document_schema == "0.1",
                location=f"{location}.evidence[{index}]",
                report=report,
            )
            if edge:
                edges.append(edge)
        if len({edge[0] for edge in edges}) != len(edges):
            _error(report, f"{location}.evidence", "contains duplicate Evidence IDs")

    for field in ("supersedes", "superseded_by"):
        values = claim.get(field, [])
        if not isinstance(values, list) or any(not is_uuid7(value) for value in values):
            _error(report, f"{location}.{field}", "must be a list of UUIDv7 values")
        elif len(values) != len(set(values)):
            _error(report, f"{location}.{field}", "must not contain duplicates")
    if claim.get("state") == "superseded" and not claim.get("superseded_by"):
        _error(report, location, "a superseded Claim must name superseded_by")
    return str(claim_id) if claim_id else None, edges, predicate


def _json(path: Path, location: str, report: ValidationReport) -> dict[str, Any] | None:
    try:
        payload = read_bounded_regular_file(path, max_bytes=DURABLE_JSON_MAX_BYTES)
        value = strict_json_loads(payload, max_bytes=DURABLE_JSON_MAX_BYTES)
    except (OSError, ValueError, MemoryError, OverflowError, RecursionError):
        # Do not echo parser details or attacker-controlled bytes into a
        # validation report.  In particular this path is used for vault.json,
        # whose contents may contain owner-managed metadata.
        _error(report, location, "invalid JSON or unsafe record file")
        return None
    if not isinstance(value, dict):
        _error(report, location, "must be a JSON object")
        return None
    return value


def _schema_check(
    kind: str,
    value: Any,
    location: str,
    root: Path,
    report: ValidationReport,
) -> None:
    try:
        errors = schema_errors(kind, value, vault_root=root)
    except Exception as exc:
        _error(report, location, f"schema validation unavailable: {exc}")
        return
    for message in errors:
        _error(report, location, message)


def _event_representations(event: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    data = event.get("data")
    if not isinstance(data, Mapping):
        return []
    if isinstance(data.get("representation"), Mapping):
        return [data["representation"]]
    if isinstance(data.get("representations"), list):
        return [value for value in data["representations"] if isinstance(value, Mapping)]
    if "role" in data and "object" in data:
        return [data]
    return []


def _capture_object_references(record: Mapping[str, Any]) -> set[str]:
    references: set[str] = set()
    content = record.get("content")
    if isinstance(content, Mapping):
        digest = content.get("sha256")
        if isinstance(digest, str) and SHA256_RE.fullmatch(digest):
            references.add(digest)
    payload = record.get("payload")
    if isinstance(payload, Mapping):
        digest = _digest_from_ref(payload.get("object"))
        if digest is not None:
            references.add(digest)
    for representation in record.get("representations", []) if isinstance(record.get("representations"), list) else []:
        if not isinstance(representation, Mapping):
            continue
        for field in ("object", "derived_from"):
            digest = _digest_from_ref(representation.get(field))
            if digest is not None:
                references.add(digest)
    return references


def _event_object_references(event: Mapping[str, Any]) -> set[str]:
    data = event.get("data")
    if not isinstance(data, Mapping):
        return set()
    values: list[Mapping[str, Any]] = []
    if isinstance(data.get("payload"), Mapping):
        values.append(data["payload"])
    if isinstance(data.get("representation"), Mapping):
        values.append(data["representation"])
    if isinstance(data.get("representations"), list):
        values.extend(item for item in data["representations"] if isinstance(item, Mapping))
    if "object" in data:
        values.append(data)
    references: set[str] = set()
    for value in values:
        for field in ("object", "derived_from"):
            digest = _digest_from_ref(value.get(field))
            if digest is not None:
                references.add(digest)
    return references


def _representation_object_references(record: Mapping[str, Any]) -> set[str]:
    references: set[str] = set()
    representations = record.get("representations")
    for representation in representations if isinstance(representations, list) else []:
        if not isinstance(representation, Mapping):
            continue
        for field in ("object", "derived_from"):
            digest = _digest_from_ref(representation.get(field))
            if digest is not None:
                references.add(digest)
    return references


def _iter_object_files(root: Path, report: ValidationReport) -> Iterable[Path]:
    """Inventory the object tree without following any untrusted entry.

    Object paths are deliberately shallow (``aa/bb/<64 hex>``).  Walking a
    general tree and silently filtering entries is unsafe: a FIFO can block a
    later ``read_bytes`` call, while a symlink or an unexpected directory can
    hide bytes outside the durable boundary.
    """
    object_root = root / "objects" / "sha256"
    try:
        status = os.lstat(object_root)
    except FileNotFoundError:
        _error(report, "objects/sha256", "object directory is missing")
        return
    except OSError:
        _error(report, "objects/sha256", "object directory cannot be inspected safely")
        return
    if not stat.S_ISDIR(status.st_mode):
        _error(report, "objects/sha256", "object root must be a real directory")
        return

    def entries(directory: Path) -> list[tuple[str, Path, os.stat_result]]:
        try:
            values: list[tuple[str, Path, os.stat_result]] = []
            with os.scandir(directory) as scan:
                for item in scan:
                    child = directory / item.name
                    try:
                        child_status = os.lstat(child)
                    except OSError:
                        _error(report, child.relative_to(root).as_posix(), "object entry cannot be inspected")
                        continue
                    values.append((item.name, child, child_status))
            return sorted(values, key=lambda value: value[0])
        except OSError:
            _error(report, directory.relative_to(root).as_posix(), "object directory cannot be read")
            return []

    for first_name, first, first_status in entries(object_root):
        first_rel = first.relative_to(root).as_posix()
        if first.is_symlink() or not stat.S_ISDIR(first_status.st_mode):
            _error(report, first_rel, "object tree contains a non-directory entry")
            continue
        if VALID_OBJECT_COMPONENT_RE.fullmatch(first_name) is None:
            _error(report, first_rel, "object path has an invalid digest directory")
            # Continue inspecting it to report all unsafe entries, but no
            # object found there can be accepted as canonical.
        for second_name, second, second_status in entries(first):
            second_rel = second.relative_to(root).as_posix()
            if second.is_symlink() or not stat.S_ISDIR(second_status.st_mode):
                _error(report, second_rel, "object tree contains a non-directory entry")
                continue
            if VALID_OBJECT_COMPONENT_RE.fullmatch(second_name) is None:
                _error(report, second_rel, "object path has an invalid digest directory")
            for name, path, path_status in entries(second):
                rel = path.relative_to(root).as_posix()
                if stat.S_ISDIR(path_status.st_mode) or path.is_symlink():
                    _error(report, rel, "object tree contains an unexpected directory or symlink")
                    continue
                if not stat.S_ISREG(path_status.st_mode):
                    _error(report, rel, "object tree contains a non-regular file")
                    continue
                if SHA256_RE.fullmatch(name) is None or path != _object_path(root, name):
                    _error(report, rel, "object path is not the canonical SHA-256 path")
                    continue
                yield path


def _check_symlinks(root: Path, report: ValidationReport) -> None:
    # Check the roots themselves before walking: os.walk would otherwise follow
    # a symlink supplied in place of a durable store.
    for name in ("canon", "evidence", "objects", "policies", "schemas", "migrations", "quarantine"):
        base = root / name
        if base.is_symlink():
            _error(report, name, "durable stores must not be symlinks")
            continue
        if not base.exists():
            continue
        for directory, directories, files in os.walk(base, followlinks=False):
            for entry in [*directories, *files]:
                path = Path(directory) / entry
                if path.is_symlink():
                    _error(report, path.relative_to(root).as_posix(), "durable stores must not contain symlinks")
    metadata = root / "vault.json"
    if metadata.is_symlink():
        _error(report, "vault.json", "durable metadata must not be a symlink")


def _stream_object(
    path: Path,
    *,
    expected_digest: str | None = None,
    expected_size: int | None = None,
    verify_hash: bool,
) -> tuple[bool, str | None, int | None]:
    """Safely inspect one object and optionally hash it incrementally.

    The pre-open lstat, O_NOFOLLOW open, descriptor fstat, and post-read fstat
    make replacement, truncation, and growth fail closed.  No caller should
    use ``Path.is_file`` or ``read_bytes`` for durable object references.
    """
    try:
        before = os.lstat(path)
    except OSError:
        return False, None, None
    if path.is_symlink() or not stat.S_ISREG(before.st_mode):
        return False, None, None
    if expected_size is not None and before.st_size != expected_size:
        return False, None, before.st_size
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError:
        return False, None, None
    try:
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino)
            or (expected_size is not None and opened.st_size != expected_size)
        ):
            return False, None, opened.st_size
        digest = hashlib.sha256() if verify_hash else None
        size = 0
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            size += len(chunk)
            if digest is not None:
                digest.update(chunk)
        after = os.fstat(descriptor)
        if (
            not stat.S_ISREG(after.st_mode)
            or (after.st_dev, after.st_ino) != (opened.st_dev, opened.st_ino)
            or after.st_size != opened.st_size
            or size != opened.st_size
            or (expected_size is not None and size != expected_size)
        ):
            return False, None, size
        actual = digest.hexdigest() if digest is not None else None
        if expected_digest is not None and actual is not None and actual != expected_digest:
            return False, actual, size
        return True, actual, size
    except OSError:
        return False, None, None
    finally:
        os.close(descriptor)


def _remember_object_reference(
    digest: str,
    expected_size: Any,
    *,
    location: str,
    report: ValidationReport,
    references: set[str],
    expected_sizes: dict[str, set[int]],
) -> None:
    """Record an object ref and validate an optional size without trusting it."""
    references.add(digest)
    if expected_size is None:
        return
    if isinstance(expected_size, bool) or not isinstance(expected_size, int) or expected_size < 0:
        _error(report, location, "object size must be a non-negative integer")
        return
    expected_sizes.setdefault(digest, set()).add(expected_size)


def _validate_vault_unlocked(root: Path, verify_hashes: bool = True) -> ValidationReport:
    supplied_root = Path(root).expanduser()
    report = ValidationReport()
    if supplied_root.is_symlink():
        report.errors.append("vault root must not be a symlink")
        return report
    try:
        root_status = os.lstat(supplied_root)
    except OSError:
        report.errors.append("vault root cannot be inspected safely")
        return report
    if not stat.S_ISDIR(root_status.st_mode):
        report.errors.append("vault root must be a real directory")
        return report
    root = supplied_root.resolve()
    _check_symlinks(root, report)
    if (root / "vault.json").is_symlink() or any(
        (root / name).is_symlink()
        for name in ("canon", "evidence", "objects", "policies", "schemas", "migrations", "quarantine")
    ):
        return report

    metadata_path = root / "vault.json"
    if not metadata_path.exists():
        report.errors.append("vault.json is missing")
        return report
    metadata = _json(metadata_path, "vault.json", report)
    if metadata is None:
        return report
    # Policies are executable authority for context construction and retention
    # actions.  Validation must surface missing, malformed, duplicate-key,
    # non-finite, oversized, or symlinked policy files instead of allowing a
    # caller to silently fall back to defaults.
    for filename, loader in (
        ("context.json", load_context_policy),
        ("retention.json", load_retention_policy),
    ):
        try:
            loader(root)
        except (PolicyError, OSError, ValueError, TypeError, MemoryError, RecursionError):
            _error(report, f"policies/{filename}", "policy is missing, malformed, or unsafe")
    if metadata.get("schema") == "0.2":
        _schema_check("vault", metadata, "vault.json", root, report)
    elif metadata.get("schema") == "0.1":
        _warn(report, "vault.json", "legacy schema 0.1; run the documented migration before new writes")
        if not is_uuid7(metadata.get("vault_id")):
            _error(report, "vault.json", "vault_id is not UUIDv7")
        if _parse_datetime(metadata.get("created_at")) is None:
            _error(report, "vault.json", "created_at is invalid")
    else:
        _error(report, "vault.json", "unsupported schema")

    semantic_ids: dict[str, str] = {}
    document_sensitivities: dict[str, str] = {}
    claims: dict[str, tuple[Mapping[str, Any], str, str | None]] = {}
    claim_sensitivities: dict[str, tuple[str, str]] = {}
    claim_edges: list[tuple[str, str, str]] = []
    semantic_refs: list[tuple[str, str]] = []
    object_expected_sizes: dict[str, set[int]] = {}
    required_object_digests: set[str] = set()
    try:
        for document in canon_documents(root / "canon"):
            report.canon_documents += 1
            rel = document.path.relative_to(root).as_posix()
            try:
                raw = read_bounded_regular_file(
                    root / rel, max_bytes=MAX_MARKDOWN_BYTES, boundary=root
                )
            except (OSError, ValueError):
                _error(report, rel, "Canon document could not be scanned safely")
            else:
                findings = detect_credentials(raw)
                if findings:
                    names = ", ".join(sorted({finding.detector for finding in findings}))
                    _error(report, rel, f"Canon document looks like credential material ({names}); manual edit refused")
            fm = document.frontmatter
            _schema_check("canon", fm, rel, root, report)
            extension = fm.get("x-lifedb")
            if not isinstance(extension, Mapping):
                continue
            document_id = extension.get("id")
            if not is_uuid7(document_id):
                _error(report, rel, "invalid semantic UUIDv7")
                document_id_text: str | None = None
            else:
                document_id_text = str(document_id)
                if document_id_text in semantic_ids:
                    _error(report, rel, f"duplicate semantic ID also used by {semantic_ids[document_id_text]}")
                else:
                    semantic_ids[document_id_text] = rel
            document_schema = str(extension.get("schema", ""))
            if document_schema not in {"0.1", "0.2"}:
                _error(report, rel, "unsupported x-lifedb.schema")
            document_sensitivity = str(extension.get("sensitivity", ""))
            if document_sensitivity not in SENSITIVITIES:
                _error(report, rel, "invalid document sensitivity")
                document_sensitivity = "personal"
            if document_id_text is not None:
                document_sensitivities[document_id_text] = document_sensitivity
            values = extension.get("claims", [])
            if not isinstance(values, list):
                _error(report, rel, "x-lifedb.claims must be a list")
                continue
            for index, claim in enumerate(values):
                report.claims += 1
                location = f"{rel}:claims[{index}]"
                claim_id, edges, predicate = _validate_claim(
                    claim,
                    location=location,
                    document_id=document_id_text,
                    document_schema=document_schema,
                    document_sensitivity=document_sensitivity,
                    report=report,
                )
                if claim_id:
                    if claim_id in claims:
                        _error(report, location, "duplicate Claim ID")
                    else:
                        claims[claim_id] = (claim, location, predicate)
                        claim_value_sensitivity = claim.get("sensitivity", document_sensitivity) if isinstance(claim, Mapping) else None
                        if isinstance(claim_value_sensitivity, str):
                            claim_sensitivities[claim_id] = (claim_value_sensitivity, location)
                    for evidence_id, requirement in edges:
                        claim_edges.append((location, evidence_id, requirement))
                obj = claim.get("object") if isinstance(claim, Mapping) else None
                if isinstance(obj, Mapping) and is_uuid7(obj.get("ref")):
                    semantic_refs.append((f"{location}.object.ref", str(obj["ref"])))
    except Exception as exc:
        _error(report, "canon", f"parse failure: {exc}")

    # Supersession is a bidirectional graph; state changes are allowed, semantic
    # Claim identity and meaning are not overwritten.
    for claim_id, (claim, location, predicate) in claims.items():
        for old_id in claim.get("supersedes", []):
            old = claims.get(old_id)
            if old is None:
                _error(report, f"{location}.supersedes", f"unresolved Claim ID {old_id}")
                continue
            old_claim, old_location, old_predicate = old
            if old_claim.get("subject") != claim.get("subject") or old_predicate != predicate:
                _error(report, f"{location}.supersedes", "may only target the same subject and predicate")
            if claim_id not in old_claim.get("superseded_by", []):
                _error(report, old_location, f"missing superseded_by backlink to {claim_id}")
        for new_id in claim.get("superseded_by", []):
            new = claims.get(new_id)
            if new is None or claim_id not in new[0].get("supersedes", []):
                _error(report, f"{location}.superseded_by", f"missing supersedes backlink from {new_id}")
    for location, semantic_id in semantic_refs:
        if semantic_id not in semantic_ids:
            _error(report, location, f"unresolved semantic ID {semantic_id}")

    captures: dict[str, dict[str, Any]] = {}
    capture_locations: dict[str, str] = {}
    all_referenced_digests: set[str] = set()
    for path in iter_capture_paths(root):
        rel = path.relative_to(root).as_posix()
        raw = _json(path, rel, report)
        if raw is None:
            continue
        report.evidence_records += 1
        schema = raw.get("schema")
        if schema == "0.2":
            _schema_check("capture", raw, rel, root, report)
        elif schema == "0.1":
            _warn(report, rel, "legacy capture schema 0.1 has no mandatory integrity digest")
        else:
            _error(report, rel, "unsupported capture schema")
        try:
            record = read_capture(path, verify=verify_hashes)
        except ValueError as exc:
            _error(report, rel, str(exc))
            continue
        evidence_id = record.get("id")
        if not is_uuid7(evidence_id):
            _error(report, rel, "invalid Evidence UUIDv7")
            continue
        evidence_id = str(evidence_id)
        if path.name != f"{evidence_id}.json":
            _error(report, rel, "filename must equal the Evidence ID")
        if evidence_id in captures:
            _error(report, rel, f"duplicate Evidence ID also used by {capture_locations[evidence_id]}")
            continue
        captures[evidence_id] = record
        capture_locations[evidence_id] = rel
        payload = record.get("payload")
        content = record.get("content")
        if not isinstance(payload, Mapping) or not isinstance(content, Mapping):
            _error(report, rel, "payload and content must be mappings")
            continue
        retention = payload.get("retention")
        if not isinstance(retention, str) or retention not in RETENTIONS:
            _error(report, rel, "invalid retention class")
        digest = content.get("sha256")
        if not isinstance(digest, str) or SHA256_RE.fullmatch(digest) is None:
            _error(report, rel, "invalid content SHA-256")
        else:
            # Content digests are historical metadata and may legitimately
            # outlive an evicted object.  Only a present payload below turns
            # this digest into a required object reference.
            pass
        payload_object = _digest_from_ref(payload.get("object"))
        if payload.get("state") == "present":
            if payload_object is None:
                _error(report, rel, "present payload must contain a valid object reference")
            elif isinstance(digest, str) and SHA256_RE.fullmatch(digest):
                if payload_object != digest:
                    _error(report, rel, "payload object must match content.sha256")
                _remember_object_reference(
                    payload_object, content.get("size"), location=f"{rel}.payload.object",
                    report=report, references=all_referenced_digests,
                    expected_sizes=object_expected_sizes,
                )
        elif payload_object is not None:
            _remember_object_reference(
                payload_object, None, location=f"{rel}.payload.object", report=report,
                references=all_referenced_digests, expected_sizes=object_expected_sizes,
            )
        representations = record.get("representations")
        if isinstance(representations, list):
            for index, representation in enumerate(representations):
                if not isinstance(representation, Mapping):
                    continue
                for field in ("object", "derived_from"):
                    representation_digest = _digest_from_ref(representation.get(field))
                    if representation_digest is not None:
                        _remember_object_reference(
                            representation_digest, representation.get("size") if field == "object" else None,
                            location=f"{rel}.representations[{index}].{field}", report=report,
                            references=all_referenced_digests, expected_sizes=object_expected_sizes,
                        )
        if retention == "reference-only":
            if payload.get("state") != "external" or "object" in payload:
                _error(report, rel, "reference-only captures must be external and have no object")
            if not _absolute_uri(record.get("source", {}).get("uri")):
                _error(report, rel, "reference-only captures require an absolute source URI")

    events: list[dict[str, Any]] = []
    event_ids: set[str] = set()
    for path in iter_event_paths(root):
        rel = path.relative_to(root).as_posix()
        raw = _json(path, rel, report)
        if raw is None:
            continue
        report.evidence_events += 1
        _schema_check("event", raw, rel, root, report)
        try:
            event = read_event(path, verify=verify_hashes)
        except ValueError as exc:
            _error(report, rel, str(exc))
            continue
        event_id = event["id"]
        if path.name != f"{event_id}.json":
            _error(report, rel, "filename must equal the Event ID")
        if event_id in event_ids:
            _error(report, rel, "duplicate Event ID")
        event_ids.add(event_id)
        events.append(event)

    ordered_events = sorted(events, key=lambda item: (item["sequence"], item["id"]))
    previous: str | None = None
    for expected, event in enumerate(ordered_events, start=1):
        if event["sequence"] != expected:
            _error(report, f"event:{event['id']}", f"sequence must be contiguous; expected {expected}")
        if event.get("previous_event") != previous:
            _error(report, f"event:{event['id']}", f"previous_event must be {previous!r}")
        previous = event["id"]
        if event.get("event_type") in LIFECYCLE_EVENTS and event.get("target") not in captures:
            _error(report, f"event:{event['id']}", "lifecycle target does not resolve to Evidence")
        if event.get("event_type") in {"retention.changed", "retention-changed"}:
            data = event.get("data")
            location = f"event:{event['id']}.data"
            if not isinstance(data, Mapping):
                _error(report, location, "retention change data must be a mapping")
            else:
                for field in ("from", "to"):
                    value = data.get(field)
                    if not isinstance(value, str) or value not in CHANGEABLE_RETENTION_CLASSES:
                        _error(report, f"{location}.{field}", "invalid retention class")
                if not isinstance(data.get("reason"), str) or not data.get("reason", "").strip():
                    _error(report, f"{location}.reason", "must be a non-empty string")
        for representation in _event_representations(event):
            reference = representation.get("object")
            digest = _digest_from_ref(reference)
            if digest is None:
                _error(report, f"event:{event['id']}", "representation object is invalid")
            else:
                _remember_object_reference(
                    digest, representation.get("size"),
                    location=f"event:{event['id']}.representation.object",
                    report=report, references=all_referenced_digests,
                    expected_sizes=object_expected_sizes,
                )
            derived_digest = _digest_from_ref(representation.get("derived_from"))
            if derived_digest is not None:
                _remember_object_reference(
                    derived_digest, None,
                    location=f"event:{event['id']}.representation.derived_from",
                    report=report, references=all_referenced_digests,
                    expected_sizes=object_expected_sizes,
                )
            if not isinstance(representation.get("role"), str) or not representation.get("role"):
                _error(report, f"event:{event['id']}", "representation role is missing")
            if _parse_datetime(representation.get("created_at")) is None:
                _error(report, f"event:{event['id']}", "representation created_at is invalid")
        if event["event_type"].startswith("canon."):
            data = event.get("data")
            if isinstance(data, Mapping):
                for key in ("before", "after"):
                    value = data.get(key)
                    if value is None:
                        continue
                    digest = _digest_from_ref(value)
                    if digest is None:
                        _error(report, f"event:{event['id']}.data.{key}", "invalid snapshot object reference")
                    else:
                        _remember_object_reference(
                            digest, None,
                            location=f"event:{event['id']}.data.{key}",
                            report=report, references=all_referenced_digests,
                            expected_sizes=object_expected_sizes,
                        )
                        required_object_digests.add(digest)

    # Object addresses are reusable, so a representation on a low-labelled
    # record cannot downgrade bytes ever attached to a higher-labelled capture
    # or event. Keep this check in validation as well as retrieval.
    object_sensitivities: dict[str, str] = {}
    for capture in captures.values():
        label = capture.get("sensitivity")
        for digest in _capture_object_references(capture):
            if label not in SENSITIVITY_RANK:
                object_sensitivities[digest] = "restricted"
            elif digest not in object_sensitivities or SENSITIVITY_RANK[label] > SENSITIVITY_RANK[object_sensitivities[digest]]:
                object_sensitivities[digest] = label
    for event in ordered_events:
        label = event.get("sensitivity")
        for digest in _event_object_references(event):
            if label not in SENSITIVITY_RANK:
                object_sensitivities[digest] = "restricted"
            elif digest not in object_sensitivities or SENSITIVITY_RANK[label] > SENSITIVITY_RANK[object_sensitivities[digest]]:
                object_sensitivities[digest] = label
    for evidence_id, capture in captures.items():
        labels = [capture.get("sensitivity")]
        labels.extend(event.get("sensitivity") for event in ordered_events if event.get("target") == evidence_id)
        if any(label not in SENSITIVITY_RANK for label in labels):
            continue
        effective_rank = max(SENSITIVITY_RANK[label] for label in labels)
        # A capture's own raw digest is its declared payload, not a downgrade
        # of an independently captured duplicate. Explicit representations and
        # lifecycle references are the alias boundary we must reject.
        references = _representation_object_references(capture)
        references.update(
            digest
            for event in ordered_events
            if event.get("target") == evidence_id
            for digest in _event_object_references(event)
        )
        for digest in references:
            object_label = object_sensitivities.get(digest, "restricted")
            if SENSITIVITY_RANK[object_label] > effective_rank:
                _error(
                    report,
                    f"evidence:{evidence_id}",
                    f"Object {digest} is referenced below its effective sensitivity",
                )

    transaction_events: dict[str, list[dict[str, Any]]] = {}
    candidate_events: dict[str, list[dict[str, Any]]] = {}
    for event in ordered_events:
        target = event.get("target")
        event_type = str(event.get("event_type", ""))
        if not isinstance(target, str):
            continue
        if event_type.startswith("canon.") or event_type.startswith("retention.apply-"):
            transaction_events.setdefault(target, []).append(event)
        if event_type.startswith("candidate."):
            candidate_events.setdefault(target, []).append(event)

    latest_committed_by_path: dict[str, dict[str, Any]] = {}
    for transaction_id, grouped in transaction_events.items():
        types = [str(event["event_type"]) for event in grouped]
        if any(value.startswith("canon.change-") for value in types):
            prepared_name, committed_name, aborted_name = (
                "canon.change-prepared", "canon.change-committed", "canon.change-aborted"
            )
        elif any(value.startswith("canon.rollback-") for value in types):
            prepared_name, committed_name, aborted_name = (
                "canon.rollback-prepared", "canon.rollback-committed", "canon.rollback-aborted"
            )
        elif any(value.startswith("retention.apply-") for value in types):
            prepared_name, committed_name, aborted_name = (
                "retention.apply-prepared", "retention.apply-committed", "retention.apply-aborted"
            )
        else:
            continue
        prepared = [event for event in grouped if event["event_type"] == prepared_name]
        committed = [event for event in grouped if event["event_type"] == committed_name]
        aborted = [event for event in grouped if event["event_type"] == aborted_name]
        if len(prepared) != 1:
            _error(report, f"transaction:{transaction_id}", f"must contain exactly one {prepared_name}")
        if len(committed) + len(aborted) != 1:
            _error(report, f"transaction:{transaction_id}", "must contain exactly one committed or aborted terminal event")
        if committed and prepared and committed[0].get("data") != prepared[0].get("data"):
            # Retention commit intentionally summarizes rather than repeats its
            # preview; Canon commits must repeat the exact snapshot manifest.
            if committed_name.startswith("canon."):
                _error(report, f"transaction:{transaction_id}", "prepared and committed Canon manifests differ")
        if prepared_name.startswith("canon."):
            for event in [*prepared, *committed]:
                event_data = event.get("data")
                if isinstance(event_data, Mapping) and "restored" in event_data:
                    _error(
                        report,
                        f"event:{event.get('id')}.data.restored",
                        "restored is only permitted on an aborted Canon terminal",
                    )
            if aborted:
                # An aborted Canon transition is valid only after the exact
                # prepared manifest has been proven restored.  `restored` is
                # the sole permitted addition; accepting an arbitrary abort
                # payload would let a forged terminal hide a prepared write.
                aborted_data = aborted[0].get("data")
                prepared_data = prepared[0].get("data") if prepared else None
                if not isinstance(aborted_data, Mapping) or aborted_data.get("restored") is not True:
                    _error(
                        report,
                        f"event:{aborted[0].get('id')}.data.restored",
                        "aborted Canon terminal must prove restoration",
                    )
                elif not isinstance(prepared_data, Mapping):
                    _error(report, f"transaction:{transaction_id}", "aborted Canon manifest has no prepared manifest")
                else:
                    without_marker = dict(aborted_data)
                    without_marker.pop("restored", None)
                    if without_marker != dict(prepared_data):
                        _error(
                            report,
                            f"transaction:{transaction_id}",
                            "prepared and aborted Canon manifests differ",
                        )
            for event in [*prepared, *committed, *aborted]:
                _validate_canon_manifest(
                    event.get("data"),
                    operation="promotion" if prepared_name == "canon.change-prepared" else "rollback",
                    location=f"event:{event.get('id')}.data",
                    transaction_id=transaction_id,
                    report=report,
                )
        elif prepared_name == "retention.apply-prepared":
            prepared_manifest = _retention_manifest(
                prepared[0].get("data") if prepared else None,
                location=f"event:{prepared[0]['id']}.data" if prepared else f"transaction:{transaction_id}",
                report=report,
            )
            for digest, size, _ in prepared_manifest[2]:
                _remember_object_reference(
                    digest, size, location=f"event:{prepared[0]['id']}.data.candidates.object",
                    report=report, references=all_referenced_digests,
                    expected_sizes=object_expected_sizes,
                )
            committed_manifest = None
            if committed:
                committed_manifest = _retention_manifest(
                    committed[0].get("data"), location=f"event:{committed[0]['id']}.data",
                    report=report, committed=True,
                )
            if prepared and committed and prepared_manifest[:2] != committed_manifest[:2]:
                _error(report, f"transaction:{transaction_id}", "retention prepared and committed identity differs")
            if prepared and committed and prepared_manifest[2] != committed_manifest[2]:
                _error(report, f"transaction:{transaction_id}", "retention prepared and committed candidates differ")
            if prepared and committed:
                prepared_plan = prepared_manifest[0]
                if prepared_plan is not None and committed_manifest is not None:
                    if committed_manifest[0] != prepared_plan:
                        _error(report, f"transaction:{transaction_id}", "retention plan differs between prepared and committed")
        if committed and committed_name.startswith("canon."):
            data = committed[0].get("data")
            if isinstance(data, Mapping) and isinstance(data.get("path"), str):
                latest_committed_by_path[data["path"]] = committed[0]

    # Payload lifecycle records are the per-Evidence side effects of a
    # retention transaction.  Tie them to the exact prepared/committed
    # manifest so an isolated payload.evicted event cannot fabricate a state
    # transition or hide a partially applied transaction.
    retention_transactions: dict[str, dict[str, Any]] = {}
    for transaction_id, grouped in transaction_events.items():
        prepared = [e for e in grouped if e.get("event_type") == "retention.apply-prepared"]
        committed = [e for e in grouped if e.get("event_type") == "retention.apply-committed"]
        # This loop has its own transaction scope.  Do not reuse the
        # ``aborted`` list from the manifest-validation loop above: that
        # would associate the last transaction's terminal event with every
        # retention transaction in this projection.
        aborted = [e for e in grouped if e.get("event_type") == "retention.apply-aborted"]
        if not prepared:
            continue
        plan, confirmation, candidates = _retention_manifest(
            prepared[0].get("data"), location=f"event:{prepared[0]['id']}.data", report=report
        )
        retention_transactions[transaction_id] = {
            "plan": plan, "confirmation": confirmation, "candidates": candidates,
            "committed": bool(committed),
            "prepared_event": prepared[0],
            "aborted_event": aborted[0] if len(aborted) == 1 else None,
        }
    payload_by_transaction: dict[str, list[dict[str, Any]]] = {}
    for event in ordered_events:
        event_type = event.get("event_type")
        if event_type not in {
            "payload.evicted", "payload-evicted", "payload.restored", "payload-restored",
        }:
            continue
        data = event.get("data")
        location = f"event:{event['id']}.data"
        if not isinstance(data, Mapping):
            _error(report, location, "payload lifecycle data must be a mapping")
            continue
        transaction_id = data.get("transaction_id")
        if not is_uuid7(transaction_id):
            _error(report, f"{location}.transaction_id", "must be a UUIDv7")
            continue
        transaction_id = str(transaction_id)
        transaction = retention_transactions.get(transaction_id)
        if transaction is None:
            _error(report, location, "payload lifecycle event has no retention transaction")
            continue
        payload_by_transaction.setdefault(transaction_id, []).append(event)
        if event_type in {"payload.evicted", "payload-evicted"}:
            digest = _digest_from_ref(data.get("object"))
            plan = data.get("plan")
            target = event.get("target")
            if digest is None:
                _error(report, f"{location}.object", "must be a sha256 object reference")
            if not is_uuid7(target):
                _error(report, f"event:{event['id']}", "payload eviction target must be an Evidence UUIDv7")
            if plan != transaction["plan"]:
                _error(report, f"{location}.plan", "does not match retention transaction")
            expected = {
                (candidate_digest, evidence_id)
                for candidate_digest, _, evidence_ids in transaction["candidates"]
                for evidence_id in evidence_ids
            }
            if digest is not None and is_uuid7(target) and (digest, str(target)) not in expected:
                _error(report, location, "payload eviction is not in the retention manifest")
        else:
            if transaction["committed"]:
                _error(report, location, "payload restore contradicts committed retention transaction")

    # An aborted retention transaction is terminal only after its exact
    # prepared manifest has been reconciled.  In particular, every eviction
    # published after prepare must have a subsequent, matching restore before
    # abort; this prevents a forged abort from hiding a partially evicted raw
    # object.  Keep this check sequence-sensitive: append-only history is the
    # recovery proof, not merely an unordered set of plausible events.
    for transaction_id, transaction in retention_transactions.items():
        aborted_event = transaction.get("aborted_event")
        if transaction["committed"] or not isinstance(aborted_event, Mapping):
            continue
        location = f"event:{aborted_event['id']}.data"
        aborted_data = aborted_event.get("data")
        aborted_manifest = _retention_manifest(
            aborted_data, location=location, report=report
        )
        prepared_identity = (
            transaction["plan"], transaction["confirmation"], transaction["candidates"]
        )
        if aborted_manifest != prepared_identity:
            _error(report, location, "retention aborted manifest differs from prepared manifest")
        if not isinstance(aborted_data, Mapping) or aborted_data.get("restored") is not True:
            _error(report, f"{location}.restored", "aborted retention terminal must prove restoration")

        prepared_event = transaction["prepared_event"]
        prepared_sequence = prepared_event.get("sequence")
        aborted_sequence = aborted_event.get("sequence")
        if not isinstance(prepared_sequence, int) or not isinstance(aborted_sequence, int):
            continue
        lifecycle = payload_by_transaction.get(transaction_id, [])
        all_evictions = [
            event for event in lifecycle
            if event.get("event_type") in {"payload.evicted", "payload-evicted"}
        ]
        all_restores = [
            event for event in lifecycle
            if event.get("event_type") in {"payload.restored", "payload-restored"}
        ]
        evictions = [
            event for event in lifecycle
            if event.get("event_type") in {"payload.evicted", "payload-evicted"}
            and isinstance(event.get("sequence"), int)
            and prepared_sequence < event["sequence"] < aborted_sequence
        ]
        for event in all_evictions:
            sequence = event.get("sequence")
            if not isinstance(sequence, int) or not prepared_sequence < sequence < aborted_sequence:
                _error(report, f"event:{event['id']}", "payload eviction is outside the prepared-to-aborted interval")
        for event in all_restores:
            sequence = event.get("sequence")
            if not isinstance(sequence, int) or not prepared_sequence < sequence < aborted_sequence:
                _error(report, f"event:{event['id']}", "payload restore is outside the prepared-to-aborted interval")
        restores = [
            event for event in lifecycle
            if event.get("event_type") in {"payload.restored", "payload-restored"}
            and isinstance(event.get("sequence"), int)
            and prepared_sequence < event["sequence"] < aborted_sequence
        ]

        candidate_sizes = {
            (digest, evidence_id): size
            for digest, size, evidence_ids in transaction["candidates"]
            for evidence_id in evidence_ids
        }
        # Include the manifest-derived size and lifecycle sensitivity in the
        # correspondence key.  The digest alone is not enough to prove that
        # a restore compensates the exact publication that was evicted.
        eviction_keys: list[tuple[str, str, int, str | None, str]] = []
        for event in evictions:
            data = event.get("data")
            digest = _digest_from_ref(data.get("object")) if isinstance(data, Mapping) else None
            target = event.get("target")
            plan = data.get("plan") if isinstance(data, Mapping) else None
            if digest is not None and is_uuid7(target) and plan == transaction["plan"]:
                size = candidate_sizes.get((digest, str(target)))
                if size is not None:
                    eviction_keys.append((str(target), digest, size, event.get("sensitivity"), str(plan)))

        restore_keys: list[tuple[str, str, int, str | None, str]] = []
        for event in restores:
            data = event.get("data")
            location_event = f"event:{event['id']}.data"
            if not isinstance(data, Mapping):
                continue
            digest = _digest_from_ref(data.get("object"))
            target = event.get("target")
            plan = data.get("plan")
            if data.get("transaction_id") != transaction_id:
                _error(report, f"{location_event}.transaction_id", "does not match retention transaction")
            if plan != transaction["plan"]:
                _error(report, f"{location_event}.plan", "does not match retention transaction")
            if digest is None:
                _error(report, f"{location_event}.object", "must be a sha256 object reference")
            if not is_uuid7(target):
                _error(report, f"event:{event['id']}", "payload restore target must be an Evidence UUIDv7")
            if digest is not None and is_uuid7(target) and plan == transaction["plan"]:
                size = candidate_sizes.get((digest, str(target)))
                if size is not None:
                    restore_keys.append((str(target), digest, size, event.get("sensitivity"), str(plan)))
                if size is None:
                    _error(report, location_event, "payload restore is not in the retention manifest")

            # A restore may not downgrade the effective sensitivity already
            # attached to this Evidence's history.
            capture = captures.get(str(target)) if is_uuid7(target) else None
            labels: list[Any] = [capture.get("sensitivity")] if isinstance(capture, Mapping) else []
            labels.extend(
                prior.get("sensitivity")
                for prior in ordered_events
                if prior.get("target") == target and prior.get("sequence", 0) < event["sequence"]
            )
            restore_sensitivity = event.get("sensitivity")
            if restore_sensitivity not in SENSITIVITY_RANK:
                _error(report, f"event:{event['id']}.sensitivity", "invalid sensitivity")
            elif labels and all(label in SENSITIVITY_RANK for label in labels):
                floor = max(SENSITIVITY_RANK[label] for label in labels)
                if SENSITIVITY_RANK[restore_sensitivity] < floor:
                    _error(report, f"event:{event['id']}.sensitivity", "cannot lower retention restoration sensitivity")

            if digest is not None and (digest, str(target)) in candidate_sizes:
                size = candidate_sizes[(digest, str(target))]
                safe, actual, actual_size = _stream_object(
                    _object_path(root, digest),
                    expected_digest=digest,
                    expected_size=size,
                    verify_hash=True,
                )
                if not safe or actual != digest or actual_size != size:
                    _error(report, location_event, "restored source object is missing or fails digest/size validation")

        expected_restored_evidence = aborted_data.get("restored_evidence") if isinstance(aborted_data, Mapping) else None
        if (
            not isinstance(expected_restored_evidence, list)
            or any(not is_uuid7(item) for item in expected_restored_evidence)
            or [str(item) for item in expected_restored_evidence] != [key[0] for key in eviction_keys]
        ):
            _error(report, f"{location}.restored_evidence", "must exactly match evicted Evidence in sequence")
        # Matching keys must also be ordered in the same way.  Explicitly
        # require the restore sequence to be after its corresponding eviction;
        # otherwise prepare -> restore -> evict -> abort could be mistaken for
        # a successful compensation merely because both sets match.
        if len(evictions) == len(restores):
            for eviction, restore in zip(evictions, restores):
                eviction_sequence = eviction.get("sequence")
                restore_sequence = restore.get("sequence")
                if (
                    not isinstance(eviction_sequence, int)
                    or not isinstance(restore_sequence, int)
                    or restore_sequence <= eviction_sequence
                ):
                    _error(
                        report,
                        f"event:{restore['id']}",
                        "payload restoration must follow its corresponding eviction",
                    )
        if restore_keys != eviction_keys:
            _error(report, f"transaction:{transaction_id}", "payload restoration set or order does not exactly match evictions")
        if len(eviction_keys) != len(set(eviction_keys)):
            _error(report, f"transaction:{transaction_id}", "payload eviction contains duplicate target/object entries")
        if len(restore_keys) != len(set(restore_keys)):
            _error(report, f"transaction:{transaction_id}", "payload restoration contains duplicate target/object entries")

    for transaction_id, transaction in retention_transactions.items():
        if not transaction["committed"]:
            continue
        expected = {
            (digest, evidence_id)
            for digest, _, evidence_ids in transaction["candidates"]
            for evidence_id in evidence_ids
        }
        actual = {
            (_digest_from_ref(event.get("data", {}).get("object")), str(event.get("target")))
            for event in payload_by_transaction.get(transaction_id, [])
            if event.get("event_type") in {"payload.evicted", "payload-evicted"}
            and isinstance(event.get("data"), Mapping)
        }
        payload_events = [
            event for event in payload_by_transaction.get(transaction_id, [])
            if event.get("event_type") in {"payload.evicted", "payload-evicted"}
        ]
        if actual != expected or len(payload_events) != len(expected):
            _error(report, f"transaction:{transaction_id}", "committed retention lacks the exact payload event set")

    for path_value, event in latest_committed_by_path.items():
        data = event.get("data", {})
        after = _digest_from_ref(data.get("after")) if isinstance(data, Mapping) else None
        # Resolve only for the containment check; retain the unresolved path
        # for the actual read so a final symlink cannot redirect validation to
        # bytes outside Canon.
        candidate_path = root / path_value
        path = candidate_path
        try:
            path.resolve().relative_to((root / "canon").resolve())
        except (OSError, ValueError):
            _error(report, f"event:{event['id']}", "Canon transaction path escapes canon/")
            continue
        if after is None:
            _error(report, f"event:{event['id']}", "committed Canon target or after snapshot is missing")
        else:
            safe, actual, _ = _stream_object(path, expected_digest=after, verify_hash=verify_hashes)
            if not safe:
                _error(report, f"event:{event['id']}", "committed Canon target is missing or unsafe")
            elif verify_hashes and actual != after:
                _error(report, path_value, "current Canon bytes drift from the latest committed transaction")

    # Candidate terminals are a second durable projection of Canon
    # promotions.  Keep an explicit cross-index so a plausible-looking UUID
    # cannot be accepted without the corresponding committed manifest.
    committed_promotions_by_transaction: dict[str, list[dict[str, Any]]] = {}
    committed_rollbacks_by_transaction: dict[str, list[dict[str, Any]]] = {}
    rollback_sources: set[str] = set()
    for event in ordered_events:
        data = event.get("data")
        if not isinstance(data, Mapping):
            continue
        if event.get("event_type") == "canon.rollback-committed":
            rollback_of = data.get("rollback_of")
            if isinstance(rollback_of, str):
                rollback_sources.add(rollback_of)
            transaction_id = data.get("transaction_id")
            if isinstance(transaction_id, str):
                committed_rollbacks_by_transaction.setdefault(transaction_id, []).append(event)
        if event.get("event_type") != "canon.change-committed":
            continue
        transaction_id = data.get("transaction_id")
        if isinstance(transaction_id, str):
            committed_promotions_by_transaction.setdefault(transaction_id, []).append(event)

    committed_transaction_ids = set(committed_promotions_by_transaction)
    for event in ordered_events:
        if event.get("event_type") != "canon.rollback-committed":
            continue
        data = event.get("data")
        rollback_of = data.get("rollback_of") if isinstance(data, Mapping) else None
        if not isinstance(rollback_of, str) or rollback_of not in committed_transaction_ids:
            _error(report, f"event:{event['id']}.data.rollback_of", "must resolve to a committed Canon promotion")

    for candidate_id, grouped in candidate_events.items():
        created = [event for event in grouped if event["event_type"] == "candidate.created"]
        terminals = [
            event for event in grouped
            if event["event_type"] in {"candidate.promoted", "candidate.rejected"}
        ]
        if len(created) != 1:
            _error(report, f"candidate:{candidate_id}", "must contain exactly one candidate.created event")
        # A committed Canon rollback may reopen a Candidate for a subsequent
        # promotion.  Permit repeated terminal events only across an explicit
        # candidate.reopened transition; two terminals without that transition
        # remain contradictory.
        candidate_state = "pending"
        for candidate_event in grouped:
            candidate_type = candidate_event.get("event_type")
            if candidate_type in {"candidate.promoted", "candidate.rejected"}:
                if candidate_state != "pending":
                    _error(report, f"candidate:{candidate_id}", "terminal event is not from a pending state")
                candidate_state = "promoted" if candidate_type == "candidate.promoted" else "rejected"
            elif candidate_type == "candidate.reopened":
                if candidate_state != "promoted":
                    _error(report, f"candidate:{candidate_id}", "reopen event is not after a promotion")
                candidate_state = "pending"
        if len(created) == 1:
            creation = created[0]
            location = f"event:{creation.get('id')}.data"
            data = creation.get("data")
            if not isinstance(data, Mapping):
                _error(report, location, "candidate.created data must be a mapping")
            else:
                if data.get("candidate_id") != candidate_id:
                    _error(report, location, "candidate_id does not match event target")
                target_document_id = data.get("target_document_id")
                if not is_uuid7(target_document_id):
                    _error(report, f"{location}.target_document_id", "must be a UUIDv7")
                    target_document_id = None
                target_sensitivity = document_sensitivities.get(str(target_document_id), "")
                if target_document_id is not None and str(target_document_id) not in semantic_ids:
                    _error(report, f"{location}.target_document_id", "does not resolve to a Canon document")
                _validate_candidate_proposal(
                    data.get("claim"), location=f"{location}.claim", report=report,
                    document_id=str(target_document_id) if target_document_id else None,
                    document_sensitivity=target_sensitivity if target_sensitivity else "personal",
                )
                creation_sensitivity = creation.get("sensitivity")
                if creation_sensitivity not in SENSITIVITIES:
                    _error(report, f"event:{creation.get('id')}.sensitivity", "invalid sensitivity")
                elif target_sensitivity and SENSITIVITY_RANK[creation_sensitivity] < SENSITIVITY_RANK[target_sensitivity]:
                    _error(report, f"event:{creation.get('id')}.sensitivity", "cannot lower target document sensitivity")
                claim_sensitivity = data.get("claim", {}).get("sensitivity", target_sensitivity) if isinstance(data.get("claim"), Mapping) else None
                if claim_sensitivity not in SENSITIVITIES:
                    _error(report, f"{location}.claim.sensitivity", "invalid sensitivity")
                elif creation_sensitivity in SENSITIVITY_RANK and SENSITIVITY_RANK[creation_sensitivity] < SENSITIVITY_RANK[claim_sensitivity]:
                    _error(report, f"event:{creation.get('id')}.sensitivity", "cannot lower Candidate Claim sensitivity")
        for terminal_event in terminals:
            data = terminal_event.get("data")
            location = f"event:{terminal_event.get('id')}.data"
            if not isinstance(data, Mapping) or data.get("candidate_id") != candidate_id:
                _error(report, location, "candidate terminal data is inconsistent")
            elif terminal_event.get("event_type") == "candidate.promoted":
                transaction_id = data.get("transaction_id")
                claim_id = data.get("claim_id")
                if not is_uuid7(transaction_id):
                    _error(report, f"{location}.transaction_id", "must be a UUIDv7")
                if not is_uuid7(claim_id):
                    _error(report, f"{location}.claim_id", "must be a UUIDv7")
                if is_uuid7(transaction_id) and is_uuid7(claim_id):
                    matching = committed_promotions_by_transaction.get(transaction_id, [])
                    if len(matching) != 1:
                        _error(
                            report, location,
                            "transaction_id must resolve to exactly one committed Canon promotion",
                        )
                    else:
                        promotion_data = matching[0].get("data")
                        if not isinstance(promotion_data, Mapping):
                            _error(report, location, "committed Canon promotion data is invalid")
                        else:
                            if promotion_data.get("candidate") != candidate_id:
                                _error(report, location, "promotion candidate does not match terminal candidate")
                            if promotion_data.get("claim") != claim_id:
                                _error(report, location, "promotion Claim does not match terminal Claim")
            elif not isinstance(data.get("reason"), str) or not data["reason"].strip():
                _error(report, f"{location}.reason", "must be a non-empty string")
            terminal_sensitivity = terminal_event.get("sensitivity")
            if terminal_sensitivity not in SENSITIVITIES:
                _error(report, f"event:{terminal_event.get('id')}.sensitivity", "invalid sensitivity")
            elif created and created[0].get("sensitivity") in SENSITIVITY_RANK and SENSITIVITY_RANK[terminal_sensitivity] < SENSITIVITY_RANK[created[0].get("sensitivity")]:
                _error(report, f"event:{terminal_event.get('id')}.sensitivity", "cannot lower Candidate creation sensitivity")

        for reopen_event in [event for event in grouped if event.get("event_type") == "candidate.reopened"]:
            data = reopen_event.get("data")
            location = f"event:{reopen_event.get('id')}.data"
            if not isinstance(data, Mapping) or data.get("candidate_id") != candidate_id:
                _error(report, location, "candidate reopen data is inconsistent")
                continue
            for field in ("transaction_id", "claim_id", "rollback_id"):
                if not is_uuid7(data.get(field)):
                    _error(report, f"{location}.{field}", "must be a UUIDv7")
            if created and is_uuid7(data.get("transaction_id")) and is_uuid7(data.get("claim_id")):
                matching_terminal = [
                    event for event in terminals
                    if event.get("event_type") == "candidate.promoted"
                    and isinstance(event.get("data"), Mapping)
                    and event["data"].get("transaction_id") == data.get("transaction_id")
                    and event["data"].get("claim_id") == data.get("claim_id")
                ]
                if len(matching_terminal) != 1:
                    _error(report, location, "reopen does not match exactly one Candidate promotion")
                source_promotions = committed_promotions_by_transaction.get(str(data.get("transaction_id")), [])
                rollback_events = committed_rollbacks_by_transaction.get(str(data.get("rollback_id")), [])
                if len(source_promotions) != 1:
                    _error(report, location, "reopen promotion does not resolve to exactly one committed Canon promotion")
                if len(rollback_events) != 1:
                    _error(report, location, "reopen rollback_id does not resolve to exactly one committed Canon rollback")
                elif len(source_promotions) == 1:
                    source_data = source_promotions[0].get("data")
                    rollback_data = rollback_events[0].get("data")
                    if not isinstance(source_data, Mapping) or not isinstance(rollback_data, Mapping):
                        _error(report, location, "reopen Canon manifests are invalid")
                    elif (
                        rollback_events[0].get("target") != data.get("rollback_id")
                        or rollback_data.get("operation") != "rollback"
                        or rollback_data.get("rollback_of") != data.get("transaction_id")
                        or rollback_data.get("candidate") != candidate_id
                        or rollback_data.get("claim") != data.get("claim_id")
                        or source_data.get("candidate") != candidate_id
                        or source_data.get("claim") != data.get("claim_id")
                        or rollback_data.get("document") != source_data.get("document")
                        or rollback_data.get("path") != source_data.get("path")
                        or rollback_data.get("before") != source_data.get("after")
                        or rollback_data.get("after") != source_data.get("before")
                    ):
                        _error(report, location, "reopen rollback manifest disagrees with Canon promotion")
            reopen_sensitivity = reopen_event.get("sensitivity")
            if reopen_sensitivity not in SENSITIVITIES:
                _error(report, f"event:{reopen_event.get('id')}.sensitivity", "invalid sensitivity")
            elif created and created[0].get("sensitivity") in SENSITIVITY_RANK and SENSITIVITY_RANK[reopen_sensitivity] < SENSITIVITY_RANK[created[0].get("sensitivity")]:
                _error(report, f"event:{reopen_event.get('id')}.sensitivity", "cannot lower Candidate creation sensitivity")

    # Every non-rolled-back committed promotion must have exactly one matching
    # Candidate terminal.  A missing terminal is a crash-recovery gap, while a
    # rejection is an explicit contradiction that must remain visible.
    terminal_by_candidate: dict[str, list[dict[str, Any]]] = {}
    for candidate_id, grouped in candidate_events.items():
        terminal_by_candidate[candidate_id] = [
            event for event in grouped
            if event.get("event_type") in {"candidate.promoted", "candidate.rejected"}
        ]
    for transaction_id, promotion_events in committed_promotions_by_transaction.items():
        if transaction_id in rollback_sources:
            continue
        for promotion_event in promotion_events:
            data = promotion_event.get("data")
            if not isinstance(data, Mapping):
                continue
            candidate_id = data.get("candidate")
            claim_id = data.get("claim")
            if not (is_uuid7(candidate_id) and is_uuid7(claim_id)):
                continue
            terminals = terminal_by_candidate.get(candidate_id, [])
            matching_promoted = [
                event for event in terminals
                if event.get("event_type") == "candidate.promoted"
                and isinstance(event.get("data"), Mapping)
                and event["data"].get("transaction_id") == transaction_id
                and event["data"].get("claim_id") == claim_id
            ]
            if len(matching_promoted) != 1:
                _error(
                    report, f"transaction:{transaction_id}",
                    "committed Canon promotion lacks exactly one matching candidate.promoted terminal",
                )
            if any(event.get("event_type") == "candidate.rejected" for event in terminals):
                _error(
                    report, f"transaction:{transaction_id}",
                    "candidate.rejected contradicts committed Canon promotion",
                )

    # Resolve effective states once, in global sequence order.
    events_by_target: dict[str, list[dict[str, Any]]] = {}
    for event in ordered_events:
        target = event.get("target")
        if isinstance(target, str):
            events_by_target.setdefault(target, []).append(event)

    effective: dict[str, dict[str, Any]] = {}
    for evidence_id, capture in captures.items():
        projected = json.loads(json.dumps(capture))
        projected.setdefault("representations", [])
        projected.setdefault("payload", {})
        for event in events_by_target.get(evidence_id, []):
            kind = event["event_type"].replace(".", "-")
            if kind == "representation-added":
                projected["representations"].extend(dict(item) for item in _event_representations(event))
            elif kind == "retention-changed":
                data = event.get("data")
                if not isinstance(data, Mapping):
                    continue
                old_class = data.get("from")
                new_class = data.get("to")
                if (
                    old_class not in CHANGEABLE_RETENTION_CLASSES
                    or new_class not in CHANGEABLE_RETENTION_CLASSES
                ):
                    continue
                current_class = projected.get("payload", {}).get("retention")
                if current_class != old_class:
                    _error(
                        report,
                        f"event:{event['id']}.data.from",
                        f"does not match effective retention class {current_class!r}",
                    )
                    continue
                projected["payload"]["retention"] = new_class
                projected["payload"]["changed_at"] = event["recorded_at"]
            elif kind in {"payload-evicted", "payload-redacted", "payload-missing-observed"}:
                projected["payload"].pop("object", None)
                projected["payload"]["state"] = (
                    "evicted" if kind.endswith("evicted")
                    else "missing" if kind.endswith("missing-observed")
                    else "redacted"
                )
            elif kind == "payload-restored":
                projected["payload"]["state"] = "present"
                digest = projected.get("content", {}).get("sha256")
                if isinstance(digest, str):
                    projected["payload"]["object"] = f"sha256:{digest}"
        effective[evidence_id] = projected
        rel = capture_locations[evidence_id]
        payload = projected.get("payload", {})
        digest = projected.get("content", {}).get("sha256")
        if payload.get("state") == "present" and isinstance(digest, str):
            if payload.get("object") != f"sha256:{digest}":
                _error(report, rel, "present payload object must match content.sha256")
            path = _object_path(root, digest)
            expected_size = projected.get("content", {}).get("size")
            safe, actual, size = _stream_object(
                path, expected_digest=digest,
                expected_size=expected_size if isinstance(expected_size, int) and not isinstance(expected_size, bool) else None,
                verify_hash=verify_hashes,
            )
            if not safe:
                _error(report, rel, "effective present payload object is missing or unsafe")
            elif verify_hashes and actual != digest:
                _error(report, rel, "effective present payload object hash does not match content.sha256")
            elif isinstance(expected_size, int) and not isinstance(expected_size, bool) and size != expected_size:
                _error(report, rel, "payload size does not match content.size")
            required_object_digests.add(digest)
        for index, representation in enumerate(projected.get("representations", [])):
            digest = _digest_from_ref(representation.get("object")) if isinstance(representation, Mapping) else None
            if digest is None:
                _error(report, f"{rel}:representations[{index}]", "invalid object reference")
            else:
                representation_size = representation.get("size") if isinstance(representation, Mapping) else None
                safe, actual, size = _stream_object(
                    _object_path(root, digest),
                    expected_digest=digest,
                    expected_size=representation_size if isinstance(representation_size, int) and not isinstance(representation_size, bool) else None,
                    verify_hash=verify_hashes,
                )
                if not safe:
                    _error(report, f"{rel}:representations[{index}]", "retained representation object is missing or unsafe")
                elif verify_hashes and actual != digest:
                    _error(report, f"{rel}:representations[{index}]", "representation object hash does not match its path")
                required_object_digests.add(digest)

    # A Claim inherits its document sensitivity unless explicitly raised. Every
    # cited Evidence record is also raised by the complete lifecycle stream
    # targeted at that record, not merely by the capture's original envelope.
    effective_sensitivities: dict[str, str] = {}
    for evidence_id, capture in captures.items():
        values: list[Any] = [capture.get("sensitivity")]
        values.extend(event.get("sensitivity") for event in events_by_target.get(evidence_id, []))
        if any(value not in SENSITIVITY_RANK for value in values):
            _error(report, f"evidence:{evidence_id}", "effective sensitivity contains an unknown value")
            continue
        effective_sensitivities[evidence_id] = max(values, key=lambda value: SENSITIVITY_RANK[value])
    for claim_id, (claim_sensitivity, location) in claim_sensitivities.items():
        if claim_sensitivity not in SENSITIVITY_RANK:
            _error(report, f"{location}.sensitivity", "invalid effective Claim sensitivity")
            continue
        claim = claims[claim_id][0]
        evidence = claim.get("evidence", []) if isinstance(claim, Mapping) else []
        for index, item in enumerate(evidence):
            edge = _evidence_edge(
                item, legacy_allowed=True, location=f"{location}.evidence[{index}]", report=report
            )
            if not edge:
                continue
            evidence_sensitivity = effective_sensitivities.get(edge[0])
            if evidence_sensitivity is None:
                continue
            if SENSITIVITY_RANK[claim_sensitivity] < SENSITIVITY_RANK[evidence_sensitivity]:
                _error(
                    report,
                    f"{location}.sensitivity",
                    f"Claim sensitivity is lower than effective Evidence {edge[0]} sensitivity",
                )

    for location, evidence_id, requirement in claim_edges:
        projected = effective.get(evidence_id)
        if projected is None:
            _error(report, f"{location}.evidence", f"unresolved Evidence ID {evidence_id}")
            continue
        if requirement == "raw":
            if projected.get("payload", {}).get("state") != "present":
                _error(report, f"{location}.evidence", f"raw requirement is unsatisfied for {evidence_id}")
        elif requirement.startswith("representation:"):
            role = requirement.split(":", 1)[1]
            matching = [
                item for item in projected.get("representations", [])
                if isinstance(item, Mapping) and item.get("role") == role
            ]
            if not matching:
                _error(report, f"{location}.evidence", f"representation:{role} is unsatisfied for {evidence_id}")

    checked: set[str] = set()
    inventory: dict[str, Path] = {}
    for path in _iter_object_files(root, report):
        rel = path.relative_to(root).as_posix()
        digest = path.name
        expected = _object_path(root, digest) if SHA256_RE.fullmatch(digest) else None
        if expected is None or path != expected:
            _error(report, rel, "object path is not the canonical SHA-256 path")
            continue
        inventory[digest] = path
        expected_sizes = object_expected_sizes.get(digest, set())
        if len(expected_sizes) > 1:
            _error(report, rel, "object references disagree on expected size")
        expected_size = next(iter(expected_sizes), None)
        safe, actual, size = _stream_object(
            path, expected_digest=digest, expected_size=expected_size,
            verify_hash=verify_hashes,
        )
        report.objects_checked += 1
        checked.add(digest)
        if not safe:
            _error(report, rel, "object is unsafe, changed while reading, or has an unexpected size")
        elif verify_hashes and actual != digest:
            _error(report, rel, "object content does not match its path digest")
        if digest not in all_referenced_digests:
            _warn(report, rel, "orphan object is not referenced by durable data")

    # Object existence for references is checked after inventory so an evicted raw
    # digest can remain referenced historically without being treated as missing.
    for digest in sorted(required_object_digests):
        path = _object_path(root, digest)
        if digest not in inventory:
            _error(report, path.relative_to(root).as_posix(), "referenced object is missing or unsafe")
            continue
        if digest not in checked:
            expected_sizes = object_expected_sizes.get(digest, set())
            expected_size = next(iter(expected_sizes), None) if len(expected_sizes) == 1 else None
            safe, actual, _ = _stream_object(
                path, expected_digest=digest, expected_size=expected_size,
                verify_hash=verify_hashes,
            )
            report.objects_checked += 1
            if not safe:
                _error(report, path.relative_to(root).as_posix(), "referenced object is unsafe or changed while reading")
            elif verify_hashes and actual != digest:
                _error(report, path.relative_to(root).as_posix(), "object hash mismatch")

    return report


def validate_vault(root: Path, verify_hashes: bool = True) -> ValidationReport:
    """Validate one coherent durable snapshot under the vault writer lock.

    Validation reads Canon, Evidence, policies, and Objects as one operation.
    Writers use the same re-entrant lock, so nested validation (for example a
    service health check invoked by a writer) cannot deadlock or observe a
    mixed pre/post-publication state.
    """

    supplied = Path(root).expanduser().absolute()
    try:
        status = os.lstat(supplied)
    except OSError:
        return _validate_vault_unlocked(supplied, verify_hashes=verify_hashes)
    if supplied.is_symlink() or not stat.S_ISDIR(status.st_mode):
        return _validate_vault_unlocked(supplied, verify_hashes=verify_hashes)
    lock_path = supplied / "runtime" / "locks" / "writer.lock"
    lock_context = file_lock(lock_path, boundary=supplied)
    try:
        lock_context.__enter__()
    except (OSError, ValueError):
        report = ValidationReport()
        _error(report, "runtime/locks/writer.lock", "vault writer lock is unavailable")
        return report
    try:
        return _validate_vault_unlocked(supplied, verify_hashes=verify_hashes)
    finally:
        lock_context.__exit__(None, None, None)
