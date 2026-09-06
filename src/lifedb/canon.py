from __future__ import annotations

import hashlib
import json
import math
import os
import re
import secrets
import stat
from contextlib import contextmanager
from copy import deepcopy
from datetime import date, datetime
from pathlib import Path
from typing import Any, Iterator, Mapping
from urllib.parse import urlparse

import yaml

from .ids import is_uuid7, new_id
from .markdown import (
    MAX_MARKDOWN_BYTES,
    MAX_FRONTMATTER_BYTES,
    MarkdownDocument,
    BoundedStringTimestampSafeLoader,
    canon_documents,
)
from .evidence import iter_events, read_event
from .storage import DurablePublicationUncertain, file_lock, read_bounded_regular_file


PREDICATE_RE = re.compile(r"^[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*$")
ROLE_RE = re.compile(r"^[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
MAX_EVIDENCE_OBJECT_BYTES = 64 * 1024 * 1024
DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
DATETIME_RE = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$"
)

BASES = {"declared", "observed", "inferred", "imported", "computed"}
CERTAINTIES = {"confirmed", "probable", "tentative", "unknown"}
SENSITIVITIES = {"public", "personal", "sensitive", "restricted"}
SENSITIVITY_RANK = {
    "public": 0,
    "personal": 1,
    "sensitive": 2,
    "restricted": 3,
}
OBJECT_KEYS = {"ref", "text", "boolean", "number", "date", "datetime", "uri", "json"}
PROTECTED_CLAIM_FIELDS = {"id", "subject", "state", "superseded_by"}


class CanonError(RuntimeError):
    """Base class for safe Canon mutation failures."""


class CanonNotFoundError(CanonError):
    """A semantic document, Claim, Evidence record, or transaction was absent."""


class CanonIntegrityError(CanonError):
    """Durable data is malformed or has inconsistent references."""


class ConcurrentCanonChangeError(CanonError):
    """Canon changed after the transaction snapshot was prepared."""


class CanonTransactionError(CanonError):
    """A transaction failed and was compensated where possible."""


def _parse_datetime(value: Any, field: str) -> datetime:
    if not isinstance(value, str) or DATETIME_RE.fullmatch(value) is None:
        raise ValueError(f"{field} must be an RFC 3339 date-time string")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"{field} must be an RFC 3339 date-time string") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError(f"{field} must include an explicit UTC offset")
    return parsed


def _parse_temporal(value: Any, field: str) -> tuple[str, date | datetime]:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{field} must be an RFC 3339 date or date-time string")
    if DATE_RE.fullmatch(value):
        try:
            return "date", date.fromisoformat(value)
        except ValueError as exc:
            raise ValueError(f"{field} must be a valid RFC 3339 full-date") from exc
    return "datetime", _parse_datetime(value, field)


def _validate_object(value: Any) -> None:
    if not isinstance(value, Mapping):
        raise ValueError("claim object must be a mapping")
    typed = OBJECT_KEYS.intersection(value)
    if len(typed) != 1:
        raise ValueError("claim object must contain exactly one typed value")
    kind = next(iter(typed))
    allowed = {kind, "unit"} if kind == "number" else {kind}
    extras = set(value).difference(allowed)
    if extras:
        raise ValueError(f"claim object has unsupported fields: {', '.join(sorted(extras))}")

    item = value[kind]
    if kind == "ref":
        if not is_uuid7(item):
            raise ValueError("claim object ref must be a UUIDv7")
    elif kind == "text":
        if not isinstance(item, str):
            raise ValueError("claim object text must be a string")
    elif kind == "boolean":
        if not isinstance(item, bool):
            raise ValueError("claim object boolean must be a boolean")
    elif kind == "number":
        if isinstance(item, bool) or not isinstance(item, (int, float)):
            raise ValueError("claim object number must be a JSON number")
        if isinstance(item, float) and not math.isfinite(item):
            raise ValueError("claim object number must be finite")
        unit = value.get("unit")
        if "unit" in value and (not isinstance(unit, str) or not unit.strip()):
            raise ValueError("claim object unit must be a non-empty string")
    elif kind == "date":
        temporal_kind, _ = _parse_temporal(item, "claim object date")
        if temporal_kind != "date":
            raise ValueError("claim object date must be an RFC 3339 full-date")
    elif kind == "datetime":
        _parse_datetime(item, "claim object datetime")
    elif kind == "uri":
        if not isinstance(item, str) or any(character.isspace() for character in item):
            raise ValueError("claim object uri must be an absolute URI")
        try:
            parsed = urlparse(item)
            if parsed.username is not None or parsed.password is not None:
                raise ValueError("claim object uri must not contain userinfo")
        except ValueError as exc:
            raise ValueError("claim object uri must be an absolute URI without userinfo") from exc
        if not parsed.scheme or (parsed.scheme in {"http", "https"} and not parsed.netloc):
            raise ValueError("claim object uri must be an absolute URI")
    else:
        try:
            json.dumps(item, ensure_ascii=False, allow_nan=False)
        except (TypeError, ValueError) as exc:
            raise ValueError("claim object json must be a JSON value") from exc


def _validate_evidence_item(value: Any, index: int) -> str:
    location = f"claim evidence[{index}]"
    if is_uuid7(value):
        return value
    if not isinstance(value, Mapping):
        raise ValueError(f"{location} must be a UUIDv7 or an id/requires mapping")
    if set(value) != {"id", "requires"}:
        raise ValueError(f"{location} mapping must contain exactly id and requires")
    evidence_id = value.get("id")
    if not is_uuid7(evidence_id):
        raise ValueError(f"{location}.id must be a UUIDv7")
    requires = value.get("requires")
    role = requires.partition(":")[2] if isinstance(requires, str) else ""
    if not isinstance(requires, str) or (
        requires not in {"raw", "record-only"}
        and not (requires.startswith("representation:") and ROLE_RE.fullmatch(role))
    ):
        raise ValueError(
            f"{location}.requires must be raw, record-only, or representation:<role>"
        )
    return evidence_id


def validate_claim_proposal(proposal: Mapping[str, Any]) -> dict[str, Any]:
    """Validate and defensively copy a Candidate Claim proposal.

    Candidate evidence carries promotion requirements. Canon preserves the
    explicit id/requirement mappings after those requirements have been checked.
    """

    if not isinstance(proposal, Mapping):
        raise ValueError("claim proposal must be a mapping")
    protected = PROTECTED_CLAIM_FIELDS.intersection(proposal)
    if protected:
        raise ValueError(
            "claim proposal cannot set promotion-owned fields: "
            + ", ".join(sorted(protected))
        )
    required = {
        "predicate",
        "object",
        "statement",
        "basis",
        "certainty",
        "observed_at",
        "evidence",
    }
    missing = required.difference(proposal)
    if missing:
        raise ValueError("claim proposal missing: " + ", ".join(sorted(missing)))

    predicate = proposal.get("predicate")
    if not isinstance(predicate, str) or PREDICATE_RE.fullmatch(predicate) is None:
        raise ValueError("claim predicate has an invalid form")
    _validate_object(proposal.get("object"))
    statement = proposal.get("statement")
    if not isinstance(statement, str) or not statement.strip():
        raise ValueError("claim statement must be a non-empty string")
    if proposal.get("basis") not in BASES:
        raise ValueError("claim basis is invalid")
    if proposal.get("certainty") not in CERTAINTIES:
        raise ValueError("claim certainty is invalid")
    _parse_datetime(proposal.get("observed_at"), "claim observed_at")

    evidence = proposal.get("evidence")
    if not isinstance(evidence, list) or not evidence:
        raise ValueError("claim evidence must be a non-empty list")
    evidence_ids = [_validate_evidence_item(item, index) for index, item in enumerate(evidence)]
    if len(evidence_ids) != len(set(evidence_ids)):
        raise ValueError("claim evidence must not contain duplicate Evidence IDs")

    validity = proposal.get("valid")
    if validity is not None:
        if not isinstance(validity, Mapping):
            raise ValueError("claim valid must be a mapping")
        if not validity:
            raise ValueError("claim valid must contain from and/or until")
        extra_bounds = set(validity).difference({"from", "until"})
        if extra_bounds:
            raise ValueError("claim valid has unsupported fields")
        parsed_bounds: dict[str, tuple[str, date | datetime]] = {}
        for bound in ("from", "until"):
            if bound in validity:
                parsed_bounds[bound] = _parse_temporal(validity[bound], f"claim valid.{bound}")
        if "from" in parsed_bounds and "until" in parsed_bounds:
            from_kind, from_value = parsed_bounds["from"]
            until_kind, until_value = parsed_bounds["until"]
            if from_kind != until_kind:
                raise ValueError("claim valid.from and valid.until must use the same precision")
            if from_value >= until_value:  # type: ignore[operator]
                raise ValueError("claim valid.until must be later than valid.from")

    sensitivity = proposal.get("sensitivity")
    if sensitivity is not None and sensitivity not in SENSITIVITIES:
        raise ValueError("claim sensitivity is invalid")

    supersedes = proposal.get("supersedes")
    if supersedes is not None:
        if not isinstance(supersedes, list):
            raise ValueError("claim supersedes must be a list")
        if any(not is_uuid7(item) for item in supersedes):
            raise ValueError("claim supersedes must contain UUIDv7 values")
        if len(supersedes) != len(set(supersedes)):
            raise ValueError("claim supersedes must not contain duplicates")

    try:
        copied = deepcopy(dict(proposal))
        # Newly written v0.2 data is explicit.  A bare UUID is accepted only as
        # a conservative v0.1 input and is upgraded to the equivalent raw
        # requirement before any Candidate event is appended.
        copied["evidence"] = [
            {"id": item, "requires": "raw"} if isinstance(item, str) else deepcopy(dict(item))
            for item in evidence
        ]
        yaml.safe_dump(copied, allow_unicode=True)
    except (TypeError, yaml.YAMLError) as exc:
        raise ValueError("claim proposal must be safely YAML-serializable") from exc
    return copied


def _evidence_id(item: str | Mapping[str, Any]) -> str:
    return item if isinstance(item, str) else str(item["id"])


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _object_digest(stored: Any) -> str:
    value = stored[0] if isinstance(stored, tuple) else stored
    if not isinstance(value, str):
        raise CanonIntegrityError("Vault.store_object did not return a digest")
    digest = value.removeprefix("sha256:")
    if SHA256_RE.fullmatch(digest) is None:
        raise CanonIntegrityError("Vault.store_object returned an invalid digest")
    return digest


def _object_reference(digest: str) -> str:
    return f"sha256:{digest}"


def _reference_digest(reference: Any, field: str) -> str:
    if not isinstance(reference, str):
        raise CanonIntegrityError(f"{field} snapshot reference is missing")
    digest = reference.removeprefix("sha256:")
    if SHA256_RE.fullmatch(digest) is None:
        raise CanonIntegrityError(f"{field} snapshot reference is invalid")
    return digest


def _render_markdown(frontmatter: Mapping[str, Any], body: str) -> bytes:
    rendered = yaml.safe_dump(
        dict(frontmatter),
        allow_unicode=True,
        default_flow_style=False,
        sort_keys=False,
    )
    return ("---\n" + rendered + "---\n" + body).encode("utf-8")


def _parse_markdown_snapshot(path: Path) -> tuple[MarkdownDocument, bytes]:
    """Parse one exact byte snapshot so compare-and-swap covers what we edited."""

    # Reuse markdown.py's O_NOFOLLOW, regular-file, and size-bound reader.  The
    # bytes are parsed from this same read, so the CAS digest and YAML view can
    # never describe two different file versions.
    try:
        data = _read_snapshot_file(path, "Canon document")
    except (OSError, ValueError) as exc:
        raise CanonIntegrityError(f"cannot read Canon document safely: {path}: {exc}") from exc
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise CanonIntegrityError(f"Canon document is not UTF-8: {path}") from exc
    if not text.startswith("---\n"):
        raise CanonIntegrityError(f"missing opening YAML frontmatter delimiter: {path}")
    end = text.find("\n---\n", 4)
    if end < 0:
        raise CanonIntegrityError(f"missing closing YAML frontmatter delimiter: {path}")
    raw_frontmatter = text[4:end]
    if len(raw_frontmatter.encode("utf-8")) > MAX_FRONTMATTER_BYTES:
        raise CanonIntegrityError(f"YAML frontmatter exceeds the size limit: {path}")
    try:
        frontmatter = yaml.load(raw_frontmatter, Loader=BoundedStringTimestampSafeLoader)
    except (yaml.YAMLError, RecursionError, MemoryError) as exc:
        raise CanonIntegrityError(f"invalid YAML frontmatter: {path}: {exc}") from exc
    if not isinstance(frontmatter, dict):
        raise CanonIntegrityError(f"frontmatter must be a mapping: {path}")
    return MarkdownDocument(path=path, frontmatter=frontmatter, body=text[end + 5 :]), data


def _assert_no_symlink_components(path: Path, boundary: Path) -> None:
    """Reject symlinked parents before any bounded read or replacement."""
    path = Path(path).absolute()
    boundary = Path(boundary).absolute()
    try:
        relative = path.relative_to(boundary)
    except ValueError as exc:
        raise CanonIntegrityError("path escapes the durable vault boundary") from exc
    if any(component in {"", ".", ".."} for component in relative.parts):
        raise CanonIntegrityError("durable path is not normalized")
    cursor = boundary
    try:
        status = os.lstat(cursor)
    except OSError as exc:
        raise CanonIntegrityError("durable vault boundary cannot be inspected") from exc
    if not stat.S_ISDIR(status.st_mode):
        raise CanonIntegrityError("durable vault boundary is not a directory")
    for component in relative.parts[:-1]:
        cursor = cursor / component
        try:
            status = os.lstat(cursor)
        except OSError as exc:
            raise CanonIntegrityError("durable path cannot be inspected") from exc
        if not stat.S_ISDIR(status.st_mode):
            raise CanonIntegrityError("durable path parent must be a real directory")


def _read_snapshot_file(
    path: Path,
    label: str,
    *,
    max_bytes: int = MAX_MARKDOWN_BYTES,
    boundary: Path | None = None,
) -> bytes:
    """Read one regular durable file exactly once with an explicit ceiling."""
    path = Path(path).absolute()
    # Snapshot Objects and Canon files must remain inside this vault.  The
    # caller supplies paths rooted under ``root``; deriving the boundary from
    # a ``canon`` path also keeps this helper useful for standalone tests.
    if boundary is None:
        boundary = path
        for parent in path.parents:
            if parent.name in {"canon", "objects"}:
                boundary = parent.parent
                break
    _assert_no_symlink_components(path, boundary)
    try:
        return read_bounded_regular_file(path, max_bytes=max_bytes)
    except (OSError, ValueError) as exc:
        raise CanonIntegrityError(f"cannot read {label} safely: {path}: {exc}") from exc


def _atomic_replace(
    path: Path,
    data: bytes,
    *,
    expected_digest: str | None = None,
    boundary: Path | None = None,
) -> None:
    path = Path(path).absolute()
    if len(data) > MAX_MARKDOWN_BYTES:
        raise ValueError("Canon replacement exceeds the size limit")
    # Canon writes never create arbitrary directories.  Every existing parent
    # and the destination itself must be a real, in-boundary filesystem entry.
    boundary = Path(boundary or path.parent).absolute()
    _assert_no_symlink_components(path, boundary)
    try:
        relative = path.relative_to(boundary)
    except ValueError as exc:
        raise CanonIntegrityError("Canon replacement is outside its boundary") from exc
    components = relative.parts
    if not components or any(component in {"", ".", ".."} for component in components):
        raise CanonIntegrityError("Canon replacement path is invalid")
    directory_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    directory_descriptor = os.open(boundary, directory_flags)
    temporary_name: str | None = None
    try:
        # Resolve every component from a root-anchored descriptor. A lexical
        # path check alone permits an attacker to swap an ancestor after the
        # check and redirect the replacement outside Canon.
        for component in components[:-1]:
            child = os.open(component, directory_flags, dir_fd=directory_descriptor)
            os.close(directory_descriptor)
            directory_descriptor = child
        destination_name = components[-1]
        try:
            destination_status = os.stat(
                destination_name, dir_fd=directory_descriptor, follow_symlinks=False
            )
        except FileNotFoundError:
            destination_status = None
        if destination_status is not None and not stat.S_ISREG(destination_status.st_mode):
            raise CanonIntegrityError("Canon destination must be a regular file")
        previous_mode = destination_status.st_mode & 0o777 if destination_status else 0o600
        if expected_digest is not None:
            if destination_status is None:
                raise ConcurrentCanonChangeError(f"Canon changed concurrently: {path}")
            try:
                current_descriptor = os.open(
                    destination_name,
                    os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0),
                    dir_fd=directory_descriptor,
                )
            except OSError as exc:
                raise ConcurrentCanonChangeError(f"Canon changed concurrently: {path}") from exc
            try:
                opened = os.fstat(current_descriptor)
                if (opened.st_dev, opened.st_ino) != (destination_status.st_dev, destination_status.st_ino):
                    raise ConcurrentCanonChangeError(f"Canon changed concurrently: {path}")
                chunks: list[bytes] = []
                remaining = MAX_MARKDOWN_BYTES + 1
                while remaining:
                    chunk = os.read(current_descriptor, min(64 * 1024, remaining))
                    if not chunk:
                        break
                    chunks.append(chunk)
                    remaining -= len(chunk)
                current = b"".join(chunks)
                finished = os.fstat(current_descriptor)
                identity_fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
                if any(
                    getattr(finished, field) != getattr(opened, field)
                    for field in identity_fields
                ):
                    raise ConcurrentCanonChangeError(f"Canon changed concurrently: {path}")
                try:
                    final_status = os.stat(
                        destination_name, dir_fd=directory_descriptor, follow_symlinks=False
                    )
                except OSError as exc:
                    raise ConcurrentCanonChangeError(f"Canon changed concurrently: {path}") from exc
                if any(
                    getattr(final_status, field) != getattr(opened, field)
                    for field in identity_fields
                ):
                    raise ConcurrentCanonChangeError(f"Canon changed concurrently: {path}")
                if len(current) > MAX_MARKDOWN_BYTES or _sha256(current) != expected_digest:
                    raise ConcurrentCanonChangeError(f"Canon changed concurrently: {path}")
            finally:
                os.close(current_descriptor)

        # mkstemp(dir=path) is still vulnerable after the parent check. Create
        # the temporary file relative to the verified parent descriptor.
        for _ in range(32):
            candidate = f".canon-{secrets.token_hex(12)}"
            try:
                descriptor = os.open(
                    candidate,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0),
                    0o600,
                    dir_fd=directory_descriptor,
                )
                temporary_name = candidate
                break
            except FileExistsError:
                continue
        else:
            raise CanonIntegrityError("cannot create a unique Canon temporary file")
        os.fchmod(descriptor, previous_mode)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(
            temporary_name,
            destination_name,
            src_dir_fd=directory_descriptor,
            dst_dir_fd=directory_descriptor,
        )
        os.fsync(directory_descriptor)
    finally:
        if temporary_name is not None:
            try:
                os.unlink(temporary_name, dir_fd=directory_descriptor)
            except FileNotFoundError:
                pass
        os.close(directory_descriptor)


def _snapshot_state(path: Path, before_digest: str, after_digest: str) -> str:
    """Classify a Canon path without guessing across an I/O failure."""
    try:
        current = _read_snapshot_file(path, "Canon document")
    except CanonIntegrityError:
        return "unknown"
    digest = _sha256(current)
    if digest == before_digest and digest != after_digest:
        return "before"
    if digest == after_digest and digest != before_digest:
        return "after"
    return "ambiguous"


def _append_aborted(vault: Any, event_type: str, *, actor: str, data: Mapping[str, Any], target: str, sensitivity: str) -> None:
    """Append only a proven-restored abort, without persisting exception text."""
    abort_data = dict(data)
    abort_data["restored"] = True
    vault.append_event(
        event_type,
        actor=actor,
        data=abort_data,
        target=target,
        sensitivity=sensitivity,
    )


@contextmanager
def _vault_canon_lock(root: Path) -> Iterator[None]:
    # Canon, Evidence lifecycle, retention, and runtime rebuild share one durable
    # writer boundary. file_lock is re-entrant within a thread, so transaction
    # code may append audit events without deadlocking itself.
    with file_lock(root / "runtime" / "locks" / "writer.lock"):
        yield


class CanonStore:
    """Semantic-ID based, snapshot-backed Canon mutation service."""

    def __init__(self, vault: Any):
        self.vault = vault
        # Keep lexical paths intact.  Resolving here would turn a post-init
        # symlink swap into an apparently valid external Canon location.
        self.root = Path(vault.root).expanduser().absolute()
        try:
            root_status = os.lstat(self.root)
            canon_status = os.lstat(self.root / "canon")
        except OSError as exc:
            raise CanonIntegrityError("vault Canon boundary cannot be inspected") from exc
        if (
            stat.S_ISLNK(root_status.st_mode)
            or not stat.S_ISDIR(root_status.st_mode)
            or stat.S_ISLNK(canon_status.st_mode)
            or not stat.S_ISDIR(canon_status.st_mode)
        ):
            raise CanonIntegrityError("vault and Canon roots must be real directories")
        self.canon_root = self.root / "canon"

    def find_document(self, semantic_id: str) -> MarkdownDocument:
        if not is_uuid7(semantic_id):
            raise ValueError("semantic document ID must be a UUIDv7")
        matches: list[MarkdownDocument] = []
        try:
            for document in canon_documents(self.canon_root):
                extension = document.frontmatter.get("x-lifedb")
                if isinstance(extension, Mapping) and extension.get("id") == semantic_id:
                    self._safe_canon_path(document.path)
                    matches.append(document)
        except (OSError, ValueError, yaml.YAMLError) as exc:
            raise CanonIntegrityError(f"cannot parse Canon while resolving {semantic_id}: {exc}") from exc
        if not matches:
            raise CanonNotFoundError(f"Canon document not found: {semantic_id}")
        if len(matches) > 1:
            raise CanonIntegrityError(f"duplicate Canon semantic ID: {semantic_id}")
        return matches[0]

    def validate_proposal(
        self, target_document_id: str, proposal: Mapping[str, Any]
    ) -> dict[str, Any]:
        """Validate a proposal against current durable references without writing."""

        if not is_uuid7(target_document_id):
            raise ValueError("target_document_id must be a UUIDv7")
        validated = validate_claim_proposal(proposal)
        with _vault_canon_lock(self.root):
            documents = self._load_documents()
            document = self._select_document(documents, target_document_id)
            semantic_ids, claims = self._catalog(documents)
            extension = document.frontmatter.get("x-lifedb")
            if not isinstance(extension, Mapping):
                raise CanonIntegrityError("target Canon document has no x-lifedb mapping")
            document_sensitivity = extension.get("sensitivity")
            if document_sensitivity not in SENSITIVITIES:
                raise CanonIntegrityError("target Canon document has invalid sensitivity")
            self._validate_references(
                validated,
                target_id=target_document_id,
                document=document,
                semantic_ids=semantic_ids,
                claims=claims,
                document_sensitivity=document_sensitivity,
            )
        return validated

    def promote(self, candidate: Mapping[str, Any], *, actor: str) -> dict[str, Any]:
        """Append a Candidate as a Claim and return its audit transaction."""

        if not isinstance(actor, str) or not actor.strip():
            raise ValueError("actor must be a non-empty string")
        candidate_id = candidate.get("id")
        target_id = candidate.get("target_document_id")
        if not is_uuid7(candidate_id):
            raise ValueError("candidate ID must be a UUIDv7")
        if not is_uuid7(target_id):
            raise ValueError("candidate target_document_id must be a UUIDv7")
        proposal = validate_claim_proposal(candidate.get("claim", {}))
        # SPEC 8.3: numeric model confidence may remain in a pending
        # Candidate but must never enter Canon.  Reject the exact
        # Claim-level key before any lock, snapshot, object store, event
        # append, or compare-and-swap side effect.
        if "confidence" in proposal:
            raise ValueError("numeric model confidence must not be stored in Canon")

        with _vault_canon_lock(self.root):
            documents = self._load_documents()
            initially_selected = self._select_document(documents, target_id)
            document, before_bytes = _parse_markdown_snapshot(initially_selected.path)
            documents = [
                document if item.path == initially_selected.path else item for item in documents
            ]
            # The semantic ID itself may have changed between the directory
            # scan and the exact snapshot read.  Never write in that case.
            self._select_document(documents, target_id)
            semantic_ids, claims = self._catalog(documents)
            extension = document.frontmatter.get("x-lifedb")
            if not isinstance(extension, Mapping):
                raise CanonIntegrityError("target Canon document has no x-lifedb mapping")
            document_sensitivity = extension.get("sensitivity")
            if document_sensitivity not in SENSITIVITIES:
                raise CanonIntegrityError("target Canon document has invalid sensitivity")

            self._validate_references(
                proposal,
                target_id=target_id,
                document=document,
                semantic_ids=semantic_ids,
                claims=claims,
                document_sensitivity=document_sensitivity,
            )

            claim_id = new_id()
            for _ in range(7):
                if claim_id not in claims:
                    break
                claim_id = new_id()
            if claim_id in claims:
                raise CanonIntegrityError("could not allocate a unique Claim UUIDv7")
            canonical_claim = self._make_claim(proposal, target_id, claim_id)
            frontmatter = deepcopy(document.frontmatter)
            mutable_extension = frontmatter.get("x-lifedb")
            if not isinstance(mutable_extension, dict):
                raise CanonIntegrityError("target x-lifedb value is not mutable mapping data")
            mutable_claims = mutable_extension.setdefault("claims", [])
            if not isinstance(mutable_claims, list):
                raise CanonIntegrityError("target x-lifedb.claims is not a list")

            supersedes = canonical_claim.get("supersedes", [])
            for existing_claim in mutable_claims:
                if not isinstance(existing_claim, dict):
                    raise CanonIntegrityError("target Canon contains a non-mapping Claim")
                if existing_claim.get("id") not in supersedes:
                    continue
                existing_claim["state"] = "superseded"
                superseded_by = existing_claim.setdefault("superseded_by", [])
                if not isinstance(superseded_by, list):
                    raise CanonIntegrityError("superseded_by on existing Claim is not a list")
                if claim_id not in superseded_by:
                    superseded_by.append(claim_id)
            mutable_claims.append(canonical_claim)

            path = self._safe_canon_path(document.path)
            before_digest = _sha256(before_bytes)
            after_bytes = _render_markdown(frontmatter, document.body)
            if len(after_bytes) > MAX_MARKDOWN_BYTES:
                raise CanonIntegrityError("updated Canon document exceeds the size limit")
            after_digest = _sha256(after_bytes)
            stored_before = _object_digest(self.vault.store_object(before_bytes))
            stored_after = _object_digest(self.vault.store_object(after_bytes))
            if stored_before != before_digest or stored_after != after_digest:
                raise CanonIntegrityError("snapshot Object Store digest mismatch")

            transaction_id = new_id()
            relative_path = path.relative_to(self.root).as_posix()
            sensitivity = self._effective_sensitivity(document_sensitivity, proposal)
            transaction = {
                "transaction_id": transaction_id,
                "operation": "promotion",
                "actor": actor,
                "candidate": candidate_id,
                "claim": claim_id,
                "before": _object_reference(before_digest),
                "after": _object_reference(after_digest),
                "path": relative_path,
                "document": target_id,
            }
            replaced = False
            prepared_published = False
            try:
                self.vault.append_event(
                    "canon.change-prepared",
                    actor=actor,
                    data=transaction,
                    target=transaction_id,
                    sensitivity=sensitivity,
                )
                prepared_published = True
                _atomic_replace(path, after_bytes, expected_digest=before_digest, boundary=self.root)
                replaced = True
                self.vault.mark_dirty()
                self.vault.append_event(
                    "canon.change-committed",
                    actor=actor,
                    data=transaction,
                    target=transaction_id,
                    sensitivity=sensitivity,
                )
            except Exception as exc:
                # An Event append may have published its final name before a
                # directory fsync failure was observed.  The prepared and
                # committed records are then the recovery authority; writing
                # a compensating Canon version would create a durable commit
                # whose bytes no longer match its manifest.
                if isinstance(exc, DurablePublicationUncertain):
                    raise CanonTransactionError(
                        "Canon promotion Event publication is uncertain; recovery is required"
                    ) from exc
                state = _snapshot_state(path, before_digest, after_digest)
                restored = state == "before"
                restore_error: Exception | None = None
                if replaced and state == "after":
                    try:
                        _atomic_replace(path, before_bytes, expected_digest=after_digest, boundary=self.root)
                        self.vault.mark_dirty()
                        state = _snapshot_state(path, before_digest, after_digest)
                        restored = state == "before"
                    except Exception as compensation_exc:  # pragma: no cover - catastrophic I/O
                        restore_error = compensation_exc
                        state = _snapshot_state(path, before_digest, after_digest)
                        restored = state == "before"
                if restored and prepared_published:
                    try:
                        _append_aborted(
                            self.vault,
                            "canon.change-aborted",
                            actor=actor,
                            data=transaction,
                            target=transaction_id,
                            sensitivity=sensitivity,
                        )
                    except Exception:
                        # The prepared event remains the recovery record when
                        # the abort publication itself is uncertain.
                        pass
                if restore_error is not None or state != "before":
                    raise CanonTransactionError(
                        "Canon promotion publication is uncertain; recovery is required"
                    ) from exc
                if isinstance(exc, CanonError):
                    raise
                raise CanonTransactionError("Canon promotion failed; original restored") from exc
            return transaction

    def rollback(self, transaction_id: str, *, actor: str) -> dict[str, Any]:
        """Restore a committed transaction's exact before snapshot with CAS safety."""

        if not is_uuid7(transaction_id):
            raise ValueError("transaction ID must be a UUIDv7")
        if not isinstance(actor, str) or not actor.strip():
            raise ValueError("actor must be a non-empty string")

        # All Canon/Candidate transitions acquire the global writer lock
        # before the per-Candidate lock.  Rollback uses the same order, so it
        # cannot commit between Canon publication and candidate.promoted.
        with self._ordered_transaction_lock(transaction_id):
            source = self._committed_transaction(transaction_id)
            rollback_events = self._rollback_events_for_source(transaction_id)
            committed_rollbacks = [
                event for event in rollback_events if event.get("event_type") == "canon.rollback-committed"
            ]
            prepared_rollbacks = [
                event for event in rollback_events if event.get("event_type") == "canon.rollback-prepared"
            ]
            if len(committed_rollbacks) > 1 or len(prepared_rollbacks) > 1:
                raise CanonIntegrityError("source transaction has duplicate rollback states")
            if committed_rollbacks:
                existing = committed_rollbacks[0].get("data")
                if isinstance(existing, Mapping):
                    # Idempotent retry is safe only when the durable manifest,
                    # its CAS objects, and the bytes currently on disk still
                    # describe the same rollback.  Never return a historical
                    # result while silently accepting a later Canon rewrite.
                    rollback_id = existing.get("transaction_id")
                    self._validate_recovery_manifest(existing, "rollback", rollback_id)
                    if existing.get("rollback_of") != transaction_id:
                        raise CanonIntegrityError("committed rollback points at another source transaction")
                    path_value = existing.get("path")
                    path = self._safe_recovery_manifest_path(path_value)
                    before_digest = _reference_digest(existing.get("before"), "rollback before")
                    after_digest = _reference_digest(existing.get("after"), "rollback after")
                    self._verify_snapshot_object(before_digest, "rollback before")
                    self._verify_snapshot_object(after_digest, "rollback after")
                    source_path = self._safe_recovery_manifest_path(source.get("path"))
                    if path != source_path:
                        raise CanonIntegrityError("committed rollback path differs from source transaction")
                    if (
                        existing.get("before") != source.get("after")
                        or existing.get("after") != source.get("before")
                        or existing.get("document") != source.get("document")
                        or existing.get("candidate") != source.get("candidate")
                        or existing.get("claim") != source.get("claim")
                    ):
                        raise CanonIntegrityError("committed rollback manifest differs from source transaction")
                    try:
                        current_bytes = _read_snapshot_file(path, "Canon document", boundary=self.root)
                    except CanonIntegrityError:
                        current_bytes = None
                    if current_bytes is None or _sha256(current_bytes) != after_digest:
                        raise ConcurrentCanonChangeError(
                            "rollback retry refused: current Canon does not match rollback after snapshot"
                        )
                    return deepcopy(dict(existing))
                raise CanonIntegrityError("committed rollback manifest is invalid")
            if prepared_rollbacks:
                raise CanonTransactionError(
                    "source transaction has a prepared-only rollback; run Canon recovery first"
                )
            path_value = source.get("path")
            if not isinstance(path_value, str):
                raise CanonIntegrityError("transaction has no Canon path")
            path = self._safe_canon_path(self.root / path_value)
            before_digest = _reference_digest(source.get("before"), "before")
            after_digest = _reference_digest(source.get("after"), "after")
            try:
                current_bytes = _read_snapshot_file(path, "Canon document", boundary=self.root)
            except CanonIntegrityError as exc:
                raise ConcurrentCanonChangeError(
                    "rollback refused: current Canon cannot be read safely"
                ) from exc
            if _sha256(current_bytes) != after_digest:
                raise ConcurrentCanonChangeError(
                    "rollback refused: current Canon hash does not match transaction after snapshot"
                )
            try:
                before_bytes = _read_snapshot_file(
                    self._object_path(before_digest), "rollback snapshot Object", boundary=self.root
                )
            except CanonIntegrityError as exc:
                raise CanonNotFoundError(
                    f"rollback snapshot is missing: sha256:{before_digest}"
                ) from exc
            if _sha256(before_bytes) != before_digest:
                raise CanonIntegrityError("rollback snapshot hash mismatch")

            rollback_id = new_id()
            sensitivity = self._transaction_sensitivity(transaction_id)
            rollback = {
                "transaction_id": rollback_id,
                "operation": "rollback",
                "rollback_of": transaction_id,
                "actor": actor,
                "candidate": source.get("candidate"),
                "claim": source.get("claim"),
                "before": source.get("after"),
                "after": source.get("before"),
                "path": path_value,
                "document": source.get("document"),
            }
            rollback_before_digest = after_digest
            rollback_after_digest = before_digest
            replaced = False
            prepared_published = False
            try:
                self.vault.append_event(
                    "canon.rollback-prepared",
                    actor=actor,
                    data=rollback,
                    target=rollback_id,
                    sensitivity=sensitivity,
                )
                prepared_published = True
                _atomic_replace(path, before_bytes, expected_digest=after_digest, boundary=self.root)
                replaced = True
                self.vault.mark_dirty()
                self.vault.append_event(
                    "canon.rollback-committed",
                    actor=actor,
                    data=rollback,
                    target=rollback_id,
                    sensitivity=sensitivity,
                )
            except Exception as exc:
                if isinstance(exc, DurablePublicationUncertain):
                    raise CanonTransactionError(
                        "Canon rollback Event publication is uncertain; recovery is required"
                    ) from exc
                state = _snapshot_state(path, rollback_before_digest, rollback_after_digest)
                restored = state == "before"
                restore_error: Exception | None = None
                if replaced and state == "after":
                    try:
                        _atomic_replace(
                            path,
                            current_bytes,
                            expected_digest=rollback_after_digest,
                            boundary=self.root,
                        )
                        self.vault.mark_dirty()
                        state = _snapshot_state(
                            path, rollback_before_digest, rollback_after_digest
                        )
                        restored = state == "before"
                    except Exception as compensation_exc:  # pragma: no cover - catastrophic I/O
                        restore_error = compensation_exc
                        state = _snapshot_state(
                            path, rollback_before_digest, rollback_after_digest
                        )
                        restored = state == "before"
                if restored and prepared_published:
                    try:
                        _append_aborted(
                            self.vault,
                            "canon.rollback-aborted",
                            actor=actor,
                            data=rollback,
                            target=rollback_id,
                            sensitivity=sensitivity,
                        )
                    except Exception:
                        pass
                if restore_error is not None or state != "before":
                    raise CanonTransactionError(
                        "Canon rollback publication is uncertain; recovery is required"
                    ) from exc
                if isinstance(exc, CanonError):
                    raise
                raise CanonTransactionError("Canon rollback failed; current version restored") from exc
            return rollback

    @contextmanager
    def _candidate_lock_for_transaction(self, transaction_id: str) -> Iterator[None]:
        """Acquire the per-Candidate lock nested under the writer lock."""
        source = self._committed_transaction(transaction_id)
        candidate_id = source.get("candidate")
        if not is_uuid7(candidate_id):
            raise CanonIntegrityError("committed transaction candidate is invalid")
        with file_lock(self.root / "runtime" / "locks" / "candidates" / f"{candidate_id}.lock"):
            yield

    @contextmanager
    def _ordered_transaction_lock(self, transaction_id: str) -> Iterator[None]:
        with _vault_canon_lock(self.root):
            with self._candidate_lock_for_transaction(transaction_id):
                yield

    def _rollback_events_for_source(self, transaction_id: str) -> list[Mapping[str, Any]]:
        try:
            events = list(iter_events(self.vault, verify=True))
        except (OSError, ValueError) as exc:
            raise CanonIntegrityError(f"cannot read event log: {exc}") from exc
        return [
            event for event in events
            if event.get("event_type") in {
                "canon.rollback-prepared", "canon.rollback-committed", "canon.rollback-aborted"
            }
            and isinstance(event.get("data"), Mapping)
            and event["data"].get("rollback_of") == transaction_id
        ]

    def _committed_promotions_for_candidate(self, candidate_id: str) -> list[Mapping[str, Any]]:
        try:
            events = list(iter_events(self.vault, verify=True))
        except (OSError, ValueError) as exc:
            raise CanonIntegrityError(f"cannot read event log: {exc}") from exc
        promotions: list[Mapping[str, Any]] = []
        rollback_sources: set[str] = set()
        for event in events:
            data = event.get("data")
            if (
                event.get("event_type") == "canon.rollback-committed"
                and isinstance(data, Mapping)
                and isinstance(data.get("rollback_of"), str)
            ):
                rollback_sources.add(data["rollback_of"])
        for event in events:
            data = event.get("data")
            if not isinstance(data, Mapping):
                continue
            if event.get("event_type") == "canon.change-committed" and data.get("candidate") == candidate_id:
                transaction_id = data.get("transaction_id")
                if not is_uuid7(transaction_id):
                    raise CanonIntegrityError("committed Canon promotion transaction ID is invalid")
                # A committed rollback intentionally restores the before
                # snapshot, so the old promotion's after bytes no longer
                # match the live document.  Exclude it before live CAS
                # verification; only active promotions must match current
                # Canon bytes.
                if transaction_id in rollback_sources:
                    continue
                self._validate_recovery_manifest(data, "promotion", transaction_id)
                path = self._safe_recovery_manifest_path(data.get("path"))
                after_digest = _reference_digest(data.get("after"), "after")
                try:
                    current_bytes = _read_snapshot_file(path, "Canon document", boundary=self.root)
                except CanonIntegrityError:
                    current_bytes = None
                if current_bytes is None or _sha256(current_bytes) != after_digest:
                    raise ConcurrentCanonChangeError(
                        "existing Canon promotion no longer matches its committed snapshot"
                    )
                promotions.append(data)
        return [item for item in promotions if item.get("transaction_id") not in rollback_sources]

    def recover_interrupted(
        self, actor: str = "process:lifedb-canon-recovery"
    ) -> dict[str, Any]:
        """Close Canon transactions left between their prepare and terminal events.

        Recovery is deliberately observational with respect to Canon bytes: it
        never chooses a snapshot to restore.  A prepared transaction is closed
        only when the current path is an exact hash match for one (and only one)
        of its recorded snapshots.  This makes a manual edit, a missing object,
        and an ambiguous state visible to validation instead of silently losing
        user data.
        """

        if not isinstance(actor, str) or not actor.strip():
            raise ValueError("actor must be a non-empty string")
        report: dict[str, Any] = {
            "schema": "0.2",
            "recovered_committed": [],
            "recovered_aborted": [],
            "candidates_reconciled": [],
            "candidates_reopened": [],
            "unresolved": [],
        }
        with _vault_canon_lock(self.root):
            try:
                events = list(iter_events(self.vault, verify=True))
            except (OSError, ValueError) as exc:
                report["unresolved"].append({"reason": f"cannot read event log: {exc}"})
                return report
            events.sort(key=self._event_order_key)

            by_transaction: dict[str, list[Mapping[str, Any]]] = {}
            for event in events:
                event_type = event.get("event_type")
                target = event.get("target")
                if (
                    isinstance(target, str)
                    and event_type in {
                        "canon.change-prepared",
                        "canon.change-committed",
                        "canon.change-aborted",
                        "canon.rollback-prepared",
                        "canon.rollback-committed",
                        "canon.rollback-aborted",
                    }
                ):
                    by_transaction.setdefault(target, []).append(event)

            # Process in global sequence order.  In particular, a recovered
            # rollback must be known before candidate promotion reconciliation.
            for transaction_id, grouped in sorted(
                by_transaction.items(), key=lambda item: self._event_order_key(min(item[1], key=self._event_order_key))
            ):
                prepared = [
                    event
                    for event in grouped
                    if event.get("event_type")
                    in {"canon.change-prepared", "canon.rollback-prepared"}
                ]
                terminals = [
                    event
                    for event in grouped
                    if event.get("event_type")
                    in {
                        "canon.change-committed",
                        "canon.change-aborted",
                        "canon.rollback-committed",
                        "canon.rollback-aborted",
                    }
                ]
                if not prepared:
                    continue
                if len(prepared) != 1 or len(terminals) > 1:
                    self._recovery_unresolved(
                        report, transaction_id, "duplicate or contradictory Canon transaction states"
                    )
                    continue
                prepared_event = prepared[0]
                prepared_type = str(prepared_event.get("event_type"))
                operation = "promotion" if prepared_type.startswith("canon.change-") else "rollback"
                expected_terminal = {
                    "canon.change-committed", "canon.change-aborted"
                } if operation == "promotion" else {
                    "canon.rollback-committed", "canon.rollback-aborted"
                }
                if terminals and terminals[0].get("event_type") not in expected_terminal:
                    self._recovery_unresolved(report, transaction_id, "contradictory Canon transaction operation")
                    continue
                if terminals:
                    terminal = terminals[0]
                    if isinstance(terminal.get("event_type"), str) and terminal["event_type"].endswith("aborted"):
                        terminal_data = terminal.get("data")
                        if not isinstance(terminal_data, Mapping) or terminal_data.get("restored") is not True:
                            self._recovery_unresolved(
                                report,
                                transaction_id,
                                "aborted Canon terminal does not prove restoration",
                            )
                    continue
                manifest = prepared_event.get("data")
                try:
                    self._validate_recovery_manifest(manifest, operation, transaction_id)
                    assert isinstance(manifest, Mapping)
                    path = self._safe_recovery_manifest_path(manifest["path"])
                    before_digest = _reference_digest(manifest.get("before"), "before")
                    after_digest = _reference_digest(manifest.get("after"), "after")
                    self._verify_snapshot_object(before_digest, "before")
                    self._verify_snapshot_object(after_digest, "after")
                    if path.is_symlink() or not path.is_file():
                        raise CanonIntegrityError("Canon transaction path is missing or is a symlink")
                    current_document, current_bytes = _parse_markdown_snapshot(path)
                    current_extension = current_document.frontmatter.get("x-lifedb")
                    if not isinstance(current_extension, Mapping) or current_extension.get("id") != manifest.get("document"):
                        raise CanonIntegrityError("Canon transaction document does not match manifest path")
                    current_digest = _sha256(current_bytes)
                    matches_before = current_digest == before_digest
                    matches_after = current_digest == after_digest
                    if matches_before == matches_after:
                        raise CanonIntegrityError(
                            "current Canon does not match exactly one transaction snapshot"
                        )
                    event_type = (
                        "canon.change-committed" if operation == "promotion" and matches_after
                        else "canon.change-aborted" if operation == "promotion"
                        else "canon.rollback-committed" if matches_after
                        else "canon.rollback-aborted"
                    )
                    # The manifest is copied exactly.  This is important for
                    # validation and makes a recovered commit indistinguishable
                    # from a normal commit apart from its actor.
                    sensitivity = prepared_event.get("sensitivity", "personal")
                    if sensitivity not in SENSITIVITIES:
                        sensitivity = "personal"
                    terminal_data = deepcopy(dict(manifest))
                    if event_type.endswith("aborted"):
                        terminal_data["restored"] = True
                    self.vault.append_event(
                        event_type,
                        actor=actor,
                        data=terminal_data,
                        target=transaction_id,
                        sensitivity=sensitivity,
                    )
                    report[
                        "recovered_committed" if event_type.endswith("committed") else "recovered_aborted"
                    ].append(transaction_id)
                except (CanonError, OSError, ValueError, KeyError) as exc:
                    self._recovery_unresolved(report, transaction_id, str(exc))

            # Re-read after recovery so newly appended rollback commits suppress
            # promotion completion in this same invocation.
            try:
                events = list(iter_events(self.vault, verify=True))
            except (OSError, ValueError) as exc:
                report["unresolved"].append({"reason": f"cannot reread event log: {exc}"})
                return report
            events.sort(key=self._event_order_key)
            rollback_compensations = {
                data.get("rollback_of")
                for event in events
                if event.get("event_type") == "canon.rollback-committed"
                and isinstance((data := event.get("data")), Mapping)
                and isinstance(data.get("rollback_of"), str)
            }
            promotions = [
                event for event in events if event.get("event_type") == "canon.change-committed"
            ]
            candidate_events: dict[str, list[Mapping[str, Any]]] = {}
            for event in events:
                target = event.get("target")
                if isinstance(target, str) and str(event.get("event_type", "")).startswith("candidate."):
                    candidate_events.setdefault(target, []).append(event)
            invalid_candidates: set[str] = set()
            unresolved_candidates: set[str] = set()
            for candidate_id, grouped in candidate_events.items():
                created = [event for event in grouped if event.get("event_type") == "candidate.created"]
                terminal = [
                    event for event in grouped
                    if event.get("event_type") in {"candidate.promoted", "candidate.rejected"}
                ]
                if len(created) != 1 or not self._candidate_history_valid(grouped):
                    invalid_candidates.add(candidate_id)
                    self._recovery_unresolved_once(
                        report, unresolved_candidates, candidate_id,
                        "candidate creation/terminal state is contradictory"
                    )

            # A Candidate may have several committed Canon events due to a
            # damaged/duplicated log.  Reconciliation is allowed only for one
            # demonstrably valid, non-rolled-back promotion.  Grouping before
            # appending is essential: appending while iterating stale events
            # used to create duplicate candidate.promoted terminals.
            promotion_groups: dict[str, list[Mapping[str, Any]]] = {}
            for promotion in promotions:
                data = promotion.get("data")
                candidate_id = data.get("candidate") if isinstance(data, Mapping) else None
                if isinstance(candidate_id, str):
                    promotion_groups.setdefault(candidate_id, []).append(promotion)

            for candidate_id, grouped_promotions in promotion_groups.items():
                if candidate_id in invalid_candidates:
                    continue
                candidate_group = candidate_events.get(candidate_id, [])
                created = [event for event in candidate_group if event.get("event_type") == "candidate.created"]
                terminals = [
                    event for event in candidate_group
                    if event.get("event_type") in {"candidate.promoted", "candidate.rejected"}
                ]
                if len(created) != 1 or not self._candidate_history_valid(candidate_group):
                    self._recovery_unresolved_once(
                        report, unresolved_candidates, candidate_id,
                        "candidate creation/terminal state is contradictory"
                    )
                    continue
                terminals = self._candidate_active_terminals(candidate_group)
                creation_data = created[0].get("data")
                if not isinstance(creation_data, Mapping) or creation_data.get("candidate_id") != candidate_id:
                    self._recovery_unresolved_once(
                        report, unresolved_candidates, candidate_id, "candidate.created data is invalid"
                    )
                    continue

                valid_promotions: list[tuple[Mapping[str, Any], Mapping[str, Any]]] = []
                for promotion in grouped_promotions:
                    data = promotion.get("data")
                    transaction_id = data.get("transaction_id") if isinstance(data, Mapping) else None
                    claim_id = data.get("claim") if isinstance(data, Mapping) else None
                    try:
                        if not (is_uuid7(transaction_id) and is_uuid7(claim_id)):
                            raise CanonIntegrityError("committed Canon promotion identity is invalid")
                        if transaction_id in rollback_compensations:
                            continue
                        self._validate_recovery_manifest(data, "promotion", transaction_id)
                        assert isinstance(data, Mapping)
                        if data.get("candidate") != candidate_id:
                            raise CanonIntegrityError("Canon promotion candidate disagrees with event group")
                        if creation_data.get("target_document_id") != data.get("document"):
                            raise CanonIntegrityError("Candidate target disagrees with Canon promotion")
                        self._verify_snapshot_object(_reference_digest(data.get("after"), "after"), "after")
                        self._validate_candidate_snapshot_match(creation_data, data)
                        valid_promotions.append((promotion, data))
                    except (CanonError, OSError, ValueError, KeyError) as exc:
                        self._recovery_unresolved_once(
                            report, unresolved_candidates, candidate_id,
                            f"committed Canon promotion is not a valid Candidate promotion: {exc}"
                        )

                if len(valid_promotions) != 1:
                    if len(valid_promotions) > 1:
                        self._recovery_unresolved_once(
                            report, unresolved_candidates, candidate_id,
                            "multiple non-rolled-back committed Canon promotions are ambiguous"
                        )
                    continue

                _, data = valid_promotions[0]
                transaction_id = str(data["transaction_id"])
                claim_id = str(data["claim"])
                if terminals:
                    terminal_data = terminals[0].get("data")
                    terminal_type = terminals[0].get("event_type")
                    if terminal_type == "candidate.promoted":
                        if (
                            not isinstance(terminal_data, Mapping)
                            or terminal_data.get("transaction_id") != transaction_id
                            or terminal_data.get("claim_id") != claim_id
                        ):
                            self._recovery_unresolved_once(
                                report, unresolved_candidates, candidate_id,
                                "candidate promotion terminal disagrees with Canon"
                            )
                    else:
                        self._recovery_unresolved_once(
                            report, unresolved_candidates, candidate_id,
                            "candidate rejected despite committed Canon promotion"
                        )
                    continue

                try:
                    from .candidates import CandidateStore

                    candidate_projection = CandidateStore(self.vault).get(candidate_id)
                    sensitivity = created[0].get("sensitivity", "personal")
                    if sensitivity not in SENSITIVITIES:
                        raise CanonIntegrityError("candidate sensitivity is invalid")
                    with file_lock(
                        self.root / "runtime" / "locks" / "candidates" / f"{candidate_id}.lock"
                    ):
                        self.vault.append_event(
                            "candidate.promoted",
                            actor=actor,
                            data={"candidate_id": candidate_id, "transaction_id": transaction_id, "claim_id": claim_id},
                            target=candidate_id,
                            sensitivity=candidate_projection["sensitivity"],
                        )
                    if candidate_id not in report["candidates_reconciled"]:
                        report["candidates_reconciled"].append(candidate_id)
                except Exception as exc:
                    self._recovery_unresolved_once(
                        report, unresolved_candidates, candidate_id,
                        f"candidate projection is invalid: {exc}"
                    )

            # A process can die after Canon rollback commits and before the
            # Candidate projection is reopened.  Reconcile that deterministic
            # gap while holding the global Canon writer lock, then take the
            # candidate lock. All commands use this writer-before-candidate
            # order, preventing a terminal transition from being interleaved.
            for rollback_event in events:
                if rollback_event.get("event_type") != "canon.rollback-committed":
                    continue
                rollback_data = rollback_event.get("data")
                if not isinstance(rollback_data, Mapping):
                    continue
                rollback_id = rollback_data.get("transaction_id")
                source_id = rollback_data.get("rollback_of")
                candidate_id = rollback_data.get("candidate")
                claim_id = rollback_data.get("claim")
                if not (
                    is_uuid7(rollback_id)
                    and is_uuid7(source_id)
                    and is_uuid7(candidate_id)
                    and is_uuid7(claim_id)
                ):
                    self._recovery_unresolved_once(
                        report, unresolved_candidates,
                        str(rollback_id or source_id or "rollback"),
                        "Canon rollback identity is invalid",
                    )
                    continue
                candidate_group = candidate_events.get(candidate_id, [])
                matching_reopen = [
                    event for event in candidate_group
                    if event.get("event_type") == "candidate.reopened"
                    and isinstance(event.get("data"), Mapping)
                    and event["data"].get("rollback_id") == rollback_id
                ]
                if matching_reopen:
                    continue
                created = [
                    event for event in candidate_group
                    if event.get("event_type") == "candidate.created"
                ]
                if len(created) != 1:
                    self._recovery_unresolved_once(
                        report, unresolved_candidates, candidate_id,
                        "rollback Candidate creation state is contradictory",
                    )
                    continue
                try:
                    from .candidates import CandidateStore

                    with file_lock(
                        self.root / "runtime" / "locks" / "candidates" / f"{candidate_id}.lock"
                    ):
                        candidate_projection = CandidateStore(self.vault).get(candidate_id)
                        matching_source_terminal = any(
                            event.get("event_type") == "candidate.promoted"
                            and isinstance(event.get("data"), Mapping)
                            and event["data"].get("transaction_id") == source_id
                            and event["data"].get("claim_id") == claim_id
                            for event in candidate_group
                        )
                        # CandidateStore promotion compensation rolls Canon
                        # back before its candidate.promoted terminal exists.
                        # Pending is then the correct stable state; only a
                        # rollback of an actually-promoted Candidate reopens.
                        if not matching_source_terminal and candidate_projection.get("status") == "pending":
                            continue
                        if candidate_projection.get("status") != "promoted":
                            raise CanonIntegrityError(
                                "rollback Candidate is not in the promoted state"
                            )
                        # Re-read to make a retry idempotent if another recovery
                        # worker won the append race.
                        current = list(iter_events(self.vault, verify=True))
                        if any(
                            event.get("event_type") == "candidate.reopened"
                            and event.get("target") == candidate_id
                            and isinstance(event.get("data"), Mapping)
                            and event["data"].get("rollback_id") == rollback_id
                            for event in current
                        ):
                            continue
                        self.vault.append_event(
                            "candidate.reopened",
                            actor=actor,
                            data={
                                "candidate_id": candidate_id,
                                "transaction_id": source_id,
                                "claim_id": claim_id,
                                "rollback_id": rollback_id,
                            },
                            target=candidate_id,
                            sensitivity=candidate_projection["sensitivity"],
                        )
                    report["candidates_reopened"].append(candidate_id)
                except Exception as exc:
                    self._recovery_unresolved_once(
                        report, unresolved_candidates, candidate_id,
                        f"rollback Candidate projection is invalid: {exc}",
                    )
        return report

    @staticmethod
    def _event_order_key(event: Mapping[str, Any]) -> tuple[int, str]:
        sequence = event.get("sequence")
        if isinstance(sequence, bool) or not isinstance(sequence, int) or sequence < 1:
            raise CanonIntegrityError("event has an invalid global sequence")
        return sequence, str(event.get("id", ""))

    @classmethod
    def _candidate_history_valid(cls, events: list[Mapping[str, Any]]) -> bool:
        state = "pending"
        for event in sorted(events, key=cls._event_order_key):
            event_type = event.get("event_type")
            if event_type == "candidate.promoted":
                if state != "pending":
                    return False
                state = "promoted"
            elif event_type == "candidate.rejected":
                if state != "pending":
                    return False
                state = "rejected"
            elif event_type == "candidate.reopened":
                if state != "promoted":
                    return False
                state = "pending"
        return True

    @classmethod
    def _candidate_active_terminals(
        cls, events: list[Mapping[str, Any]]
    ) -> list[Mapping[str, Any]]:
        active: list[Mapping[str, Any]] = []
        for event in sorted(events, key=cls._event_order_key):
            event_type = event.get("event_type")
            if event_type == "candidate.reopened":
                active = []
            elif event_type in {"candidate.promoted", "candidate.rejected"}:
                active = [event]
        return active

    @staticmethod
    def _recovery_unresolved(report: dict[str, Any], target: str, reason: str) -> None:
        report["unresolved"].append({"target": target, "reason": reason})

    @staticmethod
    def _recovery_unresolved_once(
        report: dict[str, Any], seen: set[str], target: str, reason: str
    ) -> None:
        """Record one actionable recovery finding per target in one run."""
        if target in seen:
            return
        seen.add(target)
        CanonStore._recovery_unresolved(report, target, reason)

    def _validate_candidate_snapshot_match(
        self, creation_data: Mapping[str, Any], promotion: Mapping[str, Any]
    ) -> None:
        """Prove that a Canon after-snapshot contains this Candidate's Claim.

        The live path may have advanced since the promotion.  Therefore this
        check intentionally reads the immutable after Object, never the live
        Canon path.  It prevents a forged or accidentally cross-wired terminal
        event from being reconciled merely because its UUIDs look plausible.
        """
        target_id = creation_data.get("target_document_id")
        claim_id = promotion.get("claim")
        if not is_uuid7(target_id) or not is_uuid7(claim_id):
            raise CanonIntegrityError("Candidate snapshot identity is invalid")
        proposal = validate_claim_proposal(creation_data.get("claim", {}))
        expected = self._make_claim(proposal, target_id, claim_id)
        after_digest = _reference_digest(promotion.get("after"), "after")
        after_path = self._object_path(after_digest)
        try:
            after_bytes = _read_snapshot_file(
                after_path, "Candidate after snapshot Object", boundary=self.root
            )
        except CanonIntegrityError as exc:
            raise CanonIntegrityError("Candidate after snapshot object is unreadable") from exc
        if _sha256(after_bytes) != after_digest:
            raise CanonIntegrityError("Candidate after snapshot object hash mismatch")
        # Parse exact bytes from the immutable Object Store.  This uses the
        # same bounded YAML loader as path snapshots, while avoiding a path
        # race and preserving the CAS bytes contract.
        try:
            text = after_bytes.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise CanonIntegrityError("Candidate after snapshot is not UTF-8") from exc
        if not text.startswith("---\n"):
            raise CanonIntegrityError("Candidate after snapshot lacks frontmatter")
        end = text.find("\n---\n", 4)
        if end < 0:
            raise CanonIntegrityError("Candidate after snapshot lacks closing frontmatter")
        raw_frontmatter = text[4:end]
        if len(raw_frontmatter.encode("utf-8")) > MAX_FRONTMATTER_BYTES:
            raise CanonIntegrityError("Candidate after snapshot frontmatter is too large")
        try:
            frontmatter = yaml.load(raw_frontmatter, Loader=BoundedStringTimestampSafeLoader)
        except (yaml.YAMLError, RecursionError, MemoryError) as exc:
            raise CanonIntegrityError("Candidate after snapshot YAML is invalid") from exc
        if not isinstance(frontmatter, Mapping):
            raise CanonIntegrityError("Candidate after snapshot frontmatter is not a mapping")
        extension = frontmatter.get("x-lifedb")
        if not isinstance(extension, Mapping) or extension.get("id") != target_id:
            raise CanonIntegrityError("Candidate after snapshot target document does not match")
        claims = extension.get("claims")
        if not isinstance(claims, list):
            raise CanonIntegrityError("Candidate after snapshot claims are not a list")
        matches = [claim for claim in claims if isinstance(claim, Mapping) and claim.get("id") == claim_id]
        if len(matches) != 1:
            raise CanonIntegrityError("Candidate Claim is absent or duplicated in after snapshot")
        actual = matches[0]
        # Compare the full generated Claim.  This covers identity, subject,
        # predicate, object, statement, evidence, temporal fields, and any
        # proposal extension fields retained by _make_claim.
        if dict(actual) != expected:
            raise CanonIntegrityError("Candidate Claim does not match after snapshot")

    def _safe_recovery_manifest_path(self, value: Any) -> Path:
        if not isinstance(value, str) or not value or Path(value).is_absolute():
            raise CanonIntegrityError("Canon transaction path is invalid")
        raw_path = self.root / value
        # Check the lexical path before resolving it.  Resolving first would
        # erase evidence that a manifest selected a symlink and could make a
        # recovery read or write an unexpected Canon file.
        try:
            relative_parts = raw_path.relative_to(self.root).parts
        except ValueError as exc:
            raise CanonIntegrityError("Canon transaction path escapes vault") from exc
        cursor = self.root
        for part in relative_parts:
            cursor = cursor / part
            try:
                if cursor.is_symlink():
                    raise CanonIntegrityError("Canon transaction path must not contain symlinks")
            except OSError as exc:
                raise CanonIntegrityError("Canon transaction path cannot be inspected") from exc
        path = self._safe_canon_path(raw_path)
        if path.relative_to(self.root).as_posix() != value or not value.startswith("canon/"):
            raise CanonIntegrityError("Canon transaction path must be a normalized canon-relative path")
        return path

    def _verify_snapshot_object(self, digest: str, field: str) -> None:
        path = self._object_path(digest)
        try:
            data = _read_snapshot_file(path, f"{field} snapshot Object", boundary=self.root)
        except CanonIntegrityError:
            raise CanonIntegrityError(f"{field} snapshot object is missing or corrupt") from None
        if _sha256(data) != digest:
            raise CanonIntegrityError(f"{field} snapshot object is missing or corrupt")

    def _validate_recovery_manifest(self, manifest: Any, operation: str, transaction_id: str) -> None:
        if not isinstance(manifest, Mapping):
            raise CanonIntegrityError("Canon transaction manifest must be a mapping")
        if manifest.get("transaction_id") != transaction_id or manifest.get("operation") != operation:
            raise CanonIntegrityError("Canon transaction manifest identity is inconsistent")
        for field in ("actor", "path", "document"):
            if field == "actor":
                if not isinstance(manifest.get(field), str) or not manifest[field].strip():
                    raise CanonIntegrityError("Canon transaction actor is invalid")
            elif field == "document" and not is_uuid7(manifest.get(field)):
                raise CanonIntegrityError("Canon transaction document is invalid")
        for field in ("before", "after"):
            _reference_digest(manifest.get(field), field)
        if operation == "promotion":
            for field in ("candidate", "claim"):
                if not is_uuid7(manifest.get(field)):
                    raise CanonIntegrityError(f"Canon transaction {field} is invalid")
        else:
            if not is_uuid7(manifest.get("rollback_of")):
                raise CanonIntegrityError("Canon rollback source is invalid")

    @staticmethod
    def _manifest_sensitivity(manifest: Mapping[str, Any]) -> str:
        value = manifest.get("sensitivity", "personal")
        return value if value in SENSITIVITIES else "personal"

    def _load_documents(self) -> list[MarkdownDocument]:
        try:
            documents = list(canon_documents(self.canon_root))
        except (OSError, ValueError, yaml.YAMLError) as exc:
            raise CanonIntegrityError(f"cannot parse Canon: {exc}") from exc
        for document in documents:
            self._safe_canon_path(document.path)
        return documents

    @staticmethod
    def _select_document(documents: list[MarkdownDocument], semantic_id: str) -> MarkdownDocument:
        matches = []
        for document in documents:
            extension = document.frontmatter.get("x-lifedb")
            if isinstance(extension, Mapping) and extension.get("id") == semantic_id:
                matches.append(document)
        if not matches:
            raise CanonNotFoundError(f"Canon document not found: {semantic_id}")
        if len(matches) > 1:
            raise CanonIntegrityError(f"duplicate Canon semantic ID: {semantic_id}")
        return matches[0]

    @staticmethod
    def _catalog(
        documents: list[MarkdownDocument],
    ) -> tuple[set[str], dict[str, tuple[MarkdownDocument, Mapping[str, Any]]]]:
        semantic_ids: set[str] = set()
        claims: dict[str, tuple[MarkdownDocument, Mapping[str, Any]]] = {}
        for document in documents:
            extension = document.frontmatter.get("x-lifedb")
            if not isinstance(extension, Mapping):
                continue
            semantic_id = extension.get("id")
            if is_uuid7(semantic_id):
                if semantic_id in semantic_ids:
                    raise CanonIntegrityError(f"duplicate Canon semantic ID: {semantic_id}")
                semantic_ids.add(semantic_id)
            document_claims = extension.get("claims", [])
            if not isinstance(document_claims, list):
                raise CanonIntegrityError(f"{document.path}: x-lifedb.claims is not a list")
            for claim in document_claims:
                if not isinstance(claim, Mapping):
                    raise CanonIntegrityError(f"{document.path}: Claim is not a mapping")
                claim_id = claim.get("id")
                if not is_uuid7(claim_id):
                    raise CanonIntegrityError(f"{document.path}: Claim ID is not a UUIDv7")
                if claim_id in claims:
                    raise CanonIntegrityError(f"duplicate Claim ID: {claim_id}")
                claims[claim_id] = (document, claim)
        return semantic_ids, claims

    def _validate_references(
        self,
        proposal: Mapping[str, Any],
        *,
        target_id: str,
        document: MarkdownDocument,
        semantic_ids: set[str],
        claims: dict[str, tuple[MarkdownDocument, Mapping[str, Any]]],
        document_sensitivity: str,
    ) -> None:
        obj = proposal["object"]
        if "ref" in obj and obj["ref"] not in semantic_ids:
            raise CanonNotFoundError(f"referenced Canon semantic ID not found: {obj['ref']}")

        proposal_sensitivity = proposal.get("sensitivity", document_sensitivity)
        if SENSITIVITY_RANK[proposal_sensitivity] < SENSITIVITY_RANK[document_sensitivity]:
            raise CanonIntegrityError("Claim sensitivity cannot be lower than its document")

        for item in proposal["evidence"]:
            evidence_id = _evidence_id(item)
            requirement = item["requires"] if isinstance(item, Mapping) else "raw"
            record = self._evidence_record(evidence_id, effective=requirement != "record-only")
            if record is None:
                raise CanonNotFoundError(f"Evidence record not found: {evidence_id}")
            self._check_requirement(record, requirement, evidence_id)
            evidence_sensitivity = self._evidence_sensitivity(evidence_id, record)
            if SENSITIVITY_RANK[proposal_sensitivity] < SENSITIVITY_RANK[evidence_sensitivity]:
                raise CanonIntegrityError(
                    f"Claim sensitivity is lower than Evidence {evidence_id}"
                )

        for superseded_id in proposal.get("supersedes", []):
            located = claims.get(superseded_id)
            if located is None:
                raise CanonNotFoundError(f"superseded Claim not found: {superseded_id}")
            located_document, old_claim = located
            if (
                located_document.path != document.path
                or old_claim.get("subject") != target_id
                or old_claim.get("predicate") != proposal.get("predicate")
            ):
                raise CanonIntegrityError(
                    f"superseded Claim {superseded_id} does not belong to target document and predicate"
                )
            if old_claim.get("state") not in {"active", "disputed"}:
                raise CanonIntegrityError(
                    f"superseded Claim {superseded_id} is not active or disputed"
                )
            old_sensitivity = old_claim.get("sensitivity", document_sensitivity)
            if old_sensitivity not in SENSITIVITY_RANK:
                raise CanonIntegrityError(
                    f"superseded Claim {superseded_id} has invalid sensitivity"
                )
            if SENSITIVITY_RANK[proposal_sensitivity] < SENSITIVITY_RANK[old_sensitivity]:
                raise CanonIntegrityError(
                    f"superseding Claim cannot lower sensitivity of {superseded_id}"
                )

    def _evidence_record(
        self, evidence_id: str, *, effective: bool
    ) -> Mapping[str, Any] | None:
        method_name = "effective_evidence" if effective else "load_evidence"
        reader = getattr(self.vault, method_name, None)
        try:
            if callable(reader):
                record = reader(evidence_id, verify=True)
            else:
                from .evidence import effective_evidence, load_evidence

                record = (
                    effective_evidence(self.root, evidence_id, verify=True)
                    if effective
                    else load_evidence(self.root, evidence_id, verify=True)
                )
        except (OSError, ValueError) as exc:
            raise CanonIntegrityError(f"cannot load Evidence {evidence_id}: {exc}") from exc
        if record is not None and not isinstance(record, Mapping):
            raise CanonIntegrityError(f"Evidence {evidence_id} is not a mapping")
        return record

    def _evidence_sensitivity(
        self, evidence_id: str, record: Mapping[str, Any]
    ) -> str:
        values: list[Any] = [record.get("sensitivity")]
        reader = getattr(self.vault, "events_for", None)
        try:
            if callable(reader):
                events = reader(evidence_id, verify=True)
            else:
                from .evidence import iter_events

                events = iter_events(self.root, target=evidence_id, verify=True)
            values.extend(
                event.get("sensitivity")
                for event in events
                if isinstance(event, Mapping)
            )
        except (OSError, ValueError) as exc:
            raise CanonIntegrityError(
                f"cannot resolve Evidence sensitivity for {evidence_id}: {exc}"
            ) from exc
        if any(value not in SENSITIVITY_RANK for value in values):
            raise CanonIntegrityError(
                f"Evidence {evidence_id} has an invalid effective sensitivity"
            )
        return max(values, key=lambda value: SENSITIVITY_RANK[value])

    def _check_requirement(
        self, record: Mapping[str, Any], requirement: str, evidence_id: str
    ) -> None:
        if requirement == "record-only":
            return
        if requirement == "raw":
            payload = record.get("payload")
            reference = payload.get("object") if isinstance(payload, Mapping) else None
            satisfied = (
                isinstance(payload, Mapping)
                and payload.get("state") == "present"
                and self._retained_object_matches(reference)
            )
        else:
            role = requirement.partition(":")[2]
            representations = record.get("representations")
            satisfied = isinstance(representations, list) and any(
                isinstance(item, Mapping)
                and item.get("role") == role
                and self._retained_object_matches(item.get("object"))
                for item in representations
            )
        if not satisfied:
            raise CanonIntegrityError(
                f"Evidence {evidence_id} does not satisfy requirement {requirement}"
            )

    def _retained_object_matches(self, reference: Any) -> bool:
        try:
            digest = _reference_digest(reference, "Evidence")
        except CanonIntegrityError:
            return False
        path = self._object_path(digest)
        try:
            data = _read_snapshot_file(
                path,
                "Evidence Object",
                max_bytes=MAX_EVIDENCE_OBJECT_BYTES,
                boundary=self.root,
            )
        except CanonIntegrityError:
            return False
        return _sha256(data) == digest

    @staticmethod
    def _make_claim(proposal: Mapping[str, Any], subject: str, claim_id: str) -> dict[str, Any]:
        claim: dict[str, Any] = {
            "id": claim_id,
            "subject": subject,
            "predicate": deepcopy(proposal["predicate"]),
            "object": deepcopy(proposal["object"]),
            "statement": deepcopy(proposal["statement"]),
            "basis": deepcopy(proposal["basis"]),
            "certainty": deepcopy(proposal["certainty"]),
            "state": "active",
            "observed_at": deepcopy(proposal["observed_at"]),
            "evidence": [deepcopy(dict(item)) for item in proposal["evidence"]],
        }
        for field in ("valid", "sensitivity", "supersedes"):
            if field in proposal:
                claim[field] = deepcopy(proposal[field])
        known = set(claim).union(PROTECTED_CLAIM_FIELDS)
        for field, value in proposal.items():
            if field not in known and field != "evidence":
                claim[field] = deepcopy(value)
        return claim

    @staticmethod
    def _effective_sensitivity(document_sensitivity: str, proposal: Mapping[str, Any]) -> str:
        claim_sensitivity = proposal.get("sensitivity", document_sensitivity)
        return max(
            (document_sensitivity, claim_sensitivity),
            key=lambda value: SENSITIVITY_RANK[value],
        )

    def _safe_canon_path(self, path: Path) -> Path:
        lexical = Path(path).expanduser().absolute()
        try:
            relative = lexical.relative_to(self.canon_root)
        except ValueError:
            raise CanonIntegrityError(f"Canon path escapes vault: {path}")
        if any(component in {"", ".", ".."} for component in relative.parts):
            raise CanonIntegrityError("Canon path is not normalized")
        cursor = self.canon_root
        for index, component in enumerate(relative.parts):
            cursor = cursor / component
            try:
                status = os.lstat(cursor)
            except FileNotFoundError:
                if index == len(relative.parts) - 1:
                    break
                raise CanonIntegrityError("Canon path parent is missing") from None
            except OSError as exc:
                raise CanonIntegrityError("Canon path cannot be inspected") from exc
            if stat.S_ISLNK(status.st_mode):
                raise CanonIntegrityError("Canon path must not contain symlinks")
            if index < len(relative.parts) - 1 and not stat.S_ISDIR(status.st_mode):
                raise CanonIntegrityError("Canon path parent must be a directory")
        return lexical

    def _object_path(self, digest: str) -> Path:
        object_path = getattr(self.vault, "object_path", None)
        if callable(object_path):
            return Path(object_path(digest))
        return self.root / "objects" / "sha256" / digest[:2] / digest[2:4] / digest

    def _events_for(self, target: str, event_types: set[str] | None = None) -> list[Mapping[str, Any]]:
        reader = getattr(self.vault, "events_for", None)
        if callable(reader):
            events = reader(target, event_types=event_types)
            return [event for event in events if isinstance(event, Mapping)]
        try:
            events = list(iter_events(self.root, target=target, verify=True))
        except (OSError, ValueError) as exc:
            raise CanonIntegrityError(f"cannot read event log safely: {exc}") from exc
        if event_types is not None:
            events = [event for event in events if event.get("event_type") in event_types]
        # Event order is global sequence order, not wall-clock order.  Keep
        # the fallback used by minimal/fake vaults under the same contract as
        # Vault.events_for()/iter_events().
        for event in events:
            sequence = event.get("sequence")
            if isinstance(sequence, bool) or not isinstance(sequence, int) or sequence < 1:
                raise CanonIntegrityError("event has an invalid global sequence")
        events.sort(key=lambda event: (event["sequence"], str(event.get("id", ""))))
        return events

    def _committed_transaction(self, transaction_id: str) -> Mapping[str, Any]:
        events = self._events_for(transaction_id, {"canon.change-committed"})
        matching = [
            event
            for event in events
            if isinstance(event.get("data"), Mapping)
            and event["data"].get("transaction_id") == transaction_id
        ]
        if not matching:
            raise CanonNotFoundError(f"committed Canon transaction not found: {transaction_id}")
        if len(matching) > 1:
            raise CanonIntegrityError(f"duplicate committed transaction: {transaction_id}")
        transaction = matching[0]["data"]
        if transaction.get("operation") != "promotion":
            raise CanonIntegrityError("rollback source is not a promotion transaction")
        if transaction.get("transaction_id") != transaction_id:
            raise CanonIntegrityError("committed transaction ID is inconsistent")
        if not isinstance(transaction.get("actor"), str) or not transaction["actor"].strip():
            raise CanonIntegrityError("committed transaction actor is invalid")
        for field in ("candidate", "claim", "document"):
            if not is_uuid7(transaction.get(field)):
                raise CanonIntegrityError(f"committed transaction {field} is invalid")
        _reference_digest(transaction.get("before"), "before")
        _reference_digest(transaction.get("after"), "after")
        if not isinstance(transaction.get("path"), str) or not transaction["path"]:
            raise CanonIntegrityError("committed transaction path is invalid")
        return transaction

    def _transaction_sensitivity(self, transaction_id: str) -> str:
        events = self._events_for(transaction_id, {"canon.change-committed"})
        if not events:
            return "personal"
        value = events[-1].get("sensitivity")
        return value if value in SENSITIVITIES else "personal"


def promote_candidate(vault: Any, candidate: Mapping[str, Any], *, actor: str) -> dict[str, Any]:
    """Functional wrapper for clients that do not retain a CanonStore."""

    return CanonStore(vault).promote(candidate, actor=actor)


def rollback(vault: Any, transaction_id: str, *, actor: str) -> dict[str, Any]:
    """Functional wrapper for an audited Canon rollback."""

    return CanonStore(vault).rollback(transaction_id, actor=actor)


def recover_interrupted(
    vault: Any, actor: str = "process:lifedb-canon-recovery"
) -> dict[str, Any]:
    """Recover prepared-only Canon transactions and candidate terminal gaps."""

    return CanonStore(vault).recover_interrupted(actor=actor)
