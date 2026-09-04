from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Mapping

from .evidence import iter_captures, iter_events
from .index import effective_evidence_sensitivity
from .ids import is_uuid7, new_id
from .markdown import canon_documents
from .policies import PolicyError, load_retention_policy_snapshot
from .storage import (
    canonical_json_bytes,
    durable_write_bytes,
    durable_write_json,
    DurablePublicationUncertain,
    file_lock,
    fsync_directory,
)
from .vault import Vault, utc_now


class RetentionError(RuntimeError):
    pass


class StaleRetentionPreview(RetentionError):
    pass


RETENTION_CLASSES = {"pinned", "durable", "grace", "derivative-only", "reference-only"}
CHANGEABLE_RETENTION_CLASSES = RETENTION_CLASSES - {"reference-only"}


def _parse_time(value: Any) -> datetime | None:
    if not isinstance(value, str) or re.fullmatch(
        r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|[+-]\d{2}:\d{2})",
        value,
    ) is None:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo is not None else None


def _digest(reference: Any) -> str | None:
    if not isinstance(reference, str) or not reference.startswith("sha256:"):
        return None
    value = reference.removeprefix("sha256:")
    if len(value) != 64 or any(character not in "0123456789abcdef" for character in value):
        return None
    return value


def _max_sensitivity(values: list[str]) -> str:
    order = {"public": 0, "personal": 1, "sensitive": 2, "restricted": 3}
    if any(value not in order for value in values):
        raise RetentionError("unknown sensitivity; retention apply fails closed")
    return max(values, default="personal", key=order.__getitem__)


def _regular_path(path: Path, *, label: str) -> os.stat_result:
    """Open-path-independent lstat guard used before any retention mutation."""

    try:
        metadata = path.lstat()
    except OSError as exc:
        raise RetentionError(f"{label} is unavailable: {path}") from exc
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise RetentionError(f"{label} must be a regular non-symlink file: {path}")
    return metadata


def _directory_flags() -> int:
    return (
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )


def _relative_parts(path: Path, boundary: Path) -> tuple[str, ...]:
    try:
        relative = Path(os.path.abspath(path)).relative_to(Path(os.path.abspath(boundary)))
    except ValueError:
        raise RetentionError("retention path escaped the vault boundary") from None
    if not relative.parts or any(part in {"", ".", ".."} for part in relative.parts):
        raise RetentionError("retention path contains an unsafe component")
    return tuple(relative.parts)


def _open_fixed_directory(
    path: Path, *, boundary: Path, create: bool = False
) -> int:
    """Open a directory below ``boundary`` without following any alias.

    The returned descriptor pins the directory object.  All subsequent
    mutation of entries in that directory must use this descriptor, so a
    pathname swap cannot redirect retention into an external directory.
    """

    parts = _relative_parts(path, boundary)
    current_fd = os.open(Path(os.path.abspath(boundary)), _directory_flags())
    try:
        for part in parts:
            try:
                child_fd = os.open(part, _directory_flags(), dir_fd=current_fd)
            except FileNotFoundError:
                if not create:
                    raise
                try:
                    os.mkdir(part, 0o700, dir_fd=current_fd)
                except FileExistsError:
                    pass
                fsync_directory(current_fd)
                child_fd = os.open(part, _directory_flags(), dir_fd=current_fd)
            os.close(current_fd)
            current_fd = child_fd
        if create:
            os.fchmod(current_fd, 0o700)
        return current_fd
    except BaseException:
        os.close(current_fd)
        raise


def _open_fixed_file(
    path: Path, *, boundary: Path, flags: int | None = None
) -> tuple[int, int, str]:
    """Open a regular file and pin its parent directory from the vault root."""

    parts = _relative_parts(path, boundary)
    parent = Path(os.path.abspath(boundary))
    if len(parts) > 1:
        parent = parent.joinpath(*parts[:-1])
    parent_fd = _open_fixed_directory(parent, boundary=boundary)
    open_flags = (flags if flags is not None else os.O_RDONLY) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(parts[-1], open_flags, dir_fd=parent_fd)
    except BaseException:
        os.close(parent_fd)
        raise
    return descriptor, parent_fd, parts[-1]


def _entry_stat(directory_fd: int, name: str) -> os.stat_result | None:
    try:
        return os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise RetentionError("retention entry cannot be inspected safely") from exc


def _streaming_digest_fd(
    descriptor: int, *, expected_digest: str, expected_size: int | None = None, label: str = "object"
) -> int:
    """Hash an already pinned regular-file descriptor with bounded memory."""

    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise RetentionError(f"{label} is not a regular file")
        if expected_size is not None and metadata.st_size != expected_size:
            raise RetentionError(f"{label} size does not match retention manifest")
        digest = hashlib.sha256()
        size = 0
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
            size += len(chunk)
        finished = os.fstat(descriptor)
        if digest.hexdigest() != expected_digest:
            raise RetentionError(f"{label} digest does not match retention manifest")
        if expected_size is not None and size != expected_size:
            raise RetentionError(f"{label} size changed while being read")
        if finished.st_size != size:
            raise RetentionError(f"{label} changed while being read")
        return size
    except OSError as exc:
        raise RetentionError(f"{label} cannot be read safely") from exc


def _streaming_digest(
    path: Path,
    *,
    expected_digest: str,
    expected_size: int | None = None,
    boundary: Path | None = None,
    directory_fd: int | None = None,
    entry_name: str | None = None,
) -> int:
    """Validate one object through an O_NOFOLLOW descriptor with bounded memory.

    Manager mutation paths pass a pinned ``directory_fd``.  The standalone
    form remains available for preview callers and retains the old API.
    """

    if directory_fd is not None:
        name = entry_name or path.name
        status = _entry_stat(directory_fd, name)
        if status is None or stat.S_ISLNK(status.st_mode) or not stat.S_ISREG(status.st_mode):
            raise RetentionError(f"object must be a regular non-symlink file: {path}")
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(name, flags, dir_fd=directory_fd)
        except OSError as exc:
            raise RetentionError(f"object cannot be opened safely: {path}") from exc
        try:
            opened = os.fstat(descriptor)
            if any(
                getattr(opened, field) != getattr(status, field)
                for field in ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
            ):
                raise RetentionError(f"object changed while being opened: {path}")
            return _streaming_digest_fd(
                descriptor,
                expected_digest=expected_digest,
                expected_size=expected_size,
            )
        finally:
            os.close(descriptor)

    _regular_path(path, label="object")
    try:
        if path.resolve(strict=True) != path.absolute():
            raise RetentionError(f"object path is not canonical: {path}")
    except OSError as exc:
        raise RetentionError(f"object path cannot be resolved safely: {path}") from exc
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    parent_fd: int | None = None
    try:
        if boundary is not None:
            descriptor, parent_fd, _ = _open_fixed_file(path, boundary=boundary, flags=flags)
        else:
            descriptor = os.open(path, flags)
    except OSError as exc:
        raise RetentionError(f"object cannot be opened safely: {path}") from exc
    try:
        return _streaming_digest_fd(descriptor, expected_digest=expected_digest, expected_size=expected_size)
    finally:
        os.close(descriptor)
        if parent_fd is not None:
            os.close(parent_fd)


def _same_filesystem(path: Path, *, boundary: Path, label: str) -> None:
    """Reject a retention path on a different device (including a mount)."""

    try:
        path_device = os.lstat(path).st_dev
        boundary_device = os.lstat(boundary).st_dev
    except OSError as exc:
        raise RetentionError(f"{label} filesystem cannot be inspected safely") from exc
    if path_device != boundary_device:
        raise RetentionError(f"{label} is on a different filesystem")


class RetentionManager:
    """Explicit, preview-bound raw payload eviction.

    No method is scheduled automatically. apply() requires the exact confirmation
    digest returned by preview() and re-evaluates all dependencies under the
    vault-global writer lock.
    """

    def __init__(self, vault: Vault):
        self.vault = vault
        self.root = vault.root
        self.policy_path = self.root / "policies" / "retention.json"
        self.plan_root = self.root / "runtime" / "retention"
        self.lock_path = self.root / "runtime" / "locks" / "writer.lock"

    def _ensure_runtime_layout(self) -> None:
        """Create/check disposable paths without following vault aliases."""

        try:
            root_status = os.lstat(self.root)
        except OSError as exc:
            raise RetentionError("vault root cannot be inspected safely") from exc
        if not stat.S_ISDIR(root_status.st_mode):
            raise RetentionError("vault root must be a real directory")

        for path in (self.root / "runtime", self.root / "runtime" / "locks", self.plan_root):
            try:
                descriptor = _open_fixed_directory(path, boundary=self.root, create=True)
            except (OSError, RetentionError) as exc:
                raise RetentionError("runtime path could not be created or inspected safely") from exc
            else:
                os.close(descriptor)

        try:
            lock_status = os.lstat(self.lock_path)
        except FileNotFoundError:
            try:
                durable_write_bytes(
                    self.lock_path,
                    b"",
                    exclusive=True,
                    mode=0o600,
                    boundary=self.root,
                )
                lock_status = os.lstat(self.lock_path)
            except FileExistsError:
                lock_status = os.lstat(self.lock_path)
            except (OSError, ValueError) as exc:
                raise RetentionError("retention writer lock could not be created safely") from exc
        except OSError as exc:
            raise RetentionError("retention writer lock cannot be inspected safely") from exc
        if not stat.S_ISREG(lock_status.st_mode):
            raise RetentionError("retention writer lock must be a regular file")

    @contextmanager
    def _writer_lock(self):
        # file_lock predates the Vault boundary API and creates its parent with
        # plain mkdir. Establish all parents and the final lock atomically first.
        self._ensure_runtime_layout()
        with file_lock(self.lock_path, boundary=self.root):
            yield

    def _policy(self) -> tuple[dict[str, Any], str]:
        try:
            snapshot = load_retention_policy_snapshot(self.vault)
        except (OSError, PolicyError, ValueError) as exc:
            raise RetentionError(f"cannot read retention policy: {exc}") from exc
        value = snapshot.value
        holds = value.get("holds", {})
        evidence_holds = holds.get("evidence", [])
        for evidence_id in evidence_holds:
            if not is_uuid7(evidence_id):
                raise RetentionError("retention holds.evidence must contain Evidence UUIDv7 values")
            if self.vault.load_evidence(evidence_id) is None:
                raise RetentionError(f"retention hold references unknown Evidence {evidence_id}")
        for reference in holds.get("objects", []):
            if _digest(reference) is None:
                raise RetentionError(
                    "retention holds.objects must contain exact sha256:<64 lowercase hex> references"
                )
        return value, snapshot.digest

    def _object_status(self, digest: str) -> tuple[bool, int, str | None]:
        path = self.vault.object_path(digest)
        try:
            canonical = path.resolve(strict=True)
        except OSError:
            return False, 0, "object is missing"
        if canonical != path.absolute():
            return False, 0, "object path is not canonical or contains a symlink"
        try:
            _same_filesystem(path, boundary=self.root, label="object")
            size = _streaming_digest(path, expected_digest=digest, boundary=self.root)
        except RetentionError as exc:
            return False, 0, str(exc)
        return True, size, None

    def change(
        self,
        evidence_id: str,
        retention: str,
        *,
        actor: str,
        reason: str,
    ) -> dict[str, Any]:
        """Append an explicit retention-class transition for one capture."""

        if not is_uuid7(evidence_id):
            raise ValueError("evidence_id must be a UUIDv7")
        if not isinstance(actor, str) or not actor.strip():
            raise ValueError("retention actor must be a non-empty string")
        if not isinstance(reason, str) or not reason.strip():
            raise ValueError("retention reason must be a non-empty string")
        if retention not in CHANGEABLE_RETENTION_CLASSES:
            raise ValueError("invalid target retention class")

        # Validate and append under the same vault-global lock used by all
        # durable writers, so two concurrent changes cannot share a stale class.
        with self._writer_lock():
            capture = self.vault.load_evidence(evidence_id)
            if capture is None:
                raise RetentionError(f"Evidence not found: {evidence_id}")
            effective = self.vault.effective_evidence(evidence_id)
            if effective is None:
                raise RetentionError(f"Evidence not found: {evidence_id}")
            payload = effective.get("payload")
            current = payload.get("retention") if isinstance(payload, Mapping) else None
            if current not in RETENTION_CLASSES:
                raise RetentionError("capture has an invalid retention class")
            if current == "reference-only":
                raise RetentionError("reference-only Evidence cannot be converted")
            if current == retention:
                raise RetentionError(f"Evidence retention is already {retention}")
            sensitivity = self._effective_sensitivity(evidence_id)
            return self.vault.append_event(
                "retention.changed",
                actor=actor,
                target=evidence_id,
                sensitivity=sensitivity,
                data={"from": current, "to": retention, "reason": reason.strip()},
            )

    @staticmethod
    def _edge(item: Any) -> tuple[str | None, str]:
        if isinstance(item, str):
            return item, "raw"
        if isinstance(item, Mapping):
            return item.get("id") if isinstance(item.get("id"), str) else None, str(
                item.get("requires", "")
            )
        return None, ""

    def _claim_raw_requirements(self) -> set[str]:
        required: set[str] = set()
        for document in canon_documents(self.root / "canon"):
            extension = document.frontmatter.get("x-lifedb", {})
            claims = extension.get("claims", []) if isinstance(extension, Mapping) else []
            for claim in claims if isinstance(claims, list) else []:
                if not isinstance(claim, Mapping) or claim.get("state") not in {"active", "disputed"}:
                    continue
                for item in claim.get("evidence", []):
                    evidence_id, requirement = self._edge(item)
                    if evidence_id and requirement == "raw":
                        required.add(evidence_id)
        return required

    def _protected_object_digests(self) -> set[str]:
        protected: set[str] = set()
        for event in iter_events(self.vault, verify=True):
            data = event.get("data")
            if not isinstance(data, Mapping):
                continue
            if event.get("event_type", "").startswith("canon."):
                for field in ("before", "after"):
                    value = _digest(data.get(field))
                    if value:
                        protected.add(value)
            representation = data.get("representation")
            if isinstance(representation, Mapping):
                values = [representation]
            elif isinstance(data.get("representations"), list):
                values = data["representations"]
            elif "role" in data and "object" in data:
                values = [data]
            else:
                values = []
            for item in values if isinstance(values, list) else []:
                if isinstance(item, Mapping):
                    value = _digest(item.get("object"))
                    if value:
                        protected.add(value)
        return protected

    def _durable_sequence(self) -> int:
        return max((event["sequence"] for event in iter_events(self.vault, verify=True)), default=0)

    def _effective_sensitivity(self, evidence_id: str) -> str:
        """Return the highest sensitivity attached to one Evidence dependency."""
        try:
            record = self.vault.load_evidence(evidence_id, verify=True)
            if record is None:
                raise RetentionError(f"Evidence not found: {evidence_id}")
            value = effective_evidence_sensitivity(self.vault, record)
        except RetentionError:
            raise
        except Exception as exc:
            raise RetentionError(
                "Evidence sensitivity could not be resolved; retention fails closed"
            ) from exc
        return value if value in {"public", "personal", "sensitive", "restricted"} else "restricted"

    def _candidate_sensitivity(self, candidates: list[Mapping[str, Any]]) -> str:
        values: list[str] = []
        for candidate in candidates:
            evidence = candidate.get("evidence")
            if not isinstance(evidence, list) or not evidence:
                raise RetentionError("retention candidate has no Evidence references")
            for evidence_id in evidence:
                if not isinstance(evidence_id, str):
                    raise RetentionError("retention candidate contains an invalid Evidence ID")
                values.append(self._effective_sensitivity(evidence_id))
        return _max_sensitivity(values)

    def _preview_data(self, *, now: datetime) -> dict[str, Any]:
        policy, policy_hash = self._policy()
        grace_before = now - timedelta(days=policy["grace_days"])
        raw_required = self._claim_raw_requirements()
        protected_digests = self._protected_object_digests()
        holds = policy.get("holds", {})
        held_evidence = set(holds.get("evidence", []))
        held_objects = {value.removeprefix("sha256:") for value in holds.get("objects", [])}

        groups: dict[str, list[tuple[dict[str, Any], dict[str, Any]]]] = {}
        for capture in iter_captures(self.vault, verify=True):
            effective = self.vault.effective_evidence(capture["id"])
            if effective is None or effective.get("payload", {}).get("state") != "present":
                continue
            digest = _digest(effective.get("payload", {}).get("object"))
            if digest:
                groups.setdefault(digest, []).append((capture, effective))

        candidates: list[dict[str, Any]] = []
        blocked: list[dict[str, Any]] = []
        for digest, references in sorted(groups.items()):
            reasons: list[str] = []
            evidence_ids = sorted(str(capture["id"]) for capture, _ in references)
            object_valid, object_size, object_error = self._object_status(digest)
            if not object_valid:
                reasons.append(object_error or "object failed integrity validation")
            if digest in protected_digests:
                reasons.append("object is a Canon snapshot or retained representation")
            if digest in held_objects or any(value in held_evidence for value in evidence_ids):
                reasons.append("owner or legal hold")
            if any(value in raw_required for value in evidence_ids):
                reasons.append("active Claim requires raw bytes")
            for capture, effective in references:
                evidence_id = str(capture["id"])
                effective_payload = effective.get("payload", {})
                retention = effective_payload.get("retention")
                if retention in {"pinned", "durable"}:
                    reasons.append(f"{evidence_id} retention is {retention}")
                elif retention == "grace":
                    grace_origin = effective_payload.get("changed_at", capture.get("ingested_at"))
                    grace_started = _parse_time(grace_origin)
                    if grace_started is None or grace_started > grace_before:
                        reasons.append(f"{evidence_id} grace period has not expired")
                elif retention == "derivative-only":
                    all_representations = effective.get("representations", [])
                    representations = []
                    if not isinstance(all_representations, list):
                        reasons.append(f"{evidence_id} representations is malformed")
                        all_representations = []
                    for item in all_representations:
                        if not isinstance(item, Mapping):
                            reasons.append(f"{evidence_id} has a malformed representation")
                            continue
                        role = item.get("role")
                        representation_digest = _digest(item.get("object"))
                        if not isinstance(role, str) or not role.strip() or representation_digest is None:
                            reasons.append(f"{evidence_id} has a malformed representation")
                            continue
                        valid, _, error = self._object_status(representation_digest)
                        if not valid:
                            reasons.append(
                                f"{evidence_id} representation {role!r} is invalid: "
                                f"{error or 'object failed integrity validation'}"
                            )
                            continue
                        representations.append(item)
                    required_roles = capture.get("payload", {}).get("required_representations", [])
                    if not isinstance(required_roles, list) or any(
                        not isinstance(role, str) or not role.strip() for role in required_roles
                    ):
                        reasons.append(f"{evidence_id} required representation roles are malformed")
                        required_roles = []
                    roles = {str(item.get("role")) for item in representations}
                    if required_roles:
                        missing = [role for role in required_roles if role not in roles]
                        if missing:
                            reasons.append(
                                f"{evidence_id} lacks required representation roles: {', '.join(missing)}"
                            )
                    elif not representations:
                        reasons.append(f"{evidence_id} has no retained representation")
                else:
                    reasons.append(f"{evidence_id} retention does not permit raw eviction")
            object_path = self.vault.object_path(digest)
            entry = {
                "object": f"sha256:{digest}",
                "size": object_size,
                "evidence": evidence_ids,
            }
            if reasons:
                entry["reasons"] = sorted(set(reasons))
                blocked.append(entry)
            elif not object_valid:
                entry["reasons"] = sorted(set(reasons))
                blocked.append(entry)
            else:
                candidates.append(entry)
        return {
            "schema": "0.2",
            "policy": policy_hash,
            "durable_sequence": self._durable_sequence(),
            "candidates": candidates,
            "blocked": blocked,
            "estimated_bytes": sum(item["size"] for item in candidates),
        }

    @staticmethod
    def _confirmation(value: Mapping[str, Any]) -> str:
        unsigned = {key: item for key, item in value.items() if key not in {"confirmation"}}
        return "sha256:" + hashlib.sha256(canonical_json_bytes(unsigned)).hexdigest()

    def preview(self, *, now: datetime | None = None, persist: bool = True) -> dict[str, Any]:
        resolved_now = now or datetime.now(timezone.utc)
        if resolved_now.tzinfo is None:
            raise ValueError("retention preview time must include an explicit offset")
        with self._writer_lock():
            plan = {
                **self._preview_data(now=resolved_now),
                "id": new_id(),
                "created_at": resolved_now.isoformat().replace("+00:00", "Z"),
            }
            plan["confirmation"] = self._confirmation(plan)
            if persist:
                durable_write_json(
                    self.plan_root / f"{plan['id']}.json",
                    plan,
                    exclusive=True,
                    mode=0o600,
                    boundary=self.root,
                )
            return plan

    def _load_plan(self, plan_id: str) -> dict[str, Any]:
        if not is_uuid7(plan_id):
            raise ValueError("retention plan ID must be a UUIDv7")
        path = self.plan_root / f"{plan_id}.json"
        try:
            metadata = _regular_path(path, label="retention preview")
            if path.resolve(strict=True) != path.absolute():
                raise RetentionError("retention preview path is not canonical")
            if metadata.st_size > 1024 * 1024:
                raise RetentionError("retention preview exceeds the maximum size")
            flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
            descriptor, parent_fd, _ = _open_fixed_file(path, boundary=self.root, flags=flags)
            try:
                raw_parts: list[bytes] = []
                while True:
                    part = os.read(descriptor, 65536)
                    if not part:
                        break
                    raw_parts.append(part)
                    if sum(len(item) for item in raw_parts) > 1024 * 1024:
                        raise RetentionError("retention preview exceeds the maximum size")
                raw = b"".join(raw_parts)
            finally:
                os.close(descriptor)
                os.close(parent_fd)
            value = json.loads(
                raw.decode("utf-8"),
                parse_constant=lambda item: (_ for _ in ()).throw(
                    ValueError(f"non-finite JSON value {item!r}")
                ),
                object_pairs_hook=self._unique_json_object,
            )
        except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
            raise RetentionError(f"cannot read retention preview {plan_id}: {exc}") from exc
        self._validate_plan(value, plan_id)
        return value

    @staticmethod
    def _unique_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        value: dict[str, Any] = {}
        for key, item in pairs:
            if key in value:
                raise ValueError(f"duplicate JSON property {key!r}")
            value[key] = item
        return value

    @staticmethod
    def _validate_manifest_candidate(
        candidate: Any, *, label: str = "candidate", allow_reasons: bool = False
    ) -> None:
        if not isinstance(candidate, Mapping):
            raise RetentionError(f"retention {label} must be an object")
        keys = set(candidate)
        permitted = {"object", "size", "evidence"} | ({"reasons"} if allow_reasons else set())
        if not keys.issubset(permitted):
            raise RetentionError(f"retention {label} has unexpected fields")
        digest = _digest(candidate.get("object"))
        size = candidate.get("size")
        evidence = candidate.get("evidence")
        if digest is None or isinstance(size, bool) or not isinstance(size, int) or size < 0:
            raise RetentionError(f"retention {label} has invalid object or size")
        if not isinstance(evidence, list) or not evidence or len(set(evidence)) != len(evidence):
            raise RetentionError(f"retention {label} evidence must be a unique non-empty list")
        if any(not isinstance(item, str) or not is_uuid7(item) for item in evidence):
            raise RetentionError(f"retention {label} evidence contains an invalid ID")
        if "reasons" in candidate:
            reasons = candidate["reasons"]
            if not isinstance(reasons, list) or any(not isinstance(item, str) for item in reasons):
                raise RetentionError(f"retention {label} reasons are malformed")

    @classmethod
    def _validate_plan(cls, value: Any, plan_id: str) -> None:
        if not isinstance(value, dict) or value.get("schema") != "0.2" or value.get("id") != plan_id:
            raise RetentionError("retention preview is malformed")
        expected_fields = {
            "schema", "id", "policy", "durable_sequence", "candidates", "blocked",
            "estimated_bytes", "created_at", "confirmation",
        }
        if set(value) != expected_fields:
            raise RetentionError("retention preview has unexpected or missing fields")
        if _digest(value.get("policy")) is None or not is_uuid7(value.get("id")):
            raise RetentionError("retention preview has invalid IDs or policy digest")
        sequence = value.get("durable_sequence")
        if isinstance(sequence, bool) or not isinstance(sequence, int) or sequence < 0:
            raise RetentionError("retention preview has invalid durable sequence")
        created = _parse_time(value.get("created_at"))
        if created is None:
            raise RetentionError("retention preview created_at is invalid")
        candidates = value.get("candidates")
        blocked = value.get("blocked")
        if not isinstance(candidates, list) or not isinstance(blocked, list):
            raise RetentionError("retention preview candidate lists are malformed")
        all_objects: set[str] = set()
        for item in candidates:
            cls._validate_manifest_candidate(item)
            obj = item["object"]
            if obj in all_objects:
                raise RetentionError("retention preview contains duplicate objects")
            all_objects.add(obj)
        for item in blocked:
            cls._validate_manifest_candidate(item, label="blocked entry", allow_reasons=True)
        estimated = value.get("estimated_bytes")
        if isinstance(estimated, bool) or not isinstance(estimated, int) or estimated < 0:
            raise RetentionError("retention preview has invalid estimated_bytes")
        if estimated != sum(item["size"] for item in candidates):
            raise RetentionError("retention preview estimated_bytes is inconsistent")
        if value.get("confirmation") != cls._confirmation(value):
            raise RetentionError("retention preview confirmation digest is invalid")

    def _compensate_moves(
        self, moved: list[tuple[str, int, str, int, str, Path, Path]]
    ) -> tuple[bool, list[str]]:
        """Restore every tracked rename, reporting partial compensation.

        The caller records a move immediately after ``os.replace``; this
        method consequently covers failures in every later chmod, fsync, and
        digest check. Only exact manifest paths in ``moved`` are touched.
        """

        complete = True
        restored: list[str] = []
        for digest, source_fd, source_name, quarantine_fd, destination_name, source, destination in reversed(moved):
            try:
                source_status = _entry_stat(source_fd, source_name)
                destination_status = _entry_stat(quarantine_fd, destination_name)
                if source_status is not None and (
                    stat.S_ISLNK(source_status.st_mode) or not stat.S_ISREG(source_status.st_mode)
                ):
                    raise RetentionError("retention compensation encountered an unsafe source")
                if destination_status is not None and (
                    stat.S_ISLNK(destination_status.st_mode)
                    or not stat.S_ISREG(destination_status.st_mode)
                ):
                    raise RetentionError("retention compensation encountered an unsafe quarantine")
                source_exists = source_status is not None
                destination_exists = destination_status is not None
                if source_exists:
                    _streaming_digest(
                        source,
                        expected_digest=digest,
                        directory_fd=source_fd,
                        entry_name=source_name,
                    )
                if destination_exists:
                    _streaming_digest(
                        destination,
                        expected_digest=digest,
                        directory_fd=quarantine_fd,
                        entry_name=destination_name,
                    )
                if source_exists:
                    if destination_exists:
                        os.unlink(destination_name, dir_fd=quarantine_fd)
                        fsync_directory(quarantine_fd)
                elif destination_exists:
                    os.replace(
                        destination_name,
                        source_name,
                        src_dir_fd=quarantine_fd,
                        dst_dir_fd=source_fd,
                    )
                    descriptor = os.open(
                        source_name,
                        os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
                        dir_fd=source_fd,
                    )
                    try:
                        os.fchmod(descriptor, 0o400)
                        os.fsync(descriptor)
                    finally:
                        os.close(descriptor)
                    fsync_directory(source_fd)
                    fsync_directory(quarantine_fd)
                    _streaming_digest(
                        source,
                        expected_digest=digest,
                        directory_fd=source_fd,
                        entry_name=source_name,
                    )
                else:
                    raise RetentionError("retention compensation found both copies missing")
                restored.append(digest)
            except BaseException:
                complete = False
        return complete, restored

    @staticmethod
    def _comparable(plan: Mapping[str, Any]) -> dict[str, Any]:
        return {
            key: plan.get(key)
            for key in ("policy", "durable_sequence", "candidates", "estimated_bytes")
        }

    def apply(self, plan_id: str, *, confirmation: str, actor: str) -> dict[str, Any]:
        if not isinstance(actor, str) or not actor.strip():
            raise ValueError("retention actor must be a non-empty string")
        plan = self._load_plan(plan_id)
        if confirmation != plan.get("confirmation"):
            raise RetentionError("confirmation does not match the exact retention preview")
        created = _parse_time(plan.get("created_at"))
        if created is None:
            raise RetentionError("retention preview created_at is invalid")
        transaction_id = new_id()
        moved: list[tuple[str, int, str, int, str, Path, Path]] = []
        evicted_targets: list[str] = []
        evidence_sensitivities: dict[str, str] = {}
        quarantine_fd: int | None = None
        source_fds: list[int] = []

        def close_move_fds() -> None:
            nonlocal quarantine_fd
            if quarantine_fd is not None:
                try:
                    os.close(quarantine_fd)
                except OSError:
                    pass
                quarantine_fd = None
            for descriptor in source_fds:
                try:
                    os.close(descriptor)
                except OSError:
                    pass
            source_fds.clear()
        with self._writer_lock():
            current = self._preview_data(now=created)
            if self._comparable(current) != self._comparable(plan):
                raise StaleRetentionPreview("retention preview is stale; generate and confirm a new preview")
            for candidate in plan["candidates"]:
                for evidence_id in candidate["evidence"]:
                    record = self.vault.load_evidence(evidence_id)
                    if record is None:
                        raise RetentionError(
                            f"retention preview references missing Evidence {evidence_id}"
                        )
                    evidence_sensitivities[evidence_id] = self._effective_sensitivity(evidence_id)
            sensitivity = self._candidate_sensitivity(plan["candidates"])
            self.vault.append_event(
                "retention.apply-prepared",
                actor=actor,
                target=transaction_id,
                sensitivity=sensitivity,
                data={"plan": plan_id, "confirmation": confirmation, "candidates": plan["candidates"]},
            )
            try:
                quarantine_root = self.root / "quarantine" / "retention" / transaction_id
                quarantine_fd = _open_fixed_directory(
                    quarantine_root, boundary=self.root, create=True
                )
                for candidate in plan["candidates"]:
                    digest = candidate["object"].removeprefix("sha256:")
                    source = self.vault.object_path(digest)
                    destination = quarantine_root / digest
                    source_fd = _open_fixed_directory(
                        source.parent, boundary=self.root, create=False
                    )
                    source_fds.append(source_fd)
                    source_name = source.name
                    destination_name = destination.name
                    destination_status = _entry_stat(quarantine_fd, destination_name)
                    if destination_status is not None:
                        raise RetentionError("quarantine destination already exists")
                    source_status = _entry_stat(source_fd, source_name)
                    if source_status is None or stat.S_ISLNK(source_status.st_mode) or not stat.S_ISREG(source_status.st_mode):
                        raise RetentionError("retention source must be a regular non-symlink file")
                    _streaming_digest(
                        source,
                        expected_digest=digest,
                        expected_size=candidate["size"],
                        directory_fd=source_fd,
                        entry_name=source_name,
                    )
                    try:
                        os.replace(
                            source_name,
                            destination_name,
                            src_dir_fd=source_fd,
                            dst_dir_fd=quarantine_fd,
                        )
                    except OSError as exc:
                        # An interrupted rename cannot be classified as
                        # pre-publication: the kernel may have committed the
                        # directory entry before reporting the error.
                        raise DurablePublicationUncertain(destination) from exc
                    # Track immediately: chmod/fsync/hash validation can all
                    # fail after the rename and must remain compensable.
                    moved.append(
                        (
                            digest,
                            source_fd,
                            source_name,
                            quarantine_fd,
                            destination_name,
                            source,
                            destination,
                        )
                    )
                    try:
                        descriptor = os.open(
                            destination_name,
                            os.O_RDONLY
                            | getattr(os, "O_CLOEXEC", 0)
                            | getattr(os, "O_NOFOLLOW", 0),
                            dir_fd=quarantine_fd,
                        )
                        try:
                            os.fchmod(descriptor, 0o400)
                            os.fsync(descriptor)
                        finally:
                            os.close(descriptor)
                        fsync_directory(source_fd)
                        fsync_directory(quarantine_fd)
                    except OSError as exc:
                        # Rename is visible, but its file/parent durability is
                        # unknown.  Keep prepared + exact quarantine manifest;
                        # recovery must reconcile both pinned locations.
                        raise DurablePublicationUncertain(destination) from exc
                    _streaming_digest(
                        destination,
                        expected_digest=digest,
                        expected_size=candidate["size"],
                        directory_fd=quarantine_fd,
                        entry_name=destination_name,
                    )
                    for evidence_id in candidate["evidence"]:
                        self.vault.append_event(
                            "payload.evicted",
                            actor=actor,
                            target=evidence_id,
                            sensitivity=sensitivity,
                            data={
                                "transaction_id": transaction_id,
                                "plan": plan_id,
                                "object": candidate["object"],
                                "payload": {
                                    "reason": "explicit retention preview applied",
                                    "policy": plan["policy"],
                                },
                            },
                        )
                        evicted_targets.append(evidence_id)
                committed = self.vault.append_event(
                    "retention.apply-committed",
                    actor=actor,
                    target=transaction_id,
                    sensitivity=sensitivity,
                    data={
                        "plan": plan_id,
                        "confirmation": confirmation,
                        "candidates": plan["candidates"],
                        "freed_bytes": plan["estimated_bytes"],
                    },
                )
            except DurablePublicationUncertain:
                # Publication may already be visible although directory fsync
                # was uncertain. Leave the exact manifest in quarantine for
                # recovery; never compensate or clean an ambiguous mutation.
                close_move_fds()
                raise
            except BaseException as exc:
                compensated, _ = self._compensate_moves(moved)
                close_move_fds()
                if not compensated:
                    # Keep only the prepared event. Recovery can then inspect
                    # every exact manifest pair and finish deterministically.
                    raise RetentionError(
                        "retention apply failed; compensation is incomplete and recovery is required"
                    ) from exc
                try:
                    for evidence_id in evicted_targets:
                        self.vault.append_event(
                            "payload.restored",
                            actor="process:lifedb-retention-recovery",
                            target=evidence_id,
                            sensitivity=evidence_sensitivities.get(evidence_id, "restricted"),
                            data={
                                "transaction_id": transaction_id,
                                "plan": plan_id,
                                "object": next(
                                    candidate["object"]
                                    for candidate in plan["candidates"]
                                    if evidence_id in candidate["evidence"]
                                ),
                                "payload": {"reason": "apply failed"},
                            },
                        )
                    self.vault.append_event(
                        "retention.apply-aborted",
                        actor="process:lifedb-retention-recovery",
                        target=transaction_id,
                        sensitivity=sensitivity,
                        data={
                            "plan": plan_id,
                            "confirmation": confirmation,
                            "candidates": plan["candidates"],
                            "restored": True,
                            "restored_evidence": evicted_targets,
                            "error_type": type(exc).__name__,
                        },
                    )
                except BaseException as recovery_exc:
                    # Never mark the transaction terminal until the complete
                    # restoration trail is durable. Recovery remains available.
                    raise RetentionError(
                        "retention apply failed after compensation; recovery is required"
                    ) from recovery_exc
                raise RetentionError("retention apply failed and was compensated") from exc

            try:
                for digest, _, _, quarantine_fd, destination_name, _, destination in moved:
                    # A committed transaction may clean only the exact quarantine
                    # object named by its manifest.  Never unlink by glob or by
                    # source pathname (a same-digest source can be a new reference).
                    _streaming_digest(
                        destination,
                        expected_digest=digest,
                        directory_fd=quarantine_fd,
                        entry_name=destination_name,
                    )
                    os.unlink(destination_name, dir_fd=quarantine_fd)
                    fsync_directory(quarantine_fd)
            finally:
                close_move_fds()
            return {
                "schema": "0.2",
                "transaction_id": transaction_id,
                "event": committed["id"],
                "objects_evicted": len(moved),
                "evidence_updated": len(evicted_targets),
                "freed_bytes": plan["estimated_bytes"],
            }

    def recover_interrupted(self) -> dict[str, Any]:
        """Repair only transactions whose durable manifest is unambiguous.

        Every manifest and every candidate object is validated before any
        rename/unlink.  Ambiguous or malformed state is reported as unresolved
        and left untouched for an operator to inspect.
        """

        recovered: list[str] = []
        cleaned: list[str] = []
        unresolved: list[str] = []
        with self._writer_lock():
            try:
                events = list(iter_events(self.vault, verify=True))
            except Exception:
                # Event corruption is itself an unresolved recovery boundary;
                # do not attempt to infer transactions from a partial scan.
                return {"schema": "0.2", "recovered": [], "cleaned": [], "unresolved": ["event-log"]}
            by_transaction: dict[str, list[dict[str, Any]]] = {}
            for event in events:
                event_type = event.get("event_type")
                if event_type in {
                    "retention.apply-prepared", "retention.apply-committed", "retention.apply-aborted"
                }:
                    target = event.get("target")
                    if not isinstance(target, str) or not is_uuid7(target):
                        continue
                    by_transaction.setdefault(target, []).append(event)

            eviction_events = [
                event for event in events
                if event.get("event_type") in {"payload.evicted", "payload-evicted"}
            ]
            for transaction_id, transaction_events in sorted(by_transaction.items()):
                prepared_events = [
                    event for event in transaction_events
                    if event.get("event_type") == "retention.apply-prepared"
                ]
                committed_events = [
                    event for event in transaction_events
                    if event.get("event_type") == "retention.apply-committed"
                ]
                aborted_events = [
                    event for event in transaction_events
                    if event.get("event_type") == "retention.apply-aborted"
                ]
                if len(prepared_events) != 1 or len(committed_events) > 1 or len(aborted_events) > 1:
                    unresolved.append(transaction_id)
                    continue
                if committed_events and aborted_events:
                    unresolved.append(transaction_id)
                    continue
                if aborted_events:
                    # An already-aborted transaction is terminal and must be
                    # left alone on subsequent recovery passes.
                    continue
                prepared = prepared_events[0]
                data = prepared.get("data")
                if not isinstance(data, Mapping):
                    unresolved.append(transaction_id)
                    continue
                # The prepared event is the durable recovery manifest.  Do
                # not make its authority conditional on a disposable preview
                # file surviving a runtime reset.
                if set(data) != {"plan", "confirmation", "candidates"}:
                    unresolved.append(transaction_id)
                    continue
                plan_id = data.get("plan")
                confirmation = data.get("confirmation")
                candidates = data.get("candidates")
                if (
                    not is_uuid7(plan_id)
                    or not isinstance(confirmation, str)
                    or _digest(confirmation) is None
                    or not isinstance(candidates, list)
                ):
                    unresolved.append(transaction_id)
                    continue
                # The preview remains useful as an optional cross-check when
                # present.  Its absence is expected after a disposable
                # runtime reset; a present but malformed or mismatching plan
                # is treated as tampering/ambiguity and fails closed.
                plan_path = self.plan_root / f"{plan_id}.json"
                try:
                    os.lstat(plan_path)
                except FileNotFoundError:
                    plan = None
                except OSError:
                    unresolved.append(transaction_id)
                    continue
                else:
                    try:
                        plan = self._load_plan(plan_id)
                    except (OSError, RetentionError, ValueError):
                        unresolved.append(transaction_id)
                        continue
                    if (
                        confirmation != plan.get("confirmation")
                        or candidates != plan.get("candidates")
                    ):
                        unresolved.append(transaction_id)
                        continue
                try:
                    for candidate in candidates:
                        self._validate_manifest_candidate(candidate)
                except RetentionError:
                    unresolved.append(transaction_id)
                    continue
                if len({item["object"] for item in candidates}) != len(candidates):
                    unresolved.append(transaction_id)
                    continue
                if committed_events:
                    committed_data = committed_events[0].get("data")
                    if not isinstance(committed_data, Mapping):
                        unresolved.append(transaction_id)
                        continue
                    if set(committed_data) != {
                        "plan", "confirmation", "candidates", "freed_bytes"
                    }:
                        unresolved.append(transaction_id)
                        continue
                    committed_candidates = committed_data.get("candidates")
                    if (
                        committed_data.get("plan") != plan_id
                        or _digest(committed_data.get("confirmation")) is None
                        or committed_data.get("confirmation") != confirmation
                        or committed_candidates != candidates
                        or isinstance(committed_data.get("freed_bytes"), bool)
                        or not isinstance(committed_data.get("freed_bytes"), int)
                        or committed_data.get("freed_bytes") != sum(item["size"] for item in candidates)
                    ):
                        unresolved.append(transaction_id)
                        continue
                for candidate in candidates:
                    for evidence_id in candidate["evidence"]:
                        try:
                            record = self.vault.load_evidence(evidence_id)
                            if record is None:
                                raise RetentionError("manifest references missing Evidence")
                            content = record.get("content")
                            if (
                                not isinstance(content, Mapping)
                                or content.get("sha256")
                                != candidate["object"].removeprefix("sha256:")
                            ):
                                raise RetentionError(
                                    "manifest Evidence reference does not match object"
                                )
                        except Exception:
                            unresolved.append(transaction_id)
                            break
                    if transaction_id in unresolved:
                        break
                if transaction_id in unresolved:
                    continue

                quarantine_root = self.root / "quarantine" / "retention" / transaction_id

                # A transaction directory is an exact manifest, not a
                # best-effort cache.  Unexpected entries (including a symlink,
                # FIFO, or nested directory) make the state ambiguous and are
                # never touched by recovery.
                expected_names = {
                    candidate["object"].removeprefix("sha256:") for candidate in candidates
                }
                quarantine_fd: int | None = None
                try:
                    quarantine_fd = _open_fixed_directory(
                        quarantine_root, boundary=self.root, create=False
                    )
                    os.fchmod(quarantine_fd, 0o700)
                except FileNotFoundError:
                    # No quarantine bytes can exist if the exact transaction
                    # directory is absent; source-side validation still applies.
                    quarantine_fd = None
                except OSError:
                    unresolved.append(transaction_id)
                    continue
                if quarantine_fd is not None:
                    try:
                        actual_names: set[str] = set()
                        with os.scandir(quarantine_fd) as entries:
                            for entry in entries:
                                actual_names.add(entry.name)
                                entry_status = entry.stat(follow_symlinks=False)
                                if (
                                    entry.name not in expected_names
                                    or not stat.S_ISREG(entry_status.st_mode)
                                    or entry.is_symlink()
                                ):
                                    raise RetentionError("quarantine contains an unexpected entry")
                        if not actual_names.issubset(expected_names):
                            raise RetentionError("quarantine manifest has extra entries")
                    except (OSError, RetentionError):
                        os.close(quarantine_fd)
                        unresolved.append(transaction_id)
                        continue

                # First validate every source/quarantine pair.  This is the
                # key no-partial-recovery guarantee.
                pairs: list[tuple[dict[str, Any], Path, Path, str, int, str, str]] = []
                invalid = False
                for candidate in candidates:
                    digest = candidate["object"].removeprefix("sha256:")
                    source = self.vault.object_path(digest)
                    quarantined = quarantine_root / digest
                    source_exists = source.exists() or source.is_symlink()
                    source_fd: int | None = None
                    source_name = source.name
                    destination_name = quarantined.name
                    try:
                        source_fd = _open_fixed_directory(source.parent, boundary=self.root)
                    except OSError:
                        invalid = True
                        break
                    quarantine_exists = (
                        quarantine_fd is not None
                        and _entry_stat(quarantine_fd, destination_name) is not None
                    )
                    if not source_exists and not quarantine_exists:
                        # A committed transaction normally has already cleaned
                        # its quarantine copy and must not be reported as
                        # unresolved merely because both durable copies are
                        # gone.  For prepared-only this is ambiguous and is
                        # intentionally unresolved.
                        if committed_events:
                            pairs.append(
                                (candidate, source, quarantined, digest, source_fd, source_name, destination_name)
                            )
                            continue
                        invalid = True
                        os.close(source_fd)
                        break
                    try:
                        if source_exists:
                            _streaming_digest(
                                source,
                                expected_digest=digest,
                                expected_size=candidate["size"],
                                directory_fd=source_fd,
                                entry_name=source_name,
                            )
                        if quarantine_exists:
                            _streaming_digest(
                                quarantined,
                                expected_digest=digest,
                                expected_size=candidate["size"],
                                directory_fd=quarantine_fd,
                                entry_name=destination_name,
                            )
                    except RetentionError:
                        invalid = True
                        os.close(source_fd)
                        break
                    pairs.append(
                        (candidate, source, quarantined, digest, source_fd, source_name, destination_name)
                    )
                if invalid:
                    if quarantine_fd is not None:
                        os.close(quarantine_fd)
                    for pair in pairs:
                        os.close(pair[4])
                    unresolved.append(transaction_id)
                    continue

                if committed_events:
                    # Commit means source removal is complete.  Only clean
                    # exact, digest-verified quarantine residue.  A source
                    # file is intentionally never touched here.
                    try:
                        for _, _, quarantined, digest, _, _, destination_name in pairs:
                            if quarantine_fd is not None and _entry_stat(quarantine_fd, destination_name) is not None:
                                _streaming_digest(
                                    quarantined,
                                    expected_digest=digest,
                                    directory_fd=quarantine_fd,
                                    entry_name=destination_name,
                                )
                                os.unlink(destination_name, dir_fd=quarantine_fd)
                                fsync_directory(quarantine_fd)
                    except (OSError, RetentionError):
                        if quarantine_fd is not None:
                            os.close(quarantine_fd)
                        for pair in pairs:
                            os.close(pair[4])
                        unresolved.append(transaction_id)
                        continue
                    if quarantine_fd is not None:
                        os.close(quarantine_fd)
                    for pair in pairs:
                        os.close(pair[4])
                    cleaned.append(transaction_id)
                    continue

                # Prepared-only: source-only means no move occurred; quarantine
                # only is moved back; both valid copies keep source and remove
                # only the quarantine duplicate.  Never process a partly
                # validated manifest.
                restored_targets: list[str] = []
                try:
                    for candidate, source, quarantined, digest, source_fd, source_name, destination_name in pairs:
                        source_exists = _entry_stat(source_fd, source_name) is not None
                        quarantine_exists = (
                            quarantine_fd is not None
                            and _entry_stat(quarantine_fd, destination_name) is not None
                        )
                        if quarantine_exists and not source_exists:
                            assert quarantine_fd is not None
                            os.replace(
                                destination_name,
                                source_name,
                                src_dir_fd=quarantine_fd,
                                dst_dir_fd=source_fd,
                            )
                            descriptor = os.open(
                                source_name,
                                os.O_RDONLY
                                | getattr(os, "O_CLOEXEC", 0)
                                | getattr(os, "O_NOFOLLOW", 0),
                                dir_fd=source_fd,
                            )
                            try:
                                os.fchmod(descriptor, 0o400)
                                os.fsync(descriptor)
                            finally:
                                os.close(descriptor)
                            fsync_directory(source_fd)
                            fsync_directory(quarantine_fd)
                        elif quarantine_exists and source_exists:
                            assert quarantine_fd is not None
                            os.unlink(destination_name, dir_fd=quarantine_fd)
                            fsync_directory(quarantine_fd)
                        for evidence_id in candidate["evidence"]:
                            related_eviction = any(
                                event.get("target") == evidence_id
                                and isinstance(event.get("data"), Mapping)
                                and event["data"].get("transaction_id") == transaction_id
                                and event["data"].get("plan") == plan_id
                                    and event["data"].get("object") == candidate["object"]
                                for event in eviction_events
                            )
                            effective = self.vault.effective_evidence(evidence_id)
                            if related_eviction and effective and effective.get("payload", {}).get("state") != "present":
                                self.vault.append_event(
                                    "payload.restored",
                                    actor="process:lifedb-retention-recovery",
                                    target=evidence_id,
                                    sensitivity=self._effective_sensitivity(evidence_id),
                                    data={
                                        "transaction_id": transaction_id,
                                        "plan": plan_id,
                                        "object": candidate["object"],
                                        "payload": {"reason": "recovered prepared-only eviction"},
                                    },
                                )
                                restored_targets.append(evidence_id)
                    self.vault.append_event(
                        "retention.apply-aborted",
                        actor="process:lifedb-retention-recovery",
                        target=transaction_id,
                        sensitivity="restricted",
                        data={
                            "plan": plan_id,
                            "confirmation": confirmation,
                            "candidates": candidates,
                            "restored": True,
                            "reason": "prepared transaction recovered after interruption",
                            "restored_evidence": restored_targets,
                        },
                    )
                except (OSError, RetentionError, ValueError):
                    if quarantine_fd is not None:
                        os.close(quarantine_fd)
                    for pair in pairs:
                        os.close(pair[4])
                    unresolved.append(transaction_id)
                    continue
                if quarantine_fd is not None:
                    os.close(quarantine_fd)
                for pair in pairs:
                    os.close(pair[4])
                recovered.append(transaction_id)
        return {
            "schema": "0.2",
            "recovered": recovered,
            "cleaned": cleaned,
            "unresolved": unresolved,
        }


def preview_retention(vault: Vault, **kwargs: Any) -> dict[str, Any]:
    return RetentionManager(vault).preview(**kwargs)


def apply_retention(
    vault: Vault, plan_id: str, *, confirmation: str, actor: str
) -> dict[str, Any]:
    return RetentionManager(vault).apply(plan_id, confirmation=confirmation, actor=actor)


def change_retention(
    vault: Vault,
    evidence_id: str,
    retention: str,
    *,
    actor: str,
    reason: str,
) -> dict[str, Any]:
    return RetentionManager(vault).change(
        evidence_id, retention, actor=actor, reason=reason
    )
