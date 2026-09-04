"""Loading and validating the durable policies which control LifeDB behavior.

Policies are owner-managed durable input, but they are still an authorization
boundary.  A malformed, non-finite, or otherwise unexpected policy therefore
fails closed instead of falling back to an in-process template.
"""

from __future__ import annotations

import json
import hashlib
import os
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, TYPE_CHECKING

from .schema_validation import schema_errors

if TYPE_CHECKING:
    from .vault import Vault


MAX_CONTEXT_BUDGET = 1_000_000
CONTEXT_BUDGET_FIELDS = (
    "budget_chars",
    "core_chars",
    "continuity_chars",
    "relevant_chars",
)


class PolicyError(ValueError):
    """A policy cannot safely be used as executable authority."""


POLICY_MAX_BYTES = 1024 * 1024


@dataclass(frozen=True)
class PolicySnapshot:
    """One exact durable policy read.

    Callers which both authorize and act on a policy must use this snapshot;
    re-reading the path between those operations would reintroduce a TOCTOU
    window.  ``raw`` is deliberately retained so its digest identifies the
    bytes that were actually parsed, not a re-serialized approximation.
    """

    value: dict[str, Any]
    raw: bytes
    sha256: str

    @property
    def digest(self) -> str:
        return f"sha256:{self.sha256}"


def _vault_root(vault_or_root: Vault | Path | str) -> Path:
    # ``Path`` exposes a ``root`` property (usually ``/``), so path-like
    # callers must be handled before looking for a Vault-style ``.root``.
    root = (
        vault_or_root
        if isinstance(vault_or_root, (str, os.PathLike))
        else getattr(vault_or_root, "root", vault_or_root)
    )
    return Path(root).expanduser().absolute()


def _finite_constant(value: str) -> Any:
    raise ValueError(f"non-finite JSON value {value!r} is not permitted")


def _read_json_policy_snapshot(root: Path, filename: str) -> PolicySnapshot:
    if not isinstance(filename, str) or filename not in {"context.json", "retention.json"}:
        raise PolicyError("unsupported policy filename")
    path = root / "policies" / filename
    # Traverse from the vault descriptor.  Path-level lstat followed by
    # os.open(path) has a parent-directory replacement window in which
    # ``policies`` can become a symlink to an external authority file.
    directory_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0)
    if hasattr(os, "O_NOFOLLOW"):
        directory_flags |= os.O_NOFOLLOW
    root_descriptor = policies_descriptor = descriptor = -1
    try:
        root_status = os.lstat(root)
        if not stat.S_ISDIR(root_status.st_mode):
            raise PolicyError(f"vault root must be a real directory: {root}")
        root_descriptor = os.open(root, directory_flags)
        policies_descriptor = os.open("policies", directory_flags, dir_fd=root_descriptor)
        descriptor = os.open(
            filename,
            os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=policies_descriptor,
        )
        try:
            metadata = os.fstat(descriptor)
            if not stat.S_ISREG(metadata.st_mode):
                raise PolicyError(f"policy must be a regular file: {path}")
            if metadata.st_size > POLICY_MAX_BYTES:
                raise PolicyError(
                    f"policy exceeds the maximum size of {POLICY_MAX_BYTES} bytes: {path}"
                )
            chunks: list[bytes] = []
            remaining = POLICY_MAX_BYTES + 1
            while remaining:
                chunk = os.read(descriptor, min(65536, remaining))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            raw = b"".join(chunks)
            finished = os.fstat(descriptor)
            identity = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
            if any(getattr(finished, key) != getattr(metadata, key) for key in identity):
                raise PolicyError("policy changed during safe read")
            try:
                after = os.stat(filename, dir_fd=policies_descriptor, follow_symlinks=False)
            except OSError as exc:
                raise PolicyError("policy changed during safe read") from exc
            if not stat.S_ISREG(after.st_mode) or any(
                getattr(after, key) != getattr(finished, key) for key in identity
            ):
                raise PolicyError("policy changed during safe read")
        finally:
            os.close(descriptor)
            descriptor = -1
        if len(raw) > POLICY_MAX_BYTES:
            raise PolicyError(
                f"policy exceeds the maximum size of {POLICY_MAX_BYTES} bytes: {path}"
            )
        value = json.loads(
            raw.decode("utf-8"),
            parse_constant=_finite_constant,
            object_pairs_hook=_unique_object,
        )
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        if isinstance(exc, PolicyError):
            raise
        raise PolicyError(f"cannot read policy {path}: {exc}") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if policies_descriptor >= 0:
            os.close(policies_descriptor)
        if root_descriptor >= 0:
            os.close(root_descriptor)
    if not isinstance(value, dict):
        raise PolicyError(f"policy {path} must be a JSON object")
    # A second explicit check keeps this invariant obvious even if the JSON
    # decoder implementation changes.
    try:
        json.dumps(value, allow_nan=False)
    except (TypeError, ValueError, OverflowError, RecursionError) as exc:
        raise PolicyError(f"policy {path} must contain finite JSON values") from exc
    return PolicySnapshot(value=value, raw=raw, sha256=hashlib.sha256(raw).hexdigest())


def _read_json_policy(root: Path, filename: str) -> dict[str, Any]:
    return _read_json_policy_snapshot(root, filename).value


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError(f"duplicate JSON property {key!r}")
        value[key] = item
    return value


def _read_policy_snapshot(root: Path, filename: str, kind: str) -> PolicySnapshot:
    # Keep parsing and schema validation in one operation.  The returned hash
    # is over exactly the bytes read by the descriptor above.
    path = root / "policies" / filename
    snapshot = _read_json_policy_snapshot(root, filename)
    value = snapshot.value
    _validate_schema(root, kind, value, path)
    return snapshot


def _validate_schema(root: Path, kind: str, value: dict[str, Any], path: Path) -> None:
    try:
        errors = schema_errors(kind, value, vault_root=root)
    except Exception as exc:
        raise PolicyError(f"cannot validate policy {path}: {exc}") from exc
    if errors:
        raise PolicyError(f"invalid policy {path}: {errors[0]}")


def _validate_context_cross_fields(value: Mapping[str, Any], path: Path) -> None:
    total = value["budget_chars"]
    layers = [value[name] for name in CONTEXT_BUDGET_FIELDS[1:]]
    # JSON Schema validates each number; this check expresses the relationship
    # between the total and its independently configurable layers.
    if sum(layers) > total:
        raise PolicyError(
            f"invalid policy {path}: layer budgets must sum to no more than budget_chars"
        )
    if any(layer > total for layer in layers):
        raise PolicyError(
            f"invalid policy {path}: each layer budget must not exceed budget_chars"
        )


def load_context_policy(vault_or_root: Vault | Path | str) -> dict[str, Any]:
    """Load the current context policy, validating schema and budget rules."""

    root = _vault_root(vault_or_root)
    path = root / "policies" / "context.json"
    snapshot = _read_policy_snapshot(root, path.name, "context-policy")
    _validate_context_cross_fields(snapshot.value, path)
    return snapshot.value


def load_retention_policy(vault_or_root: Vault | Path | str) -> dict[str, Any]:
    """Load the current retention policy as strict, inert v0.2 policy data."""

    root = _vault_root(vault_or_root)
    path = root / "policies" / "retention.json"
    return load_retention_policy_snapshot(vault_or_root).value


def load_retention_policy_snapshot(vault_or_root: Vault | Path | str) -> PolicySnapshot:
    """Return the exact strict retention policy bytes, value, and digest."""

    root = _vault_root(vault_or_root)
    return _read_policy_snapshot(root, "retention.json", "retention-policy")


def load_policy(vault_or_root: Vault | Path | str, kind: str) -> dict[str, Any]:
    """Load a named durable policy (convenience API for policy tooling)."""

    if kind in {"context", "context-policy", "context_policy"}:
        return load_context_policy(vault_or_root)
    if kind in {"retention", "retention-policy", "retention_policy"}:
        return load_retention_policy(vault_or_root)
    raise PolicyError(f"unknown LifeDB policy kind: {kind}")


def context_budget_profile(policy: Mapping[str, Any]) -> dict[str, int]:
    """Extract a validated policy's integer budget maxima for an HTTP profile."""

    return {name: int(policy[name]) for name in CONTEXT_BUDGET_FIELDS}
