from __future__ import annotations

import os
import re
import stat
import sys
from datetime import datetime
from pathlib import Path
from typing import Any, Iterable

from jsonschema import Draft202012Validator, FormatChecker

from .storage import read_bounded_regular_file, strict_json_loads


MAX_SCHEMA_BYTES = 4 * 1024 * 1024
RFC3339_RE = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$"
)


def _strict_datetime(value: Any) -> bool:
    if not isinstance(value, str) or RFC3339_RE.fullmatch(value) is None:
        return False
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return False
    return parsed.tzinfo is not None


SCHEMA_FILES = {
    "vault": "vault.schema.json",
    "canon": "canon-document.schema.json",
    "capture": "evidence-record.schema.json",
    "event": "evidence-event.schema.json",
    "context": "context-pack.schema.json",
    "context-policy": "context-policy.schema.json",
    "retention-policy": "retention-policy.schema.json",
}


def schema_directories(vault_root: Path | None = None) -> Iterable[Path]:
    # A vault's versioned schemas are authoritative for that vault.  In
    # particular, do not let a stale v0.1-era flat copy shadow the schemas
    # shipped with the current vault format.
    if vault_root is not None:
        vault_schemas = Path(vault_root).expanduser().absolute() / "schemas"
        yield vault_schemas / "0.2"
        yield vault_schemas
    configured = os.environ.get("LIFEDB_SCHEMA_DIR")
    if configured:
        yield Path(configured).expanduser().resolve()
    # Source checkout / editable install.
    yield Path(__file__).resolve().parents[2] / "schemas"
    # Wheel installation via setuptools data-files.
    yield Path(sys.prefix) / "share" / "lifedb" / "schemas"
    # Docker image keeps a human-visible copy here as well.
    yield Path("/app/schemas")


def schema_path(kind: str, vault_root: Path | None = None) -> Path:
    try:
        filename = SCHEMA_FILES[kind]
    except KeyError as exc:
        raise ValueError(f"unknown LifeDB schema kind: {kind}") from exc
    # Once a vault is supplied, its versioned schema directory is the sole
    # machine-authoritative source.  Falling back to a stale flat copy (or a
    # package copy) would make a damaged vault appear valid after restore.
    if vault_root is not None:
        supplied_root = Path(vault_root).expanduser().absolute()
        if not supplied_root.name:
            raise FileNotFoundError("LifeDB vault root is not a usable directory")
        canonical_root = supplied_root.parent.resolve() / supplied_root.name
        if canonical_root.is_symlink() or not canonical_root.is_dir():
            raise FileNotFoundError("LifeDB vault root is not a real directory")
        versioned = canonical_root / "schemas" / "0.2" / filename
        current = canonical_root
        try:
            for component in ("schemas", "0.2"):
                current = current / component
                status = os.lstat(current)
                if not stat.S_ISDIR(status.st_mode):
                    raise FileNotFoundError("LifeDB schema directory is not a real directory")
            status = os.lstat(versioned)
        except OSError:
            status = None
        if status is not None and stat.S_ISREG(status.st_mode):
            return versioned
        raise FileNotFoundError(
            f"LifeDB authoritative schema {filename} was not found or is not a regular file: {versioned}"
        )
    checked: list[str] = []
    for directory in schema_directories(vault_root):
        candidate = directory / filename
        checked.append(str(candidate))
        # Schema inputs are trusted only when they are ordinary files.  This
        # avoids silently following a schema symlink out of the vault.
        try:
            directory_status = os.lstat(directory)
            candidate_status = os.lstat(candidate)
        except OSError:
            continue
        if stat.S_ISDIR(directory_status.st_mode) and stat.S_ISREG(candidate_status.st_mode):
            return candidate
    raise FileNotFoundError(
        f"LifeDB schema {filename} was not found; checked: {', '.join(checked)}"
    )


def _load_schema_file(
    path_text: str, *, boundary: Path | None = None
) -> dict[str, Any]:
    path = Path(path_text)
    try:
        payload = read_bounded_regular_file(
            path, max_bytes=MAX_SCHEMA_BYTES, boundary=boundary
        )
        value = strict_json_loads(payload, max_bytes=MAX_SCHEMA_BYTES)
    except (OSError, ValueError, MemoryError, OverflowError, RecursionError):
        raise ValueError("schema file is not valid bounded strict JSON") from None
    if not isinstance(value, dict):
        raise ValueError(f"{path}: schema must be a JSON object")
    Draft202012Validator.check_schema(value)
    return value


def load_schema(kind: str, vault_root: Path | None = None) -> dict[str, Any]:
    boundary = None
    if vault_root is not None:
        supplied_root = Path(vault_root).expanduser().absolute()
        boundary = supplied_root.parent.resolve() / supplied_root.name
    return _load_schema_file(str(schema_path(kind, vault_root)), boundary=boundary)


def schema_errors(
    kind: str,
    instance: Any,
    *,
    vault_root: Path | None = None,
) -> list[str]:
    checker = FormatChecker()
    checker.checks("date-time")(_strict_datetime)
    validator = Draft202012Validator(load_schema(kind, vault_root), format_checker=checker)
    errors: list[str] = []
    for error in sorted(validator.iter_errors(instance), key=lambda item: list(item.absolute_path)):
        location = "$." + ".".join(str(part) for part in error.absolute_path)
        if location == "$.":
            location = "$"
        errors.append(f"{location}: {error.message}")
    return errors
