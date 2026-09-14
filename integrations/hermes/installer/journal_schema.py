from __future__ import annotations

import base64
import hashlib
import json
import os
import stat
from pathlib import Path
from typing import TypeAlias

from .journal_limits import MAX_CONFIG_BYTES, MAX_JOURNAL_BYTES, MAX_MARKER_BYTES
from .journal_phase import OPERATIONS, PHASES, TREE_NAMES, validate_phase
from .models import Identity, InstallerError, Journal

_JSON: TypeAlias = str | int | float | bool | None | list["_JSON"] | dict[str, "_JSON"]


def fail() -> InstallerError:
    return InstallerError("Hermes installer operation failed")


def path_value(value: str | None) -> None:
    if value is None:
        return
    candidate = Path(value)
    if candidate.is_absolute() or not candidate.parts or ".." in candidate.parts or len(candidate.parts) > 4 or any(not part or any(ord(char) < 32 or ord(char) == 127 for char in part) for part in candidate.parts) or candidate.parts[0] not in {"plugins", ".lifedb-backups"}:
        raise fail()


def _identity(value: _JSON) -> Identity:
    fields = {"device", "inode", "owner_uid", "kind", "mode", "size", "mtime_ns", "sha256"}
    if not isinstance(value, dict) or set(value) != fields:
        raise fail()
    names = ("device", "inode", "owner_uid", "mode", "size", "mtime_ns")
    if not all(type(value[name]) is int for name in names) or not isinstance(value["kind"], str) or not isinstance(value["sha256"], str):
        raise fail()
    try:
        return Identity(value["device"], value["inode"], value["owner_uid"], value["kind"], value["mode"], value["size"], value["mtime_ns"], value["sha256"])
    except (TypeError, ValueError) as error:
        raise fail() from error


def identity_or_none(value: _JSON) -> Identity | None:
    return None if value is None else _identity(value)


def identity_data(identity: Identity | None) -> dict[str, _JSON] | None:
    if identity is None:
        return None
    return {"device": identity.device, "inode": identity.inode, "owner_uid": identity.owner_uid, "kind": identity.kind, "mode": identity.mode, "size": identity.size, "mtime_ns": identity.mtime_ns, "sha256": identity.sha256}


def _safe(identity: Identity | None, kind: str) -> None:
    if identity is None or identity.kind != kind or identity.owner_uid != os.geteuid():
        raise fail()
    if kind == "file" and identity.mode != 0o600 or kind == "directory" and identity.mode & 0o022:
        raise fail()


def _safe_config(identity: Identity | None) -> None:
    if identity is None or identity.kind != "file" or identity.owner_uid != os.geteuid() or identity.mode & 0o022:
        raise fail()


def base64_bytes(value: str, limit: int) -> bytes:
    if not isinstance(value, str):
        raise fail()
    try:
        decoded = base64.b64decode(value.encode("ascii"), validate=True)
    except (ValueError, UnicodeEncodeError, base64.binascii.Error) as error:
        raise fail() from error
    if base64.b64encode(decoded).decode("ascii") != value or len(decoded) > limit:
        raise fail()
    return decoded


def manifest(value: _JSON) -> dict[str, Identity]:
    if not isinstance(value, dict) or any(name not in TREE_NAMES for name in value):
        raise fail()
    result = {name: _identity(item) for name, item in value.items()}
    if any(item.kind != "file" or item.owner_uid != os.geteuid() or item.mode != 0o600 for item in result.values()):
        raise fail()
    return result


def _pairs(pairs: list[tuple[str, _JSON]]) -> dict[str, _JSON]:
    result: dict[str, _JSON] = {}
    for key, item in pairs:
        if key in result:
            raise fail()
        result[key] = item
    return result


def decode_bytes(raw: bytes, home: Path) -> Journal:
    if len(raw) > MAX_JOURNAL_BYTES:
        raise fail()
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_pairs)
    except (UnicodeError, json.JSONDecodeError, InstallerError) as error:
        if isinstance(error, InstallerError):
            raise
        raise fail() from error
    if raw != json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8"):
        raise fail()
    return decode_value(value, home)


def decode_value(value: _JSON, home: Path) -> Journal:
    required = set(journal_data(Journal(home, "install", "prepared", None, None))) | {"schema", "home"}
    if not isinstance(value, dict) or set(value) != required or type(value.get("schema")) is not int or value.get("schema") != 1 or value.get("home") != str(home):
        raise fail()
    operation, phase = value["operation"], value["phase"]
    if not isinstance(operation, str) or operation not in OPERATIONS or not isinstance(phase, str) or phase not in PHASES:
        raise fail()
    strings = ("old_config_b64", "old_marker_b64")
    if not all(isinstance(value[name], str) for name in strings) or type(value["old_root_exists"]) is not bool or type(value["old_marker_exists"]) is not bool or type(value["config_exists"]) is not bool:
        raise fail()
    if not isinstance(value["staging"], (str, type(None))) or not isinstance(value["quarantine"], (str, type(None))):
        raise fail()
    path_value(value["staging"])
    path_value(value["quarantine"])
    if type(value["old_config_mode"]) is not int or type(value["old_config_mtime_ns"]) is not int or type(value["old_marker_mode"]) is not int or type(value["old_marker_mtime_ns"]) is not int or value["old_config_mode"] < 0 or value["old_config_mode"] > 0o777 or value["old_config_mtime_ns"] < 0 or value["old_marker_mode"] < 0 or value["old_marker_mode"] > 0o777 or value["old_marker_mtime_ns"] < 0:
        raise fail()
    old_config, old_marker = base64_bytes(value["old_config_b64"], MAX_CONFIG_BYTES), base64_bytes(value["old_marker_b64"], MAX_MARKER_BYTES)
    desired_config = None if value["desired_config_b64"] is None else base64_bytes(value["desired_config_b64"], MAX_CONFIG_BYTES)
    desired_marker = None if value["desired_marker_b64"] is None else base64_bytes(value["desired_marker_b64"], MAX_MARKER_BYTES)
    for digest in (value["desired_config_hash"], value["desired_marker_hash"]):
        if digest is not None and (not isinstance(digest, str) or len(digest) != 64 or any(char not in "0123456789abcdef" for char in digest)):
            raise fail()
    if desired_config is not None and hashlib.sha256(desired_config).hexdigest() != value["desired_config_hash"] or desired_marker is not None and hashlib.sha256(desired_marker).hexdigest() != value["desired_marker_hash"]:
        raise fail()
    if value["old_config_b64"] and not value["config_exists"]:
        raise fail()
    identities = {name: identity_or_none(value[name]) for name in ("config_identity", "staging_identity", "quarantine_identity", "live_identity", "lock_identity", "binary_identity", "old_marker_identity", "old_live_identity", "observed_config_identity", "observed_marker_identity")}
    for name in ("config_identity", "observed_config_identity"):
        identity = identities[name]
        if identity is not None:
            _safe_config(identity)
    for name in ("lock_identity", "old_marker_identity", "observed_marker_identity"):
        identity = identities[name]
        if identity is not None:
            _safe(identity, "file")
    binary = identities["binary_identity"]
    if binary is not None and (binary.kind != "file" or binary.owner_uid != os.geteuid() or binary.mode & 0o022 or not binary.mode & 0o111):
        raise fail()
    for name in ("live_identity", "old_live_identity"):
        identity = identities[name]
        if identity is not None:
            _safe(identity, "directory")
    if value["config_exists"] and (identities["config_identity"] is None or identities["config_identity"].sha256 != hashlib.sha256(old_config).hexdigest() or identities["config_identity"].size != len(old_config) or identities["config_identity"].mode != value["old_config_mode"] or identities["config_identity"].mtime_ns != value["old_config_mtime_ns"]):
        raise fail()
    if not value["config_exists"] and (identities["config_identity"] is not None or value["old_config_mode"] or value["old_config_mtime_ns"]):
        raise fail()
    if value["old_marker_exists"] and (identities["old_marker_identity"] is None or identities["old_marker_identity"].sha256 != hashlib.sha256(old_marker).hexdigest() or identities["old_marker_identity"].size != len(old_marker)):
        raise fail()
    if value["old_marker_exists"] and (value["old_marker_mode"] != identities["old_marker_identity"].mode or value["old_marker_mtime_ns"] != identities["old_marker_identity"].mtime_ns):
        raise fail()
    if not value["old_marker_exists"] and (identities["old_marker_identity"] is not None or old_marker or value["old_marker_mode"] or value["old_marker_mtime_ns"]):
        raise fail()
    for digest, data in ((value["desired_config_hash"], desired_config), (value["desired_marker_hash"], desired_marker)):
        if (digest is None) != (data is None) or data is not None and hashlib.sha256(data).hexdigest() != digest:
            raise fail()
    for observed, data, digest in ((identities["observed_config_identity"], desired_config, value["desired_config_hash"]), (identities["observed_marker_identity"], desired_marker, value["desired_marker_hash"])):
        if observed is not None and (data is None or observed.sha256 != digest or observed.size != len(data)):
            raise fail()
    if value["old_root_exists"] and (identities["old_live_identity"] is None or identities["old_live_identity"].kind != "directory"):
        raise fail()
    if not value["old_root_exists"] and identities["old_live_identity"] is not None:
        raise fail()
    old_tree, cleanup = manifest(value["old_tree_manifest"]), manifest(value["cleanup_manifest"])
    if value["old_root_exists"] != bool(old_tree) or value["old_root_exists"] and (set(old_tree) != TREE_NAMES or identities["old_live_identity"] is None) or not value["old_root_exists"] and cleanup:
        raise fail()
    if value["old_root_exists"] and (not value["old_marker_exists"] or old_tree[".lifedb-owner.json"] != identities["old_marker_identity"]):
        raise fail()
    if phase in {"cleanup_intent", "cleanup_pending", "committed"} and operation in {"install", "uninstall"} and value["old_root_exists"] and cleanup != old_tree:
        raise fail()
    deleted = value["cleanup_deleted"]
    if not isinstance(deleted, list) or not all(isinstance(name, str) for name in deleted) or len(set(deleted)) != len(deleted) or any(name not in cleanup for name in deleted):
        raise fail()
    journal = Journal(home=home, operation=operation, phase=phase, staging=value["staging"], quarantine=value["quarantine"], old_root_exists=value["old_root_exists"], config_exists=value["config_exists"], old_config_b64=value["old_config_b64"], old_config_mode=value["old_config_mode"], old_marker_b64=value["old_marker_b64"], old_marker_mode=value["old_marker_mode"], old_marker_mtime_ns=value["old_marker_mtime_ns"], config_identity=identities["config_identity"], staging_identity=identities["staging_identity"], quarantine_identity=identities["quarantine_identity"], live_identity=identities["live_identity"], lock_identity=identities["lock_identity"], old_tree_manifest=old_tree, desired_config_hash=value["desired_config_hash"], desired_marker_hash=value["desired_marker_hash"], old_config_mtime_ns=value["old_config_mtime_ns"], cleanup_manifest=cleanup, cleanup_deleted=tuple(deleted), binary_identity=identities["binary_identity"], old_marker_exists=value["old_marker_exists"], old_marker_identity=identities["old_marker_identity"], old_live_identity=identities["old_live_identity"], desired_config_b64=value["desired_config_b64"], desired_marker_b64=value["desired_marker_b64"], observed_config_identity=identities["observed_config_identity"], observed_marker_identity=identities["observed_marker_identity"])
    validate_phase(journal)
    return journal


def journal_fields(journal: Journal) -> dict[str, _JSON]:
    return {name: getattr(journal, name) for name in Journal.__dataclass_fields__ if name != "journal_identity"}


def journal_data(journal: Journal) -> dict[str, _JSON]:
    result: dict[str, _JSON] = {"schema": 1, "home": str(journal.home)}
    for name, value in journal_fields(journal).items():
        if name.endswith("_identity"):
            result[name] = identity_data(value)
        elif name in {"old_tree_manifest", "cleanup_manifest"}:
            result[name] = {key: identity_data(item) for key, item in value.items()}
        elif name == "cleanup_deleted":
            result[name] = list(value)
        elif name not in {"home"}:
            result[name] = value
    return result


def identity_from_stat(info: os.stat_result, raw: bytes) -> Identity:
    return Identity(info.st_dev, info.st_ino, info.st_uid, "file", stat.S_IMODE(info.st_mode), info.st_size, info.st_mtime_ns, hashlib.sha256(raw).hexdigest())
