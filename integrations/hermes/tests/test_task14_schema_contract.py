from __future__ import annotations

import base64
from dataclasses import replace
import hashlib
import os
from pathlib import Path
import unittest

from integrations.hermes.installer.journal_schema import _JSON, decode_value, identity_data, journal_data
from integrations.hermes.installer.models import Identity, InstallerError, Journal
from integrations.hermes.installer.source import OWNED_FILES


def _identity(
    digest: str,
    size: int,
    *,
    kind: str = "file",
    mode: int = 0o600,
    mtime_ns: int = 4,
) -> Identity:
    return Identity(1, size + 2, os.geteuid(), kind, mode, size, mtime_ns, digest)


def _file(raw: bytes, *, mtime_ns: int = 4) -> Identity:
    return _identity(hashlib.sha256(raw).hexdigest(), len(raw), mtime_ns=mtime_ns)


def _record(**changes: _JSON) -> dict[str, _JSON]:
    old_config = b"old-config"
    old_marker = b"old-marker"
    old_marker_identity = _file(old_marker)
    tree = {name: _file(name.encode()) for name in OWNED_FILES}
    tree[".lifedb-owner.json"] = old_marker_identity
    journal = Journal(
        Path("/tmp/hermes"),
        "disable",
        "prepared",
        None,
        None,
        old_root_exists=True,
        config_exists=True,
        old_config_b64=base64.b64encode(old_config).decode("ascii"),
        old_config_mode=0o600,
        old_marker_b64=base64.b64encode(old_marker).decode("ascii"),
        old_marker_mode=0o600,
        old_marker_mtime_ns=4,
        config_identity=_file(old_config),
        live_identity=_identity("b" * 64, 0, kind="directory", mode=0o700),
        lock_identity=_file(b"lock"),
        old_tree_manifest=tree,
        old_config_mtime_ns=4,
        binary_identity=_identity("c" * 64, 1, mode=0o700),
        old_marker_exists=True,
        old_marker_identity=old_marker_identity,
        old_live_identity=_identity("b" * 64, 0, kind="directory", mode=0o700),
    )
    data = journal_data(journal)
    data.update(changes)
    return data


def _intended(data: dict[str, _JSON], config: bytes = b"new-config", marker: bytes = b"new-marker") -> None:
    data["desired_config_b64"] = base64.b64encode(config).decode("ascii")
    data["desired_config_hash"] = hashlib.sha256(config).hexdigest()
    data["desired_marker_b64"] = base64.b64encode(marker).decode("ascii")
    data["desired_marker_hash"] = hashlib.sha256(marker).hexdigest()


def _observed(data: dict[str, _JSON], config: bytes = b"new-config", marker: bytes = b"new-marker") -> None:
    data["observed_config_identity"] = identity_data(_file(config))
    data["observed_marker_identity"] = identity_data(_file(marker))


class Task14SchemaContractTests(unittest.TestCase):
    def assert_rejected(self, data: dict[str, _JSON]) -> None:
        with self.assertRaises(InstallerError):
            decode_value(data, Path("/tmp/hermes"))

    def test_disable_and_enable_expose_the_complete_phase_chain(self) -> None:
        for operation in ("disable", "enable"):
            data = _record(operation=operation, phase="config_intent")
            _intended(data)
            decode_value(data, Path("/tmp/hermes"))
            data["phase"] = "config_published"
            _observed(data, config=b"new-config")
            decode_value(data, Path("/tmp/hermes"))
            data["phase"] = "marker_intent"
            data["observed_marker_identity"] = None
            decode_value(data, Path("/tmp/hermes"))
            data["phase"] = "marker_published"
            _observed(data)
            decode_value(data, Path("/tmp/hermes"))
            data["phase"] = "commit_intent"
            decode_value(data, Path("/tmp/hermes"))
            data["phase"] = "committed"
            decode_value(data, Path("/tmp/hermes"))

    def test_uninstall_accepts_root_config_commit_and_cleanup_boundaries(self) -> None:
        for phase in ("prepared", "old_root_rename_intent", "quarantined", "config_intent", "config_published", "commit_intent", "committed", "cleanup_intent", "cleanup_pending"):
            data = _record(operation="uninstall", phase=phase)
            if phase in {"config_intent", "config_published", "commit_intent", "committed", "cleanup_intent", "cleanup_pending"}:
                data["desired_config_b64"] = ""
                data["desired_config_hash"] = hashlib.sha256(b"").hexdigest()
            if phase in {"config_published", "commit_intent", "committed", "cleanup_intent", "cleanup_pending"}:
                data["observed_config_identity"] = identity_data(_file(b""))
            if phase == "old_root_rename_intent":
                data["quarantine"] = "plugins/.lifedb-quarantine-x"
                data["quarantine_identity"] = None
                data["live_identity"] = identity_data(_identity("b" * 64, 0, kind="directory", mode=0o700))
            if phase in {"quarantined", "config_intent", "config_published", "commit_intent", "committed", "cleanup_intent", "cleanup_pending"}:
                data["quarantine"] = "plugins/.lifedb-quarantine-x"
                data["quarantine_identity"] = identity_data(_identity("d" * 64, 0, kind="directory", mode=0o700))
                data["live_identity"] = None
            if phase in {"committed", "cleanup_intent", "cleanup_pending"}:
                data["cleanup_manifest"] = data["old_tree_manifest"]
            decode_value(data, Path("/tmp/hermes"))

    def test_upgrade_install_commit_retains_the_old_tree_for_cleanup(self) -> None:
        data = _record(operation="install", phase="committed")
        data["staging"] = None
        data["staging_identity"] = None
        data["quarantine"] = "plugins/.lifedb-quarantine-x"
        data["quarantine_identity"] = identity_data(_identity("d" * 64, 0, kind="directory", mode=0o700))
        data["live_identity"] = identity_data(_identity("e" * 64, 0, kind="directory", mode=0o700))
        data["cleanup_manifest"] = data["old_tree_manifest"]
        _intended(data)
        _observed(data)
        decode_value(data, Path("/tmp/hermes"))

    def test_intent_accepts_empty_intended_bytes_without_future_identity(self) -> None:
        data = _record(phase="config_intent")
        _intended(data, config=b"", marker=b"")
        decoded = decode_value(data, Path("/tmp/hermes"))
        self.assertIsNone(decoded.observed_config_identity)
        self.assertIsNone(decoded.observed_marker_identity)

    def test_post_mutation_observation_must_match_intended_bytes(self) -> None:
        data = _record(phase="config_published")
        _intended(data)
        _observed(data, config=b"wrong")
        self.assert_rejected(data)

    def test_present_empty_old_marker_is_a_real_preimage(self) -> None:
        data = _record(old_marker_exists=True, old_marker_b64="", old_marker_identity=identity_data(_file(b"")))
        data["old_tree_manifest"][".lifedb-owner.json"] = data["old_marker_identity"]
        decode_value(data, Path("/tmp/hermes"))

    def test_future_quarantine_identity_is_absent_only_before_rename(self) -> None:
        data = _record(operation="uninstall", phase="old_root_rename_intent", quarantine="plugins/.lifedb-quarantine-x", quarantine_identity=None)
        decode_value(data, Path("/tmp/hermes"))
        data["phase"] = "quarantined"
        self.assert_rejected(data)

    def test_binary_identity_is_required_for_every_operation_boundary(self) -> None:
        for operation in ("disable", "enable", "uninstall"):
            data = _record(operation=operation, phase="prepared", binary_identity=None)
            self.assert_rejected(data)

        data = _record()
        binary = data["binary_identity"]
        self.assertIsInstance(binary, dict)
        binary["mode"] = 0o600
        self.assert_rejected(data)

    def test_config_identity_rejects_group_or_world_writable_modes(self) -> None:
        for mode in (0o664, 0o666):
            data = _record()
            identity = data["config_identity"]
            self.assertIsInstance(identity, dict)
            identity["mode"] = mode
            data["old_config_mode"] = mode
            self.assert_rejected(data)

    def test_wrong_runtime_types_are_sanitized(self) -> None:
        for field, value in (("desired_config_b64", 1), ("desired_marker_b64", []), ("desired_config_hash", False), ("cleanup_deleted", "name")):
            data = _record(phase="config_intent")
            _intended(data)
            data[field] = value
            self.assert_rejected(data)

    def test_cleanup_manifest_is_the_complete_old_snapshot(self) -> None:
        data = _record(operation="uninstall", phase="committed")
        _intended(data, config=b"")
        data["observed_config_identity"] = identity_data(_file(b""))
        data["quarantine"] = "plugins/.lifedb-quarantine-x"
        data["quarantine_identity"] = identity_data(_identity("d" * 64, 0, kind="directory", mode=0o700))
        data["live_identity"] = None
        data["cleanup_manifest"] = {"plugin.yaml": data["old_tree_manifest"]["plugin.yaml"]}
        self.assert_rejected(data)


if __name__ == "__main__":
    unittest.main()
