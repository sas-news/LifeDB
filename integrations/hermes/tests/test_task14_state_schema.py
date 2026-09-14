from __future__ import annotations

import base64
import hashlib
import os
from pathlib import Path
import unittest

from integrations.hermes.installer.journal_schema import _JSON, decode_value, identity_data, journal_data
from integrations.hermes.installer.models import Identity, InstallerError, Journal


def identity(kind: str = "file", digest: str = "a" * 64, size: int = 3, mode: int = 0o600) -> Identity:
    return Identity(1, 2, os.geteuid(), kind, mode, size, 4, digest)


def journal_identity() -> dict[str, _JSON]:
    return {"device": 1, "inode": 2, "owner_uid": os.geteuid(), "kind": "file", "mode": 0o600, "size": 3, "mtime_ns": 4, "sha256": "a" * 64}


def record(**changes: _JSON) -> dict[str, _JSON]:
    journal = Journal(Path("/tmp/hermes"), "install", "prepared", "plugins/.lifedb-staging-x", None,
                      staging_identity=identity("directory", size=0, mode=0o700))
    data = journal_data(journal)
    data.update(changes)
    return data


class Task14StateSchemaTests(unittest.TestCase):
    def assert_rejected(self, data: dict[str, _JSON]) -> None:
        with self.assertRaises(InstallerError):
            decode_value(data, Path("/tmp/hermes"))

    def test_fresh_intent_requires_observed_future_identities(self) -> None:
        self.assert_rejected(record(
            phase="config_intent", desired_config_hash="a" * 64,
            desired_marker_hash="b" * 64,
        ))

    def test_intent_does_not_require_future_inodes(self) -> None:
        data = record(phase="config_intent", desired_config_b64=base64.b64encode(b"new").decode(),
                      desired_marker_b64=base64.b64encode(b"mark").decode(),
                      lock_identity=journal_identity(), binary_identity=identity_data(identity(mode=0o700)),
                      live_identity=identity_data(identity("directory", size=0)),
                      staging=None, staging_identity=None,
                      observed_marker_identity=identity_data(identity(digest=hashlib.sha256(b"mark").hexdigest(), size=4)))
        data["desired_config_hash"] = hashlib.sha256(b"new").hexdigest()
        data["desired_marker_hash"] = hashlib.sha256(b"mark").hexdigest()
        decoded = decode_value(data, Path("/tmp/hermes"))
        self.assertIsNone(decoded.observed_config_identity)
        self.assertIsNotNone(decoded.observed_marker_identity)

    def test_post_mutation_requires_observed_identities(self) -> None:
        data = record(phase="config_published", desired_config_hash="a" * 64,
                      desired_marker_hash="b" * 64)
        self.assert_rejected(data)

    def test_old_marker_is_not_compared_to_desired_marker(self) -> None:
        old = b"old-marker"
        data = record(old_marker_exists=True, old_marker_b64=base64.b64encode(old).decode(),
                      old_marker_mode=0o600, old_marker_mtime_ns=4,
                      old_marker_identity=identity(digest=hashlib.sha256(old).hexdigest()),
                      desired_marker_hash="b" * 64)
        self.assert_rejected(data)

    def test_old_tree_requires_exact_owned_snapshot(self) -> None:
        data = record(old_root_exists=True, old_tree_manifest={"plugin.yaml": identity()})
        self.assert_rejected(data)

    def test_cleanup_pending_cannot_drop_snapshot(self) -> None:
        self.assert_rejected(record(phase="cleanup_pending", old_root_exists=False))

    def test_cleanup_progress_is_unique_and_ordered(self) -> None:
        data = record(cleanup_manifest={"plugin.yaml": identity()}, cleanup_deleted=["plugin.yaml", "plugin.yaml"])
        self.assert_rejected(data)

    def test_observed_digest_and_size_are_exact(self) -> None:
        raw = b"new"
        data = record(phase="config_published", desired_config_b64=base64.b64encode(raw).decode(),
                      desired_config_hash=hashlib.sha256(raw).hexdigest(),
                      desired_marker_b64=base64.b64encode(b"mark").decode(),
                      desired_marker_hash=hashlib.sha256(b"mark").hexdigest(),
                      observed_config_identity=identity(digest="c" * 64, size=len(raw)),
                      observed_marker_identity=identity(digest=hashlib.sha256(b"mark").hexdigest(), size=4))
        self.assert_rejected(data)


if __name__ == "__main__":
    unittest.main()
