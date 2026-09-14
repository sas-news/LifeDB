from __future__ import annotations

import os
import secrets
import stat
import tempfile
from dataclasses import dataclass
from pathlib import Path


class BootstrapError(RuntimeError):
    """A bootstrap input or atomic publication was refused."""


@dataclass(frozen=True, slots=True)
class BootstrapReceipt:
    vault: Path
    token_path: Path
    created: bool
    token_bytes: int
    vault_id: str


def _validate_token(path: Path) -> bytes:
    try:
        status = path.lstat()
    except FileNotFoundError:
        raise BootstrapError("token file is absent") from None
    if stat.S_ISLNK(status.st_mode) or not stat.S_ISREG(status.st_mode):
        raise BootstrapError("token path must be a regular file")
    if status.st_uid != os.geteuid():
        raise BootstrapError("token file must be owned by the current user")
    if stat.S_IMODE(status.st_mode) != 0o600:
        raise BootstrapError("token file mode must be 0600")
    payload = path.read_bytes()
    if len(payload) < 32 or any(byte in b" \t\r\n\v\f" for byte in payload):
        raise BootstrapError("token must be at least 32 bytes without whitespace")
    return payload


def _validate_parent(path: Path) -> None:
    try:
        status = path.lstat()
    except FileNotFoundError:
        raise BootstrapError("token parent must be an existing directory") from None
    if stat.S_ISLNK(status.st_mode) or not stat.S_ISDIR(status.st_mode):
        raise BootstrapError("token parent must be a real directory")


def _create_token(path: Path) -> tuple[bytes, bool]:
    payload = secrets.token_urlsafe(32).encode("ascii")
    _validate_parent(path.parent)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags, 0o600)
    except FileExistsError:
        return _validate_token(path), False
    try:
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError("short token write")
            view = view[written:]
        os.fchmod(descriptor, 0o600)
        os.fsync(descriptor)
    except OSError as error:
        raise BootstrapError("token publication failed") from error
    finally:
        os.close(descriptor)
    parent_descriptor = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0))
    try:
        os.fsync(parent_descriptor)
    finally:
        os.close(parent_descriptor)
    return payload, True


def bootstrap(vault_path: Path, token_path: Path) -> BootstrapReceipt:
    """Initialize an external vault and atomically create or validate its token."""
    from lifedb.vault import Vault

    if not token_path.is_absolute():
        raise BootstrapError("token path must be absolute")
    _validate_parent(token_path.parent)
    try:
        token, created = _create_token(token_path) if not token_path.exists() else (_validate_token(token_path), False)
        vault = Vault(vault_path)
        metadata = vault.init()
    except (OSError, ValueError, TypeError) as error:
        raise BootstrapError("bootstrap refused") from error
    return BootstrapReceipt(vault.root, token_path, created, len(token), str(metadata["vault_id"]))


def bootstrap_scenario() -> tuple[str, ...]:
    """Run bootstrap against an external temporary vault without exposing its token."""
    with tempfile.TemporaryDirectory(prefix="lifedb-task16-bootstrap-") as directory:
        root = Path(directory)
        receipt = bootstrap(root / "vault", root / "token")
        replay = bootstrap(root / "vault", root / "token")
        if not receipt.created or replay.created or receipt.vault_id != replay.vault_id:
            raise BootstrapError("bootstrap replay contract")
    return ("ok",)


__all__ = ["BootstrapError", "BootstrapReceipt", "bootstrap"]
