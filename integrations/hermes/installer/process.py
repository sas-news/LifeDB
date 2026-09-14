from __future__ import annotations

from dataclasses import dataclass
import hashlib
import subprocess
import re
from pathlib import Path
import os
import stat
import tempfile
from typing import BinaryIO, Mapping, Sequence

from .models import Identity, InstallerError

_VERSION = re.compile(r"Hermes Agent v(\d+\.\d+\.\d+) \(2026\.8\.31\) · upstream ([0-9a-f]{7,40})")
_INSTALL = re.compile(r"Install directory: [^\x00-\x1f\x7f\r\n]+")
_METHOD = re.compile(r"Install method: (git|pip|uv|editable|system|unknown)")
_PYTHON = re.compile(r"Python: \d+\.\d+\.\d+")
_SDK = re.compile(r"OpenAI SDK: [^\x00-\x1f\x7f\r\n]+")
_UPDATE = re.compile(r"Update available: \d+ commits behind — run 'hermes update'")


@dataclass(frozen=True, slots=True)
class ProcessResult:
    stdout: bytes
    stderr: bytes
    returncode: int


@dataclass(frozen=True, slots=True)
class BinaryResolution:
    path: Path
    identity: Identity
    descriptor: int = -1
    backing: BinaryIO | None = None


def check_version_output(stdout: bytes, stderr: bytes, returncode: int) -> None:
    if returncode != 0 or stderr or len(stdout) > 1_048_576 or not stdout.endswith(b"\n") or b"\r" in stdout:
        raise InstallerError("Hermes installer operation failed")
    try:
        lines = stdout[:-1].decode("utf-8").split("\n")
    except UnicodeDecodeError as error:
        raise InstallerError("Hermes installer operation failed") from error
    if len(lines) != 6 or not all(lines):
        raise InstallerError("Hermes installer operation failed")
    version = _VERSION.fullmatch(lines[0])
    if version is None or version.group(1) != "0.21.0" or _INSTALL.fullmatch(lines[1]) is None or _METHOD.fullmatch(lines[2]) is None or _PYTHON.fullmatch(lines[3]) is None or _SDK.fullmatch(lines[4]) is None or _UPDATE.fullmatch(lines[5]) is None:
        raise InstallerError("Hermes installer operation failed")


def run_argv(argv: Sequence[str], timeout: float = 10.0, env: Mapping[str, str] | None = None, pass_fds: Sequence[int] = ()) -> ProcessResult:
    try:
        result = subprocess.run(tuple(argv), capture_output=True, check=False, timeout=timeout, env=None if env is None else dict(env), pass_fds=tuple(pass_fds))
    except (OSError, subprocess.TimeoutExpired) as error:
        raise InstallerError("Hermes installer operation failed") from error
    return ProcessResult(result.stdout, result.stderr, result.returncode)


def child_env(home: Path) -> dict[str, str]:
    return {"HOME": str(home), "HERMES_HOME": str(home), "PATH": "/usr/local/bin:/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"}


def resolve_binary(binary: str) -> BinaryResolution:
    if not binary or any(ord(char) < 32 or ord(char) == 127 for char in binary):
        raise InstallerError("Hermes installer operation failed")
    if os.path.isabs(binary):
        candidates = [Path(binary)]
    else:
        if "/" in binary or "\\" in binary:
            raise InstallerError("Hermes installer operation failed")
        entries = os.environ.get("PATH", "").split(os.pathsep)
        if not entries or any(not item for item in entries):
            raise InstallerError("Hermes installer operation failed")
        candidates = []
        for item in entries:
            directory = Path(item)
            if not directory.is_absolute() or any(ord(char) < 32 or ord(char) == 127 for char in item):
                raise InstallerError("Hermes installer operation failed")
            try:
                info = directory.lstat()
            except OSError as error:
                raise InstallerError("Hermes installer operation failed") from error
            if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode) or info.st_mode & 0o022:
                raise InstallerError("Hermes installer operation failed")
            candidates.append(directory / binary)
    for candidate in candidates:
        try:
            info = candidate.lstat()
            if stat.S_ISREG(info.st_mode) and not stat.S_ISLNK(info.st_mode) and info.st_mode & 0o111:
                if info.st_uid != os.geteuid() and candidate.parent not in {Path("/usr/bin"), Path("/bin"), Path("/usr/local/bin")}:
                    continue
                descriptor = os.open(candidate, os.O_RDONLY | os.O_NOFOLLOW)
                try:
                    opened = os.fstat(descriptor)
                    if (opened.st_dev, opened.st_ino) != (info.st_dev, info.st_ino):
                        raise InstallerError("Hermes installer operation failed")
                    identity = Identity(opened.st_dev, opened.st_ino, opened.st_uid, "file", stat.S_IMODE(opened.st_mode), opened.st_size, opened.st_mtime_ns, _digest_fd(descriptor, opened.st_size))
                    backing: BinaryIO | None = None
                    temporary_path: str | None = None
                    if hasattr(os, "memfd_create"):
                        executable = os.memfd_create("lifedb-hermes", os.MFD_CLOEXEC)
                    else:
                        executable, temporary_path = tempfile.mkstemp(prefix=".lifedb-hermes-")
                    try:
                        offset = 0
                        while offset < opened.st_size:
                            chunk = os.pread(descriptor, min(65_536, opened.st_size - offset), offset)
                            if not chunk:
                                raise InstallerError("Hermes installer operation failed")
                            os.write(executable, chunk)
                            offset += len(chunk)
                        os.fchmod(executable, stat.S_IMODE(opened.st_mode))
                        os.fsync(executable)
                        if temporary_path is not None:
                            os.close(executable)
                            executable = os.open(temporary_path, os.O_RDONLY | os.O_NOFOLLOW)
                            os.unlink(temporary_path)
                        os.set_inheritable(executable, True)
                    except (OSError, InstallerError):
                        if backing is None:
                            os.close(executable)
                        else:
                            backing.close()
                        if temporary_path is not None:
                            Path(temporary_path).unlink(missing_ok=True)
                        raise
                    os.close(descriptor)
                    return BinaryResolution(candidate.absolute(), identity, executable, backing)
                except (OSError, InstallerError):
                    os.close(descriptor)
                    raise
        except InstallerError:
            raise
        except OSError:
            continue
    raise InstallerError("Hermes installer operation failed")


def _digest_fd(descriptor: int, size: int) -> str:
    digest = hashlib.sha256()
    remaining = size
    offset = 0
    while remaining:
        chunk = os.pread(descriptor, min(65_536, remaining), offset)
        if not chunk:
            raise InstallerError("Hermes installer operation failed")
        digest.update(chunk)
        offset += len(chunk)
        remaining -= len(chunk)
    return digest.hexdigest()


def _verified_path(resolution: BinaryResolution) -> str:
    current = _descriptor_identity(resolution.descriptor) if resolution.descriptor >= 0 else None
    if current is None or (current.owner_uid, current.kind, current.mode, current.size, current.sha256) != (resolution.identity.owner_uid, resolution.identity.kind, resolution.identity.mode, resolution.identity.size, resolution.identity.sha256):
        raise InstallerError("Hermes installer operation failed")
    return f"/proc/self/fd/{resolution.descriptor}"


def _descriptor_identity(descriptor: int) -> Identity:
    info = os.fstat(descriptor)
    return Identity(info.st_dev, info.st_ino, info.st_uid, "file", stat.S_IMODE(info.st_mode), info.st_size, info.st_mtime_ns, _digest_fd(descriptor, info.st_size))


def _run_verified(resolution: BinaryResolution, arguments: Sequence[str], home: Path) -> ProcessResult:
    return run_argv((_verified_path(resolution), *arguments), timeout=30.0, env=child_env(home), pass_fds=(resolution.descriptor,))


def _close_resolution(resolution: BinaryResolution) -> None:
    if resolution.descriptor >= 0:
        if resolution.backing is None:
            os.close(resolution.descriptor)
        else:
            resolution.backing.close()


def require_version(binary: str, home: Path) -> None:
    resolution = resolve_binary(binary)
    try:
        result = _run_verified(resolution, ("--version",), home)
        check_version_output(result.stdout, result.stderr, result.returncode)
    finally:
        _close_resolution(resolution)


def resolved_identity(binary: str) -> Identity:
    resolution = resolve_binary(binary)
    try:
        return resolution.identity
    finally:
        _close_resolution(resolution)


def run_host_checks(binary: str, plugin_path: str, home: Path) -> None:
    resolution = resolve_binary(binary)
    try:
        result = _run_verified(resolution, ("--version",), home)
        check_version_output(result.stdout, result.stderr, result.returncode)
        result = _run_verified(resolution, ("plugins", "doctor", plugin_path, "--ci"), home)
        if result.returncode != 0 or result.stderr:
            raise InstallerError("Hermes installer operation failed")
    finally:
        _close_resolution(resolution)
