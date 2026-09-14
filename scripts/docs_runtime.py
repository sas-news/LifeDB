from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import tempfile
import threading
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from collections.abc import Mapping
from typing import Final, TypeAlias

Json: TypeAlias = str | int | float | bool | None | dict[str, "Json"] | list["Json"]


class RuntimeScenarioError(RuntimeError):
    """An observed runtime contract did not match the documented outcome."""


class ResponseFormatError(ValueError):
    """A LifeDB response was not a JSON object."""


@dataclass(frozen=True, slots=True)
class HttpObservation:
    status: int
    body: dict[str, Json]
    headers: dict[str, str]
    cache_control: str | None
    dirty: bool | None
    indexed_sequence: int | None
    durable_sequence: int | None
    error: str | None = None


@dataclass(frozen=True, slots=True)
class CliObservation:
    returncode: int
    value: Json
    stderr: str


def _body(payload: bytes) -> dict[str, Json]:
    if not payload:
        return {}
    loaded = json.loads(payload.decode("utf-8"))
    if not isinstance(loaded, dict):
        raise ResponseFormatError("LifeDB response was not a JSON object")
    return loaded


def request(
    base: str,
    path: str,
    token: str | None = None,
    data: bytes | None = None,
    *,
    timeout: float = 3.0,
) -> HttpObservation:
    headers = {"Content-Type": "application/json"}
    if token is not None:
        headers["Authorization"] = f"Bearer {token}"
    outgoing = urllib.request.Request(
        base + path,
        data=data,
        headers=headers,
        method="POST" if data is not None else "GET",
    )
    try:
        response_context = urllib.request.urlopen(outgoing, timeout=timeout)
    except urllib.error.HTTPError as error:
        with error:
            return _observation(error.code, error.headers, error.read())
    except (urllib.error.URLError, TimeoutError, OSError) as error:
        return HttpObservation(0, {}, {}, None, None, None, None, type(error).__name__)
    with response_context:
        return _observation(response_context.status, response_context.headers, response_context.read())


def _observation(status: int, headers: Mapping[str, str], payload: bytes) -> HttpObservation:
    values = {str(key): str(value) for key, value in headers.items()}
    body = _body(payload)
    watermark = body.get("watermark")
    if not isinstance(watermark, dict):
        watermark = body
    dirty = watermark.get("dirty")
    indexed = watermark.get("indexed_sequence")
    durable = watermark.get("durable_sequence")
    return HttpObservation(
        status,
        body,
        values,
        values.get("Cache-Control"),
        dirty if isinstance(dirty, bool) else None,
        indexed if isinstance(indexed, int) else None,
        durable if isinstance(durable, int) else None,
    )


def _files(vault: Path) -> tuple[tuple[str, int, str], ...]:
    entries: list[tuple[str, int, str]] = []
    for path in sorted(item for item in vault.rglob("*") if item.is_file()):
        payload = path.read_bytes()
        entries.append((str(path.relative_to(vault)), len(payload), hashlib.sha256(payload).hexdigest()))
    return tuple(entries)


def _cli(vault: Path, *arguments: str) -> CliObservation:
    environment = {"PATH": os.environ["PATH"], "PYTHONPATH": str(Path(__file__).parents[1] / "src")}
    completed = subprocess.run(
        [sys.executable, "-c", "from lifedb.cli import main; raise SystemExit(main())", "--vault", str(vault), *arguments],
        capture_output=True,
        text=True,
        env=environment,
        check=False,
    )
    value: Json = json.loads(completed.stdout)
    return CliObservation(completed.returncode, value, completed.stderr)


def _turn(turn_id: str, assistant_text: str = "The answer remains durable.") -> bytes:
    return json.dumps({
        "host": "opencode", "session_id": "docs-session", "turn_id": turn_id,
        "workspace": "/tmp/docs-runtime", "user_text": "Remember the durable answer.",
        "assistant_text": assistant_text, "captured_at": "2026-09-12T00:00:00Z",
    }).encode("utf-8")


def runtime_scenario() -> tuple[str, ...]:
    from lifedb.index import index_watermark
    from lifedb.server import LifeDBServer
    from lifedb.vault import Vault

    token: Final[str] = "docs-runtime-token-with-more-than-32-bytes-2026"
    with tempfile.TemporaryDirectory(prefix="lifedb-task16-") as directory:
        root = Path(directory)
        vault = Vault(root / "vault")
        vault.init()
        server = LifeDBServer(("127.0.0.1", 0), vault, api_token=token)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        base = f"http://127.0.0.1:{server.server_port}"
        try:
            health = request(base, "/health")
            missing = request(base, "/v1/context", data=b"{}")
            wrong = request(base, "/v1/context", token="wrong-token-000000000000000000000000", data=b"{}")
            context = request(base, "/v1/context", token=token, data=b"{}")
            created = request(base, "/v1/turns", token=token, data=_turn("docs-turn"))
            replay = request(base, "/v1/turns", token=token, data=_turn("docs-turn"))
            conflict = request(base, "/v1/turns", token=token, data=_turn("docs-turn", "Changed answer."))
            before = _files(vault.root)
            credential = request(base, "/v1/turns", token=token, data=_turn("credential", "sk-proj-abcdefghij1234567890XY"))
            after = _files(vault.root)
            rebuilt = request(base, "/v1/rebuild", token=token, data=b"")
            validated = _cli(vault.root, "validate")
            searched = _cli(vault.root, "search", "durable")
            doctored = _cli(vault.root, "doctor")
            watermark = index_watermark(vault)
            statuses = (health.status, context.status, created.status, replay.status, missing.status, wrong.status, conflict.status, credential.status, rebuilt.status)
            if statuses != (200, 200, 201, 201, 401, 401, 409, 422, 200) or before != after:
                raise RuntimeScenarioError("runtime HTTP contract")
            if any(observation.cache_control != "no-store" for observation in (health, context, created, replay, conflict, credential, rebuilt)):
                raise RuntimeScenarioError("runtime cache contract")
            if not (validated.returncode == searched.returncode == doctored.returncode == 0 and watermark["dirty"] is False):
                raise RuntimeScenarioError("runtime CLI contract")
            return ("200", "201", "401", "409", "422", "clean")
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)


def failure_scenario() -> tuple[str, ...]:
    """Exercise authentication refusal, conflict, and bounded service-down paths."""
    from lifedb.server import LifeDBServer
    from lifedb.vault import Vault

    token = "docs-failure-token-with-more-than-32-bytes-2026"
    with tempfile.TemporaryDirectory(prefix="lifedb-task16-failure-") as directory:
        root = Path(directory)
        vault = Vault(root / "vault")
        vault.init()
        server = LifeDBServer(("127.0.0.1", 0), vault, api_token=token)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            base = f"http://127.0.0.1:{server.server_port}"
            unauthorized = request(base, "/v1/context", data=b"{}").status
            first = request(base, "/v1/turns", token=token, data=_turn("failure-turn"))
            conflict = request(base, "/v1/turns", token=token, data=_turn("failure-turn", "different"))
            if (unauthorized, first.status, conflict.status) != (401, 201, 409):
                raise RuntimeScenarioError("failure HTTP contract")
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)
        stopped = request("http://127.0.0.1:1", "/health", timeout=0.2)
        if stopped.status != 0 or any(root.rglob("spool*")):
            raise RuntimeScenarioError("failure service-down contract")
        bare = LifeDBServer(("127.0.0.1", 0), vault, api_token=None)
        bare_thread = threading.Thread(target=bare.serve_forever, daemon=True)
        bare_thread.start()
        try:
            unconfigured = request(
                f"http://127.0.0.1:{bare.server_port}",
                "/v1/context",
                token=token,
                data=b"{}",
            )
        finally:
            bare.shutdown()
            bare.server_close()
            bare_thread.join(timeout=2)
        if unconfigured.status != 503:
            raise RuntimeScenarioError("failure unconfigured contract")
    return ("401", "409", "503")


__all__ = [
    "CliObservation", "HttpObservation", "ResponseFormatError", "RuntimeScenarioError",
    "failure_scenario", "request", "runtime_scenario",
]
