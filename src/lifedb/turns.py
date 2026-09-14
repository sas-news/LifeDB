from __future__ import annotations

import hashlib
from collections.abc import Mapping
from dataclasses import dataclass
from typing import TypedDict

from .auth import validate_sensitivity
from .storage import canonical_json_bytes, strict_json_loads
from .vault import parse_time
from ._json_types import JSONValue

TURN_MEDIA_TYPE = "application/vnd.lifedb.agent-turn+json"
TURN_FILENAME = "turn.json"
TURN_EVIDENCE_KIND = "conversation"
TURN_FORMAT = "lifedb.agent-turn/v1"
TURN_HOSTS: tuple[str, ...] = ("opencode", "hermes")

MAX_ID_CHARS = 256
MAX_WORKSPACE_CHARS = 4096
MAX_TEXT_CHARS = 200_000
MAX_LABEL_CHARS = 256
MAX_TIMESTAMP_CHARS = 128
MAX_TURN_REQUEST_BYTES = 2 * 1024 * 1024

_KNOWN_FIELDS = frozenset(
    {
        "host",
        "session_id",
        "turn_id",
        "workspace",
        "user_text",
        "assistant_text",
        "captured_at",
        "model",
        "platform",
        "sensitivity",
    }
)


class TurnValidationError(ValueError):
    """A strict turn request failed closed; the message never echoes input."""


def _check_encodable(value: str, field: str) -> None:
    try:
        _ = value.encode("utf-8")
    except UnicodeEncodeError:
        raise TurnValidationError(f"invalid turn {field}") from None


class TurnIngestArgs(TypedDict):
    data: bytes
    source_kind: str
    source_metadata: dict[str, str]
    external_id: str
    media_type: str
    filename: str
    kind: str
    captured_at: str
    sensitivity: str


def _check_opaque_id(value: JSONValue, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise TurnValidationError(f"invalid turn {field}")
    if len(value) > MAX_ID_CHARS:
        raise TurnValidationError(f"invalid turn {field}")
    if any(ord(item) < 0x20 or ord(item) == 0x7F for item in value):
        raise TurnValidationError(f"invalid turn {field}")
    _check_encodable(value, field)
    return value


def _check_text(value: JSONValue, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise TurnValidationError(f"invalid turn {field}")
    if len(value) > MAX_TEXT_CHARS:
        raise TurnValidationError(f"invalid turn {field}")
    for item in value:
        code = ord(item)
        if code in (0x09, 0x0A, 0x0D):
            continue
        if code < 0x20 or code == 0x7F:
            raise TurnValidationError(f"invalid turn {field}")
    _check_encodable(value, field)
    return value


def _check_label(value: JSONValue, field: str) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or not value.strip():
        raise TurnValidationError(f"invalid turn {field}")
    if len(value) > MAX_LABEL_CHARS:
        raise TurnValidationError(f"invalid turn {field}")
    if any(ord(item) < 0x20 or ord(item) == 0x7F for item in value):
        raise TurnValidationError(f"invalid turn {field}")
    _check_encodable(value, field)
    return value


def _check_workspace(value: JSONValue) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise TurnValidationError("invalid turn workspace")
    if any(ord(item) < 0x20 or ord(item) == 0x7F for item in value):
        raise TurnValidationError("invalid turn workspace")
    normalized = value.strip()
    if not normalized:
        raise TurnValidationError("invalid turn workspace")
    if len(normalized) > MAX_WORKSPACE_CHARS:
        raise TurnValidationError("invalid turn workspace")
    _check_encodable(normalized, "workspace")
    return normalized


def _check_captured_at(value: JSONValue) -> str:
    if not isinstance(value, str):
        raise TurnValidationError("invalid turn captured_at")
    if len(value) > MAX_TIMESTAMP_CHARS:
        raise TurnValidationError("invalid turn captured_at")
    try:
        parsed = parse_time(value)
    except (TypeError, ValueError):
        raise TurnValidationError("invalid turn captured_at") from None
    return parsed.isoformat().replace("+00:00", "Z")


def _check_sensitivity(value: JSONValue) -> str | None:
    if value is None:
        return None
    try:
        return validate_sensitivity(value, field="sensitivity")
    except (TypeError, ValueError):
        raise TurnValidationError("invalid turn sensitivity") from None


@dataclass(frozen=True, slots=True)
class TurnRequest:
    """One validated completed agent turn; the server derives all provenance."""

    host: str
    session_id: str
    turn_id: str
    workspace: str | None
    user_text: str
    assistant_text: str
    captured_at: str
    model: str | None
    platform: str | None
    sensitivity: str | None

    @property
    def source_kind(self) -> str:
        return self.host

    @property
    def session_label(self) -> str:
        return f"agent:{self.host}:session:{self.session_id}"

    @property
    def external_id(self) -> str:
        identity = "\x00".join((self.host, self.session_id, self.turn_id))
        return "turn-v1:" + hashlib.sha256(identity.encode("utf-8")).hexdigest()

    @property
    def media_type(self) -> str:
        return TURN_MEDIA_TYPE

    @property
    def filename(self) -> str:
        return TURN_FILENAME

    @property
    def evidence_kind(self) -> str:
        return TURN_EVIDENCE_KIND

    def canonical_bytes(self) -> bytes:
        return canonical_json_bytes(
            {
                "assistant_text": self.assistant_text,
                "captured_at": self.captured_at,
                "format": TURN_FORMAT,
                "host": self.host,
                "model": self.model,
                "platform": self.platform,
                "session_id": self.session_id,
                "session_label": self.session_label,
                "turn_id": self.turn_id,
                "user_text": self.user_text,
                "workspace": self.workspace,
            }
        )

    def source_metadata(self) -> dict[str, str]:
        metadata: dict[str, str] = {
            "host": self.host,
            "session": self.session_label,
            "turn": self.turn_id,
        }
        if self.workspace is not None:
            metadata["workspace"] = self.workspace
        return metadata

    def ingest_kwargs(self, *, sensitivity: str) -> TurnIngestArgs:
        try:
            resolved = validate_sensitivity(sensitivity, field="sensitivity")
        except (TypeError, ValueError):
            raise TurnValidationError("invalid turn sensitivity") from None
        return {
            "data": self.canonical_bytes(),
            "source_kind": self.source_kind,
            "source_metadata": self.source_metadata(),
            "external_id": self.external_id,
            "media_type": self.media_type,
            "filename": self.filename,
            "kind": self.evidence_kind,
            "captured_at": self.captured_at,
            "sensitivity": resolved,
        }


def parse_turn_request(value: JSONValue) -> TurnRequest:
    """Validate a decoded strict-JSON mapping into a frozen TurnRequest."""
    if not isinstance(value, Mapping):
        raise TurnValidationError("invalid turn request")
    if set(value) - _KNOWN_FIELDS:
        raise TurnValidationError("unknown turn field")
    host = value.get("host")
    if not isinstance(host, str) or host not in TURN_HOSTS:
        raise TurnValidationError("invalid turn host")
    return TurnRequest(
        host=host,
        session_id=_check_opaque_id(value.get("session_id"), "session_id"),
        turn_id=_check_opaque_id(value.get("turn_id"), "turn_id"),
        workspace=_check_workspace(value.get("workspace")),
        user_text=_check_text(value.get("user_text"), "user_text"),
        assistant_text=_check_text(value.get("assistant_text"), "assistant_text"),
        captured_at=_check_captured_at(value.get("captured_at")),
        model=_check_label(value.get("model"), "model"),
        platform=_check_label(value.get("platform"), "platform"),
        sensitivity=_check_sensitivity(value.get("sensitivity")),
    )


def parse_turn_bytes(payload: bytes) -> TurnRequest:
    """Decode bounded strict JSON (duplicate keys rejected) into a TurnRequest."""
    try:
        decoded: JSONValue = strict_json_loads(payload, max_bytes=MAX_TURN_REQUEST_BYTES)
    except (TypeError, ValueError):
        raise TurnValidationError("invalid turn JSON") from None
    return parse_turn_request(decoded)
