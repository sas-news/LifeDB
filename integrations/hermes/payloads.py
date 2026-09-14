from __future__ import annotations

import json
from typing import Final, NotRequired, TypedDict


class ContextPayload(TypedDict):
    client: str
    query: str
    session: NotRequired[str]
    workspace: NotRequired[str]
    limit: NotRequired[int]
    sensitivity_ceiling: NotRequired[str]
    budget_chars: NotRequired[int]
    core_chars: NotRequired[int]
    continuity_chars: NotRequired[int]
    relevant_chars: NotRequired[int]


class TurnPayload(TypedDict):
    assistant_text: str
    captured_at: str
    host: str
    session_id: str
    turn_id: str
    user_text: str
    workspace: NotRequired[str]


SerializedPayload = bytes
MAX_PAYLOAD_BYTES: Final = 4_194_304


class PayloadError(ValueError):
    """A typed payload cannot satisfy the bounded bridge contract."""


def _canonical(value: ContextPayload | TurnPayload) -> bytes:
    result = json.dumps(
        value, ensure_ascii=False, separators=(",", ":"), sort_keys=True
    ).encode("utf-8")
    if len(result) > MAX_PAYLOAD_BYTES:
        raise PayloadError("payload exceeds configured limit")
    return result


def context_payload(
    *, query: str, client: str, session: str | None = None,
    workspace: str | None = None, limit: int | None = None,
    sensitivity_ceiling: str | None = None, budget_chars: int | None = None,
    core_chars: int | None = None, continuity_chars: int | None = None,
    relevant_chars: int | None = None,
) -> bytes:
    """Serialize the scalar context request with stable JSON bytes."""
    value: ContextPayload = {
        "client": client,
        "query": query,
    }
    if session is not None:
        value["session"] = session
    if workspace is not None:
        value["workspace"] = workspace
    if limit is not None:
        value["limit"] = limit
    if sensitivity_ceiling is not None:
        value["sensitivity_ceiling"] = sensitivity_ceiling
    if budget_chars is not None:
        value["budget_chars"] = budget_chars
    if core_chars is not None:
        value["core_chars"] = core_chars
    if continuity_chars is not None:
        value["continuity_chars"] = continuity_chars
    if relevant_chars is not None:
        value["relevant_chars"] = relevant_chars
    return _canonical(value)


def turn_payload(
    *, session_id: str, turn_id: str, user_text: str, assistant_text: str,
    captured_at: str, workspace: str | None = None,
) -> bytes:
    """Serialize the approved text-only Hermes turn fields."""
    value: TurnPayload = {
        "assistant_text": assistant_text,
        "captured_at": captured_at,
        "host": "hermes",
        "session_id": session_id,
        "turn_id": turn_id,
        "user_text": user_text,
    }
    if workspace is not None:
        value["workspace"] = workspace
    return _canonical(value)
