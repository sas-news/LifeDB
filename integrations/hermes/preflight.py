from __future__ import annotations

from collections.abc import Callable, Sequence
import os
from typing import Mapping, Protocol

from .bridge import RequestTransport, post_json
from .context_pack import parse_context_pack
from .logging_utils import log_outcome
from .payloads import context_payload
from .settings import ConfigReader, PluginSettings, SettingsError, load_settings
from .transport import StdlibTransport, TransportFailure


ContextResult = dict[str, str]
Scalar = str | int | float | bool | None


class TransportFactory(Protocol):
    def __call__(self, max_response_bytes: int) -> RequestTransport: ...


def _clean(value: str | None, maximum: int) -> str | None:
    if not isinstance(value, str) or not value.strip() or len(value.strip()) > maximum:
        return None
    if any(ord(character) < 0x20 or ord(character) == 0x7F for character in value):
        return None
    return value


def _label(value: str | None) -> str | None:
    return _clean(value, 480)


def _workspace(settings: PluginSettings, current_directory: Callable[[], str]) -> str | None:
    if settings.workspace is not None:
        return settings.workspace
    try:
        candidate = current_directory()
    except OSError:
        return None
    return candidate if isinstance(candidate, str) and os.path.isabs(candidate) else None


def create_preflight(
    context: ConfigReader,
    *,
    transport_factory: TransportFactory | None = None,
    cwd: Callable[[], str] = os.getcwd,
) -> Callable[..., ContextResult | None]:
    """Create a synchronous Hermes preflight callback with captured seams."""
    factory = transport_factory or (lambda cap: StdlibTransport(cap))

    def callback(
        *,
        session_id: str | None = None,
        task_id: str | None = None,
        turn_id: str | None = None,
        user_message: str | None = None,
        conversation_history: Sequence[str | Mapping[str, Scalar]] | None = None,
        is_first_turn: bool | None = None,
        model: str | None = None,
        platform: str | None = None,
        parent_session_id: str | None = None,
        sender_id: str | None = None,
        **_extras: Scalar,
    ) -> ContextResult | None:
        del conversation_history, is_first_turn, model, platform, parent_session_id, sender_id
        if _label(session_id) is None or _label(task_id) is None or _label(turn_id) is None:
            return None
        query = _clean(user_message, 4_096)
        if query is None:
            return None
        try:
            loaded = load_settings(context, include_context=True)
            workspace = _workspace(loaded, cwd)
            payload = context_payload(
                query=query, client="hermes", session=f"agent:hermes:session:{session_id}",
                workspace=workspace, limit=loaded.limit, sensitivity_ceiling=loaded.sensitivity,
                budget_chars=loaded.budget_chars, core_chars=loaded.core_chars,
                continuity_chars=loaded.continuity_chars, relevant_chars=loaded.relevant_chars,
            )
            result = post_json(factory(loaded.max_response_bytes), loaded, "/v1/context", payload)
            if result is None:
                log_outcome("context.fetch", "fail-open", warning=True)
                return None
            if (
                result.status < 200
                or result.status >= 300
                or len(result.body) > loaded.max_response_bytes
            ):
                raise TransportFailure("invalid context pack")
            decoded = parse_context_pack(result.body, max_bytes=loaded.max_response_bytes)
            if decoded is None:
                raise TransportFailure("invalid context pack")
            log_outcome("context.fetch", "ok")
            return {"context": decoded["rendered_markdown"]}
        except (OSError, UnicodeError, TypeError, ValueError, KeyError, RuntimeError, SettingsError, TransportFailure):
            log_outcome("context.fetch", "fail-open", warning=True)
            return None

    return callback
