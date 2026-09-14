from __future__ import annotations

from collections import OrderedDict
from collections.abc import Callable
from datetime import datetime, timezone
from enum import StrEnum
from threading import Lock
from typing import Final, Protocol

from .bridge import RequestTransport, post_json
from .logging_utils import log_outcome
from .payloads import turn_payload
from .settings import ConfigReader, SettingsError, load_settings
from .transport import TransportFailure

_MAX_ID_CHARS: Final = 256
_MAX_TEXT_CHARS: Final = 200_000
HookValue = str | int | float | bool | None | list[str] | dict[str, str]
TurnKey = tuple[str, str]


class GuardLimitError(ValueError):
    """The lifecycle state capacity is outside its bounded contract."""


class TimestampError(ValueError):
    """The injected clock did not provide an aware timestamp."""


class TransportFactory(Protocol):
    def __call__(self, max_response_bytes: int) -> RequestTransport: ...


class Clock(Protocol):
    def __call__(self) -> datetime: ...


class _State(StrEnum):
    CANDIDATE = "candidate"
    FINALIZING = "finalizing"
    TERMINAL = "terminal"


class _Entry:
    def __init__(self, state: _State, user_text: str | None = None, assistant_text: str | None = None) -> None:
        self.state = state
        self.user_text = user_text
        self.assistant_text = assistant_text


class _LifecycleState:
    def __init__(self, limit: int) -> None:
        if isinstance(limit, bool) or not isinstance(limit, int) or limit < 1:
            raise GuardLimitError("invalid lifecycle capacity")
        self._limit = limit
        self._entries: OrderedDict[TurnKey, _Entry] = OrderedDict()
        self._lock = Lock()

    def candidate(self, key: TurnKey, user_text: str, assistant_text: str) -> None:
        with self._lock:
            if key in self._entries:
                return
            if len(self._entries) >= self._limit:
                self._evict_terminal()
            if len(self._entries) >= self._limit:
                return
            self._entries[key] = _Entry(_State.CANDIDATE, user_text, assistant_text)

    def finalize(self, key: TurnKey) -> tuple[str, str] | None:
        with self._lock:
            entry = self._entries.get(key)
            if entry is None or entry.state is not _State.CANDIDATE:
                return None
            entry.state = _State.FINALIZING
            return entry.user_text or "", entry.assistant_text or ""

    def terminalize(self, key: TurnKey) -> None:
        with self._lock:
            entry = self._entries.get(key)
            if entry is None:
                self._evict_terminal()
                if len(self._entries) >= self._limit:
                    return
                self._entries[key] = _Entry(_State.TERMINAL)
                return
            entry.state = _State.TERMINAL
            entry.user_text = None
            entry.assistant_text = None

    def _evict_terminal(self) -> None:
        for key, entry in self._entries.items():
            if entry.state is _State.TERMINAL:
                del self._entries[key]
                return


def _bounded_id(value: HookValue) -> str | None:
    if not isinstance(value, str) or not value.strip() or len(value) > _MAX_ID_CHARS:
        return None
    if any(character.isspace() or ord(character) < 0x20 or ord(character) == 0x7F for character in value):
        return None
    try:
        value.encode("utf-8")
    except UnicodeEncodeError:
        return None
    return value


def _bounded_text(value: HookValue) -> str | None:
    if not isinstance(value, str) or not value.strip() or len(value) > _MAX_TEXT_CHARS:
        return None
    if any((ord(character) < 0x20 and character not in "\t\n\r") or ord(character) == 0x7F for character in value):
        return None
    try:
        value.encode("utf-8")
    except UnicodeEncodeError:
        return None
    return value


def _timestamp(clock: Clock) -> str:
    value = clock()
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise TimestampError("clock must return an aware datetime")
    return value.astimezone(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def make_lifecycle_callbacks(
    context: ConfigReader,
    transport_factory: TransportFactory,
    clock: Clock,
    *,
    guard_limit: int = 128,
) -> tuple[Callable[..., None], Callable[..., None]]:
    """Build the buffered observer and authoritative terminal finalizer."""
    state = _LifecycleState(guard_limit)

    def post_llm_call(
        *,
        session_id: HookValue = None,
        turn_id: HookValue = None,
        user_message: HookValue = None,
        assistant_response: HookValue = None,
        **extras: HookValue,
    ) -> None:
        del extras
        session = _bounded_id(session_id)
        turn = _bounded_id(turn_id)
        user_text = _bounded_text(user_message)
        assistant_text = _bounded_text(assistant_response)
        if session is None or turn is None or user_text is None or assistant_text is None:
            return None
        state.candidate((session, turn), user_text, assistant_text)
        return None

    def on_session_end(
        *,
        session_id: HookValue = None,
        turn_id: HookValue = None,
        completed: HookValue = None,
        failed: HookValue = None,
        interrupted: HookValue = None,
        **extras: HookValue,
    ) -> None:
        del extras
        session = _bounded_id(session_id)
        turn = _bounded_id(turn_id)
        if session is None or turn is None:
            return None
        key = (session, turn)
        if not isinstance(completed, bool) or not isinstance(failed, bool) or not isinstance(interrupted, bool):
            state.terminalize(key)
            return None
        if not completed or failed or interrupted:
            state.terminalize(key)
            return None
        texts = state.finalize(key)
        if texts is None:
            return None
        try:
            settings = load_settings(context, include_context=True)
            payload = turn_payload(
                session_id=session,
                turn_id=turn,
                user_text=texts[0],
                assistant_text=texts[1],
                captured_at=_timestamp(clock),
                workspace=settings.workspace,
            )
            result = post_json(
                transport_factory(settings.max_response_bytes),
                settings,
                "/v1/turns",
                payload,
            )
            if result is not None and result.status in {200, 201}:
                log_outcome("turn.capture", "ok")
            elif result is not None and result.status in {400, 401, 409, 422}:
                log_outcome("turn.capture", "rejected", warning=True)
            else:
                log_outcome("turn.capture", "fail-open", warning=True)
        except (
            OSError,
            RuntimeError,
            TypeError,
            UnicodeError,
            SettingsError,
            TimestampError,
            TransportFailure,
        ):
            log_outcome("turn.capture", "fail-open", warning=True)
        finally:
            state.terminalize(key)
        return None

    return post_llm_call, on_session_end
