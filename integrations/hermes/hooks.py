from __future__ import annotations

from collections.abc import Callable
from datetime import datetime, timezone

from .postflight import make_lifecycle_callbacks
from .preflight import ContextResult, create_preflight
from .settings import ConfigReader
from .transport import StdlibTransport


HookCallback = Callable[..., ContextResult | None]
ConfiguredHook = tuple[str, HookCallback]


def configured_hooks(context: ConfigReader) -> tuple[ConfiguredHook, ConfiguredHook, ConfiguredHook]:
    """Build the supported synchronous hooks without reading configuration."""
    preflight = create_preflight(context)
    postflight, session_end = make_lifecycle_callbacks(
        context,
        lambda max_response_bytes: StdlibTransport(max_response_bytes),
        lambda: datetime.now(timezone.utc),
    )
    return ("pre_llm_call", preflight), ("post_llm_call", postflight), ("on_session_end", session_end)
