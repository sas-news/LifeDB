from __future__ import annotations

from collections.abc import Callable
from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:
    from .preflight import ContextResult


class RegistrationContext(Protocol):
    def register_hook(self, hook_name: str, callback: Callable[..., ContextResult | None]) -> None: ...


def register(context: RegistrationContext) -> None:
    """Register the three supported general Hermes lifecycle hooks."""
    from .hooks import configured_hooks

    for hook_name, callback in configured_hooks(context):
        context.register_hook(hook_name, callback)
