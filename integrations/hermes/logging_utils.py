from __future__ import annotations

import logging
import re
from typing import Final


LOGGER = logging.getLogger("lifedb.hermes")
_OUTCOMES: Final = frozenset({"ok", "fail-open", "rejected", "dropped"})
_OPERATION = re.compile(r"^[a-z][a-z0-9]*(?:\.[a-z][a-z0-9]*)*$")


def log_outcome(operation: str, outcome: str, *, warning: bool = False) -> None:
    """Emit only bounded operation and outcome classifications."""
    safe_operation = operation if _OPERATION.fullmatch(operation) else "unknown"
    safe_outcome = outcome if outcome in _OUTCOMES else "fail-open"
    log = LOGGER.warning if warning else LOGGER.info
    log("lifedb bridge operation=%s outcome=%s", safe_operation[:64], safe_outcome)
