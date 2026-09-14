from __future__ import annotations


class VaultValueError(ValueError):
    """A validated Vault value or durable-state contract was not satisfied."""


class VaultTypeError(TypeError):
    """A Vault operation received a value of an unsupported type."""
