"""Dynamic threat-intelligence provider discovery."""

from __future__ import annotations

import importlib
from importlib import metadata
from typing import Iterable

from ..core.base import BaseThreatProvider


class ThreatProviderManager:
    """Discover built-in and installed entry-point threat providers."""

    ENTRY_POINT_GROUP = "clamguardian.threat_providers"

    def __init__(self, providers: Iterable[BaseThreatProvider] = ()) -> None:
        self._providers: dict[str, BaseThreatProvider] = {}
        for provider in providers:
            self.register(provider)

    def register(self, provider: BaseThreatProvider) -> None:
        """Register a provider by its stable name."""
        if not provider.name:
            raise ValueError("Threat provider name cannot be empty")
        self._providers[provider.name] = provider

    def load_entry_points(self) -> tuple[str, ...]:
        """Load all installed providers from the configured entry-point group."""
        loaded: list[str] = []
        entries = metadata.entry_points()
        selected = entries.select(group=self.ENTRY_POINT_GROUP) if hasattr(entries, "select") else entries.get(self.ENTRY_POINT_GROUP, [])
        for entry in selected:
            provider = entry.load()
            if isinstance(provider, type):
                provider = provider()
            if not isinstance(provider, BaseThreatProvider):
                raise TypeError(f"Entry point {entry.name!r} is not a BaseThreatProvider")
            self.register(provider)
            loaded.append(provider.name)
        return tuple(loaded)

    def load_module(self, module_name: str, attribute: str = "provider") -> BaseThreatProvider:
        """Load a provider object from a Python module and register it."""
        module = importlib.import_module(module_name)
        candidate = getattr(module, attribute)
        provider = candidate() if isinstance(candidate, type) else candidate
        if not isinstance(provider, BaseThreatProvider):
            raise TypeError(f"{module_name}.{attribute} is not a BaseThreatProvider")
        self.register(provider)
        return provider

    def get(self, name: str) -> BaseThreatProvider:
        """Return a registered provider or raise KeyError."""
        return self._providers[name]

    def names(self) -> tuple[str, ...]:
        """Return provider names in deterministic order."""
        return tuple(sorted(self._providers))
