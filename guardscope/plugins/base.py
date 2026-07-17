"""Plugin protocol + registry."""

from __future__ import annotations

from typing import List, Protocol, runtime_checkable

from ..core.models import Finding


@runtime_checkable
class Plugin(Protocol):
    """A post-parser enrichment hook."""

    name: str
    description: str

    def enrich(self, finding: Finding) -> Finding:
        """Return an enriched (or unchanged) finding."""


_REGISTRY: dict[str, Plugin] = {}


def register_plugin(p: Plugin) -> None:
    _REGISTRY[p.name] = p


def get_plugin(name: str) -> Plugin | None:
    return _REGISTRY.get(name)


def list_plugins() -> List[Plugin]:
    return list(_REGISTRY.values())


def run_plugins(f: Finding) -> Finding:
    """Apply every registered plugin in order to a finding."""

    for p in _REGISTRY.values():
        f = p.enrich(f)
    return f