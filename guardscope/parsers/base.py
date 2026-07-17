"""Parser protocol and registry helpers."""

from __future__ import annotations

from typing import List, Protocol, runtime_checkable

from ..core.models import Finding


class ParseError(Exception):
    """Raised when a parser cannot process the given input."""


@runtime_checkable
class Parser(Protocol):
    """A tool that converts a report into normalized findings."""

    name: str
    description: str

    def parse(self, text: str) -> List[Finding]:
        ...


_REGISTRY: dict[str, Parser] = {}


def register_parser(p: Parser) -> None:
    """Register a parser instance by its ``name``."""

    _REGISTRY[p.name] = p


def get_parser(name: str) -> Parser | None:
    return _REGISTRY.get(name)


def registered_parsers() -> List[Parser]:
    return list(_REGISTRY.values())