"""Parser dispatch.

Maps a source name or file extension to a registered parser. Auto-discovers
the built-in parsers on import.
"""

from __future__ import annotations

import os
from typing import List

from .base import Parser, ParseError, get_parser, register_parser
from .nmap import NmapParser
from .zap import ZapParser
from .sarif import SarifParser
from .bandit import BanditParser
from .semgrep import SemgrepParser
from .trivy import TrivyParser
from .pipaudit import PipAuditParser


def _bootstrap() -> None:
    for p in (
        NmapParser(),
        ZapParser(),
        SarifParser(),
        BanditParser(),
        SemgrepParser(),
        TrivyParser(),
        PipAuditParser(),
    ):
        register_parser(p)


_bootstrap()


_EXT_MAP = {
    ".xml": "nmap",
    ".nmap": "nmap",
    ".zap": "zap",
    ".sarif": "sarif",
    ".bandit": "bandit",
    ".semgrep": "semgrep",
    ".trivy": "trivy",
    ".pip-audit": "pipaudit",
}


_SNIFF_RULES = (
    ("nmap", lambda t: "<nmaprun" in t),
    ("sarif", lambda t: "\"sarif\"" in t.lower() or ("runs" in t and "$schema" in t and "2.1.0" in t)),
    ("zap", lambda t: "\"alerts\"" in t and ("riskcode" in t or "pluginid" in t)),
    ("trivy", lambda t: "Vulnerabilities" in t and ("ArtifactName" in t or "FixedVersion" in t)),
    ("pipaudit", lambda t: "\"vulns\"" in t),
    ("bandit", lambda t: "issue_severity" in t and "test_id" in t),
    ("semgrep", lambda t: "check_id" in t and "extra" in t),
)


def dispatch(source: str | None, file_path: str | None, text: str | None = None) -> Parser:
    """Return a parser for a given source name, file path, or text snippet."""

    if source:
        p = get_parser(source.lower())
        if p is None:
            raise ParseError(f"No parser registered for source '{source}'")
        return p
    if file_path:
        ext = os.path.splitext(file_path)[1].lower()
        name = _EXT_MAP.get(ext)
        if name is not None:
            p = get_parser(name)
            if p is None:
                raise ParseError(f"Parser '{name}' not registered")
            return p
    if text:
        for name, predicate in _SNIFF_RULES:
            if predicate(text):
                p = get_parser(name)
                if p is not None:
                    return p
    raise ParseError(
        "Could not dispatch a parser; provide --source, a recognized extension, or recognizable content"
    )


def list_parsers() -> List[Parser]:
    from .base import registered_parsers

    return registered_parsers()