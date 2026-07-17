"""Severity / CVSS / CWE / OWASP normalization.

Different scanners use different vocabularies for the same thing. This module
contains a single, conservative set of mappings:

* ``normalize_severity`` — fold any tool's severity label to a
  :class:`Severity` enum.
* ``normalize_confidence`` — fold any tool's confidence label.
* ``severity_to_cvss`` — deterministic CVSS approximation. This is **not** a
  full NVD-grade score; it is a transparent heuristic useful for sorting.
* ``map_cwe`` / ``map_owasp`` — text → CWE / OWASP labels, with safe fallbacks.
"""

from __future__ import annotations

import re
from typing import Iterable, List

from .models import Confidence, Severity

SEVERITY_RANK = {
    Severity.CRITICAL: 5,
    Severity.HIGH: 4,
    Severity.MEDIUM: 3,
    Severity.LOW: 2,
    Severity.INFO: 1,
    Severity.UNKNOWN: 0,
}


def normalize_severity(value) -> Severity:
    """Map a free-form severity label to a :class:`Severity`."""

    if value is None:
        return Severity.UNKNOWN
    if isinstance(value, Severity):
        return value
    s = str(value).strip().lower()
    if not s:
        return Severity.UNKNOWN
    # Common tool aliases.
    aliases = {
        "crit": Severity.CRITICAL,
        "critical": Severity.CRITICAL,
        "blocker": Severity.CRITICAL,
        "high": Severity.HIGH,
        "error": Severity.HIGH,
        "h": Severity.HIGH,
        "medium": Severity.MEDIUM,
        "med": Severity.MEDIUM,
        "moderate": Severity.MEDIUM,
        "warning": Severity.MEDIUM,
        "m": Severity.MEDIUM,
        "low": Severity.LOW,
        "minor": Severity.LOW,
        "l": Severity.LOW,
        "info": Severity.INFO,
        "informational": Severity.INFO,
        "information": Severity.INFO,
        "note": Severity.INFO,
        "debug": Severity.INFO,
        "negligible": Severity.INFO,
        "unknown": Severity.UNKNOWN,
        "none": Severity.UNKNOWN,
    }
    if s in aliases:
        return aliases[s]
    if "crit" in s:
        return Severity.CRITICAL
    if "high" in s:
        return Severity.HIGH
    if "med" in s or "moderate" in s:
        return Severity.MEDIUM
    if "low" in s:
        return Severity.LOW
    if "info" in s:
        return Severity.INFO
    return Severity.UNKNOWN


def normalize_confidence(value) -> Confidence:
    """Map a free-form confidence label to a :class:`Confidence`."""

    if value is None:
        return Confidence.MEDIUM
    if isinstance(value, Confidence):
        return value
    s = str(value).strip().lower()
    if s in {"high", "h", "confirmed", "strong"}:
        return Confidence.HIGH
    if s in {"low", "l", "weak", "tentative"}:
        return Confidence.LOW
    if s in {"medium", "med", "moderate", "m", "default"}:
        return Confidence.MEDIUM
    return Confidence.MEDIUM


def severity_to_cvss(severity: Severity) -> float:
    """Transparent CVSS approximation from a normalized severity.

    Not an NVD-grade score; used purely for relative sorting and display.
    """

    table = {
        Severity.CRITICAL: 9.5,
        Severity.HIGH: 7.5,
        Severity.MEDIUM: 5.0,
        Severity.LOW: 3.0,
        Severity.INFO: 1.0,
        Severity.UNKNOWN: 0.0,
    }
    return table.get(severity, 0.0)


CWE_PATTERN = re.compile(r"CWE-?\s*(\d+)", re.IGNORECASE)


def map_cwe(value) -> List[str]:
    """Extract CWE identifiers from a string or iterable."""

    if value is None:
        return []
    if isinstance(value, (list, tuple, set)):
        out: List[str] = []
        for v in value:
            out.extend(map_cwe(v))
        return sorted(set(out))
    s = str(value)
    ids = CWE_PATTERN.findall(s)
    return sorted({"CWE-" + i for i in ids})


OWASP_PATTERN = re.compile(r"A(\d{2}):(\d{4})", re.IGNORECASE)


def map_owasp(value) -> List[str]:
    """Extract OWASP Top-N labels from a string or iterable."""

    if value is None:
        return []
    if isinstance(value, (list, tuple, set)):
        out: List[str] = []
        for v in value:
            out.extend(map_owasp(v))
        return sorted(set(out))
    s = str(value)
    matches = OWASP_PATTERN.findall(s)
    return sorted({"A" + a + ":" + b for a, b in matches})