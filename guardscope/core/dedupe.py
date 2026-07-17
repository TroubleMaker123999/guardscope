"""Deduplication of findings by stable fingerprint.

A list of findings is collapsed into a list of unique fingerprints. For each
fingerprint we keep the first finding but also record a ``duplicate_count``
attribute (set via ``object.__setattr__`` to bypass Pydantic's frozen-by-default
field set) so callers can report "seen 3x".
"""

from __future__ import annotations

from typing import Dict, List

from .models import Finding
from .fingerprint import fingerprint_finding


def deduplicate(findings: List[Finding]) -> List[Finding]:
    """Return ``findings`` with duplicates collapsed, preserving order.

    Each returned finding gains a transient ``duplicate_count`` attribute that
    reflects how many times it was seen (>=1).
    """

    seen: Dict[str, Finding] = {}
    for f in findings:
        if not f.fingerprint:
            fingerprint_finding(f)
        key = f.fingerprint
        if key in seen:
            existing = seen[key]
            object.__setattr__(existing, "duplicate_count", getattr(existing, "duplicate_count", 1) + 1)
            # If a duplicate carries more evidence, merge it.
            if not existing.evidence and f.evidence:
                existing.evidence = f.evidence
            continue
        object.__setattr__(f, "duplicate_count", 1)
        seen[key] = f
    return list(seen.values())