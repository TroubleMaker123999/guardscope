"""Stable fingerprint computation for findings.

The fingerprint is a sha256 hex digest computed from a small, canonical set
of attributes that uniquely identify a finding across tools and runs:

    source | asset | title | (sorted CWE list)

The title is normalized (lowercased, whitespace-collapsed) before hashing, so
trivial formatting differences do not break deduplication.
"""

from __future__ import annotations

import hashlib
import re
from typing import Iterable

from .models import Finding

_WS_RE = re.compile(r"\s+")


def _norm(s: str) -> str:
    s = (s or "").strip().lower()
    s = _WS_RE.sub(" ", s)
    return s


def fingerprint_from_parts(
    source: str,
    asset: str,
    title: str,
    cwe: Iterable[str] | None = None,
) -> str:
    """Compute a stable fingerprint from raw parts."""

    parts = [
        _norm(source),
        _norm(asset),
        _norm(title),
        ",".join(sorted({_norm(c) for c in (cwe or []) if c})),
    ]
    payload = "|".join(parts).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def fingerprint_finding(f: Finding) -> str:
    """Compute (or recompute) the fingerprint of a Finding."""

    fp = fingerprint_from_parts(
        f.source,
        f.asset,
        f.title,
        f.cwe,
    )
    if not f.fingerprint:
        # Pydantic v2: avoid recursion through field validator.
        object.__setattr__(f, "fingerprint", fp)
    return fp