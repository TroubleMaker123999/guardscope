"""Risk scoring and sorting.

Risk score combines:

* severity rank (critical=5 .. unknown=0)
* confidence rank (high=3 .. low=1)
* CVSS (0..10)
* duplicate count (more occurrences → higher attention)

The combined score is a float; ``risk_sort`` returns findings in descending
risk order.
"""

from __future__ import annotations

from typing import List

from .models import Confidence, Finding, Severity
from .normalize import SEVERITY_RANK

_CONF_RANK = {
    Confidence.HIGH: 3,
    Confidence.MEDIUM: 2,
    Confidence.LOW: 1,
}


def risk_score(f: Finding) -> float:
    """Compute a composite risk score for a finding."""

    sev = SEVERITY_RANK.get(f.severity, 0)
    conf = _CONF_RANK.get(f.confidence, 2)
    cvss = max(0.0, min(10.0, float(f.cvss or 0.0)))
    dup = float(getattr(f, "duplicate_count", 1) or 1)
    return round(sev * 5.0 + conf * 2.0 + cvss * 1.0 + (dup - 1) * 1.5, 3)


def risk_sort(findings: List[Finding]) -> List[Finding]:
    """Return findings sorted by risk score (descending)."""

    return sorted(findings, key=risk_score, reverse=True)