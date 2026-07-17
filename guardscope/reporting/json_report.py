"""JSON report renderer."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Iterable

from ..core.models import Finding


def render_json(findings: Iterable[Finding], *, title: str = "GuardScope Report") -> str:
    findings = list(findings)
    counts: dict[str, int] = {}
    for f in findings:
        counts[f.severity.value] = counts.get(f.severity.value, 0) + 1

    return json.dumps(
        {
            "title": title,
            "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "summary": counts,
            "total": len(findings),
            "findings": [f.to_dict() for f in findings],
        },
        indent=2,
        sort_keys=False,
    )