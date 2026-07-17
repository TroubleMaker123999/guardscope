"""SARIF 2.1.0 report renderer.

We emit a minimal but spec-conformant SARIF document. Findings map to SARIF
``results``; severity to ``level``; a default rule is synthesized from the
fingerprint so each finding has a stable ``ruleId``.
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from typing import Iterable

from ..core.models import Finding, Severity

_SEVERITY_TO_LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "warning",
    Severity.INFO: "note",
    Severity.UNKNOWN: "none",
}

_SEVERITY_TO_TAG = {
    Severity.CRITICAL: "security-severity:9.5",
    Severity.HIGH: "security-severity:7.5",
    Severity.MEDIUM: "security-severity:5.0",
    Severity.LOW: "security-severity:3.0",
    Severity.INFO: "security-severity:1.0",
    Severity.UNKNOWN: "security-severity:0.0",
}


def render_sarif(findings: Iterable[Finding], *, title: str = "GuardScope Report") -> str:
    findings = list(findings)
    rules = []
    results = []
    seen_rule_ids: set[str] = set()

    for f in findings:
        rid = f.fingerprint[:16] or "unknown"
        if rid not in seen_rule_ids:
            seen_rule_ids.add(rid)
            rules.append(
                {
                    "id": rid,
                    "name": (f.title or "finding")[:64],
                    "shortDescription": {"text": f.title or "Finding"},
                    "fullDescription": {"text": f.description or ""},
                    "defaultConfiguration": {"level": _SEVERITY_TO_LEVEL.get(f.severity, "none")},
                    "properties": {
                        "tags": [_SEVERITY_TO_TAG.get(f.severity, "security-severity:0.0")],
                        "security-severity": f"{f.cvss:.1f}",
                        "cwe": f.cwe,
                    },
                }
            )
        loc: dict = {}
        if f.asset:
            loc = {
                "physicalLocation": {
                    "artifactLocation": {"uri": f.asset},
                }
            }
        results.append(
            {
                "ruleId": rid,
                "level": _SEVERITY_TO_LEVEL.get(f.severity, "none"),
                "message": {"text": f.description or f.title or ""},
                "locations": [loc] if loc else [],
                "properties": {
                    "security-severity": f"{f.cvss:.1f}",
                    "confidence": f.confidence.value,
                    "source": f.source,
                    "fingerprint": f.fingerprint,
                },
            }
        )

    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "guardscope",
                        "version": "0.1.0",
                        "informationUri": "https://example.invalid/guardscope",
                        "rules": rules,
                    }
                },
                "invocations": [
                    {
                        "executionSuccessful": True,
                        "endTimeUtc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                    }
                ],
                "results": results,
                "properties": {"title": title},
            }
        ],
    }
    return json.dumps(sarif, indent=2)