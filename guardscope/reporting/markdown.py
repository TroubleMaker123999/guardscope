"""Markdown report renderer."""

from __future__ import annotations

from datetime import datetime, timezone
from io import StringIO
from typing import Iterable

from ..core.models import Finding, Severity

_SEVERITY_BADGES = {
    Severity.CRITICAL: "[CRITICAL]",
    Severity.HIGH: "[HIGH]",
    Severity.MEDIUM: "[MEDIUM]",
    Severity.LOW: "[LOW]",
    Severity.INFO: "[INFO]",
    Severity.UNKNOWN: "[UNKNOWN]",
}


def render_markdown(findings: Iterable[Finding], *, title: str = "GuardScope Report") -> str:
    findings = list(findings)
    by_sev: dict[str, int] = {}
    for f in findings:
        by_sev[f.severity.value] = by_sev.get(f.severity.value, 0) + 1

    out = StringIO()
    out.write(f"# {title}\n\n")
    out.write(f"_Generated at {datetime.now(timezone.utc).isoformat(timespec='seconds')}_\n\n")
    out.write("## Summary\n\n")
    if not findings:
        out.write("No findings.\n\n")
    else:
        out.write("| Severity | Count |\n|---|---|\n")
        for sev in ("critical", "high", "medium", "low", "info", "unknown"):
            if by_sev.get(sev):
                out.write(f"| {sev.capitalize()} | {by_sev[sev]} |\n")
        out.write(f"\n**Total: {len(findings)}**\n\n")

    out.write("## Findings\n\n")
    for i, f in enumerate(findings, 1):
        badge = _SEVERITY_BADGES.get(f.severity, "[UNKNOWN]")
        out.write(f"### {i}. {badge} {f.title or 'Untitled finding'}\n\n")
        out.write(f"- **ID**: `{f.id}`\n")
        out.write(f"- **Fingerprint**: `{f.fingerprint[:16]}…`\n")
        out.write(f"- **Source**: `{f.source}`\n")
        out.write(f"- **Asset**: `{f.asset}`\n")
        out.write(f"- **Severity**: `{f.severity.value}`\n")
        out.write(f"- **Confidence**: `{f.confidence.value}`\n")
        out.write(f"- **CVSS**: `{f.cvss:.1f}`\n")
        if f.cwe:
            out.write(f"- **CWE**: {', '.join(f.cwe)}\n")
        if f.owasp:
            out.write(f"- **OWASP**: {', '.join(f.owasp)}\n")
        if f.description:
            out.write(f"\n{f.description}\n\n")
        if f.evidence:
            out.write("**Evidence**\n\n```\n" + f.evidence.strip() + "\n```\n\n")
        if f.remediation:
            out.write(f"**Remediation**: {f.remediation}\n\n")
        out.write("---\n\n")
    return out.getvalue()