"""Generic SARIF 2.1.0 parser.

Only stdlib JSON. The parser walks ``runs[*].results[*]`` and converts each
``result`` into a :class:`Finding`. SARIF ``level`` is mapped to severity,
``properties.tags`` and ``properties.cwe`` are inspected for CWE / OWASP.
"""

from __future__ import annotations

import json
from typing import Any, Dict, List

from ..core.fingerprint import fingerprint_finding
from ..core.models import Confidence, Finding
from ..core.normalize import map_cwe, map_owasp, normalize_confidence, normalize_severity
from .base import ParseError, Parser


_LEVEL_MAP = {
    "error": "high",
    "warning": "medium",
    "note": "low",
    "none": "info",
}


class SarifParser:
    name = "sarif"
    description = "Generic SARIF 2.1.0 JSON parser"

    def parse(self, text: str) -> List[Finding]:
        try:
            data = json.loads(text)
        except json.JSONDecodeError as exc:
            raise ParseError(f"Invalid JSON: {exc}") from exc

        if not isinstance(data, dict) or "runs" not in data:
            raise ParseError("Not a SARIF document (missing 'runs')")

        findings: List[Finding] = []
        for run in data.get("runs", []) or []:
            tool = (run.get("tool") or {}).get("driver") or {}
            tool_name = tool.get("name") or "sarif"
            rules = {r.get("id"): r for r in (tool.get("rules") or [])}
            for r in run.get("results", []) or []:
                rule_id = r.get("ruleId") or ""
                rule = rules.get(rule_id) or {}
                rule_desc = rule.get("shortDescription") or rule.get("fullDescription") or {}
                rule_text = (
                    rule_desc.get("text")
                    if isinstance(rule_desc, dict)
                    else str(rule_desc)
                ) or rule_id
                msg = r.get("message") or {}
                msg_text = msg.get("text") if isinstance(msg, dict) else str(msg)

                level = r.get("level") or rule.get("defaultConfiguration", {}).get("level") or "warning"
                sev_str = _LEVEL_MAP.get(str(level).lower(), "medium")
                severity = normalize_severity(sev_str)

                # Location
                asset = ""
                locs = r.get("locations") or []
                if locs:
                    pl = locs[0].get("physicalLocation") or {}
                    art = pl.get("artifactLocation") or {}
                    uri = art.get("uri") or ""
                    region = pl.get("region") or {}
                    line = region.get("startLine") or ""
                    asset = f"{uri}:{line}" if uri else ""

                # Properties (CWE / OWASP / confidence)
                props: Dict[str, Any] = {}
                if isinstance(r.get("properties"), dict):
                    props.update(r["properties"])
                if isinstance(rule.get("properties"), dict):
                    props.update(rule["properties"])
                cwe = map_cwe(props.get("cwe") or props.get("cweId") or rule.get("properties", {}).get("cwe"))
                owasp = map_owasp(props.get("owasp") or props.get("security-severity") or "")
                if not owasp:
                    for tag in props.get("tags") or []:
                        owasp.extend(map_owasp(str(tag)))
                confidence = normalize_confidence(props.get("confidence"))

                sev_score = props.get("security-severity")
                cvss = 0.0
                if sev_score is not None:
                    try:
                        cvss = float(sev_score)
                    except (TypeError, ValueError):
                        cvss = 0.0

                f = Finding(
                    title=str(rule_text),
                    description=str(msg_text or ""),
                    severity=severity,
                    confidence=confidence,
                    cvss=cvss,
                    cwe=cwe,
                    owasp=owasp,
                    source=tool_name.lower(),
                    asset=asset,
                    evidence=str(msg_text or "")[:512],
                    remediation=str((rule.get("helpUri") or props.get("helpUri") or ""))[:512],
                )
                fingerprint_finding(f)
                findings.append(f)
        return findings