"""pip-audit JSON parser.

pip-audit's ``--format json`` output is a JSON array of dependency objects:

.. code-block:: json

    [
      {
        "name": "requests",
        "version": "2.20.0",
        "vulns": [
          {
            "id": "PYSEC-2023-74",
            "fix_versions": ["2.31.0"],
            "description": "...",
            "aliases": ["CVE-2023-32681"],
            "cwe": {"id": "CWE-20"}
          }
        ]
      }
    ]
"""

from __future__ import annotations

import json
from typing import Any, Dict, List

from ..core.fingerprint import fingerprint_finding
from ..core.models import Confidence, Finding
from ..core.normalize import map_cwe
from .base import ParseError, Parser


_SEV_BY_ALIAS = {
    "critical": "critical",
    "high": "high",
    "moderate": "medium",
    "medium": "medium",
    "low": "low",
    "info": "info",
    "informational": "info",
}


class PipAuditParser:
    name = "pipaudit"
    description = "pip-audit JSON parser"

    def parse(self, text: str) -> List[Finding]:
        try:
            data = json.loads(text)
        except json.JSONDecodeError as exc:
            raise ParseError(f"Invalid JSON: {exc}") from exc

        deps: List[Dict[str, Any]]
        if isinstance(data, dict) and "dependencies" in data:
            deps = data["dependencies"]
        elif isinstance(data, list):
            deps = data
        else:
            raise ParseError("Unrecognized pip-audit JSON shape")

        from ..core.normalize import normalize_severity, Severity  # local import to avoid cycle

        findings: List[Finding] = []
        for d in deps:
            name = d.get("name") or ""
            version = d.get("version") or ""
            for v in d.get("vulns") or []:
                aliases = v.get("aliases") or []
                cwe_field = v.get("cwe") or {}
                if isinstance(cwe_field, dict):
                    cwe_ids = cwe_field.get("id")
                else:
                    cwe_ids = cwe_field
                cwe = map_cwe(cwe_ids)
                fix_versions = v.get("fix_versions") or v.get("fix_versions") or []

                vid = v.get("id") or (aliases[0] if aliases else "")
                sev_raw = (v.get("severity") or "").lower() if isinstance(v.get("severity"), str) else ""
                sev = normalize_severity(_SEV_BY_ALIAS.get(sev_raw, v.get("severity")))

                cvss = 0.0
                cvss_data = v.get("cvss") or {}
                if isinstance(cvss_data, dict):
                    for k, val in cvss_data.items():
                        try:
                            cvss = float(val)
                            break
                        except (TypeError, ValueError):
                            continue
                elif isinstance(cvss_data, (int, float)):
                    cvss = float(cvss_data)

                title = f"{name} {version}: {vid}" if name else str(vid)
                asset = f"{name}@{version}" if name else str(vid)
                remediation = (
                    f"Upgrade {name} to {' / '.join(fix_versions)}" if fix_versions else "Upgrade the package to a fixed version."
                )
                evidence = f"{vid} aliases={','.join(aliases)} fix={','.join(fix_versions)}"

                f = Finding(
                    title=title,
                    description=str(v.get("description") or ""),
                    severity=sev,
                    confidence=Confidence.HIGH,
                    cvss=cvss,
                    source="pip-audit",
                    asset=asset,
                    evidence=evidence,
                    remediation=remediation,
                    cwe=cwe,
                )
                fingerprint_finding(f)
                findings.append(f)
        return findings