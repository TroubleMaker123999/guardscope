"""Semgrep JSON parser.

Semgrep's ``--json`` output:

.. code-block:: json

    {
      "results": [
        {
          "check_id": "python.lang.security.audit.eval",
          "path": "app.py",
          "start": {"line": 10},
          "end":   {"line": 10},
          "extra": {
            "severity": "WARNING",
            "message": "Detected eval() ...",
            "metadata": {"cwe": ["CWE-95"]}
          }
        }
      ]
    }
"""

from __future__ import annotations

import json
from typing import Any, Dict, List

from ..core.fingerprint import fingerprint_finding
from ..core.models import Confidence, Finding
from ..core.normalize import map_cwe, map_owasp, normalize_severity
from .base import ParseError, Parser


class SemgrepParser:
    name = "semgrep"
    description = "Semgrep JSON parser"

    _SEV = {
        "INFO": "info",
        "WARNING": "medium",
        "ERROR": "high",
        "CRITICAL": "critical",
    }

    def parse(self, text: str) -> List[Finding]:
        try:
            data = json.loads(text)
        except json.JSONDecodeError as exc:
            raise ParseError(f"Invalid JSON: {exc}") from exc

        results: List[Dict[str, Any]] = []
        if isinstance(data, list):
            results = data
        elif isinstance(data, dict) and "results" in data:
            results = data.get("results") or []
        else:
            raise ParseError("Unrecognized Semgrep JSON shape")

        findings: List[Finding] = []
        for r in results:
            extra = r.get("extra") or {}
            sev_raw = extra.get("severity") or r.get("severity")
            sev = normalize_severity(self._SEV.get(str(sev_raw).upper(), sev_raw))

            metadata = extra.get("metadata") or {}
            cwe = map_cwe(metadata.get("cwe") or metadata.get("cwe2022-top25"))
            owasp = map_owasp(metadata.get("owasp") or metadata.get("owasp-web") or "")
            short_msg = extra.get("short_message") or metadata.get("short_description")
            message = extra.get("message") or short_msg or ""

            path = r.get("path") or ""
            start = r.get("start") or {}
            line = start.get("line") or ""
            asset = f"{path}:{line}" if path else ""

            snippet = (extra.get("lines") or "").strip()

            f = Finding(
                title=str(r.get("check_id") or "semgrep finding"),
                description=str(message),
                severity=sev,
                confidence=Confidence.MEDIUM,
                source="semgrep",
                asset=asset,
                evidence=snippet,
                remediation="See the Semgrep rule documentation linked from check_id.",
                cwe=cwe,
                owasp=owasp,
            )
            fingerprint_finding(f)
            findings.append(f)
        return findings