"""Bandit JSON parser.

Bandit's report has shape:

.. code-block:: json

    {
      "results": [
        {
          "test_id": "B105",
          "test_name": "hardcoded_password_string",
          "issue_severity": "MEDIUM",
          "issue_confidence": "HIGH",
          "filename": "app.py",
          "line_number": 12,
          "code": "password = '...'",
          "issue_cwe": {"id": 259, "link": "..."},
          "issue_text": "..."
        }
      ]
    }
"""

from __future__ import annotations

import json
from typing import Any, Dict, List

from ..core.fingerprint import fingerprint_finding
from ..core.models import Confidence, Finding
from ..core.normalize import map_cwe, normalize_confidence, normalize_severity
from .base import ParseError, Parser


class BanditParser:
    name = "bandit"
    description = "Bandit (Python security) JSON parser"

    def parse(self, text: str) -> List[Finding]:
        try:
            data = json.loads(text)
        except json.JSONDecodeError as exc:
            raise ParseError(f"Invalid JSON: {exc}") from exc
        if not isinstance(data, dict) or "results" not in data:
            raise ParseError("Not a Bandit JSON document")

        findings: List[Finding] = []
        for r in data.get("results", []) or []:
            sev = normalize_severity(r.get("issue_severity"))
            conf = normalize_confidence(r.get("issue_confidence"))
            cwe_field = r.get("issue_cwe") or {}
            if isinstance(cwe_field, dict):
                cwe_id = cwe_field.get("id") or cwe_field.get("link")
            else:
                cwe_id = cwe_field
            cwe = map_cwe(cwe_id)
            if not cwe and cwe_id:
                cwe = ["CWE-" + str(cwe_id)]

            filename = r.get("filename") or ""
            line = r.get("line_number") or ""
            asset = f"{filename}:{line}" if filename else ""
            code = r.get("code") or ""
            evidence = code if code else r.get("issue_text") or ""

            f = Finding(
                title=f"{r.get('test_name') or r.get('test_id') or 'Bandit finding'}",
                description=str(r.get("issue_text") or ""),
                severity=sev,
                confidence=conf,
                source="bandit",
                asset=asset,
                evidence=evidence,
                remediation="Review the flagged code; replace hardcoded secrets with environment lookups; validate inputs; see Bandit docs.",
                cwe=cwe,
            )
            fingerprint_finding(f)
            findings.append(f)
        return findings