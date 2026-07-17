"""Trivy JSON parser.

Trivy (image/filesystem/iac) scan output:

.. code-block:: json

    {
      "ArtifactName": "alpine:3.18",
      "Results": [
        {
          "Target": "alpine:3.18 (alpine 3.18.4)",
          "Class": "os-pkgs",
          "Type": "alpine",
          "Vulnerabilities": [
            {
              "VulnerabilityID": "CVE-2023-...",
              "PkgName": "openssl",
              "InstalledVersion": "1.1.1k",
              "FixedVersion": "1.1.1l",
              "Severity": "HIGH",
              "Title": "openssl: ...",
              "Description": "...",
              "CweIDs": ["CWE-310"]
            }
          ]
        }
      ]
    }
"""

from __future__ import annotations

import json
from typing import Any, Dict, List

from ..core.fingerprint import fingerprint_finding
from ..core.models import Confidence, Finding
from ..core.normalize import map_cwe, normalize_severity
from .base import ParseError, Parser


class TrivyParser:
    name = "trivy"
    description = "Trivy (image / fs / iac) JSON parser"

    def parse(self, text: str) -> List[Finding]:
        try:
            data = json.loads(text)
        except json.JSONDecodeError as exc:
            raise ParseError(f"Invalid JSON: {exc}") from exc

        results = data.get("Results") if isinstance(data, dict) else None
        if results is None:
            raise ParseError("Not a Trivy JSON document (no 'Results')")

        artifact = data.get("ArtifactName") or ""
        findings: List[Finding] = []
        for r in results:
            target = r.get("Target") or artifact
            rclass = r.get("Class") or "unknown"
            for v in r.get("Vulnerabilities") or []:
                sev = normalize_severity(v.get("Severity"))
                cwe = map_cwe(v.get("CweIDs") or v.get("CWE"))
                pkg = v.get("PkgName") or ""
                installed = v.get("InstalledVersion") or ""
                fixed = v.get("FixedVersion") or ""
                vid = v.get("VulnerabilityID") or ""
                title = v.get("Title") or v.get("Summary") or f"{vid} {pkg}"
                asset = f"{target} :: {pkg}@{installed}" if pkg else target
                evidence = (
                    f"{vid} severity={sev.value} pkg={pkg} installed={installed} fixed={fixed}"
                )
                remediation = f"Upgrade {pkg} to {fixed or 'the fixed version'}" if pkg else "Apply the vendor fix."

                f = Finding(
                    title=str(title),
                    description=str(v.get("Description") or ""),
                    severity=sev,
                    confidence=Confidence.HIGH,
                    source="trivy",
                    asset=asset,
                    evidence=evidence,
                    remediation=remediation,
                    cwe=cwe,
                )
                if vid:
                    f.title = f"[{vid}] " + f.title
                fingerprint_finding(f)
                findings.append(f)
        return findings