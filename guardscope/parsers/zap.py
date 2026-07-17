"""OWASP ZAP JSON parser.

ZAP's ``report.json`` shape (subset):

.. code-block:: json

    {
      "site": [
        {
          "@host": "127.0.0.1",
          "@port": "8080",
          "alerts": [
            {
              "pluginid": "10202",
              "name": "Absence of Anti-CSRF Tokens",
              "riskcode": "2",
              "confidence": "2",
              "riskdesc": "Medium (Medium)",
              "desc": "...",
              "uri": "http://127.0.0.1:8080/",
              "solution": "...",
              "cweid": "352",
              "wascid": "9",
              "reference": "...",
              "evidence": "..."
            }
          ]
        }
      ]
    }

The parser also accepts a flat list-of-alerts variant. Missing fields are
tolerated.
"""

from __future__ import annotations

import json
from typing import Any, Dict, Iterable, List

from ..core.fingerprint import fingerprint_finding
from ..core.models import Confidence, Finding
from ..core.normalize import map_cwe, normalize_confidence, normalize_severity
from .base import ParseError, Parser


def _risk_to_severity(riskcode: Any, riskdesc: Any = None):
    """Map ZAP riskcode → Severity.

    ZAP uses: 0=Informational, 1=Low, 2=Medium, 3=High, 4=Critical (newer).
    Some builds use 1=High, 2=Medium, 3=Low, 4=Informational (legacy).
    """

    try:
        rc = int(str(riskcode))
    except (TypeError, ValueError):
        return normalize_severity(riskdesc)
    # Newer convention first
    new = {0: "info", 1: "low", 2: "medium", 3: "high", 4: "critical"}
    if rc in new:
        return normalize_severity(new[rc])
    return normalize_severity(riskdesc)


class ZapParser:
    name = "zap"
    description = "OWASP ZAP JSON report parser"

    def parse(self, text: str) -> List[Finding]:
        try:
            data = json.loads(text)
        except json.JSONDecodeError as exc:
            raise ParseError(f"Invalid JSON: {exc}") from exc

        findings: List[Finding] = []
        alerts: Iterable[Dict[str, Any]] = []

        if isinstance(data, dict) and "site" in data:
            for site in data.get("site", []) or []:
                host = site.get("@host") or site.get("host") or ""
                port = site.get("@port") or site.get("port") or ""
                for alert in site.get("alerts", []) or []:
                    alert = dict(alert)
                    alert.setdefault("_host", host)
                    alert.setdefault("_port", port)
                    alerts = [*alerts, alert]
        elif isinstance(data, list):
            alerts = data
        elif isinstance(data, dict) and "alerts" in data:
            alerts = data["alerts"]
        else:
            raise ParseError("Unrecognized ZAP JSON shape")

        for a in alerts:
            host = a.get("_host") or a.get("host") or ""
            port = a.get("_port") or a.get("port") or ""
            uri = a.get("uri") or ""
            name = a.get("name") or a.get("alert") or "ZAP finding"
            desc = a.get("desc") or a.get("description") or ""
            riskcode = a.get("riskcode") or a.get("risk") or a.get("riskdesc")
            riskdesc = a.get("riskdesc") or a.get("risk")
            conf_raw = a.get("confidence") or a.get("confidenceDesc")
            solution = a.get("solution") or a.get("remediation") or ""
            evidence = a.get("evidence") or a.get("otherinfo") or ""
            cweid = a.get("cweid") or a.get("cwe")
            pluginid = a.get("pluginid") or a.get("id") or ""

            sev = _risk_to_severity(riskcode, riskdesc)
            conf = normalize_confidence(conf_raw)
            cwe = map_cwe(cweid) or (["CWE-" + str(cweid)] if cweid else [])

            asset = uri or (f"{host}:{port}" if host else "")

            f = Finding(
                title=name,
                description=desc,
                severity=sev,
                confidence=conf,
                source="zap",
                asset=asset,
                evidence=evidence,
                remediation=solution,
                cwe=cwe,
            )
            if pluginid:
                f.title = f"[ZAP-{pluginid}] " + f.title
            fingerprint_finding(f)
            findings.append(f)

        return findings