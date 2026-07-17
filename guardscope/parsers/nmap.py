"""Nmap XML parser.

Parses ``<nmaprun>``/``<host>``/``<port>`` output using the Python standard
library only. For each open port a low/info-severity finding is generated with
the service banner (if any) as evidence.
"""

from __future__ import annotations

import xml.etree.ElementTree as ET
from typing import List

from ..core.fingerprint import fingerprint_finding
from ..core.models import Confidence, Finding, Severity
from ..core.normalize import normalize_severity
from .base import ParseError, Parser


class NmapParser:
    name = "nmap"
    description = "Nmap XML report (<nmaprun>) parser"

    def parse(self, text: str) -> List[Finding]:  # noqa: D401
        if not text or "<nmaprun" not in text:
            raise ParseError("Not an Nmap XML document")
        try:
            root = ET.fromstring(text)
        except ET.ParseError as exc:
            raise ParseError(f"Invalid XML: {exc}") from exc

        findings: List[Finding] = []
        for host in root.findall("host"):
            addr_el = host.find("address")
            host_ip = addr_el.get("addr") if addr_el is not None else "unknown"
            for port in host.findall("ports/port"):
                port_id = port.get("portid") or "0"
                protocol = port.get("protocol") or "tcp"
                state_el = port.find("state")
                state = state_el.get("state") if state_el is not None else "unknown"
                service_el = port.find("service")
                svc_name = service_el.get("name") if service_el is not None else ""
                svc_product = service_el.get("product") if service_el is not None else ""
                svc_version = service_el.get("version") if service_el is not None else ""

                title = f"Open port {port_id}/{protocol} on {host_ip}"
                description_bits = [
                    f"State: {state}",
                    f"Service: {svc_name or 'unknown'}",
                ]
                if svc_product:
                    description_bits.append(f"Product: {svc_product}")
                if svc_version:
                    description_bits.append(f"Version: {svc_version}")

                evidence = f"{host_ip}:{port_id}/{protocol} {state} {svc_name} {svc_product} {svc_version}".strip()

                sev = Severity.INFO
                if svc_name in {"telnet", "ftp", "rsh", "rlogin"}:
                    sev = Severity.MEDIUM

                findings.append(
                    Finding(
                        title=title,
                        description="; ".join(description_bits),
                        severity=sev,
                        confidence=Confidence.HIGH,
                        cvss=0.0 if sev == Severity.INFO else 5.0,
                        source="nmap",
                        asset=f"{host_ip}:{port_id}/{protocol}",
                        evidence=evidence,
                        remediation="Close or restrict the port if it is not required; restrict source addresses; require TLS where applicable.",
                    )
                )
                fingerprint_finding(findings[-1])
        return findings