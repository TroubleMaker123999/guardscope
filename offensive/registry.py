"""Static catalog of lab targets checked into this repo.

Read by the CLI's ``lab list`` command; no network or filesystem access.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class LabTarget:
    key: str
    name: str
    host: str
    port: int
    description: str
    compose_file: str  # path relative to repo root


LAB_TARGETS: tuple[LabTarget, ...] = (
    LabTarget(
        key="juice-shop",
        name="juice-shop",
        host="127.0.0.1",
        port=3000,
        description="OWASP Juice Shop, modern web vulns.",
        compose_file="offensive/lab_targets/compose/juice-shop.yml",
    ),
    LabTarget(
        key="dvwa",
        name="dvwa",
        host="127.0.0.1",
        port=8081,
        description="Damn Vulnerable Web Application (security=low).",
        compose_file="offensive/lab_targets/compose/dvwa.yml",
    ),
    LabTarget(
        key="vuln-node",
        name="vuln-node",
        host="127.0.0.1",
        port=3001,
        description="Vulnerable Node.js app for SSRF / prototype pollution.",
        compose_file="offensive/lab_targets/compose/vuln-node.yml",
    ),
)
