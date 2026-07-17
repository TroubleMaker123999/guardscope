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
        port=13000,
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
    # NOTE: vuln-node was originally planned but its source image on
    # ghcr.io is access-controlled (401 Unauthorized). It is parked in
    # ``offensive/lab_targets/compose.disabled/`` so we don't lose the
    # recipe and it stays out of the active catalog.
)
