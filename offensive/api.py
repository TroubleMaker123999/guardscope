"""HTTP API for the offensive module.

Mounted by :func:`guardscope.api.app.create_app` under the
``/offensive/*`` prefix. Every endpoint that triggers a runner routes through
:mod:`offensive.scope_guard`, so the loopback + registered-lab + rate-limit
checks cannot be bypassed by talking to HTTP instead of the CLI.

The endpoints are intentionally narrow:

* :func:`availability` reports which of the four external tools (Nmap, Hydra,
  sqlmap, Nuclei) are installed so the frontend can disable controls.
* :func:`list_labs` returns the curated lab catalog (host/port/description)
  so the UI can suggest targets.
* :func:`scan` / :func:`brute` / :func:`sqli` / :func:`nuclei` kick off one
  attack run synchronously and return a structured summary.
* :func:`list_runs` reads the audit DB so the UI can render a history
  without reaching into the filesystem.
"""

from __future__ import annotations

import json
import re
import shutil
from pathlib import Path
from typing import List, Optional

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from . import audit
from .hydra_runner import (
    ALLOWED_SERVICES as HYDRA_SERVICES,
    run_bruteforce,
)
from .nmap_runner import (
    ALLOWED_SCAN_TYPES,
    ALLOWED_SCRIPT_CATEGORIES,
    run_scan as nmap_run_scan,
)
from .nuclei_runner import (
    ALLOWED_TEMPLATE_CATEGORIES,
    is_available as nuclei_available,
    run_scan as nuclei_run_scan,
)
from .registry import LAB_TARGETS
from .scope_guard import ScopeViolation
from .sqlmap_runner import run_sqlmap


router = APIRouter(prefix="/offensive", tags=["offensive"])


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------


class AvailabilityOut(BaseModel):
    nmap: bool
    hydra: bool
    sqlmap: bool
    nuclei: bool


class LabTargetOut(BaseModel):
    key: str
    name: str
    host: str
    port: int
    description: str
    compose_file: str


class NmapScanIn(BaseModel):
    target: str = Field(..., description="loopback host, optionally host:port")
    ports: str = Field("1-1024", description="nmap port spec")
    scan_type: str = Field("-sV", description="-sT or -sV")
    scripts: List[str] = Field(default_factory=list)


class HydraBruteIn(BaseModel):
    target: str
    service: str
    username: str
    wordlist_path: str
    port: Optional[int] = None
    throttle: int = 4


class SqlmapIn(BaseModel):
    target: str
    url: str
    level: int = 1
    risk: int = 1


class NucleiIn(BaseModel):
    target: str
    url: str
    categories: List[str] = Field(default_factory=list)


class RunOut(BaseModel):
    ok: bool
    tool: str
    target: str
    summary: str
    output_path: Optional[str] = None
    injectable: Optional[bool] = None
    matched: Optional[int] = None


class AuditEntryOut(BaseModel):
    id: str
    timestamp: float
    actor: str
    action: str
    target: str
    exit_code: Optional[int]
    summary: str


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _offensive_out_dir() -> Path:
    """Per-request output directory; relative to the API working directory."""

    path = Path("./offensive-reports")
    path.mkdir(parents=True, exist_ok=True)
    return path


def _wrap(action: str, runner, **kwargs) -> RunOut:
    """Run a runner, translate :class:`ScopeViolation` to HTTP 400."""

    try:
        result = runner(**kwargs)
    except ScopeViolation as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except FileNotFoundError as exc:
        raise HTTPException(status_code=412, detail=str(exc)) from exc
    except subprocess.TimeoutExpired as exc:  # type: ignore[name-defined]
        raise HTTPException(
            status_code=504, detail=f"tool timed out: {exc}"
        ) from exc

    output_path = getattr(result, "xml_path", None) or getattr(
        result, "log_path", None
    ) or getattr(result, "stdout_path", None) or getattr(result, "jsonl_path", None)
    return RunOut(
        ok=True,
        tool=action,
        target=getattr(result, "target", kwargs.get("target", "")),
        summary=getattr(result, "summary", ""),
        output_path=str(output_path) if output_path else None,
        injectable=getattr(result, "injectable", None),
        matched=getattr(result, "matched", None),
    )


# `subprocess` is imported lazily so `import offensive.api` doesn't drag the
# runner modules into anything that just wants the routers.
import subprocess  # noqa: E402  (intentional lazy import)


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.get("/availability", response_model=AvailabilityOut)
def availability() -> AvailabilityOut:
    """Which of the four optional binaries are present."""

    return AvailabilityOut(
        nmap=shutil.which("nmap") is not None,
        hydra=shutil.which("hydra") is not None,
        sqlmap=shutil.which("sqlmap") is not None,
        nuclei=nuclei_available(),
    )


@router.get("/labs", response_model=List[LabTargetOut])
def list_labs() -> List[LabTargetOut]:
    """Static lab catalog (not the registry)."""

    return [
        LabTargetOut(
            key=t.key,
            name=t.name,
            host=t.host,
            port=t.port,
            description=t.description,
            compose_file=t.compose_file,
        )
        for t in LAB_TARGETS
    ]


@router.post("/scan", response_model=RunOut)
def scan(body: NmapScanIn) -> RunOut:
    """Run an Nmap scan (loopback + lab-registered)."""

    if body.scan_type not in ALLOWED_SCAN_TYPES:
        raise HTTPException(
            status_code=400,
            detail=(
                f"scan_type {body.scan_type!r} not allowed; "
                f"use one of {sorted(ALLOWED_SCAN_TYPES)}"
            ),
        )
    return _wrap(
        "nmap",
        nmap_run_scan,
        target=body.target,
        ports=body.ports,
        scan_type=body.scan_type,
        scripts=body.scripts or None,
        out_dir=_offensive_out_dir(),
    )


@router.post("/brute", response_model=RunOut)
def brute(body: HydraBruteIn) -> RunOut:
    """Online credential test against a loopback service."""

    if body.service not in HYDRA_SERVICES:
        raise HTTPException(
            status_code=400,
            detail=f"service {body.service!r} not in allowlist {sorted(HYDRA_SERVICES)}",
        )
    return _wrap(
        "hydra",
        run_bruteforce,
        target=body.target,
        service=body.service,
        username=body.username,
        wordlist=Path(body.wordlist_path),
        port=body.port,
        throttle=body.throttle,
        out_dir=_offensive_out_dir(),
    )


@router.post("/sqli", response_model=RunOut)
def sqli(body: SqlmapIn) -> RunOut:
    """Run sqlmap against a loopback URL."""

    if body.level < 1 or body.level > 2:
        raise HTTPException(
            status_code=400, detail="sqlmap level must be 1 or 2"
        )
    if body.risk < 1 or body.risk > 2:
        raise HTTPException(
            status_code=400, detail="sqlmap risk must be 1 or 2"
        )
    return _wrap(
        "sqlmap",
        run_sqlmap,
        target=body.target,
        url=body.url,
        level=body.level,
        risk=body.risk,
        out_dir=_offensive_out_dir(),
    )


@router.post("/nuclei", response_model=RunOut)
def nuclei(body: NucleiIn) -> RunOut:
    """Run Nuclei (requires the binary; else HTTP 412)."""

    if not nuclei_available():
        raise HTTPException(
            status_code=412,
            detail="nuclei binary not installed on this host",
        )
    for cat in body.categories:
        if cat not in ALLOWED_TEMPLATE_CATEGORIES:
            raise HTTPException(
                status_code=400,
                detail=(
                    f"category {cat!r} not in allowlist "
                    f"{sorted(ALLOWED_TEMPLATE_CATEGORIES)}"
                ),
            )
    return _wrap(
        "nuclei",
        nuclei_run_scan,
        target=body.target,
        url=body.url,
        categories=body.categories or None,
        out_dir=_offensive_out_dir(),
    )


@router.get("/runs", response_model=List[AuditEntryOut])
def list_runs(limit: int = 50) -> List[AuditEntryOut]:
    """Recent attack invocations from the audit log."""

    limit = max(1, min(limit, 500))
    rows = audit.latest(limit=limit)
    # Filter to *offensive* actions only — they all share the `nmap.`,
    # `hydra.`, `sqlmap.`, or `nuclei.` prefix.
    pat = re.compile(r"^(nmap|hydra|sqlmap|nuclei)\.")
    return [
        AuditEntryOut(
            id=r.id,
            timestamp=r.timestamp,
            actor=r.actor,
            action=r.action,
            target=r.target,
            exit_code=r.exit_code,
            summary=r.summary,
        )
        for r in rows
        if pat.match(r.action)
    ]
