"""FastAPI HTTP API for GuardScope.

Exposes:

* ``GET  /health``         — liveness probe
* ``GET  /labs``           — list registered local labs
* ``POST /labs``           — register a new local lab (host must be local)
* ``GET  /scope/check``    — check whether a host is within scope
* ``GET  /findings``       — list findings (filters: severity, source)
* ``GET  /findings/{id}``  — fetch one finding (with evidence)
* ``POST /findings``       — create a finding
* ``DELETE /findings/{id}``— delete a finding
* ``POST /import``         — import a scanner report (multipart or JSON)
* ``POST /report``         — render a report (md/html/json/sarif)
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path as _Path
from typing import List, Optional

from fastapi import FastAPI, HTTPException, Query, Request, UploadFile, File, Form
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse, Response
from pydantic import BaseModel, Field

from .. import __version__
from ..core.db import (
    delete_finding,
    get_finding,
    init_db,
    list_evidence,
    list_findings,
    save_findings,
)
from ..core.dedupe import deduplicate
from ..core.fingerprint import fingerprint_finding
from ..core.models import Confidence, Finding, Severity
from ..core.scoring import risk_score, risk_sort
from ..lab.registry import Lab, LabRegistry
from ..lab.scope import ScopeError, assert_in_scope, is_local_host
from ..parsers.manager import dispatch
from ..plugins import run_plugins
from ..reporting import render_html, render_json, render_markdown, render_sarif


# ---------------------------------------------------------------------------
# Pydantic request/response models
# ---------------------------------------------------------------------------


class FindingIn(BaseModel):
    title: str
    description: str = ""
    severity: Severity = Severity.UNKNOWN
    confidence: Confidence = Confidence.MEDIUM
    cvss: float = 0.0
    cwe: List[str] = Field(default_factory=list)
    owasp: List[str] = Field(default_factory=list)
    source: str = "manual"
    asset: str = ""
    evidence: str = ""
    remediation: str = ""


class FindingOut(BaseModel):
    id: str
    fingerprint: str
    title: str
    description: str
    severity: str
    confidence: str
    cvss: float
    cwe: List[str]
    owasp: List[str]
    source: str
    asset: str
    evidence: str
    remediation: str
    created_at: str
    updated_at: str
    duplicate_count: int = 1


class LabIn(BaseModel):
    name: str
    host: str
    port: int
    description: str = ""


class LabOut(BaseModel):
    id: str
    name: str
    host: str
    port: int
    description: str = ""
    created_at: str = ""


class ImportResult(BaseModel):
    parser: str
    imported: int
    unique: int
    findings: List[FindingOut]


class ReportResponse(BaseModel):
    format: str
    body: str


# ---------------------------------------------------------------------------
# App factory
# ---------------------------------------------------------------------------


# Origins that must never be admitted to the CORS allow-list, even if an
# operator explicitly types them into the env. ``*`` would silently widen to
# any origin; the literal browser-origin ``null`` is a known smuggling
# target. Compared case-insensitively.
_FORBIDDEN_CORS_ORIGINS: frozenset[str] = frozenset({"*", "null"})


def _cors_origins_from_env() -> list[str]:
    """Resolve the CORS allow-list.

    Default is a strict loopback-only set suitable for the bundled Vite dev
    server. Operators may extend it via ``GUARDSCOPE_CORS_ORIGINS`` (a
    comma-separated list). The wildcard origin is never used by default,
    and ``*`` / the literal browser-origin ``null`` are also filtered out of
    the env-supplied list to prevent silent widening.
    """

    default_origins = [
        "http://127.0.0.1:5173",
        "http://localhost:5173",
    ]
    raw = os.environ.get("GUARDSCOPE_CORS_ORIGINS")
    if raw is None:
        return list(default_origins)
    extra: list[str] = []
    for piece in raw.split(","):
        o = piece.strip()
        if not o:
            continue
        if o.lower() in _FORBIDDEN_CORS_ORIGINS:
            continue
        extra.append(o)
    merged: list[str] = []
    seen: set[str] = set()
    for o in default_origins + extra:
        if o and o not in seen:
            merged.append(o)
            seen.add(o)
    return merged


def create_app(db_path: str | None = None) -> FastAPI:
    """Build a FastAPI app bound to the given SQLite database."""

    # The ``offensive`` package lives as a sibling top-level directory rather
    # than inside ``guardscope`` (so it stays out of the published Python
    # package). When the FastAPI factory is invoked by uvicorn with
    # ``factory=True`` the current working directory is not automatically on
    # ``sys.path``, so we add it here — but only if it's missing.
    cwd = _Path(os.getcwd()).resolve()
    cwd_str = str(cwd)
    if cwd_str not in sys.path:
        sys.path.insert(0, cwd_str)
    db = db_path or os.environ.get("GUARDSCOPE_DB") or "./guardscope.db"
    init_db(db)
    labs = LabRegistry(db)

    app = FastAPI(
        title="GuardScope",
        version=__version__,
        description="Defense-oriented, authorization-scoped vulnerability management.",
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=_cors_origins_from_env(),
        allow_credentials=False,
        allow_methods=["GET", "POST", "DELETE", "OPTIONS"],
        allow_headers=["Content-Type", "Accept"],
        max_age=600,
    )

    # ------------------------------------------------------------------ plugins
    # Mount the offensive HTTP API alongside the defensive one. The router
    # lives in a sibling top-level package (``offensive``) so importing it
    # here keeps `guardscope.api` free of any attack-tool imports.
    try:
        from offensive.api import router as offensive_router

        app.include_router(offensive_router)
    except ImportError as exc:
        # The offensive package is optional; if it's not installed for any
        # reason, the defensive surface still works. We log so the operator
        # can diagnose why /offensive/* endpoints return 404.
        import logging

        logging.getLogger("guardscope.api").warning(
            "offensive module not mounted: %s", exc
        )
        offensive_router = None  # type: ignore[assignment]  # noqa: F841

    # ------------------------------------------------------------------ helpers
    def _to_out(f: Finding, dup: int = 1) -> FindingOut:
        d = f.to_dict()
        d["duplicate_count"] = dup
        return FindingOut(**d)

    # ------------------------------------------------------------------ routes
    @app.get("/health")
    def health():
        return {"status": "ok", "version": __version__, "db": db}

    @app.get("/labs", response_model=List[LabOut])
    def list_labs():
        return [LabOut(**l.to_dict()) for l in labs.list()]

    @app.post("/labs", response_model=LabOut)
    def add_lab(lab: LabIn):
        try:
            created = labs.register(lab.name, lab.host, lab.port, lab.description)
        except ScopeError as exc:
            raise HTTPException(status_code=400, detail=str(exc))
        return LabOut(**created.to_dict())

    @app.delete("/labs/{name}")
    def remove_lab(name: str):
        ok = labs.remove(name)
        if not ok:
            raise HTTPException(status_code=404, detail=f"lab '{name}' not found")
        return {"removed": name}

    @app.get("/scope/check")
    def scope_check(host: str = Query(...), port: Optional[int] = None):
        registered = [l.host for l in labs.list()]
        try:
            assert_in_scope(host, registered_hosts=registered)
        except ScopeError as exc:
            return JSONResponse(
                status_code=400,
                content={"host": host, "in_scope": False, "reason": str(exc)},
            )
        return {"host": host, "in_scope": True, "registered": True}

    @app.get("/findings", response_model=List[FindingOut])
    def list_findings_route(
        severity: Optional[str] = Query(None),
        source: Optional[str] = Query(None),
        sort: Optional[str] = Query(None, description="risk|created_at|severity"),
        limit: int = Query(1000, ge=1, le=10000),
    ):
        items = list_findings(db, severity=severity, source=source)
        if sort == "risk":
            items = risk_sort(items)
        return [_to_out(f) for f in items[:limit]]

    @app.get("/findings/{finding_id}", response_model=FindingOut)
    def get_finding_route(finding_id: str):
        f = get_finding(db, finding_id)
        if f is None:
            raise HTTPException(status_code=404, detail="finding not found")
        ev = list_evidence(db, finding_id)
        if ev and not f.evidence:
            f.evidence = ev[-1].snippet
        return _to_out(f)

    @app.post("/findings", response_model=FindingOut, status_code=201)
    def create_finding_route(payload: FindingIn):
        f = Finding(**payload.model_dump())
        if not f.fingerprint:
            fingerprint_finding(f)
        f = run_plugins(f)
        saved = save_findings(db, [f])
        return _to_out(saved[0])

    @app.delete("/findings/{finding_id}")
    def delete_finding_route(finding_id: str):
        ok = delete_finding(db, finding_id)
        if not ok:
            raise HTTPException(status_code=404, detail="finding not found")
        return {"deleted": finding_id}

    @app.post("/import", response_model=ImportResult)
    async def import_route(
        request: Request,
        source: Optional[str] = Form(None),
        text: Optional[str] = Form(None),
        file: Optional[UploadFile] = File(None),
    ):
        # Accept either a raw JSON body, multipart with `file`, or inline `text`.
        body_text: str | None = None
        parser_name: str | None = source
        if text is not None:
            body_text = text
            dispatch_path: str | None = None
        elif file is not None:
            raw = await file.read()
            body_text = raw.decode("utf-8", errors="replace")
            # If no source was given, let dispatch sniff the filename.
            dispatch_path = file.filename if parser_name is None else None
        else:
            raw = await request.body()
            if not raw:
                raise HTTPException(status_code=400, detail="empty body")
            try:
                payload = json.loads(raw.decode("utf-8"))
            except json.JSONDecodeError:
                raise HTTPException(status_code=400, detail="body must be JSON with {source, text} or multipart")
            if not isinstance(payload, dict) or "text" not in payload:
                raise HTTPException(status_code=400, detail="JSON body must have 'text' field")
            body_text = payload["text"]
            parser_name = parser_name or payload.get("source")
            dispatch_path = None

        if not body_text:
            raise HTTPException(status_code=400, detail="no report text provided")
        try:
            if parser_name:
                parser = dispatch(parser_name, None, body_text)
            else:
                parser = dispatch(None, dispatch_path, body_text)
        except Exception as exc:
            raise HTTPException(status_code=400, detail=f"parser dispatch failed: {exc}")
        try:
            raw_findings = parser.parse(body_text)
        except Exception as exc:
            raise HTTPException(status_code=400, detail=f"parse failed: {exc}")

        # Enrich + dedup + score.
        enriched: List[Finding] = []
        for f in raw_findings:
            if not f.fingerprint:
                fingerprint_finding(f)
            enriched.append(run_plugins(f))
        unique = deduplicate(enriched)
        unique = risk_sort(unique)
        # Persist.
        save_findings(db, unique)

        return ImportResult(
            parser=parser.name,
            imported=len(raw_findings),
            unique=len(unique),
            findings=[_to_out(f, getattr(f, "duplicate_count", 1)) for f in unique],
        )

    @app.post("/report", response_model=ReportResponse)
    def report_route(
        format: str = Query("markdown", pattern="^(markdown|html|json|sarif)$"),
        title: str = Query("GuardScope Report"),
        severity: Optional[str] = Query(None),
        source: Optional[str] = Query(None),
        sort: Optional[str] = Query("risk"),
    ):
        items = list_findings(db, severity=severity, source=source)
        if sort == "risk":
            items = risk_sort(items)
        if format == "markdown":
            body = render_markdown(items, title=title)
        elif format == "html":
            body = render_html(items, title=title)
        elif format == "json":
            body = render_json(items, title=title)
        elif format == "sarif":
            body = render_sarif(items, title=title)
        else:
            raise HTTPException(status_code=400, detail="unsupported format")
        return ReportResponse(format=format, body=body)

    @app.get("/report/raw", responses={200: {"content": {"text/html": {}, "text/markdown": {}, "application/json": {}}}})
    def report_raw(
        format: str = Query("markdown", pattern="^(markdown|html|json|sarif)$"),
        title: str = Query("GuardScope Report"),
        severity: Optional[str] = Query(None),
        source: Optional[str] = Query(None),
    ):
        items = list_findings(db, severity=severity, source=source)
        items = risk_sort(items)
        if format == "markdown":
            return PlainTextResponse(render_markdown(items, title=title), media_type="text/markdown")
        if format == "html":
            return HTMLResponse(render_html(items, title=title))
        if format == "json":
            return JSONResponse(json.loads(render_json(items, title=title)))
        if format == "sarif":
            return JSONResponse(json.loads(render_sarif(items, title=title)), media_type="application/sarif+json")
        raise HTTPException(status_code=400, detail="unsupported format")

    return app