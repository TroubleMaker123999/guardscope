"""Typer CLI for GuardScope."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Optional

import typer

from . import __version__
from .core.db import delete_finding, get_finding, init_db, list_findings, save_findings
from .core.dedupe import deduplicate
from .core.fingerprint import fingerprint_finding
from .core.models import Confidence, Finding, Severity
from .core.scoring import risk_sort
from .lab.registry import LabRegistry
from .lab.scope import ScopeError, assert_in_scope, is_local_host
from .parsers.manager import dispatch, list_parsers
from .plugins import run_plugins
from .reporting import render_html, render_json, render_markdown, render_sarif

app = typer.Typer(add_completion=False, help="GuardScope — defensive vulnerability management CLI.")

labs_app = typer.Typer(help="Manage local lab targets.")
app.add_typer(labs_app, name="labs")


def _default_db() -> str:
    return os.environ.get("GUARDSCOPE_DB") or "./guardscope.db"


def _ensure_db(db: str) -> str:
    init_db(db)
    return db


@app.command()
def version() -> None:
    """Print the GuardScope version."""
    typer.echo(__version__)


@app.command()
def serve(
    db: str = typer.Option(_default_db(), "--db", help="SQLite DB path"),
    host: str = typer.Option("127.0.0.1", "--host", help="Bind host (default 127.0.0.1)"),
    port: int = typer.Option(8000, "--port", help="Bind port"),
    reload: bool = typer.Option(False, "--reload", help="Auto-reload (dev only)"),
) -> None:
    """Run the FastAPI server (uvicorn)."""
    import uvicorn

    if host not in ("127.0.0.1", "localhost", "::1"):
        typer.echo(f"refused: server must bind to loopback; got {host}", err=True)
        raise typer.Exit(2)
    _ensure_db(db)
    os.environ["GUARDSCOPE_DB"] = db
    uvicorn.run("guardscope.api.app:create_app", host=host, port=port, reload=reload, factory=True)


@app.command(name="import")
def import_report(
    file: Path = typer.Option(..., "--file", exists=True, readable=True, help="Path to scanner report"),
    source: Optional[str] = typer.Option(None, "--source", help="Force a parser (nmap|zap|sarif|bandit|semgrep|trivy|pipaudit)"),
    db: str = typer.Option(_default_db(), "--db"),
    pretty: bool = typer.Option(True, "--pretty/--raw"),
) -> None:
    """Import a scanner report into the database."""
    db = _ensure_db(db)
    text = file.read_text(encoding="utf-8", errors="replace")
    try:
        parser = dispatch(source, str(file), text)
    except Exception as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(2)
    try:
        raw = parser.parse(text)
    except Exception as exc:
        typer.echo(f"error: parse failed: {exc}", err=True)
        raise typer.Exit(2)
    enriched = [run_plugins(f) for f in raw]
    for f in enriched:
        if not f.fingerprint:
            fingerprint_finding(f)
    unique = deduplicate(enriched)
    unique = risk_sort(unique)
    save_findings(db, unique)
    counts: dict[str, int] = {}
    for f in unique:
        counts[f.severity.value] = counts.get(f.severity.value, 0) + 1
    payload = {
        "parser": parser.name,
        "imported": len(raw),
        "unique": len(unique),
        "summary": counts,
    }
    typer.echo(json.dumps(payload, indent=2 if pretty else None))


@app.command()
def report(
    db: str = typer.Option(_default_db(), "--db"),
    format: str = typer.Option("markdown", "--format", help="markdown|html|json|sarif"),
    out: Optional[Path] = typer.Option(None, "--out", help="Write to file (default: stdout)"),
    title: str = typer.Option("GuardScope Report", "--title"),
    severity: Optional[str] = typer.Option(None, "--severity"),
    source: Optional[str] = typer.Option(None, "--source"),
) -> None:
    """Render a report."""
    db = _ensure_db(db)
    items = list_findings(db, severity=severity, source=source)
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
        typer.echo(f"error: unknown format '{format}'", err=True)
        raise typer.Exit(2)
    if out:
        out.write_text(body, encoding="utf-8")
        typer.echo(f"wrote {out} ({len(body)} bytes)")
    else:
        typer.echo(body)


@app.command()
def demo(
    db: str = typer.Option(_default_db(), "--db"),
    reset: bool = typer.Option(True, "--reset/--no-reset", help="Wipe findings before seeding"),
) -> None:
    """Seed demo findings (no external tools required)."""
    db = _ensure_db(db)
    if reset:
        from sqlalchemy import delete as sa_delete
        from sqlalchemy.orm import Session

        from .core.db import FindingORM, make_engine

        engine = make_engine(db)
        with Session(engine) as s:
            s.execute(sa_delete(FindingORM))
            s.commit()

    demo_path = Path(__file__).parent / "data" / "demo_findings.json"
    payload = json.loads(demo_path.read_text(encoding="utf-8"))
    items: list[Finding] = []
    for raw in payload:
        sev = Severity(raw.get("severity", "unknown"))
        conf = Confidence(raw.get("confidence", "medium"))
        f = Finding(
            title=raw["title"],
            description=raw.get("description", ""),
            severity=sev,
            confidence=conf,
            cvss=float(raw.get("cvss", 0.0)),
            cwe=list(raw.get("cwe", [])),
            owasp=list(raw.get("owasp", [])),
            source=raw.get("source", "demo"),
            asset=raw.get("asset", ""),
            evidence=raw.get("evidence", ""),
            remediation=raw.get("remediation", ""),
        )
        fingerprint_finding(f)
        items.append(run_plugins(f))
    save_findings(db, items)
    typer.echo(f"seeded {len(items)} demo findings into {db}")


class _NullCtx:
    def __enter__(self): return self
    def __exit__(self, *a): return False


@labs_app.command("list")
def labs_list(
    db: str = typer.Option(_default_db(), "--db"),
) -> None:
    """List registered local labs."""
    reg = LabRegistry(_ensure_db(db))
    rows = reg.list()
    if not rows:
        typer.echo("(no labs registered)")
        return
    for l in rows:
        typer.echo(f"- {l.name}\t{l.host}:{l.port}\t{l.description}")


@labs_app.command("register")
def labs_register(
    name: str = typer.Option(..., "--name"),
    host: str = typer.Option(..., "--host"),
    port: int = typer.Option(..., "--port"),
    description: str = typer.Option("", "--description"),
    db: str = typer.Option(_default_db(), "--db"),
) -> None:
    """Register a local lab (host must be localhost/127.0.0.1)."""
    reg = LabRegistry(_ensure_db(db))
    try:
        lab = reg.register(name=name, host=host, port=port, description=description)
    except ScopeError as exc:
        typer.echo(f"refused: {exc}", err=True)
        raise typer.Exit(2)
    typer.echo(f"registered {lab.name} -> {lab.host}:{lab.port}")


@labs_app.command("remove")
def labs_remove(
    name: str = typer.Option(..., "--name"),
    db: str = typer.Option(_default_db(), "--db"),
) -> None:
    """Remove a registered lab."""
    reg = LabRegistry(_ensure_db(db))
    if reg.remove(name):
        typer.echo(f"removed {name}")
    else:
        typer.echo(f"no such lab: {name}", err=True)
        raise typer.Exit(2)


@app.command(name="scope-check")
def scope_check(
    host: str = typer.Option(..., "--host"),
    port: Optional[int] = typer.Option(None, "--port"),
    db: str = typer.Option(_default_db(), "--db"),
) -> None:
    """Check whether a host is within local-lab scope."""
    reg = LabRegistry(_ensure_db(db))
    registered_hosts = [l.host for l in reg.list()]
    # If no labs are registered yet, only enforce the loopback check.
    effective = registered_hosts if registered_hosts else None
    try:
        normalized = assert_in_scope(host, registered_hosts=effective)
        typer.echo(f"in-scope: {normalized}")
    except ScopeError as exc:
        typer.echo(f"rejected: {exc}", err=True)
        raise typer.Exit(2)


@app.command()
def parsers() -> None:
    """List available parsers."""
    for p in list_parsers():
        typer.echo(f"- {p.name}\t{p.description}")


@app.command()
def findings(
    db: str = typer.Option(_default_db(), "--db"),
    severity: Optional[str] = typer.Option(None, "--severity"),
    source: Optional[str] = typer.Option(None, "--source"),
    limit: int = typer.Option(50, "--limit"),
    show: bool = typer.Option(False, "--show", help="Print full finding JSON"),
) -> None:
    """List findings (compact)."""
    db = _ensure_db(db)
    items = list_findings(db, severity=severity, source=source)
    items = risk_sort(items)
    items = items[:limit]
    if not items:
        typer.echo("(no findings)")
        return
    for f in items:
        typer.echo(
            f"[{f.severity.value.upper():<8}] {f.title}  ({f.source} @ {f.asset})"
        )
    if show:
        typer.echo("")
        typer.echo(json.dumps([f.to_dict() for f in items], indent=2))


@app.command()
def delete(
    finding_id: str = typer.Option(..., "--id"),
    db: str = typer.Option(_default_db(), "--db"),
) -> None:
    """Delete a finding by id."""
    db = _ensure_db(db)
    if delete_finding(db, finding_id):
        typer.echo(f"deleted {finding_id}")
    else:
        typer.echo("not found", err=True)
        raise typer.Exit(2)


def main() -> None:  # pragma: no cover
    app()


if __name__ == "__main__":  # pragma: no cover
    main()