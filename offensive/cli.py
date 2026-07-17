"""Typer CLI for the offensive module.

Mirrors the style of :mod:`guardscope.cli` so muscle memory carries over. The
only commands exposed here are tight wrappers around the runners; the scope
guard is invoked inside each runner, not at the CLI boundary (defense in
depth).
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import List, Optional

import typer

from . import audit
from .hydra_runner import ALLOWED_SERVICES, run_bruteforce
from .nmap_runner import run_scan as nmap_run_scan
from .nuclei_runner import ALLOWED_TEMPLATE_CATEGORIES, is_available as nuclei_available, run_scan as nuclei_run_scan
from .registry import LAB_TARGETS
from .scope_guard import ScopeViolation
from .sqlmap_runner import run_sqlmap

app = typer.Typer(help="Offensive tooling against registered loopback labs only.")
lab_app = typer.Typer(help="Manage offensive lab targets.")
audit_app = typer.Typer(help="Inspect the audit log.")
app.add_typer(lab_app, name="lab")
app.add_typer(audit_app, name="audit")


def _default_out() -> Path:
    return Path("./offensive-reports").resolve()


def _die(exc: ScopeViolation) -> "None":
    typer.echo(f"[scope-guard] {exc}", err=True)
    raise typer.Exit(code=2)


@app.command()
def scan(
    target: str = typer.Option(..., help="loopback host to scan, e.g. 127.0.0.1"),
    ports: str = typer.Option("1-1024", help="Nmap port spec"),
    scan_type: str = typer.Option("-sV", help="-sT or -sV only"),
    scripts: Optional[str] = typer.Option(None, help="comma-separated safe NSE categories"),
    out_dir: Path = typer.Option(_default_out(), help="output directory"),
    db_path: Optional[str] = typer.Option(None, help="GuardScope SQLite DB path"),
) -> None:
    """Run an Nmap scan against a registered loopback target."""

    script_list = [s.strip() for s in scripts.split(",")] if scripts else None
    try:
        result = nmap_run_scan(
            target,
            ports=ports,
            scan_type=scan_type,
            scripts=script_list,
            out_dir=out_dir,
            db_path=db_path,
        )
    except ScopeViolation as exc:
        _die(exc)
        return  # type: ignore[unreachable]
    typer.echo(result.summary)


@app.command()
def brute(
    target: str = typer.Option(..., help="loopback host"),
    service: str = typer.Option(..., help=f"one of {sorted(ALLOWED_SERVICES)}"),
    username: str = typer.Option(..., help="single login to test"),
    wordlist: Path = typer.Option(..., help="path to a local wordlist file"),
    port: Optional[int] = typer.Option(None, help="optional service port"),
    throttle: int = typer.Option(4, help="attempts per second"),
    out_dir: Path = typer.Option(_default_out()),
    db_path: Optional[str] = typer.Option(None),
) -> None:
    """Run an online credential test against a loopback service."""

    try:
        result = run_bruteforce(
            target,
            service,
            username=username,
            wordlist=wordlist,
            port=port,
            throttle=throttle,
            out_dir=out_dir,
            db_path=db_path,
        )
    except ScopeViolation as exc:
        _die(exc)
        return  # type: ignore[unreachable]
    typer.echo(result.summary)


@app.command()
def sqli(
    target: str = typer.Option(..., help="loopback host"),
    url: str = typer.Option(..., help="full URL, e.g. http://127.0.0.1:3000/rest/products/search?q="),
    level: int = typer.Option(1, help="sqlmap level, clamped to [1, 2]"),
    risk: int = typer.Option(1, help="sqlmap risk, clamped to [1, 2]"),
    out_dir: Path = typer.Option(_default_out()),
    db_path: Optional[str] = typer.Option(None),
) -> None:
    """Run sqlmap against a registered loopback URL."""

    try:
        result = run_sqlmap(target, url, level=level, risk=risk, out_dir=out_dir,
                            db_path=db_path)
    except ScopeViolation as exc:
        _die(exc)
        return  # type: ignore[unreachable]
    typer.echo(result.summary)


@app.command()
def nuclei(
    target: str = typer.Option(..., help="loopback host"),
    url: str = typer.Option(..., help="URL, e.g. http://127.0.0.1:3000/"),
    categories: Optional[str] = typer.Option(None, help="comma-separated categories"),
    out_dir: Path = typer.Option(_default_out()),
    db_path: Optional[str] = typer.Option(None),
) -> None:
    """Run Nuclei against a registered loopback URL (requires nuclei binary)."""

    cat_list = (
        [c.strip() for c in categories.split(",") if c.strip()]
        if categories
        else sorted(ALLOWED_TEMPLATE_CATEGORIES)
    )
    try:
        result = nuclei_run_scan(target, url, categories=cat_list, out_dir=out_dir,
                                  db_path=db_path)
    except ScopeViolation as exc:
        _die(exc)
        return  # type: ignore[unreachable]
    typer.echo(result.summary)


@lab_app.command("list")
def lab_list() -> None:
    """List the curated offensive lab targets."""

    typer.echo(f"{'KEY':<12} {'NAME':<14} {'BIND':<22} DESCRIPTION")
    for t in LAB_TARGETS:
        typer.echo(f"{t.key:<12} {t.name:<14} {t.host}:{t.port:<6} {t.description}")


@lab_app.command("up")
def lab_up(
    key: str = typer.Argument(..., help="target key, e.g. juice-shop"),
    project_root: Path = typer.Option(Path("."), help="repo root"),
) -> None:
    """docker compose up a curated lab target (loopback only)."""

    target = next((t for t in LAB_TARGETS if t.key == key), None)
    if target is None:
        typer.echo(f"unknown lab key: {key}", err=True)
        raise typer.Exit(code=1)
    compose = project_root / target.compose_file
    if not compose.is_file():
        typer.echo(f"missing compose file: {compose}", err=True)
        raise typer.Exit(code=1)
    typer.echo(f"starting {target.key} from {compose} (loopback only)")
    import subprocess
    rc = subprocess.call(["docker", "compose", "-f", str(compose), "up", "-d"])
    sys.exit(rc)


@audit_app.command("show")
def audit_show(
    limit: int = typer.Option(20, help="max rows"),
    action: Optional[str] = typer.Option(None, help="filter by action label"),
    target: Optional[str] = typer.Option(None, help="filter by target"),
) -> None:
    """Pretty-print the audit log."""

    rows = audit.query(audit.AuditQuery(limit=limit, action=action, target=target))
    for r in rows:
        typer.echo(
            f"[{r.timestamp:.0f}] actor={r.actor!r} action={r.action!r} "
            f"target={r.target!r} exit={r.exit_code} :: {r.summary}"
        )


@audit_app.command("count")
def audit_count(
    action: str = typer.Option(..., help="action label to count"),
    since_seconds: int = typer.Option(60, help="window in seconds"),
) -> None:
    """Count recent invocations of an action (used for rate-limit inspection)."""

    import time
    n = audit.count_action(action, time.time() - since_seconds)
    typer.echo(f"{action}: {n} invocation(s) in the last {since_seconds}s")


if __name__ == "__main__":
    app()
