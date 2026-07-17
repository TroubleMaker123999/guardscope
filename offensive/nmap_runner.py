"""Nmap wrapper that funnels every call through ``scope_guard``.

Only ``-sT`` (TCP connect) and ``-sV`` (service detection) are exposed by
default — both are non-intrusive against loopback services. Stealth scans
(``-sS``/SYN, ``-sF``/FIN, ``-sX``/Xmas, ``-Pn``/no-ping) are intentionally
not exposed. The wrapper does not auto-build aggressive scripts (``--script``
is restricted to the ``safe`` and ``discovery`` categories).
"""

from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional

from .scope_guard import (
    AuthorizedRun,
    ScopeViolation,
    assert_authorized,
    record_completion,
    resolve_target,
)

ALLOWED_SCAN_TYPES = {"-sT", "-sV"}
ALLOWED_SCRIPT_CATEGORIES = {"safe", "discovery", "version"}

DEFAULT_TIMEOUT_SECONDS = 120


@dataclass
class NmapResult:
    target: str
    command: List[str]
    xml_path: Path
    summary: str


def nmap_binary() -> str:
    path = shutil.which("nmap")
    if path is None:
        raise ScopeViolation(
            "nmap binary not found in PATH; install with `apt-get install nmap`"
        )
    return path


def run_scan(
    target: str,
    *,
    ports: str = "1-1024",
    scan_type: str = "-sV",
    scripts: Optional[List[str]] = None,
    out_dir: Path,
    actor: Optional[str] = None,
    audit_db: Optional[Path] = None,
    db_path: Optional[str] = None,
    timeout: int = DEFAULT_TIMEOUT_SECONDS,
) -> NmapResult:
    """Run an nmap scan against a registered loopback target.

    ``scan_type`` must be in :data:`ALLOWED_SCAN_TYPES` (no stealth variants).
    ``scripts`` is restricted to allowlisted categories to avoid pulling in
    intrusive NSE scripts that perform brute force, exploitation, etc.
    """

    if scan_type not in ALLOWED_SCAN_TYPES:
        raise ScopeViolation(
            f"scan_type {scan_type!r} not allowed; use one of {sorted(ALLOWED_SCAN_TYPES)}"
        )

    host = resolve_target(target)
    run: AuthorizedRun = assert_authorized(
        host,
        action="nmap.scan",
        actor=actor,
        db_path=db_path,
        audit_db=audit_db,
    )

    args: List[str] = [nmap_binary(), scan_type, "-p", ports, "--open", "-oX", "-"]
    if scripts:
        for cat in scripts:
            if cat not in ALLOWED_SCRIPT_CATEGORIES:
                raise ScopeViolation(
                    f"script category {cat!r} is not in the allowlist "
                    f"({sorted(ALLOWED_SCRIPT_CATEGORIES)})"
                )
        args.extend(["--script", ",".join(scripts)])
    args.append(host)

    out_dir.mkdir(parents=True, exist_ok=True)
    xml_path = out_dir / f"nmap-{run.actor}-{int(run.started_at)}.xml"

    try:
        proc = subprocess.run(
            args,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        stdout = proc.stdout
        if isinstance(stdout, bytes):
            stdout = stdout.decode("utf-8", errors="replace")
        xml_path.write_text(stdout, encoding="utf-8", errors="replace")
        exit_code = proc.returncode
        summary = (
            f"nmap scanned {host} ports={ports} scan_type={scan_type}; "
            f"exit={exit_code}; xml={xml_path.name}; size={xml_path.stat().st_size}B"
        )
    except subprocess.TimeoutExpired as exc:
        xml_path.write_text("", encoding="utf-8")
        exit_code = -1
        summary = f"nmap timed out after {timeout}s against {host}"
        record_completion(
            run,
            exit_code=exit_code,
            params={"ports": ports, "scan_type": scan_type, "scripts": scripts},
            summary=summary,
            audit_db=audit_db,
        )
        raise ScopeViolation(summary) from exc

    record_completion(
        run,
        exit_code=exit_code,
        params={"ports": ports, "scan_type": scan_type, "scripts": scripts},
        summary=summary,
        audit_db=audit_db,
    )
    return NmapResult(target=host, command=args, xml_path=xml_path, summary=summary)
