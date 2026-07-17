"""Optional Nuclei wrapper.

Nuclei is a Go binary that is NOT shipped via apt; deployment is operator's
job. If the binary is absent, :func:`is_available` returns ``False`` and
:func:`run_scan` raises a friendly :class:`ScopeViolation` explaining how to
install it.

When present, the wrapper restricts execution to the ``technologies`` and
``exposures`` template categories — not the ``vulnerabilities`` category —
to keep this from doubling as a one-click exploitation tool. Severity filter
is forced to ``info,low,medium`` (high/critical templates by default include
exploit-prone chains that the existing scope guard cannot safely gate).
"""

from __future__ import annotations

import json
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

ALLOWED_TEMPLATE_CATEGORIES = {"technologies", "exposures", "misconfiguration"}
SEVERITY_WHITELIST = ("info", "low", "medium")


def is_available() -> bool:
    return shutil.which("nuclei") is not None


@dataclass
class NucleiResult:
    target: str
    url: str
    command: List[str]
    jsonl_path: Path
    summary: str
    matched: int


def run_scan(
    target: str,
    url: str,
    *,
    categories: Optional[List[str]] = None,
    out_dir: Path,
    actor: Optional[str] = None,
    audit_db: Optional[Path] = None,
    db_path: Optional[str] = None,
    timeout: int = 240,
) -> NucleiResult:
    if not is_available():
        raise ScopeViolation(
            "nuclei not installed; install with `go install "
            "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest`"
        )

    cats = list(categories or sorted(ALLOWED_TEMPLATE_CATEGORIES))
    for c in cats:
        if c not in ALLOWED_TEMPLATE_CATEGORIES:
            raise ScopeViolation(
                f"nuclei category {c!r} not in allowlist "
                f"{sorted(ALLOWED_TEMPLATE_CATEGORIES)}"
            )

    host = resolve_target(target)
    run: AuthorizedRun = assert_authorized(
        host,
        action="nuclei.scan",
        actor=actor,
        db_path=db_path,
        audit_db=audit_db,
    )

    args: List[str] = [
        "nuclei",
        "-u", url,
        "-severity", ",".join(SEVERITY_WHITELIST),
        "-tags", "tech,exposure",
        "-json",
        "-silent",
    ]
    for c in cats:
        args.extend(["-t", c])

    out_dir.mkdir(parents=True, exist_ok=True)
    jsonl_path = out_dir / f"nuclei-{run.actor}-{int(run.started_at)}.jsonl"

    proc = subprocess.run(
        args,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )
    jsonl_path.write_text(proc.stdout, encoding="utf-8", errors="replace")
    matched = sum(
        1
        for line in proc.stdout.splitlines()
        if line.strip().startswith("{") and _is_valid_jsonl(line)
    )
    summary = (
        f"nuclei scanned {url} categories={cats}; exit={proc.returncode}; "
        f"matched={matched}; jsonl={jsonl_path.name}"
    )
    record_completion(
        run,
        exit_code=proc.returncode,
        params={"url": url, "categories": cats},
        summary=summary,
        audit_db=audit_db,
    )
    return NucleiResult(
        target=host,
        url=url,
        command=args,
        jsonl_path=jsonl_path,
        summary=summary,
        matched=matched,
    )


def _is_valid_jsonl(line: str) -> bool:
    try:
        json.loads(line)
        return True
    except json.JSONDecodeError:
        return False
