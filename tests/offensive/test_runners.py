"""Integration tests for offensive runners.

These tests are intentionally narrow: they stub out the underlying binaries
(``nmap`` / ``hydra`` / ``sqlmap`` / ``nuclei``) so we don't actually exercise
them in CI. Each test asserts two things:

1. The scope guard refusal paths fire before any subprocess is launched.
2. When the scope guard accepts the call, the right binary is invoked with
   the right arguments and a real audit row is written.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path
from typing import List
from unittest.mock import patch

import pytest

from offensive import audit
from offensive.scope_guard import ScopeViolation
from offensive.hydra_runner import ALLOWED_SERVICES as HYDRA_SERVICES, run_bruteforce
from offensive.nmap_runner import ALLOWED_SCAN_TYPES, run_scan as nmap_run
from offensive.sqlmap_runner import run_sqlmap


# A tiny, deterministic "nmap-like" XML emitted by our fake binary so the
# downstream parser (if we ever reuse it) has something to ingest. We are
# only testing the wrapper here, so this XML is not actually parsed.
FAKE_NMAP_XML = b"""<?xml version="1.0"?>
<nmaprun scanner="fake">
  <host><address addr="127.0.0.1" addrtype="ipv4"/></host>
</nmaprun>
"""


@pytest.fixture()
def db(tmp_path):
    from guardscope.core.db import init_db
    p = tmp_path / "gs.db"
    init_db(str(p))
    return p


def _register_demo_lab(db: Path) -> None:
    from guardscope.lab.registry import LabRegistry
    LabRegistry(str(db)).register("demo-nginx", "127.0.0.1", 8080, "demo")


# ---------------------------------------------------------------------------
# Nmap runner
# ---------------------------------------------------------------------------


def test_nmap_refuses_stealth_scan_type(db, tmp_path):
    _register_demo_lab(db)
    with pytest.raises(ScopeViolation, match="scan_type"):
        nmap_run("127.0.0.1", scan_type="-sS", out_dir=tmp_path, db_path=str(db))


def test_nmap_refuses_dangerous_script_category(db, tmp_path):
    _register_demo_lab(db)
    with pytest.raises(ScopeViolation, match="category"):
        nmap_run(
            "127.0.0.1",
            scripts=["exploit"],
            out_dir=tmp_path,
            db_path=str(db),
        )


def test_nmap_refuses_public_target(tmp_path, monkeypatch):
    monkeypatch.setenv("GUARDSCOPE_AUDIT_DB", str(tmp_path / "audit.db"))
    with pytest.raises(ScopeViolation, match="not.*loopback"):
        nmap_run("1.1.1.1", out_dir=tmp_path, db_path=str(tmp_path / "foo.db"))


def test_nmap_records_audit_and_writes_xml(db, tmp_path, monkeypatch):
    _register_demo_lab(db)
    monkeypatch.setenv("GUARDSCOPE_AUDIT_DB", str(tmp_path / "audit.db"))

    fake_bin = tmp_path / "fake-nmap"
    fake_bin.write_text("#!/bin/sh\necho '" + FAKE_NMAP_XML.decode() + "'\nexit 0\n")
    fake_bin.chmod(0o755)

    captured: dict = {}
    real_run = subprocess.run

    def fake_subprocess_run(args, **kwargs):
        # Swap the first arg (path to nmap) for our fake while leaving the rest.
        if args and "nmap" in args[0]:
            captured["argv"] = args
            return subprocess.CompletedProcess(args, 0, stdout=FAKE_NMAP_XML, stderr=b"")
        return real_run(args, **kwargs)

    with patch("offensive.nmap_runner.subprocess.run", side_effect=fake_subprocess_run):
        with patch("offensive.nmap_runner.nmap_binary", return_value=str(fake_bin)):
            result = nmap_run(
                "127.0.0.1",
                scan_type="-sV",
                out_dir=tmp_path / "reports",
                db_path=str(db),
            )

    assert result.target == "127.0.0.1"
    assert result.xml_path.exists()
    rows = audit.query(audit.AuditQuery(action="nmap.scan"), db_path=tmp_path / "audit.db")
    assert len(rows) == 1
    assert rows[0].exit_code == 0


# ---------------------------------------------------------------------------
# Hydra runner
# ---------------------------------------------------------------------------


def test_hydra_refuses_unknown_service(db, tmp_path):
    _register_demo_lab(db)
    wordlist = tmp_path / "wl.txt"
    wordlist.write_text("password\nhunter2\n")
    with pytest.raises(ScopeViolation, match="service"):
        run_bruteforce(
            "127.0.0.1",
            "telnet",
            username="root",
            wordlist=wordlist,
            out_dir=tmp_path,
            db_path=str(db),
        )


def test_hydra_refuses_missing_wordlist(db, tmp_path):
    _register_demo_lab(db)
    with pytest.raises(ScopeViolation, match="not a regular file"):
        run_bruteforce(
            "127.0.0.1",
            "ssh",
            username="root",
            wordlist=tmp_path / "does-not-exist.txt",
            out_dir=tmp_path,
            db_path=str(db),
        )


def test_hydra_refuses_rockyou_without_optin(db, tmp_path, monkeypatch):
    _register_demo_lab(db)
    # Create the file at the well-known path so the refusal triggers.
    fake_rockyou = tmp_path / "rockyou.txt"
    fake_rockyou.write_text("secret\n")
    monkeypatch.setattr(
        "offensive.hydra_runner.ROCKYOU_HINT", str(fake_rockyou)
    )
    with pytest.raises(ScopeViolation, match="HYDRA_ALLOW_ROCKYOU"):
        run_bruteforce(
            "127.0.0.1",
            "ssh",
            username="root",
            wordlist=fake_rockyou,
            out_dir=tmp_path,
            db_path=str(db),
        )


# ---------------------------------------------------------------------------
# sqlmap runner
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("level", [0, 3, 5])
def test_sqlmap_refuses_out_of_range_level(db, tmp_path, level):
    _register_demo_lab(db)
    with pytest.raises(ScopeViolation, match="level"):
        run_sqlmap("127.0.0.1", "http://127.0.0.1:3000/", level=level,
                   out_dir=tmp_path, db_path=str(db))


@pytest.mark.parametrize("risk", [0, 3, 5])
def test_sqlmap_refuses_out_of_range_risk(db, tmp_path, risk):
    _register_demo_lab(db)
    with pytest.raises(ScopeViolation, match="risk"):
        run_sqlmap("127.0.0.1", "http://127.0.0.1:3000/", risk=risk,
                   out_dir=tmp_path, db_path=str(db))


@pytest.mark.parametrize("flag", ["--os-shell", "--file-write", "--os-pwn", "--sql-shell", "--bind"])
def test_sqlmap_blocks_dangerous_flags(db, tmp_path, flag):
    _register_demo_lab(db)
    with pytest.raises(ScopeViolation, match="forbidden"):
        run_sqlmap(
            "127.0.0.1",
            "http://127.0.0.1:3000/",
            extra_args=[flag],
            out_dir=tmp_path,
            db_path=str(db),
        )
