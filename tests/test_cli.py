"""CLI smoke tests."""

from __future__ import annotations

from pathlib import Path

from typer.testing import CliRunner

from guardscope.cli import app


def test_version():
    r = CliRunner().invoke(app, ["version"])
    assert r.exit_code == 0, r.output
    assert "0.1.0" in r.output


def test_parsers_listing():
    r = CliRunner().invoke(app, ["parsers"])
    assert r.exit_code == 0, r.output
    for name in ("nmap", "zap", "sarif", "bandit", "semgrep", "trivy", "pipaudit"):
        assert name in r.output


def test_demo_seeds_findings(tmp_path: Path):
    db = str(tmp_path / "cli.db")
    r = CliRunner().invoke(app, ["demo", "--db", db])
    assert r.exit_code == 0, r.output
    r = CliRunner().invoke(app, ["findings", "--db", db, "--show"])
    assert r.exit_code == 0, r.output
    assert "seeded" in r.output or "demo" in r.output.lower()


def test_import_via_cli(tmp_path: Path):
    db = str(tmp_path / "cli.db")
    fixture = Path("tests/fixtures/nmap_sample.xml").resolve()
    r = CliRunner().invoke(app, ["import", "--db", db, "--file", str(fixture)])
    assert r.exit_code == 0, r.output
    r = CliRunner().invoke(app, ["findings", "--db", db])
    assert r.exit_code == 0
    assert "127.0.0.1" in r.output


def test_report_via_cli(tmp_path: Path):
    db = str(tmp_path / "cli.db")
    CliRunner().invoke(app, ["demo", "--db", db])
    out = tmp_path / "report.md"
    r = CliRunner().invoke(app, ["report", "--db", db, "--format", "markdown", "--out", str(out)])
    assert r.exit_code == 0, r.output
    assert out.exists()
    assert "GuardScope Report" in out.read_text()


def test_labs_register_rejects_external(tmp_path: Path):
    db = str(tmp_path / "cli.db")
    r = CliRunner().invoke(
        app,
        ["labs", "register", "--db", db, "--name", "evil", "--host", "example.com", "--port", "80"],
    )
    assert r.exit_code == 2
    assert "refused" in r.output


def test_labs_register_loopback(tmp_path: Path):
    db = str(tmp_path / "cli.db")
    r = CliRunner().invoke(
        app,
        ["labs", "register", "--db", db, "--name", "demo", "--host", "127.0.0.1", "--port", "8080"],
    )
    assert r.exit_code == 0, r.output
    r = CliRunner().invoke(app, ["labs", "list", "--db", db])
    assert "demo" in r.output


def test_scope_check_cli(tmp_path: Path):
    db = str(tmp_path / "cli.db")
    r = CliRunner().invoke(app, ["scope-check", "--db", db, "--host", "127.0.0.1"])
    assert r.exit_code == 0
    r = CliRunner().invoke(app, ["scope-check", "--db", db, "--host", "example.com"])
    assert r.exit_code == 2
    assert "rejected" in r.output