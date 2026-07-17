"""Parser tests for all seven built-in parsers."""

from __future__ import annotations

from guardscope.parsers import list_parsers
from guardscope.parsers.manager import dispatch


def test_parsers_registered():
    names = {p.name for p in list_parsers()}
    assert names >= {"nmap", "zap", "sarif", "bandit", "semgrep", "trivy", "pipaudit"}


def test_nmap_parser(nmap_text):
    p = dispatch("nmap", None)
    out = p.parse(nmap_text)
    assert len(out) >= 2
    assert all(f.source == "nmap" for f in out)
    assert any(f.asset.startswith("127.0.0.1:") for f in out)
    assert all(f.fingerprint for f in out)


def test_zap_parser(zap_text):
    p = dispatch("zap", None)
    out = p.parse(zap_text)
    assert len(out) == 2
    assert {f.severity.value for f in out} >= {"medium", "high"}
    assert any("CWE-352" in f.cwe for f in out)


def test_sarif_parser(sarif_text):
    p = dispatch("sarif", None)
    out = p.parse(sarif_text)
    assert len(out) == 1
    f = out[0]
    assert f.severity.value == "high"
    assert "CWE-89" in f.cwe
    assert any(o.startswith("A03:2021") for o in f.owasp)
    assert f.asset.endswith("src/api/users.py:42")


def test_bandit_parser(bandit_text):
    p = dispatch("bandit", None)
    out = p.parse(bandit_text)
    assert len(out) == 2
    assert {f.severity.value for f in out} >= {"medium", "high"}
    assert all(f.cwe for f in out)


def test_semgrep_parser(semgrep_text):
    p = dispatch("semgrep", None)
    out = p.parse(semgrep_text)
    assert len(out) == 2
    assert any("CWE-95" in f.cwe for f in out)
    assert any("A03:2021" in o for f in out for o in f.owasp)


def test_trivy_parser(trivy_text):
    p = dispatch("trivy", None)
    out = p.parse(trivy_text)
    assert len(out) == 2
    sevs = [f.severity.value for f in out]
    assert "critical" in sevs and "medium" in sevs
    assert any("CVE-2023-45853" in f.title for f in out)


def test_pipaudit_parser(pipaudit_text):
    p = dispatch("pipaudit", None)
    out = p.parse(pipaudit_text)
    assert len(out) == 2
    assert any("requests@2.20.0" == f.asset for f in out)
    assert all(f.cwe for f in out)


def test_parser_dispatch_by_extension(fixtures_dir):
    p = dispatch(None, str(fixtures_dir / "nmap_sample.xml"))
    assert p.name == "nmap"


def test_parsers_tolerate_missing_fields():
    from guardscope.parsers.zap import ZapParser

    txt = '{"site":[{"alerts":[{"name":"X"}]}]}'
    out = ZapParser().parse(txt)
    assert len(out) == 1
    assert out[0].title == "X"
    assert out[0].severity.value == "unknown"


def test_parser_rejects_garbage():
    from guardscope.parsers.base import ParseError
    from guardscope.parsers.zap import ZapParser

    try:
        ZapParser().parse("not json at all")
    except ParseError:
        return
    raise AssertionError("expected ParseError")