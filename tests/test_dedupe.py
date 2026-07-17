"""Deduplication and risk-scoring tests."""

from guardscope.core.dedupe import deduplicate
from guardscope.core.fingerprint import fingerprint_from_parts
from guardscope.core.models import Confidence, Finding, Severity
from guardscope.core.scoring import risk_score, risk_sort


def _f(title: str, severity: Severity = Severity.MEDIUM, confidence: Confidence = Confidence.MEDIUM, cvss: float = 5.0, asset: str = "a"):
    f = Finding(title=title, severity=severity, confidence=confidence, cvss=cvss, asset=asset, source="x")
    f.fingerprint = fingerprint_from_parts("x", asset, title)
    return f


def test_dedupe_collapses_duplicates():
    a = _f("Open port 80", Severity.LOW)
    b = _f("Open port 80", Severity.LOW)  # same fingerprint
    c = _f("Open port 22", Severity.LOW)
    out = deduplicate([a, b, c])
    assert len(out) == 2
    titles = [f.title for f in out]
    assert "Open port 80" in titles and "Open port 22" in titles
    by_title = {f.title: f for f in out}
    assert getattr(by_title["Open port 80"], "duplicate_count", 1) == 2


def test_risk_score_orders_by_severity():
    low = _f("low", Severity.LOW, asset="x")
    high = _f("high", Severity.HIGH, asset="x")
    crit = _f("crit", Severity.CRITICAL, asset="x")
    assert risk_score(crit) > risk_score(high) > risk_score(low)


def test_risk_score_includes_confidence():
    base = _f("x", Severity.MEDIUM, confidence=Confidence.LOW, asset="x")
    higher = _f("x", Severity.MEDIUM, confidence=Confidence.HIGH, asset="x")
    assert risk_score(higher) > risk_score(base)


def test_risk_sort_returns_descending():
    a = _f("a", Severity.LOW, asset="x")
    b = _f("b", Severity.CRITICAL, asset="x")
    c = _f("c", Severity.MEDIUM, asset="x")
    sorted_items = risk_sort([a, b, c])
    assert [f.title for f in sorted_items] == ["b", "c", "a"]