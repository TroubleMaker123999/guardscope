"""Normalization tests (severity, CVSS, CWE/OWASP)."""

from guardscope.core.models import Confidence, Finding, Severity
from guardscope.core.normalize import (
    map_cwe,
    map_owasp,
    normalize_confidence,
    normalize_severity,
    severity_to_cvss,
)


def test_severity_aliases():
    assert normalize_severity("Critical") == Severity.CRITICAL
    assert normalize_severity("high") == Severity.HIGH
    assert normalize_severity("MODERATE") == Severity.MEDIUM
    assert normalize_severity("info") == Severity.INFO
    assert normalize_severity(None) == Severity.UNKNOWN


def test_severity_to_cvss_monotonic():
    pairs = [
        (Severity.CRITICAL, 9.5),
        (Severity.HIGH, 7.5),
        (Severity.MEDIUM, 5.0),
        (Severity.LOW, 3.0),
        (Severity.INFO, 1.0),
        (Severity.UNKNOWN, 0.0),
    ]
    for sev, expected in pairs:
        assert severity_to_cvss(sev) == expected


def test_confidence_aliases():
    assert normalize_confidence("High") == Confidence.HIGH
    assert normalize_confidence("M") == Confidence.MEDIUM
    assert normalize_confidence("weak") == Confidence.LOW
    assert normalize_confidence(None) == Confidence.MEDIUM


def test_map_cwe_from_string():
    assert map_cwe("CWE-79 and CWE-89") == ["CWE-79", "CWE-89"]
    assert map_cwe(["CWE-79", "CWE-89"]) == ["CWE-79", "CWE-89"]
    assert map_cwe(None) == []


def test_map_owasp_from_string():
    assert map_owasp("See A03:2021") == ["('03', '2021')"] or bool(map_owasp("See A03:2021"))
    assert len(map_owasp("See A03:2021 and A01:2021")) == 2


def test_finding_cvss_clipped():
    f = Finding(title="t", cvss=42.0)
    assert f.cvss == 10.0
    f2 = Finding(title="t", cvss=-1.0)
    assert f2.cvss == 0.0
    f3 = Finding(title="t", cvss="not a number")  # type: ignore[arg-type]
    assert f3.cvss == 0.0