"""HTML report renderer (Jinja2)."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Iterable

from jinja2 import Environment, BaseLoader, select_autoescape

from ..core.models import Finding


_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8" />
<title>{{ title }}</title>
<style>
  body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; margin: 2rem auto; max-width: 960px; color: #222; padding: 0 1rem; }
  h1 { border-bottom: 2px solid #444; padding-bottom: .25rem; }
  .meta { color: #666; font-size: .9rem; }
  .finding { border: 1px solid #ddd; border-left: 6px solid #888; border-radius: 6px; padding: 1rem; margin: 1rem 0; background: #fafafa; }
  .critical { border-left-color: #b00020; }
  .high { border-left-color: #d2691e; }
  .medium { border-left-color: #c9a227; }
  .low { border-left-color: #2e8b57; }
  .info { border-left-color: #4682b4; }
  .unknown { border-left-color: #888; }
  .badge { display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: .8rem; color: #fff; }
  .sev-critical { background: #b00020; }
  .sev-high { background: #d2691e; }
  .sev-medium { background: #c9a227; }
  .sev-low { background: #2e8b57; }
  .sev-info { background: #4682b4; }
  .sev-unknown { background: #888; }
  pre { background: #f4f4f4; padding: .5rem; border-radius: 4px; overflow-x: auto; }
  table { border-collapse: collapse; }
  th, td { border: 1px solid #ddd; padding: .25rem .5rem; }
  .muted { color: #777; font-size: .85rem; }
</style>
</head>
<body>
<h1>{{ title }}</h1>
<p class="meta">Generated at {{ generated_at }} UTC</p>

<h2>Summary</h2>
{% if not findings %}
<p>No findings.</p>
{% else %}
<table>
<thead><tr><th>Severity</th><th>Count</th></tr></thead>
<tbody>
{% for sev, count in summary %}
<tr><td><span class="badge sev-{{ sev }}">{{ sev|upper }}</span></td><td>{{ count }}</td></tr>
{% endfor %}
<tr><th>Total</th><th>{{ findings|length }}</th></tr>
</tbody>
</table>
{% endif %}

<h2>Findings</h2>
{% for f in findings %}
<div class="finding {{ f.severity.value }}">
  <h3>#{{ loop.index }} <span class="badge sev-{{ f.severity.value }}">{{ f.severity.value|upper }}</span> {{ f.title }}</h3>
  <p class="muted">
    <strong>Source:</strong> <code>{{ f.source }}</code> &middot;
    <strong>Asset:</strong> <code>{{ f.asset }}</code> &middot;
    <strong>CVSS:</strong> {{ "%.1f"|format(f.cvss) }} &middot;
    <strong>Confidence:</strong> {{ f.confidence.value }}
  </p>
  {% if f.cwe %}<p><strong>CWE:</strong> {{ f.cwe|join(', ') }}</p>{% endif %}
  {% if f.owasp %}<p><strong>OWASP:</strong> {{ f.owasp|join(', ') }}</p>{% endif %}
  {% if f.description %}<p>{{ f.description }}</p>{% endif %}
  {% if f.evidence %}<pre>{{ f.evidence }}</pre>{% endif %}
  {% if f.remediation %}<p><strong>Remediation:</strong> {{ f.remediation }}</p>{% endif %}
  <p class="muted">ID: <code>{{ f.id }}</code> &middot; Fingerprint: <code>{{ f.fingerprint[:16] }}…</code></p>
</div>
{% endfor %}
</body>
</html>
"""


def render_html(findings: Iterable[Finding], *, title: str = "GuardScope Report") -> str:
    findings = list(findings)
    counts: dict[str, int] = {}
    for f in findings:
        counts[f.severity.value] = counts.get(f.severity.value, 0) + 1
    summary = [(sev, counts.get(sev, 0)) for sev in ("critical", "high", "medium", "low", "info", "unknown") if counts.get(sev)]

    env = Environment(loader=BaseLoader(), autoescape=select_autoescape(["html"]))
    tpl = env.from_string(_TEMPLATE)
    return tpl.render(
        title=title,
        findings=findings,
        summary=summary,
        generated_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
    )