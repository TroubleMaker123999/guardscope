# GuardScope Architecture

## Package layout

```
guardscope/
  core/
    models.py      # Pydantic Finding / Evidence / Audit schemas
    db.py          # SQLAlchemy 2 ORM + session factory
    fingerprint.py # Stable sha256 fingerprint
    normalize.py   # Severity / CVSS / CWE / OWASP mapping
    dedupe.py      # Deduplication helpers
    scoring.py     # Risk score + ordering
  parsers/
    base.py        # Parser protocol + registry
    nmap.py        # Nmap XML (xml.etree)
    zap.py         # OWASP ZAP JSON
    sarif.py       # Generic SARIF 2.1.0
    bandit.py      # Bandit JSON
    semgrep.py     # Semgrep JSON
    trivy.py       # Trivy JSON
    pipaudit.py    # pip-audit JSON
    manager.py     # File -> parser dispatch
  reporting/
    markdown.py    # Markdown
    html.py        # Jinja2 HTML
    json_report.py # JSON
    sarif_report.py# SARIF
  plugins/
    base.py        # Plugin protocol + registry
    sample.py      # Built-in sample plugin
  lab/
    registry.py    # In-memory / DB-backed lab registry
    scope.py       # Strict scope guard (localhost only)
  api/
    app.py         # FastAPI app
  cli.py           # Typer CLI
  data/
    demo_findings.json
```

## Data model

### `Finding`

Unified normalized finding. The columns are:

| Field         | Purpose                                                         |
|---------------|-----------------------------------------------------------------|
| `id`          | Internal UUID                                                   |
| `fingerprint` | Stable sha256 dedupe key (asset + signature hash)               |
| `title`       | Short human label                                               |
| `description` | Long-form description                                           |
| `severity`    | One of `critical|high|medium|low|info|unknown`                 |
| `confidence`  | `high|medium|low`                                               |
| `cvss`        | Approximated 0.0–10.0 float                                     |
| `cwe`         | List of CWE IDs (e.g. `["CWE-79"]`)                             |
| `owasp`       | List of OWASP labels (e.g. `["A03:2021 - Injection"]`)         |
| `source`      | Origin tool (`nmap`, `zap`, `sarif`, `bandit`, `semgrep`, ...)  |
| `asset`       | Affected host/port/package/path                                 |
| `evidence`    | Raw snippet or extracted evidence string                        |
| `remediation` | Suggested fix                                                   |
| `created_at`  | UTC timestamp                                                   |
| `updated_at`  | UTC timestamp                                                   |

### `Evidence`

Linked record holding the raw tool output snippet that produced the finding.
This is what the API surfaces via `/findings/{id}`.

### `Audit`

Append-only audit log (`event`, `payload`, `timestamp`) for sensitive actions
(imports, report generation, lab registration).

## Parsers

Each parser implements `parsers.base.Parser.parse(text) -> list[Finding]`.
Parsers are intentionally tolerant: missing fields are replaced by safe
defaults (`severity="unknown"`, `cvss=0.0`, etc.). The `manager` module
dispatches by file extension / source name.

## Scope guard

`lab.scope.assert_in_scope(host)` is the single choke point. It rejects any
host that does not resolve to `127.0.0.1` / `::1` / `localhost`. The API and
the CLI both call this guard before any "verify" action.

## Plugin protocol

A plugin is any object implementing `plugins.base.Plugin` (a `name`, a
`description`, and an `enrich(finding) -> Finding` method). Plugins are
registered at startup and run during import.