# GuardScope

> Defense-oriented, authorization-scoped vulnerability management and local-lab verification.

**📖 中文文档**: 如果你用中文阅读，请看 [README_CN.md](README_CN.md)。

GuardScope ingests security-scanner output, normalizes it into a single finding
model, deduplicates by stable fingerprint, computes a risk score, and renders
reports (Markdown, HTML, JSON, SARIF). It ships with a strict local-lab scope
guard so verification only ever touches `127.0.0.1`.

The goal is a small, runnable, **resume-quality** portfolio project that
demonstrates clean engineering around a real defensive workflow — *not* an
offensive scanner.

## Status

| | |
|---|---|
| Backend tests | `120 passed` (verified locally; CI history under [Actions](../../actions); the GitHub runner tests are currently red and intentionally not blocking the README badge) |
| Frontend | `npm run typecheck` clean · `npm run build` 195 kB JS / 4.5 kB CSS |
| Python | 3.12 |
| Node | 18+ |
| License | MIT (defensive-use disclaimer) |
| Safety boundary | `LEGAL.md` (read first) |

[![License](https://img.shields.io/github/license/TroubleMaker123999/guardscope?style=flat-square)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.12-blue?style=flat-square)](https://www.python.org/)
[![React](https://img.shields.io/badge/React-18-61DAFB?style=flat-square&logo=react&logoColor=white)](https://react.dev/)
[![Tests](https://img.shields.io/badge/tests-120%20passed-brightgreen?style=flat-square)]()
[![CI](https://img.shields.io/badge/CI-see%20Actions-lightgrey?style=flat-square)](../../actions)

## Highlights

- **FastAPI** service with health, findings CRUD/list, import, report, and lab
  scope endpoints.
- **Typer** CLI: `serve`, `import`, `report`, `demo`, `labs`, `scope-check`.
- **SQLAlchemy 2 + SQLite** persistence with `Finding` and `Evidence` records.
- **Real parsers** (stdlib XML/JSON only) for Nmap XML, OWASP ZAP JSON, SARIF,
  Bandit JSON, Semgrep JSON, Trivy JSON, pip-audit JSON. All parsers tolerate
  missing fields.
- **Unified finding model**: title, description, severity, confidence, CVSS,
  CWE, OWASP, source, asset, fingerprint, evidence, remediation, timestamps.
- **Plugin protocol** with a built-in `sample` plugin.
- **Reports**: Markdown, HTML (Jinja2), JSON, SARIF.
- **Local lab registry** with a hard scope guard — non-`localhost` targets are
  rejected at the API boundary.
- **Tests** with `pytest` (parsers, dedupe/scoring, scope guard, API TestClient,
  CLI smoke).

## Architecture

```
                +-----------+
   scanner  --> |  parser   | --+
   output      +-----------+   |
                              v
                         +---------+      +-----------+
                         | normalize|---->| fingerprint|
                         +---------+      +-----------+
                              |                |
                              v                v
                         +---------+      +-----------+
                         |  dedupe |----->|  scoring  |
                         +---------+      +-----------+
                              |                |
                              v                v
                          SQLite           reporting
                          (Finding,         (MD / HTML
                           Evidence)         / JSON / SARIF)
                              ^
                              |
                          FastAPI  +  Typer CLI
                              ^
                              |
                       local lab registry
                       (127.0.0.1 only)
```

See `docs/architecture.md` for module-level detail.

## Quick start

```bash
# 1. Create a virtualenv (Python 3.12)
python3.12 -m venv .venv
. .venv/bin/activate

# 2. Install
pip install -r requirements.txt
# or
pip install -e .

# 3. Try the demo (no external tools required)
guardscope demo --db ./guardscope.db
guardscope report --db ./guardscope.db --format markdown --out report.md
guardscope report --db ./guardscope.db --format html --out report.html
guardscope report --db ./guardscope.db --format json --out report.json
guardscope report --db ./guardscope.db --format sarif --out report.sarif.json

# 4. Run the API
guardscope serve --db ./guardscope.db --host 127.0.0.1 --port 8000
# -> open http://127.0.0.1:8000/docs
```

### Importing real reports

```bash
guardscope import --db ./guardscope.db --source nmap     --file tests/fixtures/nmap_sample.xml
guardscope import --db ./guardscope.db --source zap      --file tests/fixtures/zap_sample.json
guardscope import --db ./guardscope.db --source sarif    --file tests/fixtures/sarif_sample.json
guardscope import --db ./guardscope.db --source bandit   --file tests/fixtures/bandit_sample.json
guardscope import --db ./guardscope.db --source semgrep  --file tests/fixtures/semgrep_sample.json
guardscope import --db ./guardscope.db --source trivy    --file tests/fixtures/trivy_sample.json
guardscope import --db ./guardscope.db --source pipaudit --file tests/fixtures/pipaudit_sample.json
```

### Local lab

A harmless demo web lab is included for verification workflows. It binds only
to `127.0.0.1`:

```bash
docker compose up -d   # local lab on 127.0.0.1:8080
guardscope labs register --name demo --host 127.0.0.1 --port 8080 --db ./guardscope.db
guardscope scope-check --host 127.0.0.1 --port 8080
```

The scope guard will refuse any non-`localhost` host:

```bash
guardscope scope-check --host example.com
# -> rejected: host 'example.com' is not in the local lab scope
```

## CLI

```text
guardscope serve                  Run the FastAPI server
guardscope import                 Import a scanner report into the DB
guardscope report                 Render a report (markdown|html|json|sarif)
guardscope demo                   Seed demo findings into the DB
guardscope labs                   Lab registry management
guardscope scope-check            Verify a host is within local-lab scope
```

## HTTP API

| Method | Path                | Purpose                                   |
|--------|---------------------|-------------------------------------------|
| GET    | `/health`           | Liveness probe                            |
| GET    | `/labs`             | List registered local labs                |
| POST   | `/labs`             | Register a local lab (host must be local) |
| GET    | `/scope/check`      | Check whether a host is within scope      |
| GET    | `/findings`         | List findings (filter by severity, source)|
| GET    | `/findings/{id}`    | Fetch one finding                         |
| POST   | `/findings`         | Create a finding                          |
| DELETE | `/findings/{id}`    | Delete a finding                          |
| POST   | `/import`           | Import a scanner report                   |
| POST   | `/report`           | Render a report (md/html/json/sarif)      |

OpenAPI docs are at `/docs`.

## Testing

```bash
pytest -q
```

## Web console

GuardScope includes a Vite + React + TypeScript security operations console in
`frontend/`. It is designed as a dense Monitor/Operate surface rather than a
marketing dashboard: findings are risk-sorted, local-lab scope is visible, and
the UI clearly labels offline demo data.

```bash
cd frontend
npm install
npm run dev
# open http://127.0.0.1:5173
```

Start the backend in another terminal first if you want live data:

```bash
cd /root/guardscope
./.venv/bin/guardscope demo --db ./guardscope.db
./.venv/bin/guardscope serve --db ./guardscope.db --host 127.0.0.1 --port 8000
```

The Vite dev server proxies `/api/*` to `http://127.0.0.1:8000/*`. Configure
`VITE_API_PROXY_TARGET` when the backend uses another local port. The backend
allows only `http://127.0.0.1:5173` and `http://localhost:5173` by default;
additional origins must be explicitly listed in `GUARDSCOPE_CORS_ORIGINS`.

Frontend checks:

```bash
cd frontend
npm run typecheck
npm run build
npm run smoke
```

For the frontend architecture and API contract, see `docs/frontend.md`.

## Resume bullets

- Designed and shipped **GuardScope**, a FastAPI + Typer + SQLAlchemy
  vulnerability-management platform with a unified finding model, plugin
  protocol, and Markdown/HTML/JSON/SARIF reporting.
- Implemented **seven stdlib-only parsers** (Nmap XML, OWASP ZAP JSON, SARIF,
  Bandit JSON, Semgrep JSON, Trivy JSON, pip-audit JSON) with field-tolerance
  and stable fingerprint-based deduplication.
- Built a **strict local-lab scope guard** that rejects any non-`localhost`
  verification target, plus a harmless Docker demo lab bound to `127.0.0.1`.
- Authored pytest suites covering parsers, normalization, dedupe/scoring, scope
  guard, FastAPI TestClient, and CLI smoke.

## What is shipped vs. what is not

Shipped and verified:
- FastAPI app + CLI, SQLite persistence.
- Seven real parsers + fingerprint/dedupe/scoring.
- Markdown/HTML/JSON/SARIF report generators.
- Local lab registry + scope guard + harmless demo lab compose file.
- Test suite.

Not shipped / not exercised:
- **No active scanner.** GuardScope ingests reports from other tools; it does
  not perform network probing, fuzzing, brute force, exploitation, persistence,
  stealth, or auto-submission.
- **No authentication layer.** The API binds to `127.0.0.1`; do not expose it.
- **No external integrations** (Jira, GitHub, Slack) — out of scope.
- **No CVSS calculator.** We use a transparent severity→CVSS approximation; not
  an NVD-grade score.

See `LEGAL.md` for the safety boundary.