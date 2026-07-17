# GuardScope Web Console

## Positioning

The frontend is an original security-operations console built around the
**Monitor + Operate** surface archetypes. It emphasizes risk-ranked findings,
severity distribution, evidence, local-lab scope, import workflows, and report
export. It is intentionally not an attack console: the backend remains an
ingestion/reporting platform with loopback-only lab scope enforcement.

## Stack

- Vite 5
- React 18
- TypeScript 5
- lucide-react for semantic interface icons
- CSS custom-property token system in `src/styles/app.css`
- Hash navigation to keep the demo dependency-light

## Development

```bash
cd frontend
npm install
npm run dev
```

The dev server binds to `127.0.0.1:5173`. Requests to `/api` are rewritten by
Vite to the FastAPI server (default `http://127.0.0.1:8000`). Override the
target with:

```bash
VITE_API_PROXY_TARGET=http://127.0.0.1:9000 npm run dev
```

The client reads `VITE_API_BASE_URL`, defaulting to `/api`. For a deployed
same-origin reverse proxy, leave it at `/api`; for a local direct API, set it to
`http://127.0.0.1:8000` and add the serving origin to
`GUARDSCOPE_CORS_ORIGINS` if it is not one of the default Vite origins.

## Views

- Dashboard: live/demo status, KPIs derived from findings, top-risk list,
  severity distribution, and registered labs.
- Findings: search/filter/risk sorting, detail inspection, evidence and
  remediation presentation.
- Local labs: register loopback labs and validate scope before any future
  verification workflow.
- Import & reports: upload supported scanner reports and download Markdown,
  HTML, JSON, or SARIF output.

When the API is unavailable, the UI switches to explicit demo mode using the
checked-in fixture-shaped data. It never labels demo records as live data.

## API contract used by the client

```text
GET  /health
GET  /findings?sort=risk&limit=1000
GET  /labs
GET  /scope/check?host=127.0.0.1
POST /labs
POST /import (multipart: file, optional source)
GET  /report/raw?format=markdown|html|json|sarif
```

The FastAPI app uses a loopback-only CORS allow-list by default. To add a
known, explicitly controlled development origin:

```bash
GUARDSCOPE_CORS_ORIGINS="https://guardscope.internal" \
  ./.venv/bin/guardscope serve --host 127.0.0.1 --port 8000
```

The environment variable extends the defaults; wildcard `*` is not used by
default.

## Production notes

- Build with `npm run build`; serve `frontend/dist` through a same-origin
  reverse proxy to the loopback API.
- Do not expose the unauthenticated API outside a trusted boundary. Add an
  authentication layer and TLS termination before team or public deployment.
- Keep `VITE_API_BASE_URL=/api` when using a reverse proxy that forwards `/api`
  to FastAPI.
- CI runs backend pytest and frontend typecheck/build without credentials.