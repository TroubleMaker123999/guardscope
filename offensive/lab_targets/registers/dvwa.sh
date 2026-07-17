#!/usr/bin/env bash
# Register DVWA into GuardScope's scope guard whitelist.
set -euo pipefail
cd "$(dirname "$0")/../.."
./.venv/bin/guardscope labs register \
  --name dvwa \
  --host 127.0.0.1 \
  --port 8081 \
  --description "DVWA (intentionally vulnerable PHP app, security=low)"
