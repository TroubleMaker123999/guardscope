#!/usr/bin/env bash
# Register the Juice Shop lab into GuardScope's scope guard whitelist.
# Run this AFTER `docker compose -f compose/juice-shop.yml up -d`.

set -euo pipefail
cd "$(dirname "$0")/../.."

./.venv/bin/guardscope labs register \
  --name juice-shop \
  --host 127.0.0.1 \
  --port 13000 \
  --description "OWASP Juice Shop (intentionally vulnerable)"
