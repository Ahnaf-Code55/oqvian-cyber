#!/usr/bin/env bash
# Wire OQVIAN into DeepSeek Harness on Linux/macOS.
# Thin wrapper — the logic lives in scripts/setup_harness.py so that the
# Windows installer can use exactly the same code path.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PY="$ROOT/.venv/bin/python"
[ -x "$PY" ] || PY="python3"
exec "$PY" "$ROOT/scripts/setup_harness.py" --root "$ROOT" "$@"
