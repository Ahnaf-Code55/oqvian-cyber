#!/usr/bin/env bash
# Rebuild OQVIAN models with Qwen2.5 tool-calling support.
#
# The GGUF's bundled template has no `.Tools` block, so Ollama never renders
# tool schemas into the prompt and the model can never emit a tool call.
# This installs the official Qwen2.5 tool template on the base model and
# rebuilds the role models on top of it.
#
# Fresh machine: pulls hf.co/bartowski/WhiteRabbitNeo-2.5-... Q4_K_M (4.7 GB)
# Existing machine: reuses the local `oqvian` model, only the template changes.
set -euo pipefail
cd "$(dirname "$0")"
export OLLAMA_HOST="${OLLAMA_HOST:-127.0.0.1:11434}"
OLLAMA="${OLLAMA_BIN:-$HOME/ollama}"
command -v "$OLLAMA" >/dev/null 2>&1 || OLLAMA="$(command -v ollama)"

TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT

if "$OLLAMA" show oqvian >/dev/null 2>&1; then
  echo "== base exists, preserving its system prompt =="
  "$OLLAMA" show oqvian --modelfile > "$TMP/base.raw"
else
  echo "== base missing, starting from models/Modelfile.base =="
  cp Modelfile.base "$TMP/base.raw"
fi

python3 - "$TMP/base.raw" "$TMP/base.mf" <<'PY'
import sys
from pathlib import Path
src = Path(sys.argv[1]).read_text().splitlines()
out, skip = [], False
for line in src:
    if line.startswith("TEMPLATE "):
        skip = True
        continue
    if skip:
        if line.strip() == '"' or line.rstrip().endswith('"""'):
            skip = False
        continue
    out.append(line)
tpl = Path("qwen-tools.template").read_text().rstrip()
Path(sys.argv[2]).write_text("\n".join(out).rstrip() + f'\n\nTEMPLATE """\n{tpl}\n"""\n')
print("prepared base modelfile")
PY

echo "== rebuilding base (pulls the GGUF on a fresh machine) =="
"$OLLAMA" create oqvian -f "$TMP/base.mf" | tail -1
"$OLLAMA" cp oqvian oqvian:defensive-offensive | tail -1

echo "== rebuilding role models =="
for r in ciso offensive defensive ir; do
  "$OLLAMA" create "oqvian-$r" -f "Modelfile.$r" | tail -1
done

echo "== verify =="
for m in oqvian oqvian-ciso oqvian-offensive oqvian-defensive oqvian-ir; do
  n=$("$OLLAMA" show "$m" --template 2>/dev/null | grep -c '\.Tools' || true)
  printf '%-22s .Tools refs: %s\n' "$m" "$n"
done
"$OLLAMA" list | head -8
