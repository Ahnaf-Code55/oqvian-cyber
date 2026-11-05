#!/usr/bin/env bash
# Build the single OQVIAN model: OQVIAN-CYBER-CONTROL-FULL UNLOCKED V1.1.
#
# One model. An abliterated (refusal-reflex removed) security base with a unified
# operator/CISO persona and the Qwen2.5 tool template, so the operator's CISO can
# drive the Kali tool surface with it.
#
# Base choice: Qwen2.5-7B-Instruct-abliterated, NOT Qwen2.5-Coder-...-abliterated.
# The abliterated *Coder* base cannot emit the <tool_call> wrapper (it fences the
# JSON in ```json, so Ollama parses zero tool calls). The abliterated *Instruct*
# base keeps the native Qwen tool-calling reflex. Verified 2026-11-06.
#
# The GGUF's bundled template has no `.Tools` block, so Ollama never renders
# tool schemas into the prompt and the model can never emit a tool call. This
# appends the official Qwen2.5 tool template from models/qwen-tools.template.
#
# Fresh machine: pulls the abliterated GGUF (~4.7 GB).
# Existing machine: rebuilds the manifest, persona and template only.
#
# Offline: set ABLITERATED_FROM=/path/to/model.gguf
set -euo pipefail
cd "$(dirname "$0")"
export OLLAMA_HOST="${OLLAMA_HOST:-127.0.0.1:11434}"
OLLAMA="${OLLAMA_BIN:-$HOME/ollama}"
command -v "$OLLAMA" >/dev/null 2>&1 || OLLAMA="$(command -v ollama)"

MODEL="oqvian-cyber-control-full-unlocked-v1.1"
PERSONA="Modelfile.unlocked"
FROM_REF="${ABLITERATED_FROM:-hf.co/mradermacher/Qwen2.5-7B-Instruct-abliterated-GGUF:Q4_K_M}"

# Compose the final Modelfile: persona from the persona file (FROM swapped to the
# chosen weights) + the tool template appended.
python3 - "$PERSONA" "$FROM_REF" "$MODEL.mf" <<'PY'
import sys
from pathlib import Path

src_path, from_ref, out_path = sys.argv[1], sys.argv[2], sys.argv[3]
src = Path(src_path).read_text().splitlines()
out, skip = [], False
for line in src:
    if line.startswith("TEMPLATE "):
        skip = True
        continue
    if skip:
        if line.strip() == '"' or line.rstrip().endswith('"""'):
            skip = False
        continue
    if line.startswith("FROM "):
        out.append(f"FROM {from_ref}")
        continue
    out.append(line)

tpl = Path("qwen-tools.template").read_text().rstrip()

# --- hardening: fail loudly instead of building a silently-wrong model ------
assert not any(l.strip() == '"""' for l in tpl.splitlines()), \
    'qwen-tools.template has a bare """ line (would close the TEMPLATE block early)'
assert any(l.startswith('FROM ') for l in out), 'persona has no FROM line'
final = "\n".join(out).rstrip() + f'\n\nTEMPLATE """\n{tpl}\n"""\n'
froms = [l for l in final.splitlines() if l.startswith('FROM ')]
assert len(froms) == 1, f'expected exactly one FROM line, found {len(froms)}: {froms}'
assert final.count('\nTEMPLATE """') == 1, 'expected exactly one TEMPLATE block'
Path(out_path).write_text(final)
print(f"prepared {out_path} (FROM {from_ref})")
PY

echo "== creating $MODEL =="
"$OLLAMA" create "$MODEL" -f "$MODEL.mf" | tail -1
rm -f "$MODEL.mf"

echo "== verify =="
"$OLLAMA" show "$MODEL" --template 2>/dev/null | grep -c '\.Tools' \
  | awk -v m="$MODEL" '{ printf "%-34s .Tools refs: %s\n", m, $1; if ($1 < 1) exit 1 }'
"$OLLAMA" show "$MODEL" 2>/dev/null | sed -n '1,12p'

# Prune every retired name (pre-rename base, multi-persona roles, pre-abliteration
# and abliterated family tags) so exactly one OQVIAN model remains.
STALE="oqvian oqvian-ciso oqvian-offensive oqvian-defensive oqvian-ir
oqvian-abliterated oqvian-abliterated-ciso oqvian-abliterated-offensive
oqvian-abliterated-defensive oqvian-abliterated-ir"
for m in $STALE; do
  if "$OLLAMA" show "$m" >/dev/null 2>&1; then
    "$OLLAMA" rm "$m" >/dev/null 2>&1 && echo "pruned $m" || echo "could not prune $m"
  fi
done
for tag in oqvian:defensive-offensive oqvian-abliterated:defensive-offensive; do
  if "$OLLAMA" show "$tag" >/dev/null 2>&1; then
    "$OLLAMA" rm "$tag" >/dev/null 2>&1 && echo "pruned $tag" || true
  fi
done

echo "== final model list =="
"$OLLAMA" list | grep -E '^(NAME|oqvian)' || true
