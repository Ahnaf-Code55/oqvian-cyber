#!/usr/bin/env bash
# Install the OQVIAN agent preset for the DeepSeek Harness (dsh).
#
# Two problems this fixes on a fresh machine:
#   1. the harness default persona introduces the model as "a coding agent"
#      and waits for permission instead of acting;
#   2. dsh injects every installed skill's name+description into the prompt —
#      174 KB / ~45k tokens on a machine with a few hundred skills, which a
#      CPU-bound model never gets through.
#
# Idempotent: safe to re-run after a dsh upgrade.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/.." && pwd)"
DSH_HOME="${DSH_HOME:-$HOME/.dsh}"
PRESET_SRC="$REPO/deploy/agent-presets/oqvian/agent.cordis.yml"
PRESET_DST="$DSH_HOME/.agent-presets/oqvian"

[ -f "$PRESET_SRC" ] || { echo "missing $PRESET_SRC" >&2; exit 1; }
mkdir -p "$PRESET_DST"
cp "$PRESET_SRC" "$PRESET_DST/agent.cordis.yml"
echo "✓ preset installed: $PRESET_DST/agent.cordis.yml"

SETTINGS="$DSH_HOME/settings.yaml"
if [ -f "$SETTINGS" ]; then
  cp "$SETTINGS" "$SETTINGS.bak.$(date +%Y%m%d-%H%M%S)"
  # Point agent-presets.default at oqvian without rewriting the rest of the file.
  python3 - "$SETTINGS" <<'PY'
import re, sys
p = sys.argv[1]
s = open(p).read()
new, n = re.subn(r"(?m)^(agent-presets:\n(?:[ \t]+.*\n)*?[ \t]+default:[ \t]*)\S+",
                 r"\1oqvian", s, count=1)
if n:
    open(p, "w").write(new)
    print("✓ agent-presets.default → oqvian")
else:
    print("! no agent-presets.default key found — add it manually:\n"
          "  agent-presets:\n    default: oqvian")
PY
else
  echo "! $SETTINGS not found — create it with:\n  agent-presets:\n    default: oqvian"
fi

echo
echo "Verify with:  dsh --profile headless --help  # then check the session prompt size"
echo "Full tool surface (22 MCP tools) is still available: export OQVIAN_TOOLSET=full"
