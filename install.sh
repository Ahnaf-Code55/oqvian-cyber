#!/usr/bin/env bash
# =============================================================================
#  OQVIAN — one-shot installer for a fresh machine.
#
#    git clone <repo> ~/oqvian-cyber && cd ~/oqvian-cyber
#    bash install.sh                 # full install
#    bash install.sh --no-tools      # skip the Kali-class toolchain (fast)
#    bash install.sh --no-model      # skip the 4.7 GB model pull
#    bash install.sh --no-index      # skip corpus + index build
#    bash install.sh --with-root     # also run install-root-tools.sh (needs sudo)
#    bash install.sh --status        # report what is present, install nothing
#
#  Target: Linux x86_64, 16 GB RAM, 4 GB VRAM. Takes 20-40 min on a fresh box.
# =============================================================================
set -uo pipefail
cd "$(dirname "$0")"
ROOT="$PWD"

DO_TOOLS=1; DO_MODEL=1; DO_INDEX=1; DO_ROOT=0; STATUS=0
for a in "$@"; do
  case "$a" in
    --no-tools)  DO_TOOLS=0 ;;
    --no-model)  DO_MODEL=0 ;;
    --no-index)  DO_INDEX=0 ;;
    --with-root) DO_ROOT=1 ;;
    --status)    STATUS=1 ;;
    --help|-h)   sed -n '3,14p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown option: $a"; exit 1 ;;
  esac
done

ok=0; skip=0; fail=0
step() { printf '\n\033[1m== %s\033[0m\n' "$*"; }
okmsg() { echo "  ok   $*"; ok=$((ok+1)); }
skipmsg() { echo "  skip $*"; skip=$((skip+1)); }
failmsg() { echo "  FAIL $*"; fail=$((fail+1)); }

have() { command -v "$1" >/dev/null 2>&1; }

# --------------------------------------------------------------------------- #
if [ "$STATUS" -eq 1 ]; then
  printf '\n\033[1m== OQVIAN status ==\033[0m\n'
  for pair in \
    "ollama:$(have ollama || [ -x "$HOME/ollama" ] && echo yes)" \
    "python:$([ -x .venv/bin/python ] && echo yes)" \
    "dsh:$(have dsh && echo yes)" \
    "node/npm:$(have npm && echo yes)" \
    "git:$(have git && echo yes)" \
    "models:$([ -f index/meta.json ] && echo yes)" \
    "index:$(grep -q '"count"' index/meta.json 2>/dev/null && echo yes)" \
    "dsh-config:$([ -d "$HOME/.dsh" ] && echo yes)" \
    "scope:$([ -f "$HOME/.config/oqvian/scope.json" ] && echo yes)"
  do
    key=${pair%%:*}; val=${pair#*:}
    printf '  %-12s %s\n' "$key" "${val:-MISSING}"
  done
  echo
  if have ollama || [ -x "$HOME/ollama" ]; then
    O="${OLLAMA_BIN:-$(have ollama && command -v ollama || echo "$HOME/ollama")}"
    echo "  models installed:"
    "$O" list 2>/dev/null | sed 's/^/    /' | head -10
    n=$("$O" show oqvian --template 2>/dev/null | grep -c '\.Tools' || true)
    printf '  oqvian tool template: %s refs %s\n' "$n" \
      "$([ "${n:-0}" -ge 1 ] && echo '(ok)' || echo '(MISSING — run models/build-models.sh)')"
  fi
  exit 0
fi

# --------------------------------------------------------------------------- #
step "1/8  hardware preflight"
chmod +x scripts/*.sh 2>/dev/null
if bash scripts/preflight.sh; then
  # shellcheck disable=SC1091
  . ./hardware.env 2>/dev/null || true
  okmsg "hardware.env written (ctx=${OQVIAN_NUM_CTX:-16384}, gpu=${OQVIAN_GPU_KIND:-none})"
else
  failmsg "preflight"
fi

# --------------------------------------------------------------------------- #
step "2/8  base dependencies"
need_pkgs=()
for c in curl git jq python3 ripgrep unzip tar gcc make; do
  have "$c" || need_pkgs+=("$c")
done
if [ ${#need_pkgs[@]} -gt 0 ]; then
  echo "  missing: ${need_pkgs[*]}"
  if have pacman; then
    echo "  run:  sudo pacman -S --needed --noconfirm ${need_pkgs[*]}"
  elif have apt-get; then
    echo "  run:  sudo apt-get install -y ${need_pkgs[*]}"
  elif have dnf; then
    echo "  run:  sudo dnf install -y ${need_pkgs[*]}"
  fi
  failmsg "install the packages above, then re-run"
else
  okmsg "curl git jq python3 rg gcc make"
fi

# python venv + mcp deps
if [ ! -x .venv/bin/python ]; then
  python3 -m venv .venv && okmsg "created .venv" || failmsg "venv create"
fi
.venv/bin/python -m pip install -q --upgrade pip 2>/dev/null || true
if .venv/bin/python -m pip install -q -r requirements.txt 2>/dev/null; then
  okmsg "python deps (requirements.txt)"
elif .venv/bin/python -m pip install -q mcp numpy httpx dnspython 2>/dev/null; then
  okmsg "python deps (inline: mcp numpy httpx dnspython)"
else
  failmsg "python deps — check network access to pypi"
fi

# --------------------------------------------------------------------------- #
step "3/8  ollama"
OLLAMA_BIN="${OLLAMA_BIN:-}"
if [ -z "$OLLAMA_BIN" ]; then
  for c in ollama "$HOME/ollama" /usr/local/bin/ollama /usr/bin/ollama; do
    have "$c" && { OLLAMA_BIN="$c"; break; }
  done
fi
if [ -z "$OLLAMA_BIN" ]; then
  echo "  ollama not found — installing to ~/.local/bin"
  curl -fsSL https://ollama.com/install.sh | sh
  OLLAMA_BIN="$(command -v ollama || echo "$HOME/.local/bin/ollama")"
fi
if [ -x "$OLLAMA_BIN" ] || have "$OLLAMA_BIN"; then
  okmsg "ollama at $OLLAMA_BIN ($("$OLLAMA_BIN" --version 2>/dev/null | head -1))"
else
  failmsg "ollama install"
fi

# start the service (user unit on systemd, nohup fallback)
systemctl --user enable --now ollama.service 2>/dev/null \
  && okmsg "ollama.service (user)" \
  || { pgrep -f 'ollama serve' >/dev/null || (nohup "$OLLAMA_BIN" serve >/tmp/opencode/ollama.log 2>&1 &) ; okmsg "ollama serve (nohup)"; }

for _ in $(seq 1 40); do
  curl -sf -m 1 http://127.0.0.1:11434/ >/dev/null && break
  sleep 0.5
done
curl -sf -m 3 http://127.0.0.1:11434/ >/dev/null && okmsg "API answers on 127.0.0.1:11434" || failmsg "API not answering"

# GPU offload env for the systemd unit
if [ -f hardware.env ]; then
  DROP="$HOME/.config/systemd/user/ollama.service.d"
  if systemctl --user cat ollama.service >/dev/null 2>&1; then
    mkdir -p "$DROP"
    {
      echo "[Service]"
      # shellcheck disable=SC1091
      . ./hardware.env
      echo "Environment=OLLAMA_FLASH_ATTENTION=1"
      echo "Environment=OLLAMA_KV_CACHE_TYPE=q8_0"
      echo "Environment=OLLAMA_KEEP_ALIVE=30m"
      [ -n "${OLLAMA_VULKAN:-}" ] && echo "Environment=OLLAMA_VULKAN=1"
      [ -n "${OLLAMA_NUM_GPU:-}" ] && echo "Environment=OLLAMA_NUM_GPU=${OLLAMA_NUM_GPU}"
    } > "$DROP/10-oqvian.conf"
    systemctl --user daemon-reload 2>/dev/null
    systemctl --user restart ollama.service 2>/dev/null
    okmsg "GPU offload drop-in $DROP/10-oqvian.conf"
  fi
fi

# --------------------------------------------------------------------------- #
if [ "$DO_MODEL" -eq 1 ]; then
  step "4/8  models (base 4.7 GB + 4 role models, shared layers)"
  if [ -n "$OLLAMA_BIN" ]; then
    OLLAMA_BIN="$OLLAMA_BIN" bash models/build-models.sh && okmsg "5 models built with tool template" || failmsg "model build"
  else
    failmsg "model build (no ollama binary)"
  fi
else
  step "4/8  models — skipped"
  skipmsg "models"
fi

# --------------------------------------------------------------------------- #
if [ "$DO_INDEX" -eq 1 ]; then
  step "5/8  knowledge corpus + FTS5 index"
  if [ -f index/meta.json ] && .venv/bin/python - <<'PY' 2>/dev/null
import json,sys
m=json.load(open("index/meta.json"))
sys.exit(0 if m.get("count",0) > 5000 else 1)
PY
  then
    skipmsg "index already built ($(.venv/bin/python -c 'import json;print(json.load(open("index/meta.json"))["count"])') docs)"
  else
    bash refresh-corpus.sh ${REFRESH_FAST:+--fast} && okmsg "corpus refreshed" || failmsg "corpus clone/download"
    .venv/bin/python -u ingest.py && okmsg "FTS5 index built" || failmsg "ingest"
  fi
else
  step "5/8  index — skipped"
  skipmsg "index"
fi

# --------------------------------------------------------------------------- #
if [ "$DO_TOOLS" -eq 1 ]; then
  step "6/8  Kali-class userland toolchain (no sudo)"
  bash install-tools.sh && okmsg "userland tools" || failmsg "some tools failed (see log above)"
else
  step "6/8  tools — skipped"
  skipmsg "tools"
fi

if [ "$DO_ROOT" -eq 1 ]; then
  step "7/8  root / BlackArch toolset (sudo required)"
  bash install-root-tools.sh && okmsg "root tools" || failmsg "root tools — re-run: bash install-root-tools.sh"
else
  step "7/8  root tools — not requested"
  skipmsg "root tools (run: bash install-root-tools.sh)"
fi

# --------------------------------------------------------------------------- #
step "8/8  harness wiring + verification"
if have dsh; then
  bash scripts/setup-harness.sh && okmsg "dsh profiles, settings, scope wired" || failmsg "setup-harness"
else
  echo "  dsh not installed. Install the harness once:"
  echo "    npm i -g @deepseek-ai/dsh@0.1.1-rc.2"
  echo "    dsh web --no-open --port 0    # creates ~/.dsh, then Ctrl-C"
  echo "    bash scripts/setup-harness.sh"
  skipmsg "harness (install dsh, then re-run this script)"
fi

.venv/bin/python mcp/smoke_test.py >/tmp/opencode/oqvian-smoke.log 2>&1 \
  && okmsg "tool server smoke test (19 checks)" \
  || { failmsg "smoke test — see /tmp/opencode/oqvian-smoke.log"; tail -5 /tmp/opencode/oqvian-smoke.log; }

# --------------------------------------------------------------------------- #
printf '\n\033[1m== summary ==\033[0m\n'
echo "  ok $ok   skipped $skip   failed $fail"
echo
if [ "$fail" -eq 0 ]; then
  cat <<'EOF'
  Ready.

    oqvian                   # web UI
    oqvian-cli "question"    # one-shot
    ollama run oqvian-ciso   # direct role model

  Scope (edit before any engagement):  ~/.config/oqvian/scope.json
  Audit trail:                         ~/.local/share/oqvian/audit.jsonl
EOF
else
  echo "  Fix the FAIL lines above and re-run: bash install.sh"
fi
[ "$fail" -eq 0 ] && [ "$STATUS" -eq 0 ] && exit 0
exit 0
