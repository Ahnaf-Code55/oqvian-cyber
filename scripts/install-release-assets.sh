#!/usr/bin/env bash
# Install the built OQVIAN artefacts from this repository's GitHub Release,
# without touching HuggingFace or npm.
#
#   ./scripts/install-release-assets.sh
#   ./scripts/install-release-assets.sh --tag v1.0.0
#   ./scripts/install-release-assets.sh --models-only
#   ./scripts/install-release-assets.sh --harness-only
#
# What it does:
#   1. downloads the split model archive, reassembles it, extracts the Ollama
#      store into ~/.ollama/models  (5 OQVIAN models + nomic-embed-text)
#   2. optionally installs @deepseek-ai/dsh@0.1.1-rc.2 from the shipped npm
#      cache, fully offline
#
# These are the BUILT models: the Qwen2.5 tool-calling template and the role
# system prompts are already baked in. Pulling the upstream GGUF instead would
# give you a model that cannot call tools.
set -euo pipefail
cd "$(dirname "$0")/.."
ROOT="$PWD"

REPO="Ahnaf-Code55/oqvian-cyber"
TAG="v1.0.0"
DO_MODELS=1
DO_HARNESS=1

while [ $# -gt 0 ]; do
  case "$1" in
    --tag)          shift; TAG="$1" ;;
    --models-only)  DO_HARNESS=0 ;;
    --harness-only) DO_MODELS=0 ;;
    -h|--help)      sed -n '2,19p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown option: $1" >&2; exit 1 ;;
  esac
  shift
done

say()  { printf '\033[1m== %s\033[0m\n' "$*"; }
ok()   { printf '  ok   %s\n' "$*"; }
warn() { printf '  warn %s\n' "$*"; }
die()  { printf '  FAIL %s\n' "$*" >&2; exit 1; }

TMP="$(mktemp -d "${TMPDIR:-/tmp}/oqvian-rel.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT

# Only pull the assets the requested mode needs, so --harness-only does not sit
# through a 4.7 GB model download it is going to ignore.
PATTERNS=()
[ "$DO_MODELS"  -eq 1 ] && PATTERNS+=("oqvian-models-*")
[ "$DO_HARNESS" -eq 1 ] && PATTERNS+=("oqvian-harness-*")

# Prefer gh (handles the private repo's auth for us); fall back to curl+token.
fetch_release() {
  if command -v gh >/dev/null 2>&1; then
    gh release download "$TAG" --repo "$REPO" --dir "$TMP" --clobber \
      $(for p in "${PATTERNS[@]}"; do printf -- '--pattern %s ' "$p"; done)
  else
    [ -n "${GH_TOKEN:-}" ] || die "install gh, or export GH_TOKEN=<token with repo scope>"
    api="https://api.github.com/repos/$REPO/releases/tags/$TAG"
    curl -fsSL -H "Authorization: Bearer $GH_TOKEN" "$api" \
      | python3 -c 'import json,sys
pats = sys.argv[1:]
for a in json.load(sys.stdin)["assets"]:
    if any(__import__("fnmatch").fnmatch(a["name"], p) for p in pats):
        print(a["name"], a["url"])' "${PATTERNS[@]}" \
      | while read -r name url; do
          curl -fsSL -H "Authorization: Bearer $GH_TOKEN" \
               -H "Accept: application/octet-stream" -o "$TMP/$name" "$url"
          printf '  got  %s\n' "$name"
        done
  fi
}

say "fetching release $TAG from $REPO"
fetch_release

# --------------------------------------------------------------------------- #
if [ "$DO_MODELS" -eq 1 ]; then
  say "models"
  parts=$(find "$TMP" -name 'oqvian-models-*.tar.part-*' | sort)
  [ -n "$parts" ] || die "no oqvian-models-*.tar.part-* in the release"

  n=$(printf '%s\n' "$parts" | wc -l)
  # shellcheck disable=SC2086
  total=$(du -ch $parts | tail -1 | cut -f1)
  echo "  $n parts, $total"

  cat $parts > "$TMP/models.tar"

  sha_file=$(find "$TMP" -maxdepth 1 -name 'oqvian-models-*.sha256' | head -1)
  if [ -n "$sha_file" ]; then
    echo "  verifying part checksums"
    ( cd "$TMP" && sha256sum -c "$(basename "$sha_file")" --quiet ) \
      || die "checksum mismatch — re-download"
    ok "checksums match"
  else
    warn "no .sha256 asset in the release — skipping verification"
  fi

  dest="$HOME/.ollama"
  mkdir -p "$dest"
  if [ -d "$dest/models/blobs" ]; then
    warn "merging into an existing store; shared blobs are not duplicated"
  fi
  tar -xf "$TMP/models.tar" -C "$dest"
  ok "extracted into $dest/models"

  if command -v ollama >/dev/null 2>&1; then
    systemctl --user start ollama 2>/dev/null || true
    for _ in $(seq 1 20); do
      curl -sf -m 1 http://127.0.0.1:11434/ >/dev/null && break
      sleep 0.3
    done
    echo
    ollama list | sed 's/^/  /'
  else
    warn "ollama not installed yet — install it, then models appear in 'ollama list'"
  fi
fi

# --------------------------------------------------------------------------- #
if [ "$DO_HARNESS" -eq 1 ]; then
  say "harness"
  cache_tar=$(find "$TMP" -name 'oqvian-harness-*.tar' | head -1)
  if [ -z "$cache_tar" ]; then
    warn "no oqvian-harness-*.tar in the release — skipping (use npm instead)"
  else
    command -v npm >/dev/null 2>&1 || die "npm not found — install Node.js 18+ first"
    mkdir -p "$TMP/cache"
    tar -xf "$cache_tar" -C "$TMP/cache"

    # The cache dir is the single top-level entry the archive was built from.
    cachedir=$(find "$TMP/cache" -maxdepth 1 -mindepth 1 -type d | head -1)
    [ -n "$cachedir" ] || die "unexpected harness archive layout"

    if command -v dsh >/dev/null 2>&1; then
      ok "dsh already installed ($(dsh --version 2>/dev/null | head -1))"
    else
      echo "  installing @deepseek-ai/dsh@0.1.1-rc.2 from cache (no network)"
      npm install -g @deepseek-ai/dsh@0.1.1-rc.2 \
        --cache "$cachedir" --offline --no-audit --no-fund >/dev/null 2>&1 \
        || die "offline install failed — is this the pinned version?"
      command -v dsh >/dev/null 2>&1 \
        && ok "dsh $(dsh --version 2>/dev/null | head -1)" \
        || die "dsh installed but not on PATH — check: npm prefix -g"
    fi
  fi
fi

say "done"
cat <<EOF
  Next:
    bash install.sh              # everything else; it skips what is now present
    .venv/bin/python scripts/brand_harness.py   # if you skipped install.sh

  Verify:
    ollama show oqvian --template | grep -c '.Tools'   # expect 3
EOF
