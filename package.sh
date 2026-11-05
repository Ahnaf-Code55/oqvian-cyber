#!/usr/bin/env bash
# Build a clean, self-contained handoff bundle.
#
#   ./package.sh                  # code + docs only (~1 MB)
#   ./package.sh --with-index     # + the built FTS5 index (saves a 9-min ingest)
#   ./package.sh --with-corpus    # + the corpus sources (saves a 559 MB download)
#   ./package.sh --all            # + index, corpus and the 4.7 GB Ollama store
#
# --all is what you hand to an air-gapped machine. Everything else assumes the
# recipient has internet for the weight pull and the corpus refresh.
#
# Never included: .venv, dist/, tools/, scope.json, audit.jsonl, settings
# backups, __pycache__, hardware.env. The recipient gets a source tree, not your
# engagement data.
set -euo pipefail
cd "$(dirname "$0")"
ROOT="$PWD"

WITH_INDEX=0; WITH_CORPUS=0; WITH_MODEL=0
OUT="$ROOT/dist"
NAME="oqvian-cyber-$(date +%Y%m%d)"

while [ $# -gt 0 ]; do
  case "$1" in
    --with-index)  WITH_INDEX=1 ;;
    --with-corpus) WITH_CORPUS=1 ;;
    --with-model)  WITH_MODEL=1 ;;
    --all)         WITH_INDEX=1; WITH_CORPUS=1; WITH_MODEL=1 ;;
    --out)         shift; OUT="$1" ;;
    -h|--help)     sed -n '2,17p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown option: $1" >&2; exit 1 ;;
  esac
  shift
done

mkdir -p "$OUT"
STAGE=$(mktemp -d "${OUT%/}/.stage.XXXXXX")
trap 'rm -rf "$STAGE"' EXIT
DEST="$STAGE/$NAME"
mkdir -p "$DEST"

say() { printf '\033[1m== %s\033[0m\n' "$*"; }

say "staging source tree"
tar -cf - -C "$ROOT" \
  --exclude='./.venv' \
  --exclude='./dist' \
  --exclude='./tools' \
  --exclude='./.git' \
  --exclude='./hardware.env' \
  --exclude='./__pycache__' \
  --exclude='*/__pycache__' \
  --exclude='*.pyc' \
  --exclude='./*.bak.*' \
  --exclude='./models/.base.raw' \
  --exclude="./$NAME.tar.gz" \
  . | tar -xf - -C "$DEST"

# Generated data is opt-in so a normal handoff stays small.
if [ "$WITH_INDEX" -eq 0 ]; then rm -rf "$DEST/index"; fi
if [ "$WITH_CORPUS" -eq 0 ]; then rm -rf "$DEST/corpus"; fi

say "stripping machine-local state"
# The scope file and the audit log belong to whoever ran the engagement.
rm -f "$DEST"/.config/oqvian/scope.json "$DEST"/audit.jsonl
rm -rf "$DEST"/.dsh
# A stray virtualenv inside the tree would be wrong on another OS.
rm -rf "$DEST"/.venv

if [ "$WITH_INDEX" -eq 1 ] && [ -f "$ROOT/index/fts.db" ]; then
  say "including index ($(du -sh "$ROOT/index" | cut -f1))"
fi
if [ "$WITH_CORPUS" -eq 1 ]; then
  say "including corpus ($(du -sh "$ROOT/corpus/raw" 2>/dev/null | cut -f1))"
fi

if [ "$WITH_MODEL" -eq 1 ]; then
  say "including Ollama model store ($(du -sh "$HOME/.ollama/models" 2>/dev/null | cut -f1))"
  # Hardlink to avoid doubling disk use; fall back to a copy on a different fs.
  if ! cp -al "$HOME/.ollama/models" "$DEST/ollama-models" 2>/dev/null; then
    cp -a "$HOME/.ollama/models" "$DEST/ollama-models"
  fi
fi

# Read-me-first at the top of the tree.
cp "$ROOT/docs/HANDOFF.md" "$DEST/HANDOFF.md"

say "writing manifest"
{
  echo "bundle:  $NAME"
  echo "built:   $(date -Iseconds)"
  echo "host:    $(uname -srm)"
  echo "index:   $([ "$WITH_INDEX" -eq 1 ] && echo included || echo 'not included (installer builds it)')"
  echo "corpus:  $([ "$WITH_CORPUS" -eq 1 ] && echo included || echo 'not included (refresh-corpus.sh fetches it)')"
  echo "weights: $([ "$WITH_MODEL" -eq 1 ] && echo 'included in ollama-models/' || echo 'not included (installer pulls 4.7 GB)')"
  echo
  echo "verify:  sha256sum -c $NAME.sha256"
} > "$DEST/BUNDLE.txt"

say "compressing"
ARCHIVE="$OUT/$NAME.tar.gz"
tar -czf "$ARCHIVE" -C "$STAGE" "$NAME"

( cd "$OUT" && sha256sum "$(basename "$ARCHIVE")" > "$NAME.sha256" )

say "done"
printf '  %s\n' "$ARCHIVE"
printf '  size      %s\n' "$(du -h "$ARCHIVE" | cut -f1)"
printf '  sha256    %s\n' "$(cut -d' ' -f1 "$OUT/$NAME.sha256")"
printf '  files     %s\n' "$(tar -tzf "$ARCHIVE" | wc -l)"
echo
echo "  hand over $ARCHIVE and $NAME.sha256."
echo "  the recipient verifies with: sha256sum -c $NAME.sha256"
