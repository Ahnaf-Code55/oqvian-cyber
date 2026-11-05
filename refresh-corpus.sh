#!/usr/bin/env bash
# Refresh the OQVIAN knowledge corpus and rebuild the search index.
# Run weekly: security data expires fast (KEV/NVD/Sigma change daily).
#
#   ./refresh-corpus.sh          # update everything (clones whatever is missing)
#   ./refresh-corpus.sh --fast   # skip the ~400 MB atomic-red-team repo
#   ./refresh-corpus.sh --no-index  # update sources only
#
# Safe on a fresh machine: anything absent is cloned/downloaded; anything
# present is fast-forwarded.
set -eu
cd "$(dirname "$0")"
ROOT="$PWD"
RAW="$ROOT/corpus/raw"
mkdir -p "$RAW"
cd "$RAW"

FAST=0
NO_INDEX=0
for a in "$@"; do
  case "$a" in
    --fast)     FAST=1 ;;
    --no-index) NO_INDEX=1 ;;
    *) echo "unknown option: $a"; exit 1 ;;
  esac
done

fetch() { # url  filename
  if curl -fsSL --retry 3 -o "$2" "$1"; then
    printf '  %-24s %s\n' "$2" "$(du -h "$2" | cut -f1)"
  else
    echo "  FAIL $2" >&2
    return 1
  fi
}

echo "== ATT&CK =="
fetch https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json \
      enterprise-attack.json

echo "== CWE =="
fetch https://cwe.mitre.org/data/xml/cwec_latest.xml.zip cwec_latest.xml.zip
rm -f cwec_v*.xml

echo "== CISA KEV =="
fetch https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json kev.json
python3 - <<'PY' 2>/dev/null || true
import json
d = json.load(open("kev.json"))
print("  KEVs:", len(d.get("vulnerabilities", [])), "catalog:", d.get("catalogVersion"))
PY

echo "== LOLBAS =="
fetch https://lolbas-project.github.io/api/lolbas.json lolbas.json

echo "== git repos (clone if missing, else fast-forward) =="
repos="SigmaHQ/sigma OWASP/wstg GTFOBins/GTFOBins.github.io"
[ "$FAST" -eq 0 ] && repos="$repos redcanaryco/atomic-red-team"

for r in $repos; do
  d=$(basename "$r")
  if [ -d "$d/.git" ]; then
    if git -C "$d" pull -q --ff-only 2>/dev/null; then
      echo "  updated $d"
    else
      echo "  kept $d (not fast-forwardable; left as is)"
    fi
  elif [ -e "$d" ]; then
    echo "  kept $d (exists, not a git checkout)"
  else
    if git clone --depth 1 -q "https://github.com/$r.git" "$d" 2>/dev/null; then
      echo "  cloned  $d"
    else
      echo "  FAIL    $d (clone failed — corpus will be incomplete)" >&2
    fi
  fi
done

if [ "$NO_INDEX" -eq 1 ]; then
  echo "== index rebuild skipped (--no-index) =="
  exit 0
fi

echo "== rebuilding index =="
cd "$ROOT"
PY="$ROOT/.venv/bin/python"
[ -x "$PY" ] || PY=python3
OLLAMA_HOST="${OLLAMA_HOST:-127.0.0.1:11434}" "$PY" -u ingest.py
echo "== done =="
