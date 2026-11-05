#!/usr/bin/env bash
# OQVIAN Kali-style toolchain — userland install (no sudo).
# Static binaries go to ~/.local/bin; source tools to ~/oqvian-cyber/tools.
set -u
BIN="$HOME/.local/bin"; mkdir -p "$BIN"
TOOLS="$HOME/oqvian-cyber/tools"; mkdir -p "$TOOLS"
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
ok=0; fail=0
say() { printf '\n== %s ==\n' "$*"; }

gh_asset() { # repo  asset-regex  binname
  local repo="$1" re="$2" out="$3"
  local url
  url=$(curl -fsSL "https://api.github.com/repos/$repo/releases/latest" \
        | jq -r --arg re "$re" '.assets[] | select(.name|test($re)) | .browser_download_url' | head -1)
  [ -n "$url" ] || { echo "!! no asset $repo / $re"; fail=$((fail+1)); return 1; }
  local f="$TMP/$(basename "$url")"
  curl -fsSL -o "$f" "$url" || { fail=$((fail+1)); return 1; }
  case "$f" in
    *.zip) unzip -qo "$f" -d "$TMP/x" ;;
    *.tar.gz|*.tgz) mkdir -p "$TMP/x"; tar -xzf "$f" -C "$TMP/x" ;;
    *.deb) dpkg-deb -x "$f" "$TMP/x" 2>/dev/null || { fail=$((fail+1)); return 1; } ;;
  esac
  local found
  found=$(find "$TMP/x" -type f -name "$out" -perm -u+x | head -1)
  [ -z "$found" ] && found=$(find "$TMP/x" -type f -name "$out" | head -1)
  [ -n "$found" ] || { echo "!! binary $out not in archive"; fail=$((fail+1)); return 1; }
  install -m 0755 "$found" "$BIN/$out"
  echo "ok $out"; ok=$((ok+1)); rm -rf "$TMP/x"
}

say "ProjectDiscovery (recon / vuln / web)"
for pd in nuclei httpx subfinder naabu dnsx katana tlsx asnmap cdncheck; do
  gh_asset projectdiscovery/$pd "_linux_amd64\\.zip$" "$pd"
done

say "ffuf / feroxbuster (content discovery)"
gh_asset ffuf/ffuf "_linux_amd64\\.tar\\.gz$" ffuf
gh_asset epi052/feroxbuster "x86_64-linux.*\\.tar\\.gz$" feroxbuster

say "cloud / container / secrets"
gh_asset aquasecurity/trivy "Linux-64bit\\.tar\\.gz$" trivy
gh_asset anchore/grype "_linux_amd64\\.tar\\.gz$" grype
gh_asset anchore/syft "_linux_amd64\\.tar\\.gz$" syft
gh_asset gitleaks/gitleaks "linux_x64\\.tar\\.gz$" gitleaks
gh_asset trufflesecurity/trufflehog "_linux_amd64\\.tar\\.gz$" trufflehog

say "gobuster"
gh_asset OJ/gobuster "gobuster_Linux_x86_64\\.tar\\.gz$" gobuster

say "amass"
gh_asset owasp-amass/amass "amass_linux_amd64\\.tar\\.gz$" amass

say "nikto + sqlmap (source, perl/python)"
[ -d "$TOOLS/nikto" ] || git clone --depth 1 -q https://github.com/sullo/nikto.git "$TOOLS/nikto" && echo "ok nikto"
[ -d "$TOOLS/sqlmap" ] || git clone --depth 1 -q https://github.com/sqlmapproject/sqlmap.git "$TOOLS/sqlmap" && echo "ok sqlmap"

say "nmap (compile from source)"
if command -v nmap >/dev/null 2>&1; then echo "already installed"; else
  v=$(curl -fsSL https://nmap.org/dist/ | grep -oE 'nmap-[0-9]+\.[0-9]+\.tar\.bz2' | sort -V | tail -1)
  if [ -n "$v" ]; then
    curl -fsSL -o "$TMP/$v" "https://nmap.org/dist/$v" && \
    tar -xjf "$TMP/$v" -C "$TMP" && \
    ( cd "$TMP/${v%.tar.bz2}" && ./configure --prefix="$HOME/.local" --without-zenmap --without-ncat --without-nping --without-ndiff >/dev/null && make -j4 >/dev/null && make install >/dev/null ) && \
    echo "ok nmap" || { echo "!! nmap build failed"; fail=$((fail+1)); }
  fi
fi

say "Python security tools (pipx)"
for p in semgrep impacket certipy-ad volatility3 oletools dirsearch wafw00f pwntools; do
  if pipx list --short 2>/dev/null | grep -qi "^$p "; then echo "already $p"; continue; fi
  if pipx install -q "$p" >/dev/null 2>&1; then echo "ok $p"; ok=$((ok+1)); else echo "!! pipx $p failed"; fail=$((fail+1)); fi
done

# NetExec is not on PyPI — it installs from git. It also does not support
# Python 3.14 yet, so provision a 3.12 interpreter with uv and keep it isolated.
say "netexec (git install, needs Python <=3.13)"
if command -v netexec >/dev/null 2>&1 || command -v nxc >/dev/null 2>&1; then
  echo "already netexec"
elif command -v uv >/dev/null 2>&1; then
  if uv tool install --python 3.12 "git+https://github.com/Pennyw0rth/NetExec" >/dev/null 2>&1; then
    echo "ok netexec (uv, python 3.12)"; ok=$((ok+1))
  else
    echo "!! netexec via uv failed"; fail=$((fail+1))
  fi
else
  echo "!! netexec skipped — install uv, then:"
  echo "   uv tool install --python 3.12 git+https://github.com/Pennyw0rth/NetExec"
  fail=$((fail+1))
fi

say "summary: ok=$ok fail=$fail"
echo "PATH check: $(ls "$BIN" | wc -l) binaries in $BIN"
