#!/usr/bin/env bash
# OQVIAN — Kali-class toolset installer for Arch/CachyOS (needs sudo password).
#
# Arch has no Kali repo; the equivalent is BlackArch (2,800+ security packages)
# plus AUR. This script maps the standard Kali tool menu onto Arch packages.
#
#   ./install-root-tools.sh                # curated core set (~110 tools, ~8 GB)
#   ./install-root-tools.sh --group web,ad # only selected groups
#   ./install-root-tools.sh --list         # show groups and packages
#   ./install-root-tools.sh --blackarch    # add the BlackArch repo first
#   ./install-root-tools.sh --everything   # blackarch-all (very large, 20 GB+)
#
# Run as your normal user (paru escalates for the install step). Do NOT run the
# whole script with sudo — paru refuses to build as root.
set -u

GROUPS="recon web exploitation passwords wireless sniffing forensics reversing ad cloud mobile c2 tunneling social"

declare -A PKGS
PKGS[recon]="nmap masscan whois dnsrecon dnsenum fierce amass subfinder theharvester recon-ng spiderfoot whatweb wafw00f nuclei httpx naabu katana tlsx dnsx cdncheck asnmap enum4linux-ng"
PKGS[web]="nikto sqlmap gobuster ffuf feroxbuster dirb dirsearch wpscan commix zaproxy burpsuite-suite whatweb nuclei"
PKGS[exploitation]="metasploit exploitdb searchsploit msfpc beef bettercap responder impacket netexec certipy evil-winrm kerbrute"
PKGS[passwords]="hashcat john hydra medusa ncrack crunch cewl hashid seclists"
PKGS[wireless]="aircrack-ng reaver bully pixiewps wifite kismet hcxdumptool hcxtools mdk4"
PKGS[sniffing]="wireshark-qt tcpdump ettercap dsniff mitmproxy socat proxychains-ng"
PKGS[forensics]="autopsy sleuthkit volatility3 binwalk foremost scalpel bulk-extractor exiftool dc3dd yara clamav oletools pdf-parser"
PKGS[reversing]="radare2 rizin ghidra gdb upx patchelf binwalk"
PKGS[ad]="bloodhound certipy netexec impacket kerbrute enum4linux-ng ldapdomaindump"
PKGS[cloud]="prowler scoutsuite pacu cloudfox trivy grype syft kube-bench kubescape"
PKGS[mobile]="apktool jadx frida objection dex2jar"
PKGS[c2]="sliver havoc mythic"
PKGS[tunneling]="chisel ligolo-ng proxychains-ng sshuttle socat"
PKGS[social]="gophish evilginx2 set"

CORE="recon web exploitation passwords sniffing forensics reversing ad cloud"
EVERYTHING=""

usage() { sed -n '2,20p' "$0" | sed 's/^# \{0,1\}//'; }

list_groups() {
  echo "groups: $GROUPS"
  echo
  for g in $GROUPS; do
    printf '%-12s %s\n' "$g" "${PKGS[$g]}"
    echo
  done
}

add_blackarch() {
  echo "== adding BlackArch repository =="
  if grep -q '^\[blackarch\]' /etc/pacman.conf; then
    echo "already configured"
  else
    curl -fsSL https://blackarch.org/strap.sh -o /tmp/blackarch-strap.sh || {
      echo "!! download failed"; return 1; }
    chmod +x /tmp/blackarch-strap.sh
    sudo /tmp/blackarch-strap.sh || { echo "!! strap failed"; return 1; }
    sudo pacman -Sy --noconfirm
  fi
  echo "ok blackarch repo"
}

install_pkgs() {
  local missing=() ok=() failed=()
  for p in "$@"; do
    if pacman -Q "$p" >/dev/null 2>&1; then ok+=("$p"); continue; fi
    missing+=("$p")
  done
  echo "already installed: ${#ok[@]}"
  echo "installing: ${#missing[@]} packages"
  [ ${#missing[@]} -eq 0 ] && return 0
  if paru -S --needed --noconfirm --skipreview "${missing[@]}"; then
    echo "ok: installed ${#missing[@]}"
  else
    echo "!! batch install had failures; retrying one by one"
    for p in "${missing[@]}"; do
      if paru -S --needed --noconfirm --skipreview "$p" >/dev/null 2>&1; then
        echo "  ok $p"
      else
        echo "  FAIL $p"; failed+=("$p")
      fi
    done
    echo "failed: ${failed[*]:-none}"
  fi
}

GROUP_SEL=""
for a in "$@"; do
  case "$a" in
    --help|-h) usage; exit 0 ;;
    --list) list_groups; exit 0 ;;
    --blackarch) add_blackarch; shift || true ;;
    --everything) EVERYTHING=1 ;;
    --group) shift; GROUP_SEL="${1:-}" ;;
    --group=*) GROUP_SEL="${a#*=}" ;;
  esac
done

command -v paru >/dev/null || { echo "paru is required (sudo pacman -S --needed base-devel git paru)"; exit 1; }

# refresh keystore/repos once
sudo pacman -Sy --noconfirm >/dev/null 2>&1 || true

if [ -n "$EVERYTHING" ]; then
  echo "== installing blackarch-all (very large) =="
  paru -S --needed --noconfirm --skipreview blackarch-all
  echo "done. run: sudo blackarch-linux-tools 2>/dev/null || true"
  exit $?
fi

if [ -n "$GROUP_SEL" ]; then
  sel="${GROUP_SEL//,/ }"
  for g in $sel; do
    [ -n "${PKGS[$g]:-}" ] || { echo "!! unknown group: $g"; echo "known: $GROUPS"; exit 1; }
  done
else
  sel="$CORE"
fi

ALL=""
for g in $sel; do
  echo "== group: $g =="
  ALL="$ALL ${PKGS[$g]}"
done

# dedupe
read -r -a UNIQ <<< "$(printf '%s\n' $ALL | awk '!seen[$0]++' | tr '\n' ' ')"
echo
echo "== installing ${#UNIQ[@]} unique packages =="
install_pkgs "${UNIQ[@]}"

echo
echo "== post-install =="
command -v updatedb >/dev/null && sudo updatedb 2>/dev/null
echo "wordlists:    /usr/share/wordlists (seclists) "
echo "nmap scripts: /usr/share/nmap/scripts ($(ls /usr/share/nmap/scripts 2>/dev/null | wc -l) files)"
echo "metasploit:   msfconsole (first run: msfdb init)"
echo "wireshark:    sudo usermod -aG wireshark \$USER   # then re-login"
echo "aircrack:     needs a monitor-mode capable adapter"
echo
echo "done."
