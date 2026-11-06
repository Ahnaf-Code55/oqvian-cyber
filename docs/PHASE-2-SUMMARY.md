# OQVIAN Phase 2 Complete ✅

**Date**: 2026-11-06  
**Commit**: `42f34cc`  
**Repo**: https://github.com/Ahnaf-Code55/oqvian-cyber

---

## What Was Built

### 3 New MCP Tools for Autonomous Attacks

#### 1. **`chain`** — Pre-defined Attack Chains

Run automated attack sequences with backtracking.

**Available Chains:**
- `web-app` — full web app assessment (recon → scan → enumerate → exploit)
- `network` — network reconnaissance and service exploitation
- `ad-attack` — Active Directory enumeration and exploitation
- `box-take` — full box takeover (initial access → privesc → root)

**Example:**
```python
# Run web app attack chain
chain(
    name="web-app",
    target="http://www.example.com",
    verbose=True,
    max_failures=3  # Stop after 3 consecutive failures
)

# Run AD attack chain
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
- Verbose output shows each step as it runs

---

#### 2. **`pivot`** — Tunnel Through Compromised Hosts

Enable lateral movement through SSH tunnels and SOCKS proxies.

**Actions:**
- `list` — show all active pivots
- `ssh_tunnel` — create SSH tunnel through pivot host
- `socks` — create SOCKS proxy for proxychains
- `scan` — scan remote network through pivot
- `close` — close a pivot tunnel

**Example:**
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
pivot(action="scan", remote_target="10.0.0.0/24")

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

#### 3. **`adapt`** — Adaptive Learning from Results

Record what worked/failed and get recommendations.

**Example:**
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

# Record success
adapt(
    technique="CVE-2021-41773",
    result="success",
    reason="path_traversal_worked",
    target="www.example.com"
)
```

**Auto-generated Recommendations:**
| Reason | Result | Recommendation |
|--------|--------|----------------|
| WAF | failed | Try encoded payloads (base64, hex, URL encoding) |
| rate_limit | failed | Slow down requests or use different source IP |
| version_mismatch | failed | Search for alternative exploits for same CVE |
| auth_required | failed | Try credential brute force or find auth bypass |
| timeout | failed | Try simpler/smaller payload or increase timeout |

**Storage**: `~/.local/share/oqvian/state/learning.json`

---

## How It Enables Autonomous Attacks

### Full Attack Chain Example

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
# ▶️  [port_scan] recon...
#    ✅ Success (567 bytes)
#
# ▶️  [vuln_scan] execute...
#    ✅ Success (890 bytes)
#    Output preview: CVE-2021-41773: Apache Path Traversal
#
# ▶️  [dir_enum] execute...
#    ✅ Success (3456 bytes)
#
# ▶️  [js_crawl] execute...
#    ✅ Success (2345 bytes)
#
# 📊 Chain Summary:
#    Total steps: 6
#    Success: 6
#    Failures: 0
#    Duration: 45.2s

# 2. Record adaptive learning
adapt(technique="CVE-2021-41773", result="success", target="www.example.com")

# 3. State is auto-updated with all discoveries
state(action="get", target="www.example.com")
# Output: {"phase": "enumerate", "discovered": {"vulns": ["CVE-2021-41773"]}, ...}

# 4. Collect loot
loot(action="add", target="www.example.com", loot_type="vuln", 
      name="CVE-2021-41773", content="Apache Path Traversal confirmed")

# 5. If we get a shell, create a pivot
pivot(action="ssh_tunnel", pivot_host="www.example.com", 
      pivot_user="www-data", tunnel_port=8080)

# 6. Scan internal network through pivot
pivot(action="scan", remote_target="192.168.1.0/24")
```

---

## Attack Chain Definitions

### web-app Chain
```
recon (HTTP probe) → tech_detect (httpx) → port_scan → 
vuln_scan (nuclei) → dir_enum (ffuf) → js_crawl (katana)
```

### network Chain
```
dns_enum → subdomain_enum → port_scan (1-65535) → 
service_enum (nmap -sV) → vuln_scan (nuclei)
```

### ad-attack Chain
```
smb_enum (netexec) → user_enum → pass_policy → 
kerberos_enum (certipy) → as_replay (GetUserSPNs)
```

### box-take Chain
```
recon → scan (nmap -p-) → vuln_scan (nuclei) → 
dir_brute (gobuster) → sql_test (sqlmap)
```

---

## Files Changed

- `mcp/server.py` — +554 lines (3 new tools + attack chain engine)
- `docs/PHASE-2-SUMMARY.md` — this file

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
```

---

## Next Steps (Phase 3)

Ready to build:
1. **Learning system** — track success rates across sessions
2. **Hacker intuition DB** — "Apache 2.4.49 → CVE-2021-41773 works 80%"
3. **Auto-update corpus** — pull new CVEs/exploits automatically
4. **Cross-session learning** — what worked on target A helps with target B

---

## Status

✅ **Phase 2 COMPLETE**

- [x] `chain` tool (pre-defined attack chains)
- [x] `pivot` tool (SSH tunnels, SOCKS proxies)
- [x] `adapt` tool (adaptive learning)
- [x] Attack chain engine with backtracking
- [x] Auto-state updates during chains
- [x] All changes committed and pushed

**Ready for Phase 3: Learning System**
