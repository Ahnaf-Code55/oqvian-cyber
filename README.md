# OQVIAN — World #1 Autonomous Hacker (on a Laptop) 🤖

**Turn your 16GB RAM laptop into an autonomous penetration testing engine.**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Model](https://img.shields.io/badge/Model-Qwen2.5--7B-blue)](https://huggingface.co/mradermacher/Qwen2.5-7B-Instruct-abliterated-GGUF)
[![RAM](https://img.shields.io/badge/RAM-16GB-green)]()
[![Tools](https://img.shields.io/badge/MCP_Tools-17-purple)]()

---

## What is OQVIAN?

OQVIAN is an **autonomous cyber warfare engine** that runs on a standard laptop (16GB RAM, 4GB VRAM). It combines:

- **Qwen2.5-7B** abliterated model (free, runs locally)
- **17 MCP tools** for recon, exploitation, and lateral movement
- **Learning system** that gets smarter with each attack
- **Autonomy engine** that attacks until goal achieved

**One command. Full attack. Zero API costs.**

```python
autonomous_hack(target="www.example.com", scope="full", aggressiveness=8)
# Output: "✅ Root access achieved in 4.5 minutes"
```

---

## Quick Start

### 1. Clone & Setup
```bash
git clone https://github.com/Ahnaf-Code55/oqvian-cyber
cd oqvian-cyber

python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
```

### 2. Pull Model
```bash
ollama pull qwen2.5:7b
# Or use the abliterated version:
ollama pull hf.co/mradermacher/Qwen2.5-7B-Instruct-abliterated-GGUF:Q4_K_M
```

### 3. Configure Scope
```json
// ~/.config/oqvian/scope.json
{
  "targets": [
    "www.example.com",
    "192.168.1.0/24",
    "localhost"
  ]
}
```

### 4. Run Autonomous Attack
```python
from mcp import server

# One-command attack
result = server.autonomous_hack(
    target="www.example.com",
    scope="full",
    aggressiveness=8,
    timeout=3600
)
print(result)
```

---

## The 17 MCP Tools

### Original Tools (5)
| Tool | Purpose |
|------|---------|
| `kb` | Knowledge base (ATT&CK, CVE, Sigma, etc.) |
| `recon` | Live recon (DNS, HTTP, TLS, ports) |
| `execute` | Run security tools (nmap, nuclei, sqlmap) |
| `governance` | Scope check and audit log |
| `transform` | Encoding helpers (base64, hex, etc.) |

### Phase 1: State Management (4)
| Tool | Purpose |
|------|---------|
| `state` | Session state tracking |
| `loot` | Findings collection |
| `searchsploit` | Exploit search |
| `searchsploit_get` | Exploit code retrieval |

### Phase 2: Autonomy (6)
| Tool | Purpose |
|------|---------|
| `chain` | Pre-defined attack chains |
| `pivot` | SSH tunnels, SOCKS proxies |
| `adapt` | Adaptive learning |
| `payload` | Reverse shell generator |
| `creds` | Auto-credential tester |
| `backtrack` | Alternative recommender |

### Phase 3: Learning (4)
| Tool | Purpose |
|------|---------|
| `learn` | Success rate tracking |
| `intuition` | Hacker intuition database |
| `update_corpus` | Auto-update CVEs |
| `aggregate` | Cross-session learning |

### Phase 4: Full Autonomy (3)
| Tool | Purpose |
|------|---------|
| `plan_attack` | Generate attack plans |
| `autonomous_hack` | One-command attack |
| `autonomous_loop` | Attack until goal |

---

## Example Attacks

### Web Application
```python
autonomous_hack(
    target="www.example.com",
    scope="web",
    aggressiveness=7
)
```

**What Happens:**
1. HTTP probe + tech detection
2. Port scan (1-1024)
3. Nuclei vulnerability scan
4. Directory brute force (ffuf)
5. JavaScript crawling (katana)
6. Exploit top vulnerabilities
7. Collect loot + report

**Output:**
```
🤖 Starting Autonomous Attack
   Target: www.example.com
   Scope: web
   
📡 Phase 1: Reconnaissance
   ✅ HTTP probe complete
   ✅ Tech detection complete (Apache 2.4.49)
   
🔍 Phase 2: Enumeration
   ✅ Vulnerability scan complete (CVE-2021-41773)
   
⚔️  Phase 3: Attack
   ✅ Path traversal exploit successful!
   ✅ Shell obtained at /tmp/shell.php
   
📊 Summary:
   Duration: 125s
   Loot: shell.php, config.php
```

---

### Network Penetration
```python
autonomous_loop(
    target="192.168.1.100",
    goal="root",
    strategies="web,ssh,smb",
    timeout=7200
)
```

**What Happens:**
```
Loop:
  1. Assess current state
  2. Plan next attack (using intuition)
  3. Execute attack (web → ssh → smb)
  4. Learn from result
  5. Update state
  6. Check if root achieved
  7. Repeat until goal or timeout
```

---

### Active Directory
```python
chain(name="ad-attack", target="dc.corp.local", 
      user="admin", pass_="password", domain="CORP.LOCAL")
```

**What Happens:**
1. SMB enumeration (netexec)
2. User enumeration
3. Password policy check
4. Kerberos enumeration (certipy)
5. AS-REP roasting
6. Golden ticket attack

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                      OQVIAN Architecture                    │
│                                                              │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐      │
│  │   MODEL      │  │   TOOLS      │  │   MEMORY     │      │
│  │  Qwen2.5-7B  │  │  17 MCP      │  │  State,      │      │
│  │  (4.7GB)     │  │  Tools       │  │  Learnings   │      │
│  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘      │
│         │                 │                 │               │
│         └─────────────────┼─────────────────┘               │
│                           │                                 │
│                           ▼                                 │
│              ┌────────────────────────┐                     │
│              │   AUTONOMY ENGINE      │                     │
│              │  ┌──────────────────┐  │                     │
│              │  │   PLANNER        │  │                     │
│              │  │ (plan_attack)    │  │                     │
│              │  └────────┬─────────┘  │                     │
│              │           │            │                     │
│              │  ┌────────▼─────────┐  │                     │
│              │  │   EXECUTOR       │  │                     │
│              │  │ (autonomous_hack)│  │                     │
│              │  └────────┬─────────┘  │                     │
│              │           │            │                     │
│              │  ┌────────▼─────────┐  │                     │
│              │  │   LEARNER        │  │                     │
│              │  │ (learn, adapt)   │  │                     │
│              │  └──────────────────┘  │                     │
│              └────────────────────────┘                     │
│                                                              │
│  Hardware: i7-11th gen, 16GB RAM, 4GB VRAM                  │
│  Memory: 9.7GB / 16GB ✅                                    │
│  Cost: $0 (all local)                                       │
└─────────────────────────────────────────────────────────────┘
```

---

## Learning System

OQVIAN gets smarter with each attack:

```python
# Record success
learn(
    action="record",
    technique="CVE-2021-41773",
    result="success",
    service="Apache",
    version="2.4.49"
)

# Query intuition next time
intuition(action="query", service="Apache", version="2.4.49")
# → "CVE-2021-41773 (87% confidence, worked 18/21 times)"
```

**Default Intuition Rules (15):**
- Apache 2.4.49 → CVE-2021-41773 (85%)
- WordPress 5.0-5.7 → wp-scanner (80%)
- Docker → docker-socket (80%)
- FortiGate 6.2 → CVE-2018-13379 (90%)
- And 11 more...

---

## Memory Usage

```
OQVIAN 7B model (Q4_K_M):     4.7 GB
Python + dependencies:         1.0 GB
MCP server:                    0.5 GB
Ollama server:                 1.0 GB
Autonomy engine:               0.3 GB
State/learning data:           0.2 GB
System overhead:               2.0 GB
──────────────────────────────────────
Total:                         9.7 GB / 16 GB ✅
Free:                          6.3 GB
```

**Performance:**
- Tokens/sec (GPU): ~10-15 tok/s
- Tokens/sec (CPU): ~3-5 tok/s
- Attack planning: ~0.5s
- Full autonomous hack: ~2-10 minutes

---

## Documentation

- **[HACKER-PLAN.md](docs/HACKER-PLAN.md)** — Master plan and architecture
- **[PHASE-1-SUMMARY.md](docs/PHASE-1-SUMMARY.md)** — State management
- **[PHASE-2-COMPLETE.md](docs/PHASE-2-COMPLETE.md)** — Attack chains & pivoting
- **[PHASE-3-COMPLETE.md](docs/PHASE-3-COMPLETE.md)** — Learning system
- **[PHASE-4-COMPLETE.md](docs/PHASE-4-COMPLETE.md)** — Full autonomy
- **[PROGRESS-SUMMARY.md](docs/PROGRESS-SUMMARY.md)** — All phases summary

---

## Requirements

- **OS**: Linux (Kali recommended), macOS, Windows WSL2
- **RAM**: 16GB minimum (8GB works but slow)
- **GPU**: 4GB VRAM recommended (CPU-only works but slower)
- **Disk**: 10GB free space
- **Python**: 3.10+
- **Ollama**: Latest version

---

## License

MIT License — use freely for authorized security testing.

---

## Contributing

1. Fork the repo
2. Create a feature branch
3. Add new MCP tools or improve existing ones
4. Submit a PR

---

## Stats

- **Total Lines Added**: ~2,500 across 4 phases
- **MCP Tools**: 17 (5 original + 12 new)
- **Documentation**: 10 files, ~2,000 lines
- **Commits**: 20+
- **Development Time**: ~1 month
- **Cost**: $0 (all local, free model)

---

## Acknowledgments

- **Qwen2.5-7B** — Base model from HuggingFace
- **Ollama** — Local LLM runtime
- **Kali Linux** — Security toolchain
- **Mitre ATT&CK** — Technique framework
- **Community** — CTF writeups, exploits, and knowledge

---

**Built with ❤️ for autonomous security testing**

**Last Updated**: 2026-11-06
