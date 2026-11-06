# OQVIAN Progress Summary

**Date**: 2026-11-06  
**Repo**: https://github.com/Ahnaf-Code55/oqvian-cyber

---

## Evolution: Tool Executor → Autonomous Hacker

### Before Phase 1
```
OQVIAN V1.2: Tool Executor
- 5 MCP tools (kb, recon, execute, governance, transform)
- Manual attack chaining
- No state tracking
- Static behavior
```

### After Phase 3
```
OQVIAN V2.0: Autonomous Hacker
- 14 MCP tools (5 original + 9 new)
- Auto attack chains
- Full state tracking
- Adaptive learning
- Cross-session knowledge
```

---

## Phase Breakdown

### Phase 1: Core Enhancements ✅

**Goal**: Add state management and exploit search

**Tools Added** (4):
1. `state` — session state management (get/set discovered, attempted, loot)
2. `loot` — collect findings (flags, creds, configs)
3. `searchsploit` — find exploits by CVE/service
4. `searchsploit_get` — get full exploit code

**Files**:
- `mcp/server.py` +374 lines
- `docs/PHASE-1-SUMMARY.md`

**Commits**:
- `c9a73a5` — feat: Phase 1 state and loot tools
- `feb0388` — feat: Phase 1 searchsploit integration

---

### Phase 2: Autonomous Loops ✅

**Goal**: Build attack chaining and lateral movement

**Tools Added** (6):
1. `chain` — pre-defined attack chains (web-app, network, ad-attack, box-take)
2. `pivot` — SSH tunnels and SOCKS proxies for lateral movement
3. `adapt` — adaptive learning from results (auto-recommendations)
4. `payload` — reverse shell generator (bash, python, php, powershell, etc.)
5. `creds` — auto-credential tester (test, brute, spray, discovered)
6. `backtrack` — alternative technique recommender

**Files**:
- `mcp/server.py` +928 lines
- `docs/PHASE-2-SUMMARY.md`
- `docs/PHASE-2-COMPLETE.md`
- `docs/PHASE-2-DIAGRAM.md`

**Commits**:
- `42f34cc` — feat: Phase 2 - attack chains, pivot, and adaptive reasoning
- `b644b77` — docs: Phase 2 summary with usage examples
- `0f893de` — feat: Phase 2 complete - payload, creds, and backtrack tools
- `7c9f426` — docs: Phase 2 complete documentation with all 6 tools
- `449ac66` — docs: Phase 2 architecture diagrams

---

### Phase 3: Learning System ✅

**Goal**: Track success rates and build hacker intuition

**Tools Added** (4):
1. `learn` — track success/failure rates across sessions
2. `intuition` — hacker intuition database (service/version → likely vulns)
3. `update_corpus` — auto-update knowledge from NVD, ExploitDB, Nuclei
4. `aggregate` — cross-session learning aggregator

**Files**:
- `mcp/server.py` +655 lines
- `docs/PHASE-3-COMPLETE.md`
- `docs/PHASE-3-DIAGRAM.md`

**Commits**:
- `5a2599d` — feat: Phase 3 - learning system with success rates, intuition, and corpus
- `836f731` — docs: Phase 3 complete documentation
- `85b8aa1` — docs: Phase 3 architecture diagrams

---

## Total Statistics

| Metric | Count |
|--------|-------|
| **Total MCP Tools** | 14 (5 original + 9 new) |
| **Lines Added to server.py** | 1,957 |
| **Documentation Files** | 8 |
| **Commits** | 13 |
| **Development Time** | ~3 weeks |
| **Cost** | $0 (all local) |

---

## Tool Catalog

### Original Tools (5)
| Tool | Purpose |
|------|---------|
| `kb` | Knowledge base search (ATT&CK, CWE, CVE, Sigma, etc.) |
| `recon` | Live evidence (DNS, HTTP, TLS, ports, subdomains) |
| `execute` | Run security tools (nmap, nuclei, sqlmap, etc.) |
| `governance` | Scope check and audit log |
| `transform` | Base64/URL/hex/rot13/md5/sha1/sha256 helpers |

### Phase 1 Tools (4)
| Tool | Purpose |
|------|---------|
| `state` | Session state management |
| `loot` | Findings collection |
| `searchsploit` | Exploit search |
| `searchsploit_get` | Exploit code retrieval |

### Phase 2 Tools (6)
| Tool | Purpose |
|------|---------|
| `chain` | Pre-defined attack chains |
| `pivot` | Lateral movement (SSH tunnels, SOCKS) |
| `adapt` | Adaptive learning |
| `payload` | Reverse shell generator |
| `creds` | Auto-credential tester |
| `backtrack` | Alternative recommender |

### Phase 3 Tools (4)
| Tool | Purpose |
|------|---------|
| `learn` | Success rate tracking |
| `intuition` | Hacker intuition database |
| `update_corpus` | Auto-update knowledge |
| `aggregate` | Cross-session learning |

---

## Capabilities Matrix

| Capability | Phase 0 | Phase 1 | Phase 2 | Phase 3 |
|------------|---------|---------|---------|---------|
| **Knowledge Search** | ✅ | ✅ | ✅ | ✅ |
| **Live Recon** | ✅ | ✅ | ✅ | ✅ |
| **Tool Execution** | ✅ | ✅ | ✅ | ✅ |
| **State Tracking** | ❌ | ✅ | ✅ | ✅ |
| **Loot Collection** | ❌ | ✅ | ✅ | ✅ |
| **Exploit Search** | ❌ | ✅ | ✅ | ✅ |
| **Attack Chaining** | ❌ | ❌ | ✅ | ✅ |
| **Lateral Movement** | ❌ | ❌ | ✅ | ✅ |
| **Adaptive Learning** | ❌ | ❌ | ✅ | ✅ |
| **Payload Generation** | ❌ | ❌ | ✅ | ✅ |
| **Credential Testing** | ❌ | ❌ | ✅ | ✅ |
| **Backtracking** | ❌ | ❌ | ✅ | ✅ |
| **Success Rates** | ❌ | ❌ | ❌ | ✅ |
| **Hacker Intuition** | ❌ | ❌ | ❌ | ✅ |
| **Auto-Update Corpus** | ❌ | ❌ | ❌ | ✅ |
| **Cross-Session Learning** | ❌ | ❌ | ❌ | ✅ |

---

## Example: Full Autonomous Attack

```python
# Phase 0: Manual
kb(query="Apache path traversal")  # Read about CVE-2021-41773
recon(action="http", target="www.example.com")  # Manual recon
execute(tool="nmap", args="-sV www.example.com")  # Manual scan
# ... manually chain everything ...

# Phase 1: State-aware
state(action="set", target="www.example.com", discovered={"ports": [80]})
chain(name="web-app", target="www.example.com")  # Auto-chain
loot(action="add", target="www.example.com", loot_type="vuln", name="CVE-2021-41773")

# Phase 2: Adaptive
chain(name="web-app", target="www.example.com")
adapt(technique="CVE-2021-41773", result="failed", reason="WAF")  # Learn
backtrack(target="www.example.com", technique="CVE-2021-41773")  # Get alternatives
payload(action="generate", language="python", lhost="10.0.0.1")  # Generate payload
creds(action="discovered", target="www.example.com")  # Test creds
pivot(action="ssh_tunnel", pivot_host="www.example.com")  # Lateral movement

# Phase 3: Learning
learn(action="record", technique="CVE-2021-41773", result="success",
      service="Apache", version="2.4.49")  # Record success
intuition(action="query", service="Apache", version="2.4.49")  # Query intuition
learn(action="stats")  # Check success rates
update_corpus(action="fetch", source="nvd")  # Update knowledge
aggregate(action="report", target="www.example.com")  # Cross-session report
```

---

## What Each Phase Enables

### Phase 1: State Awareness
```
Before: Attack → Forget
After:  Attack → Record State → Use Later
```

### Phase 2: Autonomy
```
Before: Manual chaining (run tool A, then B, then C)
After:  chain(name="web-app") → Auto-runs A → B → C → D → E
```

### Phase 3: Learning
```
Before: Same behavior every time
After:  "CVE-2021-41773 works 85% on Apache 2.4.49 → try first"
```

---

## Next: Phase 4 (Power Mode)

**Goal**: 32B model, fine-tuning, full autonomy

**Planned Features**:
1. **32B model option** — For complex reasoning and exploit development
2. **Fine-tuning** — Train on hacking corpus (CTF writeups, exploit DB)
3. **Multi-model ensemble** — Small model for recon, large for exploits
4. **Full autonomous mode** — `hack www.target.com` → get root

**Estimated Timeline**: Week 4

---

## File Structure

```
oqvian-cyber/
├── mcp/
│   └── server.py              # 3,200+ lines, 14 MCP tools
├── index/
│   ├── docs.jsonl             # Knowledge corpus
│   ├── embeddings.npy         # Vector embeddings
│   ├── meta.json              # Index metadata
│   ├── cves/                  # Fetched CVE data
│   └── corpus_meta.json       # Corpus update tracking
├── models/
│   └── Modelfile.unlocked     # V1.2 AGGRESSIVE persona
├── docs/
│   ├── HACKER-PLAN.md         # Master plan
│   ├── PHASE-1-SUMMARY.md     # Phase 1 guide
│   ├── PHASE-2-SUMMARY.md     # Phase 2 guide (initial)
│   ├── PHASE-2-COMPLETE.md    # Phase 2 guide (final)
│   ├── PHASE-2-DIAGRAM.md     # Phase 2 architecture
│   ├── PHASE-3-COMPLETE.md    # Phase 3 guide
│   ├── PHASE-3-DIAGRAM.md     # Phase 3 architecture
│   └── PROGRESS-SUMMARY.md    # This file
└── README.md

~/.local/share/oqvian/
├── audit.jsonl                # Tool call audit log
├── state/
│   ├── *.json                 # Per-target state files
│   ├── chains/                # Chain execution history
│   ├── learnings.json         # Technique results
│   ├── intuition.json         # Hacker intuition rules
│   ├── pivots.json            # Active pivot tunnels
│   └── exports/               # Exported target data
└── loot/                      # Collected findings
```

---

## Status

✅ **Phases 1-3 COMPLETE**

- [x] Phase 1: Core Enhancements (state, loot, searchsploit)
- [x] Phase 2: Autonomous Loops (chain, pivot, adapt, payload, creds, backtrack)
- [x] Phase 3: Learning System (learn, intuition, update_corpus, aggregate)
- [ ] Phase 4: Power Mode (32B model, fine-tuning, full autonomy)

**Ready for Phase 4!**

---

## Cost

💰 **$0** — All tools run locally, no API calls required.

**Model**: Qwen2.5-7B-Instruct-abliterated (free community version)  
**Runtime**: Ollama on CPU (i7-5557U, 2c/4t)  
**Storage**: ~5GB (model + index + state)

---

## Quick Start

```bash
# Clone repo
git clone https://github.com/Ahnaf-Code55/oqvian-cyber
cd oqvian-cyber

# Install dependencies
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt

# Pull model
ollama pull qwen2.5:7b

# Run server
.venv/bin/python mcp/server.py

# Test tools
.venv/bin/python -c "
from mcp import server
print(server.chain(name='web-app', target='http://localhost', verbose=False))
print(server.intuition(action='query', service='Apache', version='2.4.49'))
print(server.learn(action='stats'))
"
```

---

## Contributors

- **Ahnaf-Code55** — Author, maintainer
- **Community** — Qwen2.5-7B-Instruct-abliterated model

---

**Last Updated**: 2026-11-06
