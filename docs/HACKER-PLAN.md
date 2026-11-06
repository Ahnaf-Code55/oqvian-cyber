# OQVIAN → World #1 Autonomous Hacker

**Goal**: Transform OQVIAN from "tool executor" to "autonomous hacker brain" that can hack literally anything.

---

## Current State (V1.2)

| Layer | What It Is | Gap |
|-------|-----------|-----|
| **Model** | Qwen2.5-7B abliterated | Good, but not fine-tuned on hacking data |
| **Knowledge** | ATT&CK, CWE, CVE, Sigma, Atomic, LOLBAS, GTFOBins, WSTG | Missing: Exploit-DB, Metasploit, CTF writeups, real attack chains |
| **Tools** | 40 Kali tools via `execute` | Missing: Custom exploit runners, fuzzers, payload generators |
| **Harness** | 5 MCP tools (kb, recon, execute, governance, transform) | No autonomous loops, no state, no attack chaining |
| **Memory** | Audit log only | No session state, no discovered creds, no loot tracking |
| **Adaptation** | Static | Doesn't learn from successes/failures |

---

## Layer 1: Model (The Brain)

### Current
```
Qwen2.5-7B-Instruct-abliterated (Q4_K_M)
- 7.6B params, 32K context
- Abliterated (refusal reflex removed)
- Tool calling enabled
```

### What World #1 Needs
1. **Larger base or fine-tuned model**
   - Option A: `Qwen2.5-Coder-32B-Instruct-abliterated` (better code/reasoning)
   - Option B: Fine-tune current model on hacking corpus (CTF writeups, exploit code, recon notes)
   - Option C: Multi-model ensemble (small model for recon, large model for exploit dev)

2. **Hacker persona enhancements**
   - Current: "Execute security work"
   - Needed: "Think like an attacker, chain exploits, adapt to defenses"
   - Add: Lateral movement mindset, privilege escalation patterns, C2 awareness

3. **Reasoning capabilities**
   - Chain-of-thought for attack planning
   - Backtracking when paths fail
   - Hypothesis testing (e.g., "if this is Apache, try CVE-2021-41773")

### Action Items
- [ ] Add `Qwen2.5-Coder-32B-Instruct-abliterated` as optional "power mode"
- [ ] Fine-tune on: HackTheBox writeups, TryHackMe solutions, Exploit-DB PoCs
- [ ] Add "attack planner" system prompt section (goal → paths → execute → adapt)

---

## Layer 2: Knowledge (The Corpus)

### Current
```
~/oqvian-cyber/corpus/
├── attack/      # ATT&CK techniques
├── cve/         # CVE details
├── detection/   # Sigma rules
├── atomic/      # Atomic Red Team
├── lolbas/      # Living-off-the-land
├── gtfobins/    # GTFOBins
└── wstg/        # OWASP WSTG
```

### What World #1 Needs
1. **Exploit database**
   - Exploit-DB full text (50K+ exploits)
   - Metasploit module descriptions + payloads
   - CVE → exploit mapping (which CVE has working exploit?)

2. **Real attack chains**
   - CTF writeups (HackTheBox, TryHackMe, PicoCTF)
   - Red team engagement reports (anonymized)
   - Breach post-mortems (how they actually got in)

3. **Technology fingerprints**
   - "Apache 2.4.49 → CVE-2021-41773 (Path Traversal)"
   - "WordPress 5.8 → WPScan vulns X, Y, Z"
   - "SMBv1 → EternalBlue, MS17-010"

4. **Payload library**
   - Reverse shells (bash, python, php, java, powershell)
   - Encoders (base64, xxd, hex)
   - Obfuscation patterns (for EDR evasion)

### Action Items
- [ ] Download Exploit-DB text files (`searchsploit --json` output)
- [ ] Scrape Metasploit module docs (`msfconsole -q "show modules"`)
- [ ] Add CTF writeup corpus (HTB, TryHackMe)
- [ ] Build "tech → vuln" index (Apache version → CVEs)
- [ ] Add payload generator (language + LHOST + LPORT → shell)

---

## Layer 3: Tools (The Arsenal)

### Current
40 tools via `execute`:
```
nmap, naabu, nuclei, httpx, subfinder, amass, dnsx, katana,
ffuf, feroxbuster, gobuster, nikto, sqlmap,
hashcat, john, hydra,
netexec, certipy,
tshark, tcpdump, volatility3,
semgrep, trivy, gitleaks,
msfconsole, bettercap, masscan, aireplay-ng
```

### What World #1 Needs
1. **Exploit execution**
   - `searchsploit` integration (find → download → run)
   - `msfconsole` automation (use → set → exploit)
   - Custom Python exploit runner (for raw PoCs)

2. **Web app hacking**
   - `burpsuite` automation (via Burp Extension API)
   - `zap` (OWASP ZAP) for automated scanning
   - `xsser`, `dalfox` for XSS
   - `commix` for command injection

3. **Network pivoting**
   - `sshuttle` / `chisel` for tunneling
   - `proxychains` configuration
   - `bettercap` for ARP spoofing/MITM

4. **Active Directory**
   - `impacket` suite (secretsdump, psexec, wmiexec)
   - `bloodhound` / `neophanthasm`
   - `crackmapexec` (already have `netexec`)

5. **Payload generation**
   - `msfvenom` wrapper
   - `veil` / `theFatRat` integration
   - Custom shell generator (bash, python, php, powershell, java)

6. **Custom scripts**
   - Auto-credential tester (try discovered creds on all services)
   - Port forward manager
   - Loot collector (save flags, creds, configs)

### Action Items
- [ ] Add `searchsploit` as tool (find exploits by CVE/service)
- [ ] Add `msfvenom` wrapper (generate payloads)
- [ ] Add `burpsuite` integration (or `zap` as free alternative)
- [ ] Add `impacket` tools (secretsdump, psexec, wmiexec)
- [ ] Add `sshuttle` / `chisel` for pivoting
- [ ] Create `loot` tool (collect and organize findings)

---

## Layer 4: Harness (The Engine)

### Current
```python
# mcp/server.py
Tools: kb, recon, execute, governance, transform
- Stateless: each call independent
- No loops: model calls tool → returns → waits
- No chaining: model must plan entire attack
```

### What World #1 Needs
1. **Autonomous attack loops**
   ```
   RECON → SCAN → ENUMERATE → EXPLOIT → PRIVESC → LATERAL → EXFIL
    ↓        ↓         ↓           ↓          ↓          ↓         ↓
   (if no vuln) → try next technique
   (if exploit fails) → backtrack, try different path
   (if success) → collect loot, move to next target
   ```

2. **State management**
   - Track discovered: ports, services, versions, creds, vulns
   - Track attempted: which exploits tried, which failed/succeeded
   - Track progress: current phase, next steps

3. **Attack chaining**
   - Auto-chain: port 80 → httpx → nuclei → if vuln → exploit
   - Auto-pivot: if SSH found → try creds → if success → scan from inside
   - Auto-escalate: if user shell → check sudo → try privesc exploits

4. **Adaptive reasoning**
   - "Apache 2.4.49 found → try CVE-2021-41773"
   - "Exploit failed → try alternative (searchsploit for same CVE)"
   - "No web vulns → try SSH brute force with discovered users"

5. **Loot collection**
   - Auto-save: flags, passwords, configs, database dumps
   - Organize by target/phase
   - Export to report

### Action Items
- [ ] Add `state` tool (get/set session state: discovered, attempted, loot)
- [ ] Add `chain` tool (pre-defined attack chains: web-app, ad-attack, box-take)
- [ ] Add `pivot` tool (setup tunnel, scan through proxy)
- [ ] Add `loot` tool (collect findings, organize, export)
- [ ] Build autonomous loop: `while not root: try_next_technique()`

---

## Layer 5: Memory (The Brain's Notes)

### Current
```
~/.local/share/oqvian/audit.jsonl
- Every tool call logged
- No session state
- No discovered data stored
```

### What World #1 Needs
1. **Session state**
   ```json
   {
     "target": "www.example.com",
     "phase": "enumeration",
     "discovered": {
       "ports": [22, 80, 443, 3306],
       "services": {"22": "SSH 8.2p1", "80": "Apache 2.4.49"},
       "users": ["admin", "www-data"],
       "creds": [{"user": "admin", "pass": "password123", "source": "config leak"}],
       "vulns": ["CVE-2021-41773"]
     },
     "attempted": [
       {"technique": "CVE-2021-41773", "result": "failed", "reason": "WAF blocked"},
       {"technique": "SSH brute", "result": "success", "creds": "admin:password123"}
     ],
     "loot": [
       {"type": "shell", "path": "/tmp/shell.php", "access": "web"},
       {"type": "password", "value": "admin:password123", "service": "SSH"}
     ]
   }
   ```

2. **Persistent knowledge**
   - Common password lists (rockyou.txt, custom wordlists)
   - Known vulnerable configs
   - Exploit success rates (which exploits work most often)

3. **Cross-session learning**
   - "Apache 2.4.49 → CVE-2021-41773 works 80% of the time"
   - "WordPress sites often have wp-admin exposed"
   - "Default creds work on 15% of IoT devices"

### Action Items
- [ ] Add `~/.local/share/oqvian/state/` directory (per-target state files)
- [ ] Add `state` tool (get/set discovered, attempted, loot)
- [ ] Add `learn` tool (record what worked/failed for future reference)
- [ ] Build "hacker intuition" database (tech → likely vulns)

---

## Layer 6: Adaptation (The Learning Hacker)

### Current
```
Static: same behavior every time
```

### What World #1 Needs
1. **Learn from successes**
   - "This exploit worked on Apache 2.4.49 → try it first next time"
   - "SSH brute with rockyou.txt succeeded → prioritize for SSH"

2. **Learn from failures**
   - "CVE-2021-41773 failed (WAF) → try encoded payload"
   - "Hydra SSH failed (account lockout) → slower retry or different method"

3. **Adapt to defenses**
   - Detect WAF → use encoded payloads
   - Detect rate limiting → slow down
   - Detect EDR → use LOLBAS instead of dropped binaries

4. **Update knowledge**
   - New CVEs → add to corpus
   - New exploits → test and add success rate
   - New tools → integrate into arsenal

### Action Items
- [ ] Add `success_rate` tracking (which exploits work most)
- [ ] Add `adapt` logic (if WAF detected → encode payload)
- [ ] Add `update-corpus` script (pull new CVEs/exploits)
- [ ] Build feedback loop (attack result → update intuition)

---

## Implementation Roadmap

### Phase 1: Core Enhancements (Week 1)
1. Add `state` tool (session state management)
2. Add `loot` tool (collect findings)
3. Expand corpus (Exploit-DB, Metasploit, CTF writeups)
4. Add `searchsploit` integration

### Phase 2: Autonomous Loops (Week 2)
1. Build attack chain engine (recon → scan → exploit → privesc)
2. Add backtracking (if path fails, try alternative)
3. Add pivot support (tunnel through compromised hosts)
4. Implement adaptive reasoning

### Phase 3: Learning System (Week 3)
1. Track success/failure rates
2. Build "hacker intuition" database
3. Auto-update corpus (new CVEs, exploits)
4. Cross-session learning

### Phase 4: Power Mode (Week 4)
1. Add 32B model option (for complex reasoning)
2. Fine-tune on hacking corpus
3. Multi-model ensemble (small for recon, large for exploit dev)
4. Full autonomous mode (give target, get root)

---

## Example: World #1 Hacker in Action

**Command**: `hack www.target.com`

**What Happens**:
```
1. RECON
   → dns: A record, subdomains (subfinder, amass)
   → http: tech stack (httpx, wafw00f)
   → ports: open services (naabu, nmap)
   
2. ENUMERATE
   → web: directories (ffuf), vulns (nuclei), params (arjun)
   → state: discovered Apache 2.4.49, WordPress 5.8
   
3. ATTACK
   → lookup: CVE-2021-41773 (Apache path traversal)
   → exploit: searchsploit → run → shell obtained
   → loot: save shell, upload reverse shell
   
4. PRIVESC
   → enumerate: users, sudo rights, SUID binaries
   → lookup: kernel version → CVE-202X-XXXX
   → exploit: local privesc → root
   
5. REPORT
   → loot: all creds, flags, configs
   → chain: full attack path documented
   → state: save for future reference
```

**Result**: Root shell + full report in 15 minutes, autonomous.

---

## Decision Points

1. **Model**: Stay with 7B (fast) or add 32B (smarter)?
2. **Corpus**: How much to index? (Exploit-DB = 50K files)
3. **Autonomy**: Full autonomous loops or semi-autonomous (confirm each phase)?
4. **Learning**: Per-session only or persistent across all targets?
5. **Scope**: Keep scope.json gate or add "lab mode" (no restrictions)?

---

## Next Step

Choose which layers to build first. Recommended:
1. **State + Loot** (immediate value, enables tracking)
2. **Corpus expansion** (more knowledge = better attacks)
3. **Searchsploit integration** (auto-find exploits)
4. **Attack chains** (semi-autonomous loops)

Then iterate toward full autonomy.
