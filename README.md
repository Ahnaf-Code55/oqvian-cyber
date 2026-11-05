# OQVIAN — local cyber operations stack

A fully local defensive/offensive security assistant for a CISO and the security
team: a 7B security model, a grounded knowledge index, and a Kali-class toolchain
that the model can call itself through the DeepSeek Harness.

Nothing leaves the machine. No cloud API, no telemetry, no data retention by a
third party.

---

## Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│  DeepSeek Harness (dsh web / headless)                           │
│  agent: OQVIAN  ·  permission preset: ask  ·  audit on every call│
└───────────────┬──────────────────────────────────────────────────┘
                │ MCP over stdio (5 tools, namespaced mcp__oqvian__*)
┌───────────────▼──────────────────────────────────────────────────┐
│  OQVIAN tool server        ~/oqvian-cyber/mcp/server.py           │
│                                                                  │
│  kb          — search ATT&CK/CWE/KEV/Sigma/atomics/LOLBAS/WSTG    │
│  recon       — dns, whois, http, tls, port scan, subdomains       │
│  execute     — run nmap, nuclei, ffuf, sqlmap, trivy, …           │
│  governance  — scope + audit trail                                │
│  transform   — encode/decode/hash helpers                        │
│                                                                  │
│  scope + audit enforced inside every tool                        │
└───────┬───────────────────────┬──────────────────────────────────┘
        │                       │
┌───────▼─────────┐   ┌─────────▼──────────────────────────────────┐
│ search index    │   │ Kali-class binaries (userland, no root)    │
│ ~/oqvian-cyber/ │   │ ~/.local/bin + ~/oqvian-cyber/tools        │
│ index/fts.db    │   │ nmap nuclei httpx ffuf sqlmap nikto ...    │
│ 10.9k passages  │   └────────────────────────────────────────────┘
│ SQLite FTS5     │
└─────────────────┘
        │
┌───────▼──────────────────────────────────────────────────────────┐
│  Ollama (GPU offload where available)                            │
│  oqvian  oqvian-ciso  oqvian-offensive  oqvian-defensive  oqvian-ir│
└──────────────────────────────────────────────────────────────────┘
```

**Scope + audit** sit across the whole stack: every network tool checks
`~/.config/oqvian/scope.json` before it acts, and every call is appended to
`~/.local/share/oqvian/audit.jsonl` with user, timestamp, target and result.

---

## Models

| Model | Use |
|---|---|
| `oqvian:latest` | general defensive/offensive |
| `oqvian-ciso:latest` | board/exec briefings, risk, compliance mapping |
| `oqvian-offensive:latest` | red team, ATT&CK-mapped operations |
| `oqvian-defensive:latest` | detection engineering, hardening, triage |
| `oqvian-ir:latest` | incident response, forensics, PICERL |

All are 7.61B parameters, Q4_K_M, 16K context, sharing one 4.4 GB set of weights.

### Target hardware

Deployed on the CISO laptop, not the build machine:

| | |
|---|---|
| CPU | Intel Core i7 11th gen |
| RAM | 16 GB |
| GPU | Intel Iris Xe MAX, 4 GB VRAM (discrete) |
| Expected | 12–25 tok/s generation, 60–150 tok/s prompt processing |
| Context | 16K with q8_0 KV (~0.45 GB); 8K if VRAM is tight |

On this 2015 dev laptop (2C/4T, no AVX-512, CPU-only) it measures pp 2.0 tok/s,
tg 1.5 tok/s — enough to prove the stack works, useless for agent loops. Judge
latency on the target machine only.

Model files live in `models/`. Rebuild them all (including the Qwen2.5
tool-calling template, which the GGUF does not ship) with:

```bash
bash ~/oqvian-cyber/models/build-models.sh
```

Without that template Ollama never renders tool definitions into the prompt and
the model cannot call any tool, however the harness is wired. Verify:

```bash
ollama show oqvian --template | grep -c '.Tools'     # must be >= 1
```

---

## Install

**Linux** (target: the CISO laptop, or any x86_64 box with 16 GB RAM):

```bash
git clone <repo> ~/oqvian-cyber && cd ~/oqvian-cyber
bash install.sh                  # full: deps, ollama, models, corpus, index, tools, harness
bash install.sh --status         # report only
bash install.sh --no-tools       # models + index + harness
bash install.sh --with-root      # also install the BlackArch root toolset (sudo)
```

`install.sh` runs the eight stages below and prints a summary; re-run it after
any failure and it resumes:

1. `scripts/preflight.sh` — hardware probe, writes `hardware.env` with the
   recommended context size and GPU env (`OLLAMA_VULKAN=1` on Intel,
   `OLLAMA_NUM_GPU` on NVIDIA/AMD).
2. base packages, Python venv, `requirements.txt`.
3. Ollama install/start + a systemd drop-in carrying the GPU and KV-cache env.
4. `models/build-models.sh` — 5 models with the tool template.
5. `refresh-corpus.sh` + `ingest.py` — corpus download, FTS5 index.
6. `install-tools.sh` — Kali-class userland toolchain.
7. `install-root-tools.sh` — only with `--with-root`.
8. `scripts/setup_harness.py` — dsh profiles, settings, scope; then the smoke test.

**Windows** (CISO laptop): `deploy/windows/install.ps1`, documented in
`deploy/windows/README.md` — including the Iris Xe MAX GPU paths (Vulkan vs
Intel's IPEX-LLM build) and the WSL2 route for the tools that have no Windows
build.

Verify a deployment at any time:

```bash
.venv/bin/python mcp/smoke_test.py        # 19 checks, no LLM needed
dsh --profile web --dump-config | grep -A5 oqvian-mcp
ollama show oqvian --template | grep -c '.Tools'
```

---

## Daily use

```bash
# web UI
oqvian                       # starts ollama, then dsh web
dsh web                      # if ollama is already running

# one-shot CLI
oqvian-cli "Map T1059.001 to Sigma rules we can deploy"

# direct model, no harness
ollama run oqvian-ciso

# health
systemctl --user status ollama
ollama ps                    # PROCESSOR column: GPU vs CPU split
```

The web UI is set to permission preset **`ask`**: command execution and writes
require your approval, and every MCP tool call shows up as a prompt. Keep it that
way outside disposable VMs.

`oqvian-cli` cannot prompt, so it sets `DSH_PERMISSION_MODE=danger-full-access`
(no approval gate) and prints a warning. On that path the controls that remain
are the scope allowlist and the audit log — both enforced inside the tool server,
not by the model.

**Start here for real work:** [`docs/CISO-PLAYBOOK.md`](docs/CISO-PLAYBOOK.md) —
twelve ready prompts (exposure check, board one-pager, compliance mapping, CVE
triage, detection engineering, first hour of an incident, attack-surface review,
vendor risk, purple-team design, metrics, policy drafting, post-incident review),
each naming the model and the tools it will call.

---

## Scope (read this before scanning anything)

`~/.config/oqvian/scope.json`

```json
{
  "mode": "restricted",
  "allowed_hosts": ["localhost", "127.0.0.1"],
  "allowed_domains": ["lab.internal.example"],
  "allowed_cidrs": ["127.0.0.0/8", "10.0.0.0/8", "192.168.0.0/16"],
  "max_scan_ports": 65535
}
```

- Private RFC1918 ranges and localhost are allowed by default.
- Public targets must be listed by domain or CIDR.
- `"mode": "open"` disables the allowlist — isolated lab only.
- The model is told to stop and report when a target is out of scope; the server
  enforces it regardless of what the model says.

Check current policy from inside a session:
`mcp__oqvian__governance` with `action="scope"`.

---

## Knowledge index

10,900+ passages indexed with **SQLite FTS5 + BM25** — exact identifiers (T1059.001,
CVE-2024-3400, CWE-79) rank correctly and the index builds in seconds on CPU.
Built with:

```bash
cd ~/oqvian-cyber && .venv/bin/python ingest.py

# optional semantic layer: ~0.5 docs/s on CPU, i.e. ~6 h for the full corpus.
# When it exists, search automatically becomes hybrid (BM25 + cosine, RRF-fused):
.venv/bin/python ingest.py --embed
```

Hybrid search is worth it only on a machine with a GPU; on CPU the BM25 index is
the right default and is better at exact IDs anyway.

| Source | Content |
|---|---|
| ATT&CK | 1,670 techniques + mitigations |
| CWE 5.0 | 1,061 weaknesses |
| CISA KEV | 1,825 known-exploited CVEs |
| Sigma | 3,349 detection rules |
| Atomic Red Team | 982 test sets |
| LOLBAS | 247 Windows LOLBins |
| GTFOBins | 472 Linux binaries |
| OWASP WSTG | 1,326 testing passages |

Add your own runbooks, policies and past IR reports by dropping Markdown into
`corpus/raw/` and extending `load_markdown()` in `ingest.py`.

---

## Toolchain

**Userland, already installed (no root):** nmap, nuclei, httpx, subfinder, naabu,
amass, dnsx, katana, tlsx, asnmap, cdncheck, ffuf, feroxbuster, trivy, grype, syft,
gitleaks, trufflehog, nikto, sqlmap, semgrep, impacket, certipy, netexec,
volatility3, oletools, dirsearch, wafw00f, pwntools.

Re-run the installer: `bash ~/oqvian-cyber/install-tools.sh`

Two of these need their own interpreter: **netexec** does not support Python 3.14,
so the installer provisions Python 3.12 through `uv` and keeps it isolated; and
**amass** ships a prebuilt `amass_linux_amd64.tar.gz` rather than a zip.

**Root / system tools** (wireshark, aircrack-ng, hashcat, john, hydra,
metasploit, bloodhound, burpsuite, ghidra, autopsy, …) need sudo:

```bash
bash ~/oqvian-cyber/install-root-tools.sh --list
bash ~/oqvian-cyber/install-root-tools.sh                 # curated core
bash ~/oqvian-cyber/install-root-tools.sh --group ad,cloud
bash ~/oqvian-cyber/install-root-tools.sh --blackarch     # add BlackArch repo
bash ~/oqvian-cyber/install-root-tools.sh --everything    # blackarch-all
```

Arch/CachyOS has no Kali repo; **BlackArch** is the equivalent (2,800+ packages).
Kali NetHunter is Android-only — on a laptop the equivalent is this Kali/BlackArch
toolset plus a monitor-mode-capable Wi-Fi adapter for the wireless group.

Ask the model `mcp__oqvian__execute` with `tool="status"` to see what is actually
callable — it reports installed vs missing rather than guessing.

---

## Governance for the CISO

| Control | Where |
|---|---|
| Authorisation boundary | `~/.config/oqvian/scope.json`, enforced server-side |
| Per-action approval | web UI: dsh preset `ask` — every tool call prompts |
| One-shot CLI | `oqvian-cli` runs auto-approve (nothing can answer a prompt headless); scope + audit still apply |
| Immutable activity log | `~/.local/share/oqvian/audit.jsonl` |
| Data stays on device | Ollama on 127.0.0.1, no cloud route |
| Model cannot escalate | tools run as your user; root tools need your sudo |
| Two-person rule for destructive actions | approve each call in the web UI |
| Output review | model is a drafting aid; a human signs off |

For engagements, keep a copy of the scope file and the audit log with the report
— together they are the rules-of-engagement evidence.

---

## Files

```
~/oqvian-cyber/
├── install.sh                 one-shot installer (8 stages, idempotent)
├── ingest.py                  corpus → FTS5 index (+ optional embeddings)
├── refresh-corpus.sh          weekly corpus refresh
├── install-tools.sh           userland toolchain (no sudo)
├── install-root-tools.sh      Kali/BlackArch mapping (sudo)
├── requirements.txt           python deps for the tool server
├── docs/CISO-PLAYBOOK.md      twelve CISO workflows, ready to paste
├── oqvian / oqvian-cli        launchers (symlinked into ~/.local/bin)
├── scripts/
│   ├── preflight.sh           hardware probe → hardware.env
│   ├── setup_harness.py       dsh profiles + settings + scope (cross-platform)
│   └── setup-harness.sh       thin bash wrapper
├── deploy/windows/            install.ps1 + CISO laptop guide (Iris Xe MAX)
├── models/                    Modelfile.*, qwen-tools.template, build-models.sh
├── mcp/server.py              MCP tool server (5 public tools)
├── mcp/smoke_test.py          19 offline checks
├── index/                     docs.jsonl + fts.db + meta.json
└── corpus/raw/                ATT&CK, CWE, KEV, Sigma, atomics, WSTG, …

~/.dsh/profiles/{web,headless}/cordis.patch.yml   MCP wiring
~/.dsh/settings.yaml                              provider + models + permission
~/.config/oqvian/scope.json                       authorisation boundary
~/.local/share/oqvian/audit.jsonl                 tool audit trail
```

---

## Known limits

- **7B on CPU**: strong at recall, mapping and drafting; weak at multi-step
  reasoning. Always verify exploit details and CVE claims against the cited source.
  On the target 4 GB GPU expect 12–25 tok/s; on CPU-only 1.5–3 tok/s.
- **No fine-tuning**: RAG is the correct lever — security facts expire weekly,
  weights do not. Rebuild the index instead of the model.
- **No root by default**: raw sockets, monitor mode, packet capture and some
  AD/network attacks need the root installer or `CAP_NET_RAW`.
- **Windows is partial**: `kb`, `recon`, `governance`, `transform` are pure Python
  and work natively; `execute` only sees tools with a Windows build. Full Kali
  coverage needs WSL2.
- **Tool surface is 5, not 22**: a 7B on a 16K context cannot carry 22 JSON
  schemas plus a conversation. The 22 functions still exist internally behind
  `action`/`tool` enums.
- **Coverage is a snapshot**: re-run `ingest.py` weekly (KEV/NVD/Sigma change).
- **Model output is not a decision**: the CISO signs off, not the model.
