# OQVIAN — context for a strong second model (paste this to your LLM)

*This file is for **you**, the human operator, and for whichever frontier model
you point at it — DeepSeek, Claude, Codex, anything. Paste the whole thing into
that model's context before asking it to modify OQVIAN. It tells it what the
stack is, what we changed and why, how every piece plugs together, and which
changes will silently break it.*

---

## 1. What OQVIAN is

A fully local, offline security assistant that an operator talks to through a
browser UI or a CLI. The model itself can call Kali-class tools over MCP, and
every call is scope-checked and written to an audit log.

Three layers, and **all three must be present** or the stack fails silently:

| Layer | What | Where |
|---|---|---|
| **Model** | WhiteRabbitNeo 2.5 (a Qwen2.5-Coder-7B fine-tune), renamed OQVIAN | Ollama on `127.0.0.1:11434` |
| **Harness** | `@deepseek-ai/dsh` — the UI, the tool loop, the model routing | `npm i -g @deepseek-ai/dsh@0.1.1-rc.2` |
| **Tool server** | `mcp/server.py` — 5 tools the model calls itself | spawned by the harness over stdio |

Plus one thing that is not a component but the actual control plane:

| **Scope + audit** | `~/.config/oqvian/scope.json` and `~/.local/share/oqvian/audit.jsonl` |

**The scope file is the safety mechanism.** The model is uncensored by design —
it answers offensive and defensive questions in full working detail. What stops
it acting on the wrong host is the scope allowlist in `mcp/server.py`, enforced
server-side, plus the audit log. There is deliberately **no** safety disclaimer
in the system prompt; adding one is a defect, not a safeguard.

---

## 2. The single most important thing we changed

**Tool calling does not work out of the box.** A GGUF ships with no `.Tools`
block in its chat template, so Ollama never renders the tool schemas and the
model can never emit a tool call. It answers like a chatbot, looks perfectly
healthy, and the whole stack is dead.

The fix is in `models/qwen-tools.template` and is baked into every model:

```bash
ollama show oqvian --template | grep -c '.Tools'   # must be 3
```

**Consequence, and this is the most common failure in the whole project:**
pulling the upstream fine-tune from HuggingFace gives you the *unmodified*
weights — no `.Tools`, no OQVIAN system prompt, no role models. It still
answers questions. So the weights ship as **release assets** (already built),
not as a download reference. `AI-HANDOFF.md` §12.1 forbids `ollama pull` for
exactly this reason, and §2.3/§3.3 fetch the built artefacts.

**If your change produces a model that answers but never calls a tool, this is
almost certainly the cause. Re-extract the release models; do not rebuild.**

### There are five models, not one

```
oqvian:latest                  (alias oqvian:defensive-offensive)
oqvian-ciso / -offensive / -defensive / -ir
```

The role models are **thin entry points**: same 4.7 GB of blobs, ~4 KB of
manifest each. The only differences are the SYSTEM prompt and the temperature.
One loaded at a time.

| Model | Temperature | Job |
|---|---|---|
| `oqvian:latest` | 0.4 | general offensive + defensive engineer |
| `oqvian-ciso` | 0.35 | board/risk translation, framework mapping (NIST CSF 2.0, ISO 27001:2022, PCI DSS 4.0…) |
| `oqvian-offensive` | 0.3 | red team |
| `oqvian-defensive` | 0.3 | blue team |
| `oqvian-ir` | 0.25 | incident response |

Sources: `models/Modelfile.{base,ciso,offensive,defensive,ir}`.

---

## 3. The MCP surface — 5 tools, 22 operations

The model sees exactly five tools. Internally there are 22 functions dispatched
through `action` / `tool` enums. **If you rename or add operations, update the
Modelfiles in the same commit** — stale names in the system prompt are how the
model starts calling things that do not exist. (This bug already bit once:
role Modelfiles referenced `rag_search`, `run_tool`, `atomic_lookup`, `dns_enum`,
none of which are in the 5-tool surface.)

`tools.*` names in the harness are `mcp__oqvian__<tool>`.

### `kb` — the knowledge base

`action`: `search` | `attack` | `detection` | `atomic` | `lolbas` | `kev` |
`cve` | `cve_search` | `stats`. Params: `query`, `k` (1–20), `source`
(`attack|cwe|kev|sigma|atomic|lolbas|gtfobins|wstg`).

Retrieval is **SQLite FTS5 + BM25**. Embeddings were measured and rejected:
`nomic-embed-text` came out at ~0.46 docs/s ≈ 6.6 hours for the corpus.
`--embed` exists as an optional hybrid RRF path, but FTS5 alone is the default
and it is enough. Corpus: 10,932 documents → `index/fts.db`, built by
`ingest.py`, refreshed by `refresh-corpus.sh`. Sources: ATT&CK, CWE, CISA KEV,
Sigma, Atomic Red Team, LOLBAS, GTFOBins, OWASP WSTG.

If the answer is not in the index, the correct output is *"the knowledge base
has no answer"* — never an invented technique ID or CVE.

### `recon` — live network evidence

`action`: `dns` | `dns_enum` | `whois` | `http` | `tls` | `ports` |
`subdomains` | `fetch`. Params: `target`, `options` (record type, method, port,
range, limit). **Scope-checked before any socket is opened.**

### `execute` — the toolchain

`tool` + `args` (plain string; **no** `; & | $ > <`, one command per call):

```
nmap naabu nuclei httpx subfinder amass katana ffuf feroxbuster nikto sqlmap
semgrep trivy grype syft gitleaks trufflehog yara tshark volatility3 netexec
certipy hashcat john hydra metasploit …
```

`tool='status'` lists what is installed. Binary resolution goes through a
`TOOL_ALIASES` map in `mcp/server.py` — that map is why 22 of 35 userland tools
resolve on a box that has no root. **NetHunter is excluded: Android-only.**

### `governance`

`action='scope'` shows the authorisation boundary; `action='audit'` shows the
last *n* calls from the audit log.

### `transform`

base64 / url / hex / rot13 / md5 / sha1 / sha256 helpers.

---

## 4. Harness wiring — read this before touching it

The harness is configured by **two** mechanisms, and confusing them is the
second most common failure:

1. **`~/.dsh/profiles/<web|headless>/cordis.patch.yml`** — Cordis composition.
   This is where `llm-pi-ai` is declared *as a plugin* (in the `dsh-base`
   bundle patch, with **no config**). Each profile patch is a single
   `- insert:` list, so it cannot add a `config:` block to an existing row.
   This is where the MCP client (`oqvian-mcp`) is registered.
2. **`~/.dsh/settings.yaml`** — the user-settings document. `dsh-settings-file`
   loads `settings.yaml`, and the `llm-pi-ai:` section holds `providers`. The
   provider block there is what actually sets `streamIdleTimeoutMs`.

`scripts/setup_harness.py` is the only thing that should write either. It is
idempotent and backs up `settings.yaml` before touching it.

### How the provider is configured

```yaml
llm-pi-ai:
  providers:
    ollama-local:
      displayName: OQVIAN (local)
      api: openai-completions
      baseURL: http://127.0.0.1:11434/v1
      headers:
        Authorization: Bearer ollama      # pi-ai refuses credential-less providers
      streamIdleTimeoutMs: 1800000          # 30 min — THE CPU FIX, see below
      timeoutMs: 3600000                    # 60 min
      models: …five oqvian entries…
```

Two non-obvious facts:

- **The static bearer token is not a leak or a placeholder.** pi-ai requires a
  credential to exist; Ollama ignores auth. It exists so the CISO never has to
  create an API key. `baseURL` must keep the `/v1` suffix.
- **`timeoutMs` is in the schema but is never read** by `dsh-llm-pi-ai`. It is
  harmless noise. `streamIdleTimeoutMs` is the one that matters, and it is read
  at line ~1005 of `node_modules/@deepseek-ai/dsh-llm-pi-ai/lib/index.js` as
  `source.streamIdleTimeoutMs ?? 3e5`. The field was confirmed present and
  parsed (an invalid string value kills the adapter; a numeric value survives).

### Profiles

- `oqvian-cli` runs the **headless** profile with
  `DSH_PERMISSION_MODE=danger-full-access` (headless cannot answer prompts) —
  the web UI keeps `ask`. `oqvian-repl` interactively boots the DSH web host on a
  loopback-only random port and also forces `danger-full-access`; use it for
  server/headless machines that want an ongoing chat. Scope + audit are enforced
  **server-side** in `mcp/server.py`, so this is not a safety gap.
- `oauth` route in the dump config is the Anthropic ChatGPT OAuth card. Not
  relevant to OQVIAN.

### The harness is rebranded

`scripts/brand_harness.py` applies **9 targeted string patches** (browser title,
manifest `name`/`short_name`, `runtime productTitle`, CLI help, web startup
description, 3 system-prompt sections) — not a blanket replace over the ~119
files. It is idempotent and has a `--check` mode. If you upgrade the harness,
re-run it and re-check; that is the canary.

### Pinned version

**`@deepseek-ai/dsh@0.1.1-rc.2` — do not upgrade.** The settings schema and
the profile patches are written against this exact version. The release cache is
built for it. "Upgrading" is the third most common way to break the stack.

---

## 5. The timeout, and what it actually is

The harness has a stream **idle** watchdog (`idleWatchdog` in
`@deepseek-ai/dsh-timeout`, wired in at `dsh-llm-pi-ai/lib/index.js:1718`). It
kills a request if no chunk arrives for `streamIdleTimeoutMs`.

The default is **300,000 ms**. A CPU-only box spends longer than that evaluating
*the prompt* before the first token exists — measured prompt eval is ~543 s for
a 1,049-token context at ~2 tok/s — so the default fires during prompt eval, not
generation. GPU hardware never sees this because prompt eval takes seconds.

Fix (`scripts/setup_harness.py`): `streamIdleTimeoutMs: 1800000`,
`timeoutMs: 3600000`.

**What this does not fix.** Once the timeout is raised, a CPU run can still take
>20 minutes end-to-end (prompt eval + retries), and on CPU the model may emit
plain text instead of a tool call while it is deciding. That is model behaviour,
not a broken install — judge the e2e check on GPU hardware. Do not respond to a
slow CPU run by raising the timeout further; 30 min idle is already generous.

**Verified numbers from this box** (i7-5557U, no AVX-512, CPU-only):
prompt 2.0 tok/s, generation 1.5 tok/s. Target hardware: 12–25 tok/s with
4 GB VRAM offload. Ollama 0.33.3 has `OLLAMA_VULKAN`; Intel → `OLLAMA_VULKAN=1`,
NVIDIA/AMD → `OLLAMA_NUM_GPU=999`.

---

## 6. Install is release-first, and that is deliberate

`AI-HANDOFF.md` is written to be executed by an AI assistant on the target
machine, step by step, with expected output and a failure table. Order matters:

1. `scripts/install-release-assets.sh` — downloads the built models and the
   harness cache (**before** `install.sh`).
2. `install.sh` — 8 stages, idempotent, `--status` reports 9 components.
3. `python scripts/setup_harness.py` — profiles + provider + scope.

Details worth knowing if you modify this:

- `install-release-assets.sh` derives the repo from `git remote get-url origin`
  (falling back to a hardcoded owner for download-only copies), downloads only
  the assets the selected mode needs (`--models-only` / `--harness-only`), and
  supports `--from-dir <dir>` for air-gapped machines.
- Model parts are **split at 1900 MiB** because a GitHub release asset caps at
  2 GiB. Reassembly is `cat part-*`. Checksums are per-part.
- Extraction **streams** the parts into `tar` (`cat parts | tar -xf -`) rather
  than reassembling a second 4.7 GB archive first. Reassembling needs ~9.4 GB of
  scratch and fails on a small tmpfs. Streaming needs ~10 GB total (parts +
  extracted blobs). The Windows path uses `type part-* | tar -xf -`, with
  `copy /b` kept as an explicit fallback.
- Both installers **detect** the extracted models (template present, no stale
  tool names, all five present) and verify instead of rebuilding. Rebuilding
  would resolve the upstream `FROM hf.co/bartowski/…` reference, which fails on
  an offline machine — that was a real bug.
- `--os=win32 --cpu=x64` was used to prime the npm cache so the Windows install
  works offline too; verified with `--offline`, 449 packages, Windows `.node`
  binaries present. **A Linux-only cache would still send the Windows user to
  the registry.**

The repository is private and owned by the CISO; the models and harness ship as
release **assets**, never in git.

---

## 7. Traps — read before you start

| Trap | What happens | What to do |
|---|---|---|
| Pulling the upstream GGUF | Model answers, never calls a tool; looks healthy | §2 of this file. Re-extract the release models |
| Editing a profile `.yml` to add a provider `config:` | Patch is a single `- insert:` list; the config never lands | Provider settings live in `~/.dsh/settings.yaml`, written by `setup_harness.py` |
| `- insert:` vs `- update:` in a profile patch | Wrong verb overwrites the whole row's config | Composition replaces the whole row `config`; it does not merge |
| Renaming an MCP operation | Role Modelfiles now name tools that do not exist | Update `models/Modelfile.*` in the same commit |
| `DSH_PERMISSION_MODE=danger-full-access` on the web UI | UI stops prompting for tool calls | Only `oqvian-cli` sets it; web keeps `ask` |
| `modelRoutes: [ollama-local]` under `agent-default-model` | Already in `settings.yaml`; harmless but redundant | Leave it, or remove it — do not "fix" anything else to chase it |
| `timeoutMs` under the provider | In the schema, never read | Ignore; `streamIdleTimeoutMs` is the lever |
| Building a multi-GB artefact in `/tmp` | `/tmp` here is a 7.8 GB tmpfs — `No space left on device`. Build in `~/.cache` | — |
| Overwriting a running bash script in place | bash re-reads by byte offset → `syntax error near unexpected token` | Write to a new file, then `mv` |
| `npm --os=win32 --cpu=x64 …` | The supported way to prime a cross-platform cache | Verify with a real `--offline` install |

## 8. Known gaps (honest)

- **The e2e tool-call test is not fully green on CPU-only hardware.** It is
  slow (>20 min) and the model sometimes answers in text instead of calling
  `kb`, which is why the audit log ends up with no `kb` line. On GPU hardware
  this is a 30–120 s check and is the real acceptance test. (`kb` itself is
  proven independently: `mcp/smoke_test.py`, 19/19.)
- **`deploy/windows/install.ps1` has never been executed.** It has been reviewed
  and its brace balance checked, but there is no Windows host to parse or run
  it. Treat any Windows-only path as unverified until run on the laptop.
- **No Ruby** on the dev box → Metasploit is impractical there. CPU-only, no
  AVX-512, no passwordless sudo → `/usr/share/wordlists`, pacman/BlackArch
  root toolset and SecLists are unavailable here. `install.sh --with-root` is
  the interactive path for a machine that does have sudo.
- **Two background retries burn ~10 minutes each** when a run times out, because
  the harness retries 5 times with backoff. Do not launch a second e2e run while
  one is in flight.
- **The auth headers in the provider block are not a secret.** `Bearer ollama`
  is a static literal; Ollama ignores it. It is not a credential and should not
  be treated as one, but it also should not be copied into a request that leaves
  `127.0.0.1`.

## 9. How we validated

```bash
ollama show <m> --template | grep -c '.Tools'    # 3 on all five models
.venv/bin/python mcp/smoke_test.py               # 19/19
bash install.sh --status                          # 9 components "yes"
cat part-* | sha256sum                            # matches the source tar
bash models/build-models.sh                       # early-exits, verifies
```

One caveat: `ollama show <m> --modelfile` renders `FROM` as an **absolute local
blob path**, not the upstream ref — it is not proof of where the weights came
from. The `.Tools` count is the proof that matters.

## 10. Where the files are

| Path | What |
|---|---|
| `AI-HANDOFF.md` | The deliverable an installing AI executes. Release-first, §12.1 forbids the upstream pull |
| `scripts/setup_harness.py` | The single writer of profiles + provider + scope. Contains the timeout fix |
| `scripts/install-release-assets.sh` | Consumes release assets; offline; `--from-dir` |
| `scripts/brand_harness.py` | 9-string OQVIAN HARNESS rebrand; `--check`; idempotent |
| `scripts/preflight.sh`, `scripts/setup-harness.sh` | pre-flight and a second harness setup entry |
| `mcp/server.py` | 5 tools, 22 internals, scope + audit, FTS5/hybrid |
| `mcp/smoke_test.py` | 19 checks, no model involved |
| `models/build-models.sh` | Installs the tool template; early-exits when models are already built |
| `models/Modelfile.{base,ciso,offensive,defensive,ir}` | base prompt + 4 role prompts |
| `models/qwen-tools.template` | The Qwen2.5 tool template. **This is the file that makes tools work** |
| `install.sh` | 8-stage orchestrator, `--status`, `--no-tools/--no-model/--no-index/--with-root` |
| `deploy/windows/install.ps1` | CISO-laptop installer incl. Vulkan and model detection (**unexecuted — see §8**) |
| `package.sh` | Single-file bundle builder; no longer the primary path |
| `refresh-corpus.sh` | Clones missing corpora, `--fast`, `--no-index`; rebuilds the index |
| `docs/HANDOFF.md` | Human one-pager, release-first |
| `docs/CISO-PLAYBOOK.md` | 12 ready CISO prompts |
| `docs/DEEPSEEK-CONTEXT.md` | **This file** |

## 11. Change rules for whoever modifies this

1. Never pull upstream weights at install time. The built models are the
   deliverable.
2. Never upgrade `@deepseek-ai/dsh` past `0.1.1-rc.2` without re-verifying the
   settings schema and the profile patches.
3. If you rename or add an MCP operation, update the Modelfiles and
   `docs/CISO-PLAYBOOK.md` in the same commit.
4. Touch `.Tools` template via `models/qwen-tools.template` only — never by
   hand-editing a Modelfile in the repo, because the release models already
   have it baked in and a hand-edit does not reach the target machine.
5. `streamIdleTimeoutMs` is the CPU fix. Do not lower it; do not "tune" it per
   hardware profile.
6. Never set `"mode": "open"` in a shipped scope file. The scope file is not in
   the repo by design.
7. Run `ollama show <m> --template | grep -c '.Tools'` after any model change.
   It is the acceptance check.

---

*End of context. If anything in this file is wrong, the code wins — check the
named file and line, then fix this file in the same commit.*
