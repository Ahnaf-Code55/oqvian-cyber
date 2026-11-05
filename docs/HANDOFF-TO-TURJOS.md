# OQVIAN — install handoff

**To:** Turjos
**From:** Ahnaf
**Scope of this note:** downloading and installing the two built artefacts — the
**OQVIAN model** and the **DeepSeek harness (`dsh`)** — plus the rest of the stack
that makes them usable. Everything ships from one public GitHub release; no
HuggingFace account, no npm network, no cloud API.

Repo: <https://github.com/Ahnaf-Code55/oqvian-cyber> (public)
Release: **`v1.1.0`** · 5 assets · ~4.9 GB

---

## 1. What you are installing

| Piece | What it is | Where it comes from |
|---|---|---|
| **OQVIAN model** | one 7B model, `oqvian-cyber-control-full-unlocked-v1.1`, Q4_K_M, with the Qwen2.5 tool-calling template **baked in** | release asset (`oqvian-models-*`) → your local Ollama store |
| **DeepSeek harness** | `@deepseek-ai/dsh@0.1.1-rc.2` — the agent runtime that drives the model (branded "OQVIAN HARNESS") | shipped npm cache (`oqvian-harness-*`) |
| **Knowledge base** | 10,932 passages (ATT&CK, CWE, KEV, Sigma, Atomic Red Team, LOLBAS, GTFOBins, WSTG) in a local SQLite FTS5 index | `install.sh` builds it from the bundled corpus |
| **Tool surface** | 5 MCP tools — `kb`, `recon`, `execute`, `governance`, `transform` — over 41 Kali-class binaries | repo source + `install.sh` |
| **Tool-call bridge** | a small local process that sits between the harness and Ollama (see §6) | repo source, started automatically |

Everything runs locally. Nothing the tool calls out to leaves the machine.

> **Do not** `ollama pull` a Qwen GGUF from HuggingFace instead of using the
> release assets. The upstream GGUF has no tool template, so the model answers
> from memory and never calls a tool. That is the single most common way this
> stack quietly turns into a chatbot.

---

## 2. What the machine needs

| | Minimum | Comfortable |
|---|---|---|
| OS | Linux x86_64, Windows 11, or macOS | any |
| RAM | 16 GB | 16 GB |
| Disk | 12 GB free | 20 GB free |
| GPU | none — CPU works, but slowly | 4 GB VRAM → 12–25 tok/s |
| Network | only for the ~4.9 GB download | — |

CPU-only is real but slow: about **6 tok/s** prompt evaluation, so one agent turn
is ~25 minutes. On a GPU box the same turn is seconds to a couple of minutes.
See §8.

---

## 3. Install — Linux / macOS

```bash
# 1. get the source (public repo — no token, no GitHub login)
git clone https://github.com/Ahnaf-Code55/oqvian-cyber.git ~/oqvian-cyber
cd ~/oqvian-cyber

# 2. pull the built model + harness from the release (~4.9 GB)
#    reassembles the split archive into ~/.ollama/models and unpacks the npm cache
bash scripts/install-release-assets.sh

# 3. everything else: base deps, Python venv, Ollama, the model, the corpus,
#    the FTS5 index, the Kali-class toolchain, and the harness wiring
bash install.sh
```

`install.sh` is idempotent — re-run it after any failure and it resumes. Useful
flags:

```bash
bash install.sh --status      # report only, install nothing
bash install.sh --no-tools    # skip the Kali-class toolchain
bash install.sh --with-root   # also install the root toolset (needs sudo)
```

To install only one half of the release:

```bash
bash scripts/install-release-assets.sh --models-only    # just the model
bash scripts/install-release-assets.sh --harness-only   # just dsh + npm cache
```

### The DeepSeek harness on its own

The harness is unpacked from the release's npm cache, fully offline. If you are
not running the full installer:

```bash
bash scripts/install-release-assets.sh --harness-only
# then wire the profiles, provider and scope:
python3 scripts/setup_harness.py
```

`setup_harness.py` writes `~/.dsh/settings.yaml` (provider `ollama-local` →
`http://127.0.0.1:11435/v1`), the two dsh profiles' MCP entry, and it disables
the host's generic agent-skill catalog (see §8). Run it once after `dsh` exists.

---

## 4. Install — Windows 11

```powershell
git clone https://github.com/Ahnaf-Code55/oqvian-cyber.git $HOME\oqvian-cyber
cd $HOME\oqvian-cyber
powershell -ExecutionPolicy Bypass -File deploy\windows\install.ps1
```

The installer sets up Ollama with the Intel GPU path, the model, the corpus and
index, the harness, the **tool-call bridge** (started hidden via `pythonw`, and
registered to auto-start at logon), and runs a smoke test. 10–30 minutes once the
assets are local. Idempotent.

```powershell
.\deploy\windows\install.ps1 -Status      # components incl. 'bridge' — expect 'present'
.\deploy\windows\install.ps1 -SkipTools -SkipIndex   # partial re-run
```

Full Windows notes, including the Intel Iris Xe / Arc Vulkan path and the WSL2
route for tools with no Windows build: `deploy/windows/README.md`.

---

## 5. Prove it works

```bash
bash install.sh --status        # ten components, each should read 'yes' (incl. 'bridge')
.venv/bin/python mcp/smoke_test.py                                  # 19 checks, no model needed, ~10 s
ollama show oqvian-cyber-control-full-unlocked-v1.1 --template | grep -c '.Tools'   # expect 3
```

Then the one that actually matters — the full chain
**harness → MCP → model → tool → knowledge base**:

```bash
oqvian-cli "Call mcp__oqvian__kb with action=attack and query=T1059, then state the technique name."
```

A healthy run calls the `kb` tool and answers **Command and Scripting
Interpreter**. Give it time on a CPU-only box (see §8). If it answers *without*
calling the tool, the template is missing — run `models/build-models.sh`.

---

## 6. The bridge — why the provider points at 11435

Ollama listens on `127.0.0.1:11434`. The harness provider deliberately points at
`127.0.0.1:11435` instead — a small local process, `mcp/toolcall_proxy.py`
(`oqvian-proxy.service` on Linux, a Startup entry on Windows). It exists because:

- Ollama's own tool parser intermittently **drops a valid tool call** and returns
  an empty turn. The bridge owns the protocol, renders the schemas, parses the
  model's `<tool_call>` itself, and retries a genuinely empty turn.
- It buffers each tool turn, so its patience has to exceed the harness's. The
  service sets `OQVIAN_PROXY_TIMEOUT=3600`; the harness idle window is 60 min.

If the bridge is down, `dsh` cannot reach the provider. Bring it up:

```bash
systemctl --user start oqvian-proxy.service     # Linux
# Windows: it auto-starts at logon; or run:
#   .venv\Scripts\pythonw.exe mcp\toolcall_proxy.py
```

The `oqvian`, `oqvian-cli` and `oqvian-repl` launchers start it for you.

---

## 7. Daily use

```bash
oqvian                 # web UI (starts ollama, then dsh web)
dsh web                # web UI if ollama is already running
oqvian-repl            # interactive terminal REPL — best for a headless server
oqvian-cli "…"         # one-shot task
ollama run oqvian-cyber-control-full-unlocked-v1.1   # direct model, no harness
```

On Windows the bash launchers do not exist — invoke `dsh` directly:

```powershell
dsh web
dsh --profile headless "Map T1059.001 to Sigma rules we can deploy"
```

Start with `docs/CISO-PLAYBOOK.md` — twelve ready workflows (exposure check, CVE
triage, detection engineering, incident first hour, vendor risk, …).

---

## 8. Two things that will bite you

**1. Set your authorisation boundary first.** The scope file is per-machine and
is *not* shipped. Create it before any network work:

```json
{
  "mode": "restricted",
  "allowed_hosts": ["localhost", "127.0.0.1", "::1"],
  "allowed_domains": ["app.example.com"],
  "allowed_cidrs": ["127.0.0.0/8", "10.0.0.0/8", "192.168.1.0/24"],
  "allowed_tools": "*",
  "max_scan_ports": 65535
}
```

`~/.config/oqvian/scope.json` (Linux/macOS) or
`%USERPROFILE%\.config\oqvian\scope.json` (Windows). Anything not listed is
refused **inside the tool server**, so the model cannot talk its way past it.
There is no `"targets"` key — targets go in `allowed_hosts` / `allowed_domains` /
`allowed_cidrs`. Every call is appended to `~/.local/share/oqvian/audit.jsonl`;
that file plus the scope file is your rules-of-engagement evidence. Do not delete
it during an engagement.

**2. CPU-only is genuinely slow — don't mistake it for a hang.** At ~6 tok/s a
~9k-token agent turn is ~25 minutes; the timeouts in the harness and bridge are
sized for that (60 min). Watch progress rather than kill it:

```bash
journalctl --user -u oqvian-proxy.service -n 20   # look for a "tool turn:" line
ollama ps                                         # PROCESSOR: GPU vs CPU
```

A GPU box finishes the same turn in seconds to a couple of minutes.

---

## 9. Offline / air-gapped install

Public repo, so the assets download with plain `curl`. On a connected machine:

```bash
mkdir -p oq-rel && cd oq-rel
base=https://github.com/Ahnaf-Code55/oqvian-cyber/releases/download/v1.1.0
for f in oqvian-models-2026.11.06.tar.part-aa \
         oqvian-models-2026.11.06.tar.part-ab \
         oqvian-models-2026.11.06.tar.part-ac \
         oqvian-models-2026.11.06.sha256 \
         oqvian-harness-0.1.1-rc.2-npm-cache.tar; do
  curl -fL --retry 3 -O "$base/$f"
done
```

Carry `oq-rel/` over, then on the target:

```bash
bash scripts/install-release-assets.sh --from-dir ./oq-rel   # touches no network at all
bash install.sh
```

---

## 10. Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| Model answers, never calls a tool | `.Tools` template missing | `bash models/build-models.sh`, then check `ollama show oqvian-cyber-control-full-unlocked-v1.1 --template \| grep -c .Tools` = 3 |
| `PI_AI_ERROR: No API key for provider: ollama-local` / `MISSING_CREDENTIAL` | provider block edited or an `apiKeyEnv:` added | re-run `python3 scripts/setup_harness.py` |
| `dsh` can't reach provider / connection refused on 11435 | bridge not running | start `oqvian-proxy.service` (§6) |
| `dsh: TIMEOUT: Request timed out` on a CPU-only box | a turn took longer than the bridge timeout | bridge sets `OQVIAN_PROXY_TIMEOUT=3600`; keep it above the harness idle window |
| First turn hangs for tens of minutes, `/api/chat` 500s | prompt bigger than the model's context — usually a host skill catalog | re-run `scripts/setup_harness.py` (disables `skill-filesystem` + `tool-skill`) |
| Every network tool says `BLOCKED` | target not in scope | add it to `scope.json` — do not switch mode to `open` |
| Tool call denied / cancelled instantly | approval preset `ask` in a non-interactive run | use `oqvian-cli` (auto-approve) or the web UI (prompts) |

---

## 11. Where to read next

| File | Why |
|---|---|
| `docs/HANDOFF.md` | one-page install overview |
| `docs/CISO-PLAYBOOK.md` | twelve ready workflows — start here on day one |
| `deploy/README.md` | target matrix + the installer's guarantees |
| `deploy/windows/README.md` | Intel GPU specifics, Windows troubleshooting |
| `AI-HANDOFF.md` | the same steps written for an AI assistant to execute, with expected output per step |
| `docs/MODEL.md` | the model: id, template, sampling params, refusal posture |
