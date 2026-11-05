# AI HANDOFF — install OQVIAN

**You are an AI assistant installing OQVIAN on the user's machine.**
This file is complete. Follow it in order, run the commands, compare output to
the "expect" line, and stop at the first mismatch to consult the failure table
in §11. Do not improvise alternatives; every choice here is deliberate and
several obvious-looking "improvements" break the stack (§12).

If you cannot browse this repository: everything you need is in this file. Ask
the user to paste it, or to run the commands and paste the output back.

---

## 0. What you are installing

Three things that must all be present, because each one silently ruins the
stack if missing:

1. **The model** — WhiteRabbitNeo 2.5 (a Qwen2.5-Coder-7B fine-tune), renamed
   OQVIAN, served by Ollama on `127.0.0.1:11434`.
2. **The harness** — `@deepseek-ai/dsh` at exactly `0.1.1-rc.2`, which gives the
   model a browser UI and a tool loop.
3. **The tool server** — `mcp/server.py`, which exposes 5 tools the model calls
   itself: `kb`, `recon`, `execute`, `governance`, `transform`.

The model is 7.6B parameters at Q4_K_M: **4.7 GB** on disk, ~5.5 GB resident
with a 16K context. The machine needs 16 GB RAM and 12 GB free disk.

---

## 1. Detect the platform, then follow one branch

```bash
uname -s
```

- `Linux` / `Darwin` → **§2 Linux/macOS**
- Anything else, or `$PSVersionTable` returns a table → **§3 Windows**

Report which branch you took before continuing.

---

## 2. Linux / macOS

### 2.1 Prerequisites

```bash
git --version && python3 --version && npm --version
```

**Expect:** git 2.x, Python 3.10–3.13, npm 18+. If Python is 3.14 or newer, stop
and install 3.12 — two dependencies do not build on 3.14 yet.

```bash
command -v ollama || curl -fsSL https://ollama.com/install.sh | sh
```

**Expect:** `ollama` resolves. On macOS use `brew install ollama`.

### 2.2 Clone

The repository is **private**. The user must supply a token with `repo` scope:

```bash
export GH_TOKEN=<ask the user>
gh auth login --with-token <<< "$GH_TOKEN" || true
git clone "https://${GH_TOKEN}@github.com/Ahnaf-Code55/oqvian-cyber.git" ~/oqvian-cyber
cd ~/oqvian-cyber
```

**Expect:** 28 files, no `index/`, no `corpus/`, no `.venv/`. That is correct —
they are generated, not shipped.

### 2.3 Install

```bash
bash install.sh
```

This runs eight stages and takes 20–40 minutes. It is idempotent: if it fails,
re-run it and it resumes.

**Expect** near the end:

```
== summary ==
  ok   ...
```

and a final line reporting `install.sh --status` with nine components.

If `install.sh` reports `harness (install dsh, then re-run this script)`:

```bash
npm i -g @deepseek-ai/dsh@0.1.1-rc.2
bash install.sh
```

### 2.4 Continue to §4

---

## 3. Windows

Open **PowerShell as Administrator** for this section only. Everything else runs
as the normal user.

### 3.1 Prerequisites

```powershell
git --version; python --version; node --version; npm --version
```

**Expect:** git 2.x, Python 3.10–3.13, Node 18+.

```powershell
winget install --id Ollama.Ollama -e --accept-package-agreements --accept-source-agreements
```

**Expect:** Ollama appears in the system tray. Verify:

```powershell
ollama --version
```

### 3.2 Clone

```powershell
$env:GH_TOKEN = "<ask the user>"
git clone "https://$env:GH_TOKEN@github.com/Ahnaf-Code55/oqvian-cyber.git" "$HOME\oqvian-cyber"
cd "$HOME\oqvian-cyber"
```

### 3.3 Install

```powershell
powershell -ExecutionPolicy Bypass -File deploy\windows\install.ps1
```

**Expect:** eight stages, ending with a summary of `ok`/`skip`/`FAIL` counts.

### 3.4 Intel GPU note

The target laptop has an **Intel Iris Xe MAX (4 GB)**. Ollama reaches it through
**Vulkan**, not CUDA:

```powershell
[Environment]::SetEnvironmentVariable("OLLAMA_VULKAN","1","User")
```

Set that, then restart Ollama from the tray before the first prompt. If Vulkan
initialisation fails, the model falls back to CPU and still works — just 5–10×
slower. Do **not** install Intel's IPEX-LLM Ollama build as a "fix"; the
installer's path is the supported one.

---

## 4. The step everyone skips — verify tool calling

A GGUF carries no `.Tools` block in its chat template, so Ollama never renders
the tool schemas and **the model can never call a tool**. It answers like a
chatbot and looks fine. `models/build-models.sh` fixes this by installing the
Qwen2.5 template; `install.sh` runs it at stage 4.

Confirm it took effect:

```bash
ollama show oqvian --template | grep -c '.Tools'
```

**Expect: `3`.** If `0`, run:

```bash
bash models/build-models.sh
```

Check all five role models at once:

```bash
for m in oqvian oqvian-ciso oqvian-offensive oqvian-defensive oqvian-ir; do
  printf '%-20s %s\n' "$m" "$(ollama show "$m" --template | grep -c '.Tools')"
done
```

**Expect** `3` on every line.

---

## 5. Wire the harness to the tool server

`install.sh` stage 8 does this. Verify independently:

```bash
dsh --profile web --dump-config | grep -c oqvian-mcp
dsh --profile headless --dump-config | grep -c oqvian-mcp
```

**Expect:** a non-zero count on both.

The harness spawns `mcp/server.py` over stdio and sees exactly five tools. If
you change the server, restart the harness — the tool list is read once at boot.

---

## 6. Verify — four checks, in this order

```bash
bash install.sh --status
```

**Expect:** nine rows, every one `yes`.

```bash
.venv/bin/python mcp/smoke_test.py
```

**Expect:** `all checks passed` (19 checks, no model involved, ~10 s).

```bash
ollama list | grep oqvian
```

**Expect:** five `oqvian*` entries plus `nomic-embed-text`.

```bash
oqvian-cli "Call mcp__oqvian__kb with action=attack and query=T1059, then state the technique name."
```

**Expect:** the model calls the tool and the answer names
**Command and Scripting Interpreter**.

This last one is the only test that proves the whole chain:
harness → MCP → model → tool → knowledge base. On the target hardware it takes
30–120 seconds. On a CPU-only machine it can take 20 minutes — that is normal,
not a hang. Do not kill it before 25 minutes.

### 6.1 Prove the tool call reached the audit log

```bash
tail -3 ~/.local/share/oqvian/audit.jsonl
```

**Expect:** a JSON line whose `"tool"` is `kb` and whose `"decision"` is `ok`.
If there is no such line, the model answered from memory instead of calling the
tool — go back to §4.

---

## 7. Set the authorisation boundary

**The scope file is deliberately not in the repository.** It is per-machine and
it is what stops the agent acting on the wrong host. Create it before any
network work:

Linux/macOS — `~/.config/oqvian/scope.json`
Windows — `%USERPROFILE%\.config\oqvian\scope.json`

```json
{
  "mode": "restricted",
  "targets": ["10.0.0.0/24", "app.example.com"]
}
```

Replace the targets with the hosts the user is actually authorised to test.
Ask the user for them; **do not** invent a range and **do not** set
`"mode": "open"` — that disables the allowlist entirely.

Verify:

```bash
oqvian-cli "Use mcp__oqvian__governance with action=scope and report it."
```

**Expect:** the model reports the targets you wrote, inside `restricted` mode.

---

## 8. First real task

Tell the user to run `oqvian` (browser UI) rather than `oqvian-cli`, because the
UI prompts for every tool call and the CLI cannot prompt. Then hand them
`docs/CISO-PLAYBOOK.md` — twelve workflows to paste as-is.

---

## 9. Refresh cadence

Once a week, or before any engagement:

```bash
bash refresh-corpus.sh
```

**Expect:** KEV count around 1,700 and a catalog date within the last week.
Takes 2–10 minutes. It clones anything missing and rebuilds the index.

---

## 10. What "working" looks like, in one line

`oqvian-cli` makes a `kb` call, cites `T1059`, prints *Command and Scripting
Interpreter*, and appends a line to the audit log. Everything else is
cosmetics around that.

---

## 11. Failure table

| Symptom | Cause | Fix |
|---|---|---|
| `PI_AI_ERROR: No API key for provider: ollama-local` | pi-ai refuses a credential-less provider | The `ollama-local` block needs `headers: {Authorization: Bearer ollama}`. Re-run `python scripts/setup_harness.py` |
| `MISSING_CREDENTIAL` | same, other variant — someone added `apiKeyEnv` | Delete the `apiKeyEnv:` line under `ollama-local` |
| Model answers, never calls a tool | `.Tools` template missing | `bash models/build-models.sh`, then check §4 |
| Tool call is denied / cancelled instantly | approval preset `ask` in a non-interactive run | Use `oqvian-cli` (sets auto-approve) or the web UI (prompts) |
| `stream idle timeout after 300000ms` | CPU generation is slower than the harness idle timeout | Add `streamIdleTimeoutMs: 900000` under `ollama-local` in `~/.dsh/settings.yaml` |
| Every network tool says `BLOCKED` | target not in scope file | Add it to `scope.json` — do not switch mode to `open` |
| `ollama pull` fails | no route to HuggingFace | Use the release asset, §12.1 |
| Index build seems hung | 10,932 passages, ~9 min on the target CPU | Wait. Check `.venv/bin/python ingest.py` progress, do not restart |
| `command not found: gh` | `gh` is optional | Use plain `git clone` with the token in the URL |

---

## 12. Do not do these

1. **Do not skip `models/build-models.sh`.** Without it the stack is a chatbot
   with a security system prompt. It will still answer questions and look
   healthy, which is why this is the most common failure.
2. **Do not make the repository public.** It is private by intent.
3. **Do not add safety disclaimers to the model's system prompt.** The scope
   file is the control; the model is authorised for in-scope work only.
4. **Do not set `"mode": "open"` in the scope file** to make something work.
5. **Do not "upgrade" the harness** past `0.1.1-rc.2`. The settings schema
   changed across versions and these profiles are written against this one.
6. **Do not re-tag or retune the model.** RAG is the correct lever here: the
   facts expire weekly, the weights do not.
7. **Do not run the flag `--with-root`** unless the user has explicitly agreed
   to a root toolchain install.

### 12.1 If HuggingFace is unreachable

The weights may be attached to a GitHub Release on this repository:

```bash
gh release download --repo Ahnaf-Code55/oqvian-cyber --pattern 'oqvian-models*'
```

If no release asset exists, the model must be fetched from:

```
hf.co/bartowski/WhiteRabbitNeo-2.5-Qwen-2.5-Coder-7B-GGUF:Q4_K_M
```

with `ollama pull`, which needs a route to `huggingface.co`. If neither is
possible, this machine cannot be provisioned — report that rather than
substituting a different model.

---

## 13. Reporting back

When you are done, tell the user, in this order:

1. Which branch you took (§2 or §3) and the OS version.
2. The result of the four checks in §6, as pass/fail each.
3. Whether `ollama ps` shows `GPU` or `CPU` in the PROCESSOR column — that is
   the difference between 12–25 tok/s and 1.5–3 tok/s.
4. The scope targets you wrote, or that the user must supply them.
5. Anything from §11 that you hit and how you resolved it.

Never report success on the basis of `install.sh` exiting 0. The only success
signal is §10.
