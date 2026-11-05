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

1. **The model** — OQVIAN-CYBER-CONTROL-FULL UNLOCKED V1.1 (Qwen2.5-7B-Instruct,
   abliterated), served by Ollama on `127.0.0.1:11434`. It is **our build**, not
   the upstream download: the tool-calling template and the unified operator
   system prompt are baked in. §2.3 fetches it from this repository's release. Read §12.1
   before considering any other source.
2. **The harness** — `@deepseek-ai/dsh` at exactly `0.1.1-rc.2`, which gives the
   model a browser UI and a tool loop. It talks to the **tool-call bridge**
   (`mcp/toolcall_proxy.py`) on `127.0.0.1:11435`, which forwards to Ollama and
   shields the agent from Ollama's intermittent dropped tool calls. `install.sh`
   starts it as `oqvian-proxy.service`; `scripts/setup_harness.py` points the
   provider at it.
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

### 2.3 Get the built models and harness

**Do this before `install.sh`.** It downloads ~4.9 GB of release assets: the five
already-built models, plus a primed npm cache for the harness. No HuggingFace and
no npm registry are involved.

```bash
bash scripts/install-release-assets.sh
```

**Expect:** three parts downloaded, `checksums match`, then an `ollama list`
showing `oqvian-cyber-control-full-unlocked-v1.1` and `nomic-embed-text`, then
`dsh 0.1.1-rc.2`.

Takes 5–20 minutes depending on bandwidth. If it stops with
`install gh, or export GH_TOKEN`, re-export the token from §2.2 and re-run.

If the assets were carried over from another machine instead, point at them and
nothing touches the network:

```bash
bash scripts/install-release-assets.sh --from-dir /media/usb/oq-rel
```

### 2.4 Install the rest

```bash
bash install.sh
```

This runs eight stages and takes 20–40 minutes — but the two slow ones are now
already satisfied, so expect closer to 10. Stage 4 detects the extracted models
and verifies the template rather than rebuilding, and stage 8 finds `dsh` already
present. It is idempotent: if it fails, re-run it and it resumes.

**Expect** near the end:

```
== summary ==
  ok   ...
```

and a final line reporting `install.sh --status` with ten components.

If `install.sh` still reports `harness (install dsh, then re-run this script)`,
§2.3 did not complete — fix that rather than installing from npm.

### 2.5 Continue to §4

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

### 3.3 Get the built models and harness

**Do this before `install.ps1`.** Downloads ~4.8 GB: the already-built model
and a primed npm cache. No HuggingFace, no npm registry.

```powershell
$Rel = "$HOME\oq-rel"
New-Item -ItemType Directory -Force -Path $Rel | Out-Null
gh release download v1.1.0 --repo Ahnaf-Code55/oqvian-cyber --dir $Rel --clobber
```

If `gh` is not installed, use `git`'s credential and the API instead:

```powershell
$h = @{ Authorization = "Bearer $env:GH_TOKEN" }
Invoke-RestMethod "https://api.github.com/repos/Ahnaf-Code55/oqvian-cyber/releases/tags/v1.1.0" -Headers $h |
  Select-Object -ExpandProperty assets |
  ForEach-Object {
    Invoke-WebRequest $_.url -Headers ($h + @{ Accept = "application/octet-stream" }) -OutFile "$Rel\$($_.name)"
  }
```

**Expect:** `oqvian-harness-0.1.1-rc.2-npm-cache.tar`, three `oqvian-models-*.tar.part-*`,
and `oqvian-models-2026.11.05.sha256`.

Verify, reassemble, and extract:

```powershell
Get-Content "$Rel\oqvian-models-2026.11.05.sha256" | ForEach-Object {
    $want, $file = $_ -split '\s+', 2
    $got = (Get-FileHash "$Rel\$($file.Trim())" -Algorithm SHA256).Hash.ToLower()
    if ($got -ne $want.ToLower()) { throw "checksum mismatch: $file" }
}
Write-Host "checksums match"

# Stream the parts straight into tar, so the disk must hold the 4.7 GB of parts
# plus the 4.7 GB of extracted blobs — not a third 4.7 GB copy of the archive.
New-Item -ItemType Directory -Force -Path "$HOME\.ollama" | Out-Null
cmd /c "type ""$Rel\oqvian-models-2026.11.05.tar.part-00"" ""$Rel\oqvian-models-2026.11.05.tar.part-01"" ""$Rel\oqvian-models-2026.11.05.tar.part-02""" |
    tar -xf - -C "$HOME\.ollama"
ollama list
```

**Expect:** the five `oqvian*` entries and `nomic-embed-text`.

Needs ~10 GB free on `C:` while this runs (4.7 GB of parts, 4.7 GB of blobs).
Delete `$Rel\*.part-*` afterwards to reclaim half of it.

If `type | tar` errors on this machine, fall back to reassembling first — that
needs ~15 GB free:

```powershell
cmd /c copy /b "$Rel\oqvian-models-2026.11.05.tar.part-00+$Rel\oqvian-models-2026.11.05.tar.part-01+$Rel\oqvian-models-2026.11.05.tar.part-02" "$Rel\models.tar"
tar -xf "$Rel\models.tar" -C "$HOME\.ollama"
Remove-Item "$Rel\models.tar"
```

Then install the harness from the shipped cache, offline:

```powershell
New-Item -ItemType Directory -Force -Path "$env:TEMP\oqcache" | Out-Null
tar -xf "$Rel\oqvian-harness-0.1.1-rc.2-npm-cache.tar" -C "$env:TEMP\oqcache"
npm install -g "@deepseek-ai/dsh@0.1.1-rc.2" --cache "$env:TEMP\oqcache\dshcache" --offline --no-audit --no-fund
dsh --version
```

**Expect:** `0.1.1-rc.2`.

### 3.4 Install the rest

```powershell
powershell -ExecutionPolicy Bypass -File deploy\windows\install.ps1
```

**Expect:** eight stages, ending with a summary of `ok`/`skip`/`FAIL` counts. It
will skip the model pull and the harness install, because §3.3 satisfied them.

### 3.5 Intel GPU note

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

## 4. Confirm the tool template survived

A GGUF carries no `.Tools` block in its chat template, so Ollama would never
render the tool schemas and **the model could never call a tool**. It would
answer like a chatbot and look fine.

The release models in §2.3/§3.3 already have the Qwen2.5 template baked in — that
is the entire reason we ship a 4.7 GB artefact instead of pointing at a download.
Verify it is intact:

```bash
ollama show oqvian --template | grep -c '.Tools'
```

**Expect: `3`.** If you see `0`, something overwrote `oqvian` with the upstream
model. Do not proceed — re-extract the release models and re-check.

Check the model's tool template:

```bash
for m in oqvian-cyber-control-full-unlocked-v1.1; do
  printf '%-40s %s\n' "$m" "$(ollama show "$m" --template | grep -c '.Tools')"
done
```

**Expect** `3` on the line. Only if it shows `0`, rebuild it locally:

```bash
bash models/build-models.sh
```

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

**Expect:** ten rows, every one `yes`.

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
| Model answers, never calls a tool | `.Tools` template missing — usually an upstream pull overwrote the release model | Re-extract the release models (§2.3/§3.3), then re-check §4 |
| Tool call is denied / cancelled instantly | approval preset `ask` in a non-interactive run | Use `oqvian-cli` (sets auto-approve) or the web UI (prompts) |
| `stream idle timeout after 300000ms` | CPU generation is slower than the harness idle timeout | Add `streamIdleTimeoutMs: 900000` under `ollama-local` in `~/.dsh/settings.yaml` |
| First turn hangs for tens of minutes and never returns; Ollama logs `/api/chat` 500s | prompt exceeded `num_ctx` — usually dsh's `<available_skills>` catalog (~20k tokens on a host with many skills) | Re-run `python scripts/setup_harness.py`: it disables `skill-filesystem` + `tool-skill` in the profile. Verify `dsh --profile headless --dump-config \| grep -A2 skill-filesystem` shows `disabled: true` |
| `dsh: TIMEOUT: Request timed out` after ~30 min on a CPU-only box | the bridge buffers each tool turn (`upstream stream=False`) and its upstream timeout (1800 s) expired at the same moment the harness's idle window did — a 9k-token turn at ~6 tok/s is ~25 min | the bridge unit sets `OQVIAN_PROXY_TIMEOUT=3600` and `streamIdleTimeoutMs` is 3600000; keep the bridge timeout **above** the harness idle window. A GPU box never needs more than the default |
| Every network tool says `BLOCKED` | target not in scope file | Add it to `scope.json` — do not switch mode to `open` |
| `ollama pull` fails | no route to HuggingFace | Use the release asset, §12.1 |
| Index build seems hung | 10,932 passages, ~9 min on the target CPU | Wait. Check `.venv/bin/python ingest.py` progress, do not restart |
| `command not found: gh` | `gh` is optional | Use plain `git clone` with the token in the URL |

---

## 12. Do not do these

1. **Do not skip §2.3 / §3.3.** The built models are the deliverable. A model
   pulled from upstream cannot call tools, and it will still answer questions,
   which is why this is the most common failure.
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

### 12.1 Never `ollama pull` the upstream model

```bash
ollama pull hf.co/mradermacher/Qwen2.5-7B-Instruct-abliterated-GGUF:Q4_K_M   # NO
```

That fetches the **unmodified** abliterated base. It has no `.Tools` block and no
OQVIAN system prompt. It answers questions and looks
healthy while being unable to call a single tool — the failure this stack exists
to avoid. Everything we changed lives in the Ollama model manifests and the chat
template, and those are only in the release assets.

Same reason for the harness: `@deepseek-ai/dsh` must stay at `0.1.1-rc.2`. The
release cache is built for exactly that version.

If the release assets are unreachable, stop and report it. Do not substitute a
different model, a different quantisation, or a newer harness.

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
