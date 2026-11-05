# Handoff — installing OQVIAN on a new machine

One page. If you only read one section, read **Install**.

> Installing with an AI assistant (ChatGPT, Claude, Copilot)? Give it
> [`../AI-HANDOFF.md`](../AI-HANDOFF.md) instead — that file is written for an
> agent to execute, with expected output per step and a failure table. This one
> is for a human.

---

## 1. What you are getting

A local security assistant. A 7B model, a 10,932-passage knowledge index, and a
Kali-class toolchain, wired together so the model can call the tools itself.
Nothing leaves the machine: no cloud API, no telemetry, no vendor account.

It is **not** a scanner you point at things and forget. It retrieves, drafts and
maps. A human decides.

---

## 2. What the machine needs

| | Minimum | Comfortable |
|---|---|---|
| OS | Windows 11, macOS, Linux | any |
| RAM | 16 GB | 16 GB |
| Disk | 12 GB free | 20 GB free |
| GPU | none (CPU works, slow) | 4 GB VRAM (12–25 tok/s) |
| Network | only for the 4.7 GB weight pull | — |

Windows with an Intel Arc / Iris Xe GPU needs the **Vulkan** path, which the
installer sets automatically. Details: `deploy/windows/README.md`.

---

## 3. Install

Both platforms start the same way: clone, then pull the built models and harness
from this repository's release. That download is ~4.9 GB and replaces both the
HuggingFace pull and the npm install.

```bash
gh auth login
gh repo clone Ahnaf-Code55/oqvian-cyber ~/oqvian-cyber
cd ~/oqvian-cyber
bash scripts/install-release-assets.sh     # models + harness, no network beyond GitHub
```

### Windows

```powershell
powershell -ExecutionPolicy Bypass -File deploy\windows\install.ps1
```

Takes 10–30 minutes once the assets are in place. Re-run it any time; it is
idempotent and skips what is already done. If `gh` is unavailable, the
PowerShell equivalent of the download step is written out in
[`../AI-HANDOFF.md`](../AI-HANDOFF.md) §3.3.

### Linux / macOS

```bash
bash install.sh
```

Add `--with-root` if you have sudo and want the full root toolset
(BlackArch group mapping on Arch, apt packages elsewhere).

### No internet at all

The release assets are also how you provision a machine with no route out. On a
connected machine:

```bash
gh release download v1.0.0 --repo Ahnaf-Code55/oqvian-cyber -D ./oq-rel
```

Carry `oq-rel/` over on a USB stick, then on the target:

```bash
bash scripts/install-release-assets.sh --from-dir ./oq-rel
bash install.sh
```

`--from-dir` uses the directory in place and touches no network at all. The
Windows equivalent is written out in [`../AI-HANDOFF.md`](../AI-HANDOFF.md) §3.3.

---

## 4. Prove it works (five minutes)

```bash
bash install.sh --status                     # nine components, expect "yes"
python mcp/smoke_test.py                     # 19 checks, no model needed
ollama show oqvian --template | grep -c '.Tools'   # expect 3
```

Then the one that matters — the full chain, harness → MCP → model → tool →
knowledge base:

```bash
oqvian-cli "Call mcp__oqvian__kb with action=attack and query=T1059, then state the technique name."
```

A healthy run calls the tool and answers **Command and Scripting Interpreter**.
If it answers from memory without calling the tool, the tool template is
missing — run `models/build-models.sh`.

---

## 5. Set your own authorisation boundary

The scope file is **not** shipped — it is per-machine, and it is the control that
stops the agent acting on the wrong host. Create it before any network work:

```json
{
  "mode": "restricted",
  "targets": ["10.0.0.0/24", "app.example.com"]
}
```

Windows: `%USERPROFILE%\.config\oqvian\scope.json`
Linux/macOS: `~/.config/oqvian/scope.json`

Anything not listed is refused by the tool server — not by the prompt, so the
model cannot talk its way past it. Keep `"mode": "restricted"` for real work;
`"open"` exists only for disposable labs.

---

## 6. Two things to know before you point it at production

**Approval.** The web UI (`oqvian`) prompts for every tool call. The one-shot CLI
(`oqvian-cli`) cannot prompt, so it auto-approves and prints a warning. For an
interactive server/headless session, use `oqvian-repl` instead; it starts DSH locally
(loopback only) and runs tools in danger-bypass mode. Use the
web UI when the target matters.

**The audit log.** Every call appends a line to
`~/.local/share/oqvian/audit.jsonl`. That file plus the scope file is your
rules-of-engagement evidence. Do not delete it during an engagement.

---

## 7. Where to go next

| File | Why |
|---|---|
| `docs/CISO-PLAYBOOK.md` | twelve ready workflows — start here on day one |
| `deploy/windows/README.md` | Intel GPU specifics, troubleshooting |
| `deploy/README.md` | target matrix, what the installer guarantees |
| `README.md` | architecture, governance table, known limits |

Refreshing the knowledge base weekly is the one maintenance task:

```bash
bash refresh-corpus.sh
```

KEV and Sigma change daily; the weights do not.
