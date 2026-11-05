# OQVIAN on Windows — CISO laptop deployment

Target machine: **Intel Core i7 11th gen · 16 GB RAM · Intel Iris Xe MAX (4 GB VRAM,
discrete)**. This guide sets up the whole stack natively on Windows: Ollama with
Intel GPU offload, the single OQVIAN model, the knowledge index, the tool-call
bridge, the harness, and the tool server.

Expected performance on that machine with the GPU path working: **12–25 tok/s**
generation, prompt processing 60–150 tok/s. If it falls back to CPU only you will
see 2–4 tok/s — the difference is obvious within one prompt, see
[Troubleshooting](#troubleshooting).

---

## 1. What gets installed

| Component | Where | Size |
|---|---|---|
| Ollama (Windows service) | `%LOCALAPPDATA%\Programs\Ollama` | 700 MB |
| Model (OQVIAN-CYBER-CONTROL-FULL UNLOCKED V1.1, Q4_K_M) | `%USERPROFILE%\.ollama\models` | 4.7 GB |
| Knowledge index (10,932 passages) | `%USERPROFILE%\oqvian-cyber\index` | 120 MB |
| Corpus sources | `%USERPROFILE%\oqvian-cyber\corpus\raw` | 1.6 GB |
| Python venv + MCP server | `%USERPROFILE%\oqvian-cyber\.venv` | 90 MB |
| Tool-call bridge (127.0.0.1:11435) | started from `.venv`; auto-starts at logon | — |
| Harness (dsh + Node runtime) | `%USERPROFILE%\.dsh` | 400 MB |

Total ≈ **8 GB**. Have 15 GB free before you start.

---

## 2. Install

Open **PowerShell as your normal user** (not Administrator — Ollama installs
per-user and the models must live in your profile).

```powershell
cd $HOME
git clone <your-repo> oqvian-cyber
cd oqvian-cyber
powershell -ExecutionPolicy Bypass -File deploy\windows\install.ps1
```

If Git is not installed: `winget install --id Git.Git -e`.

The installer is idempotent — re-run it after any failure and it picks up where
it stopped. Flags:

```powershell
.\deploy\windows\install.ps1 -SkipTools      # models + index + harness only
.\deploy\windows\install.ps1 -SkipModel      # keep the existing model build
.\deploy\windows\install.ps1 -SkipIndex      # keep the existing index
.\deploy\windows\install.ps1 -Status         # report only, change nothing
```

Then start it (**PowerShell**; the launchers are bash, so invoke `dsh` directly):

```powershell
dsh web                                                  # web UI
dsh --profile headless "Map T1059.001 to Sigma rules we can deploy"   # one-shot
ollama run oqvian-cyber-control-full-unlocked-v1.1       # direct
```

The installer has already started the tool-call bridge and registered it to
start at logon, so `dsh` reaches the provider on `127.0.0.1:11435` with no
further setup.

---

## 3. Intel Iris Xe MAX — getting the GPU path working

Iris Xe MAX is a **discrete** Intel DG1 card, not an iGPU, so it is worth
offloading. There are two paths; the installer tries the first and documents the
second.

### Path A — Ollama's Vulkan backend (simplest)

Your Ollama build contains `OLLAMA_VULKAN`. The installer sets, as **user**
environment variables:

```
OLLAMA_VULKAN=1
OLLAMA_FLASH_ATTENTION=1
OLLAMA_KV_CACHE_TYPE=q8_0
OLLAMA_KEEP_ALIVE=30m
OLLAMA_HOST=127.0.0.1:11434
```

Verify after a restart of the service:

```powershell
ollama ps                 # LOADED column shows the model, PROCESSOR column shows GPU
ollama run oqvian "reply with the single word READY"
```

`PROCESSOR` should read `100% GPU`, or a split like `70%/30% CPU/GPU`. If it says
`100% CPU`, the Vulkan backend did not pick up the card: update the Intel driver
from Intel's site (not Windows Update — the OEM driver is usually stale) and make
sure both `OLLAMA_VULKAN=1` is set **and** the Ollama tray process was fully
restarted (quit from the tray, then start `ollama serve` again).

### Path B — IPEX-LLM portable Ollama (fastest on Intel Arc/Xe)

Intel's own build ships the oneAPI/IPEX kernels and is typically 20–40 % faster
than the Vulkan path on DG1.

1. Download the *Ollama portable zip* from
   <https://github.com/intel/ipex-llm/releases> (`ollama-ipex-llm-*-win.zip`).
2. Extract to `C:\ipex-ollama`.
3. Use it instead of the system Ollama:

```powershell
$env:OLLAMA_HOST = "127.0.0.1:11434"
$env:SYCL_CACHE_PERSISTENT = "1"
cd C:\ipex-ollama
.\ollama.exe serve
```

4. Point the harness at the same port — nothing else changes. Set
   `OLLAMA_BIN=C:\ipex-ollama\ollama.exe` before re-running `install.ps1 -SkipIndex`
   so the models are created with that binary.

### How much of the 7B fits in 4 GB

The Q4_K_M weights are 4.4 GB, so roughly 3.3 GB is offloaded and the rest stays
in RAM. That is the normal, expected shape on this laptop — you get most of the
speed benefit. Lowering context to 8K frees ~0.5 GB of KV cache and pushes more
layers onto the GPU:

```powershell
ollama run oqvian-cyber-control-full-unlocked-v1.1 --parameter num_ctx 8192
```

16K with `q8_0` KV (~28 KB/token, ≈0.45 GB) is the default the installer sets;
32K is possible but leaves almost no VRAM headroom.

---

## 4. What works natively and what does not

The tool server has five tools. Three are pure Python and work identically on
Windows; one needs Windows builds of the CLI tools; one is trivial.

| Tool | Windows | Notes |
|---|---|---|
| `kb` (ATT&CK/CWE/KEV/Sigma/atomics/LOLBAS/GTFOBins/WSTG) | **yes** | index is SQLite, no dependency |
| `governance` (scope + audit) | **yes** | |
| `transform` (base64/hex/hash) | **yes** | |
| `recon` (DNS/whois/HTTP/TLS/port scan/subdomains) | **yes** | pure sockets + certificate transparency |
| `execute` (nmap, nuclei, ffuf, …) | **partially** | only tools present on `PATH`; the server reports the rest as missing |

Windows builds that exist and are worth installing:

```powershell
winget install --id Insecure.Nmap -e            # nmap
# ProjectDiscovery + others: grab the *_windows_amd64.zip from each release
#   nuclei, httpx, subfinder, naabu, katana, ffuf  → put the .exe on PATH
#   trivy, gitleaks, syft, grype                   → same
```

Everything else in the Kali menu (Metasploit, BloodHound, aircrack-ng, hashcat,
the Linux-only GTFOBins), plus `.elf`/`.so` analysis and packet capture on
monitor-mode adapters, needs Linux. Use the WSL2 path below for those.

### WSL2 option — full Kali-class toolset

If the CISO needs the *whole* toolchain rather than the portable subset:

```powershell
wsl --install -d Ubuntu-24.04
```

Inside WSL, run `bash install.sh` and add the Kali repository
(`deb http://http.kali.org/kali kali-rolling main`) or use `install-root-tools.sh`.
Then install `dsh` inside WSL too and let it drive the Linux tool server — GPU
offload stays on the Windows side, so run Ollama on Windows and set
`OLLAMA_HOST=http://<windows-host-ip>:11434` in WSL, plus `OLLAMA_HOST=0.0.0.0`
on Windows (firewall-scoped to the WSL subnet only).

Do not run both arrangements at once: pick native (portable subset, GPU-friendly)
or WSL (complete toolset, needs the cross-boundary Ollama wiring).

---

## 5. Governance settings the CISO should know

| Control | File / setting | Default |
|---|---|---|
| Authorisation boundary | `%USERPROFILE%\.config\oqvian\scope.json` | restricted: RFC1918 + localhost |
| Per-action approval | `~/.dsh/settings.yaml` → `permission.defaultPreset` | `ask` |
| Audit trail | `%USERPROFILE%\.local\share\oqvian\audit.jsonl` | every tool call, append-only |
| Network exposure | `OLLAMA_HOST=127.0.0.1` | loopback only |
| Model egress | none | no cloud API, no telemetry |

Before an engagement, edit `scope.json`:

```json
{
  "mode": "restricted",
  "allowed_hosts": ["localhost"],
  "allowed_domains": ["client.example.com"],
  "allowed_cidrs": ["10.20.0.0/16"],
  "max_scan_ports": 65535
}
```

The server refuses anything outside it regardless of what the model asks for, and
the refusal is logged. Keep `scope.json` and `audit.jsonl` with the report — that
pair is your rules-of-engagement evidence.

---

## 6. Troubleshooting

**`ollama ps` says 100% CPU.**
Driver, then env var, then restart — in that order. Confirm with
`[Environment]::GetEnvironmentVariable("OLLAMA_VULKAN","User")`. Quit the tray
app fully; a stale `ollama.exe` keeps the old environment.

**First prompt takes minutes.**
Cold model load from disk (4.4 GB). Set `OLLAMA_KEEP_ALIVE=30m` (installer does)
and it stays resident. If every prompt is slow, the GPU path is not active.

**`PI_AI_ERROR: No API key for provider: ollama-local` / `MISSING_CREDENTIAL`.**
pi-ai refuses a provider that presents no credential at all, even though Ollama
ignores auth. The fix is the static header the installer writes:

```yaml
    ollama-local:
      displayName: OQVIAN (local)
      api: openai-completions
      baseURL: http://127.0.0.1:11435/v1
      headers:
        Authorization: Bearer ollama
```

Note the port: the provider points at the **tool-call bridge** on `11435`, not
Ollama's `11434`. The bridge owns the tool protocol (it renders the schemas,
parses the model's `<tool_call>`, and retries a dropped call), so pointing the
provider straight at Ollama lets a valid tool call silently vanish. If the
bridge is down, `dsh` will fail to reach the provider.

Do **not** add `apiKeyEnv:` pointing at an unset variable — that produces the
other variant of the same error. Re-run `python scripts\setup_harness.py` to
restore the block.

**`dsh` cannot reach the provider / connection refused on 11435.**
The bridge is not running. The installer starts it and registers
`%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\oqvian-bridge.cmd`
so it starts at every logon. Start it by hand to test:

```powershell
.venv\Scripts\pythonw.exe mcp\toolcall_proxy.py
# or, for visible output:
.venv\Scripts\python.exe mcp\toolcall_proxy.py
```

Then confirm it answers and re-run the installer to restore the logon entry:

```powershell
.\deploy\windows\install.ps1 -Status     # 'bridge' row must read 'present'
```

**Model answers but never calls a tool.**
The chat template lost its `.Tools` block. Rebuild:

```powershell
.\deploy\windows\install.ps1 -SkipTools -SkipIndex -SkipHarness
ollama show oqvian --template | Select-String ".Tools"    # must match 3 times
```

**`execute` says a tool is missing.**
That is accurate — `execute` only runs binaries on `PATH`. Install the Windows
build, or move to WSL2.

**Harness starts but has no `mcp__oqvian__*` tools.**
```powershell
dsh --profile web --dump-config | Select-String "oqvian-mcp"
python scripts\setup_harness.py
```

**Antivirus quarantines nmap/nuclei/hashcat.**
Expected: these are the same binaries every pentest laptop carries. Add a
folder exclusion for `%USERPROFILE%\oqvian-cyber` and `%LOCALAPPDATA%\Programs\Ollama`,
and record the exclusion in the risk register — an agent-writable directory that
AV ignores is itself a control decision.

---

## 7. Uninstall

```powershell
# model
ollama rm oqvian-cyber-control-full-unlocked-v1.1
# bridge logon entry
Remove-Item "$([Environment]::GetFolderPath('Startup'))\oqvian-bridge.cmd" -ErrorAction SilentlyContinue
# harness
npm uninstall -g @deepseek-ai/dsh
# everything else is inside these two directories
Remove-Item -Recurse -Force $HOME\oqvian-cyber, $HOME\.dsh
```
