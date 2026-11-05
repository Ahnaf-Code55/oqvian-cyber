# Deployment targets

OQVIAN is built here but deployed on the CISO laptop. Pick the path that matches
the machine.

| Target | Path | What you get |
|---|---|---|
| Linux x86_64, 16 GB RAM, any GPU | [`install.sh`](../install.sh) | everything: 5-tool MCP server, Kali-class userland toolchain, BlackArch root set (optional), full agent loop |
| Windows 11, i7 11th gen, Iris Xe MAX 4 GB | [`windows/README.md`](windows/README.md) + [`windows/install.ps1`](windows/install.ps1) | Ollama with Intel GPU offload, models, index, harness; `kb`/`recon`/`governance`/`transform` native, `execute` limited to tools with Windows builds |
| Windows + full toolset | WSL2 Ubuntu | as Linux, with Ollama on the Windows side for GPU access |

## What the installer guarantees on any target

1. **The model can actually call tools.** `models/build-models.sh` installs the
   Qwen2.5 `.Tools` template that the GGUF does not ship. Skipping this is the
   single most common way the stack silently degrades to a chatbot.
2. **Context fits the hardware.** `scripts/preflight.sh` writes `hardware.env`
   with the context size and GPU env the machine can sustain (8K CPU-only,
   16K on 4 GB VRAM, 32K on 8 GB+).
3. **The tool surface is 5, not 22.** A 7B on 16K cannot carry 22 JSON schemas
   plus a conversation. The 22 functions remain, consolidated behind
   `action`/`tool` enums.
4. **Search works offline and fast.** SQLite FTS5 + BM25 over 10,932 passages,
   built in ~9 minutes on a 2015 CPU. Embeddings are optional and slow.
5. **Scope is enforced in code, not in the prompt.** Every network tool consults
   `~/.config/oqvian/scope.json`; the model is told the boundary but cannot talk
   its way past it. Every call lands in `~/.local/share/oqvian/audit.jsonl`.
6. **The provider authenticates.** pi-ai refuses a route with no credential, so
   the Ollama profile carries a static `Authorization: Bearer ollama` header —
   Ollama ignores it, the client stops complaining, and no API-key env var has to
   exist on the CISO's machine.
7. **A dropped tool call cannot silently degrade the agent.** Ollama's tool parser
   intermittently accepts a valid call and returns an empty turn; the tool-call
   bridge (`mcp/toolcall_proxy.py`, `oqvian-proxy.service`) owns the protocol —
   it renders the schemas, parses the model's `<tool_call>` itself, and retries a
   genuinely empty turn. The harness provider points at the bridge, not Ollama
   directly.

## Verifying a new deployment

```bash
bash install.sh --status                      # ten components, every one "yes"
.venv/bin/python mcp/smoke_test.py            # 19 checks, no LLM, ~10 s
dsh --profile web --dump-config | grep -c oqvian-mcp
ollama show oqvian --template | grep -c '.Tools'
ollama ps                                     # after one prompt: GPU vs CPU split
```

The `--status` line includes `bridge`, which confirms the tool-call bridge is
answering on `127.0.0.1:11435` before you ever send a prompt.

Then the end-to-end test that proves the whole chain — harness → MCP → model →
tool → knowledge base:

```bash
oqvian-cli "Call mcp__oqvian__kb with action=attack and query=T1059, then state the technique name."
```

A healthy run calls the tool and answers *Command and Scripting Interpreter*.
