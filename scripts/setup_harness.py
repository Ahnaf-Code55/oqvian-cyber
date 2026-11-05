#!/usr/bin/env python3
"""Wire OQVIAN into DeepSeek Harness — cross-platform (Linux, macOS, Windows).

Idempotent. Creates/replaces:
  ~/.dsh/profiles/<web|headless>/cordis.patch.yml   MCP client entry
  ~/.dsh/profiles/headless/package.json             headless bundle
  ~/.dsh/settings.yaml                              provider, models, permission
  ~/.config/oqvian/scope.json                       authorisation boundary

Run:  python scripts/setup_harness.py [--root /path/to/oqvian-cyber]
"""
from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path

DSH_HOME = Path(os.environ.get("DSH_HOME") or Path.home() / ".dsh")

MODELS = [
    ("oqvian-cyber-control-full-unlocked-v1.1:latest", "OQVIAN-CYBER-CONTROL-FULL UNLOCKED V1.1"),
]

PATCH = """\
# OQVIAN toolserver — 5 tools: kb, recon, execute, governance, transform
# Scope: ~/.config/oqvian/scope.json
# Audit: ~/.local/share/oqvian/audit.jsonl
- insert:
    - id: oqvian-mcp
      name: '@deepseek-ai/dsh-mcp-client'
      config:
        transport: stdio
        serverName: oqvian
        command: {python}
        args:
          - {server}
        env:
          OLLAMA_HOST: 127.0.0.1:11434
        cwd: {root}
        toolCallTimeoutMs: 900000
        failOnStartupError: false
# Do not inject the host's agent-skill catalog into the model context. dsh
# discovers skills from ~/.dsh/skills, ~/.agents/skills and the project, and
# renders every one as a name+description entry in an <available_skills>
# system-reminder. On a host with a few hundred skills that block alone was
# ~81 KB (~20k tokens) — more than the 7B model's whole 16384-token window, so
# the prompt overflowed the context and no turn ever completed. The OQVIAN
# profile drives a fixed five-tool MCP surface; a generic skill catalog is
# irrelevant to it and must not depend on what happens to be installed.
- id: skill-filesystem
  disabled: true
- id: tool-skill
  disabled: true
"""

HEADLESS_PKG = """\
{
  "name": "dsh-profile-headless",
  "private": true,
  "dependencies": {},
  "dsh": { "profile": { "bundles": ["@deepseek-ai/dsh-base", "@deepseek-ai/dsh-headless"] } }
}
"""

SCOPE = {
    "mode": "restricted",
    "allowed_hosts": ["localhost", "127.0.0.1", "::1"],
    "allowed_domains": [],
    "allowed_cidrs": ["127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"],
    "max_scan_ports": 65535,
    "note": "Add engagement targets here. mode=open disables the allowlist (lab only).",
}


def yaml_quote(p: str) -> str:
    return p if re.fullmatch(r"[A-Za-z0-9_./:\\-]+", p) else json.dumps(p)


def python_for(root: Path) -> str:
    for c in (root / ".venv/bin/python", root / ".venv/Scripts/python.exe"):
        if c.exists():
            return str(c)
    return sys.executable


def write_profiles(root: Path) -> None:
    py = yaml_quote(python_for(root))
    srv = yaml_quote(str(root / "mcp" / "server.py"))
    cwd = yaml_quote(str(root))
    body = PATCH.format(python=py, server=srv, root=cwd)
    for prof in ("web", "headless"):
        d = DSH_HOME / "profiles" / prof
        d.mkdir(parents=True, exist_ok=True)
        (d / "cordis.patch.yml").write_text(body)
        print(f"  wrote {d / 'cordis.patch.yml'}")

    hl = DSH_HOME / "profiles" / "headless"
    pkg = hl / "package.json"
    if not pkg.exists() or "dsh-headless" not in pkg.read_text():
        pkg.write_text(HEADLESS_PKG)
        for name in ("pnpm-workspace.yaml", "cordis.yml"):
            src = DSH_HOME / "profiles" / "web" / name
            if src.exists():
                shutil.copy2(src, hl / name)
        print(f"  created headless profile ({pkg})")


def write_settings() -> None:
    p = DSH_HOME / "settings.yaml"
    if not p.exists():
        print(f"  !! {p} not found — launch dsh once, then re-run")
        return
    s = original = p.read_text()

    models = "      models:\n"
    for mid, name in MODELS:
        models += (
            f"        - id: {mid}\n"
            f"          name: {name}\n"
            "          contextWindow: 16384\n"
            "          maxTokens: 4096\n"
        )
    block = (
        "    ollama-local:\n"
        "      displayName: OQVIAN (local)\n"
        "      api: openai-completions\n"
        # Point at the OQVIAN tool-call bridge, not Ollama directly. The bridge
        # forwards to Ollama and shields the agent from its intermittent empty
        # turns (retry) and any text-form tool call. Ollama itself stays on
        # 127.0.0.1:11434. Started by install.sh / the `oqvian` launcher.
        "      baseURL: http://127.0.0.1:11435/v1\n"
        # pi-ai refuses a provider that presents no credential at all.
        # Ollama ignores auth, so a static bearer token satisfies the client
        # without requiring an API-key env var on the CISO's machine.
        "      headers:\n"
        "        Authorization: Bearer ollama\n"
        # Two independent clocks, both read from this block (docs/DEEPSEEK-CONTEXT.md §5):
        #   streamIdleTimeoutMs -> the harness's stream idle watchdog. Default 300 s;
        #     a CPU box spends longer than that evaluating the prompt, so a turn dies
        #     as "pi-ai stream idle timeout after 300000ms" before any output exists.
        #   timeoutMs -> handed to the OpenAI SDK as the per-request timeout. It must
        #     stay ABOVE the idle window, because the SDK clears its own timer only
        #     once response headers arrive.
        # The bridge is what actually makes a long CPU turn survivable -- it sends
        # headers and SSE keepalives before calling the model -- so do not treat
        # these numbers as the fix on their own. GPU machines never hit any of it.
        "      streamIdleTimeoutMs: 3600000\n"
        "      timeoutMs: 7200000\n" + models
    )

    if "ollama-local:" in s:
        s = re.sub(r"    ollama-local:\n(?:(?:      |        ).*\n)*", block, s, count=1)
    elif "\nagent-presets:\n" in s:
        s = s.replace("\nagent-presets:\n", "\n" + block + "agent-presets:\n", 1)
    else:
        s = s.rstrip() + "\n\nllm-pi-ai:\n  providers:\n" + block

    s = re.sub(
        r"(agent-default-model:\n  provider: ).*\n  model: .*\n",
        r"\1ollama-local\n  model: oqvian-cyber-control-full-unlocked-v1.1:latest\n",
        s,
        count=1,
    )
    if "permission:" in s:
        s = re.sub(r"permission:\n  defaultPreset: .*\n",
                   "permission:\n  defaultPreset: ask\n", s, count=1)

    if s != original:
        backup = p.with_suffix(p.suffix + ".bak." + time.strftime("%Y%m%d-%H%M%S"))
        backup.write_text(original)
        p.write_text(s)
        print(f"  updated {p} (backup {backup.name})")
    else:
        print(f"  {p} already configured")


def write_scope() -> None:
    p = Path.home() / ".config" / "oqvian" / "scope.json"
    if p.exists():
        print(f"  {p} exists — left untouched")
        return
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(SCOPE, indent=2))
    print(f"  wrote {p}")


def verify() -> None:
    dsh = shutil.which("dsh")
    if not dsh:
        print("  dsh not on PATH — skipping dump check")
        return
    for prof in ("web", "headless"):
        try:
            out = subprocess.run(
                [dsh, "--profile", prof, "--dump-config"],
                capture_output=True, text=True, timeout=180,
            ).stdout
        except Exception as exc:  # noqa: BLE001
            print(f"  !! {prof}: {exc}")
            continue
        print(f"  {'ok  ' if 'oqvian-mcp' in out else '!!  '}{prof} profile MCP entry")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", default=str(Path(__file__).resolve().parent.parent))
    args = ap.parse_args()
    root = Path(args.root).resolve()

    if not DSH_HOME.exists():
        print(f"!! {DSH_HOME} does not exist.")
        print("   Install and launch the harness once first:")
        print("     npm i -g @deepseek-ai/dsh@0.1.1-rc.2")
        print("     dsh web --no-open --port 0     # creates ~/.dsh, then Ctrl-C")
        print("   Then re-run this script.")
        return 1

    print("== profiles ==")
    write_profiles(root)
    print("== settings.yaml ==")
    write_settings()
    print("== scope ==")
    write_scope()
    print("== verify ==")
    verify()
    return 0


if __name__ == "__main__":
    sys.exit(main())
