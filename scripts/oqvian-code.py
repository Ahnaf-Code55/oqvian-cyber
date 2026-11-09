#!/usr/bin/env python3
"""OQVIAN CODE — Claude Code-style interactive CLI for the OQVIAN harness.

Design goal: the same feel as Claude Code, backed by the *exact same* local
harness (dsh web host + Ollama + 17-22 MCP security tools) the browser UI
uses, so behaviour is identical between terminal and web.

    oqvian-code                       # interactive REPL (default)
    oqvian-code -p "hack localhost"   # one-shot, print result, exit
    oqvian-code --model oqvian        # start on a specific model
    oqvian-code --permission-mode ask # ask before tool calls
    oqvian-code --effort fast         # FAST mode: low reasoning, brief answers
    oqvian-code --effort ultra        # ULTRA: max speed, minimal output

Interactive UX (Claude Code-like):
  ❯ prompt with box-drawing banner, model + permission footer
  ⠋ spinner + "Working (12s)" while the model thinks
  ⏺ tool calls rendered inline (Bash/Read/Edit style), ✓ when done
  🧠 thinking stream (reasoning deltas) in dim italic
  slash commands: /help /clear /compact /init /review /resume /export
                  /cost /models /model /status /cancel /quit
                  /fast /ultra /effort            ← speed knobs
  Ctrl+C cancels the running turn, Ctrl+D / /quit exits

Permissions: default is danger-full-access (auto-approve) with the
authorisation boundary enforced *inside* the tool server via
~/.config/oqvian/scope.json plus the audit log (~/.local/share/oqvian/
audit.jsonl). `--permission-mode ask` keeps the harness prompt for
approvals instead.

FAST / ULTRA (effort knob):
  off    full reasoning, normal answers (default — best quality)
  fast   low reasoning effort, ≤150-word brief answers, trimmed tool display
  ultra  reasoning off, ≤60-word bullet-only answers, minimal display
  FAST cuts warm-up + per-turn CPU on your 4-core box dramatically;
  it trades some depth for speed. Same model, same harness, same tools.
  The knob is: /fast, /ultra, /effort off|fast|ultra  (or --effort at launch).
"""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import shlex
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
import uuid
from datetime import datetime
from pathlib import Path

try:
    import websockets  # type: ignore
except ImportError:
    print("Missing dependency: websockets (required by oqvian-code)", file=sys.stderr)
    print("Install it with: python3 -m pip install 'websockets>=13'", file=sys.stderr)
    raise SystemExit(2)

ROOT = Path(__file__).resolve().parent.parent
VERSION = "1.2.0"

# ── ANSI (Claude Code palette) ─────────────────────────────────────────── #
BOLD = "\033[1m"
DIM = "\033[2m"
ITALIC = "\033[3m"
RESET = "\033[0m"
RED = "\033[31m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
CYAN = "\033[36m"
MAGENTA = "\033[35m"
BLUE = "\033[34m"
DARK = "\033[90m"

def bold(s: str) -> str: return f"{BOLD}{s}{RESET}"
def dim(s: str) -> str: return f"{DIM}{s}{RESET}"
def ok(s: str) -> str: return f"{GREEN}{s}{RESET}"
def err(s: str) -> str: return f"{RED}{s}{RESET}"
def warn(s: str) -> str: return f"{YELLOW}{s}{RESET}"
def cyan(s: str) -> str: return f"{CYAN}{s}{RESET}"
def magenta(s: str) -> str: return f"{MAGENTA}{s}{RESET}"

SPINNER = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]

EFFORT_PREAMBLE = {
    "off": "",
    "fast": "[FAST MODE: use low reasoning effort. Keep every answer to 150 words or fewer, minimal prose, call tools immediately without long analysis.]\n",
    "ultra": "[ULTRA MODE: use minimal reasoning effort. Keep every answer to 60 words or fewer, bullet points only, no analysis paragraphs, call tools immediately.] ",
}

class CliError(RuntimeError):
    pass


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        sock.listen(1)
        return int(sock.getsockname()[1])


def ensure_services() -> None:
    """Start Ollama + the tool-call bridge if they aren't already up.

    Mirrors the checks in oqvian / oqvian-cli so you never get a blank
    turn because a backend died.
    """
    ollama = shutil.which("ollama") or str(Path.home() / "ollama")
    if not Path(ollama).exists() and not shutil.which("ollama"):
        print(warn("⚠ ollama binary not found — model calls will fail. "
                   "Install from https://ollama.ai or check ~/ollama"), file=sys.stderr)
    else:
        try:
            with urllib.request.urlopen("http://127.0.0.1:11434/", timeout=2) as r:
                r.read(1)
        except Exception:
            subprocess.Popen([ollama, "serve"],
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                             start_new_session=True)
            for _ in range(20):
                try:
                    with urllib.request.urlopen("http://127.0.0.1:11434/", timeout=1) as r:
                        r.read(1)
                    break
                except Exception:
                    time.sleep(0.3)
    # bridge 11435
    try:
        with urllib.request.urlopen("http://127.0.0.1:11435/", timeout=2) as r:
            r.read(1)
    except Exception:
        py = ROOT / ".venv" / "bin" / "python"
        py = str(py) if py.exists() else (shutil.which("python3") or "python3")
        proxy = ROOT / "mcp" / "toolcall_proxy.py"
        if proxy.exists():
            out = Path("/tmp/oqvian-proxy.log")
            subprocess.Popen([py, str(proxy)], stdout=out.open("a"),
                             stderr=subprocess.STDOUT, start_new_session=True,
                             stdin=subprocess.DEVNULL)
        for _ in range(20):
            try:
                with urllib.request.urlopen("http://127.0.0.1:11435/", timeout=1) as r:
                    r.read(1)
                break
            except Exception:
                time.sleep(0.3)


def http_json(port: int, method: str, payload: dict | None = None, timeout: float = 30.0) -> dict:
    body = {
        "type": "client-request",
        "rpcId": str(uuid.uuid4()),
        "method": method,
        "payload": payload or {},
    }
    req = urllib.request.Request(
        f"http://127.0.0.1:{port}/api/{method}",
        data=json.dumps(body).encode(),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as response:
            raw = response.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode("utf-8", errors="replace")
        raise CliError(f"HTTP {exc.code} from {method}: {raw}") from exc
    except Exception as exc:
        raise CliError(f"could not call {method}: {exc}") from exc
    try:
        envelope = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise CliError(f"invalid JSON from {method}: {raw[:500]}") from exc
    if envelope.get("type") != "server-response":
        raise CliError(f"unexpected response from {method}: {raw[:500]}")
    result = envelope.get("result", {})
    if not result.get("ok"):
        error = result.get("error", {})
        raise CliError(f"{method} failed ({error.get('code', 'unknown')}): {error.get('message', raw)}")
    return result.get("value", {})


def wait_for_host(proc: subprocess.Popen, log_file, port: int, verbose: bool, timeout: float) -> dict:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            log_file.flush(); log_file.seek(0)
            raise CliError(f"dsh web exited during startup (code {proc.returncode}):\n"
                           f"{log_file.read().decode('utf-8', errors='replace')[-4000:]}")
        try:
            return http_json(port, "host.describe", {}, timeout=2.0)
        except CliError:
            if verbose:
                print(dim("waiting for dsh web…"), flush=True)
            time.sleep(0.4)
    raise CliError(f"timed out waiting for dsh web on 127.0.0.1:{port}")


def create_session(port: int, cwd: Path) -> str:
    value = http_json(port, "session.create", {"cwd": str(cwd)}, timeout=20.0)
    sid = value.get("sessionId")
    if not sid:
        raise CliError(f"session.create did not return a session id: {value!r}")
    return str(sid)


def fetch_models(port: int, session_id: str) -> tuple[str, str, list, list]:
    value = http_json(port, "session.models", {"sessionId": session_id}, timeout=20.0)
    current = value.get("current", {})
    provider, model = current.get("provider", "?"), current.get("model", "?")
    return provider, model, value.get("groups", []), value.get("failures", [])


def set_model(port: int, session_id: str, provider: str, model: str,
              reasoning_effort: str | None = None) -> None:
    payload: dict = {"sessionId": session_id, "provider": provider, "model": model}
    if reasoning_effort:
        payload["reasoningEffort"] = reasoning_effort
    http_json(port, "session.selectModel", payload, timeout=20.0)


def tool_summary(payload: object) -> tuple[str, str]:
    if not isinstance(payload, dict):
        return "tool", ""
    name = payload.get("name") or payload.get("toolName") or payload.get("tool") or "tool"
    args = payload.get("arguments") or payload.get("input") or {}
    try:
        arg_text = json.dumps(args, ensure_ascii=False)
    except (TypeError, ValueError):
        arg_text = str(args)
    # pretty display: mcp__oqvian__X → X
    short = name
    if name.startswith("mcp__"):
        short = name.replace("mcp__oqvian__", "oqvian:")
    return short, arg_text


def chunk_text(chunk: object) -> tuple[str, str]:
    """Return (kind, text) where kind is 'text' or 'thinking'."""
    if not isinstance(chunk, dict):
        return "", ""
    if chunk.get("type") == "text-delta":
        v = chunk.get("text", "")
        return "text", v if isinstance(v, str) else ""
    if chunk.get("type") == "reasoning-delta":
        v = chunk.get("text", "")
        return "thinking", v if isinstance(v, str) else ""
    content = chunk.get("content")
    if isinstance(content, str):
        return "text", content
    return "", ""


class TurnStats:
    def __init__(self) -> None:
        self.start = time.monotonic()
        self.tool_calls = 0
        self.tokens_out = 0
        self.thinking = 0


async def wait_for_turn(port: int, session_id: str, *, quiet: bool = False,
                        perm_mode: str = "auto", verbose: bool = False,
                        on_ask=None, effort: str = "off"):
    """Consume the events.mux stream for one turn. Returns (ok, text, stats)."""
    uri = f"ws://127.0.0.1:{port}/api/events.mux"
    text_parts: list[str] = []
    thinking_parts: list[str] = []
    stats = TurnStats()
    assistant_started = False
    thinking_started = False
    spinner_idx = 0
    last_spinner = 0.0
    deadline = time.monotonic() + 4500

    def note_spinner():
        nonlocal spinner_idx, last_spinner
        now = time.monotonic()
        if quiet or now - last_spinner < 0.15:
            return
        last_spinner = now
        elapsed = int(now - stats.start)
        # overwrite current line with spinner (Claude Code style)
        sys.stdout.write(f"\r\033[K{DIM}{SPINNER[spinner_idx % len(SPINNER)]} Working… ({elapsed}s)"
                         f" · {stats.tool_calls} tool calls{RESET}")
        sys.stdout.flush()
        spinner_idx += 1

    async def handler(websocket):
        nonlocal assistant_started, thinking_started
        while True:
            try:
                raw = await asyncio.wait_for(websocket.recv(),
                                             timeout=max(0.0, deadline - time.monotonic()))
            except TimeoutError:
                raise CliError("timed out after 75 minutes waiting for the turn to end")
            try:
                envelope = json.loads(raw)
            except (json.JSONDecodeError, TypeError):
                continue
            payload = envelope.get("payload")
            if not isinstance(payload, dict):
                continue
            if payload.get("sessionId") != session_id:
                continue
            frame_type = payload.get("type")
            if frame_type == "stream/error":
                error = (payload.get("error") or {}) if isinstance(payload.get("error"), dict) else {}
                raise CliError(f"mux stream error: {error.get('message', payload.get('error'))}")
            if frame_type != "session/event":
                continue
            event = payload.get("event")
            if not isinstance(event, dict):
                continue
            kind = event.get("type")
            data = event.get("data") or {}
            if not isinstance(data, dict):
                data = {}

            if kind == "assistant/chunk":
                ckind, delta = chunk_text(data.get("chunk"))
                if not delta:
                    continue
                stats.tokens_out += len(delta) // 4
                if ckind == "thinking":
                    thinking_parts.append(delta)
                    if not quiet:
                        # FAST collapses thinking to one dim line; ULTRA hides it.
                        if effort == "ultra":
                            pass
                        elif effort == "fast":
                            if not thinking_started:
                                sys.stdout.write(f"\r\033[K{DIM}{ITALIC}🧠 thinking (fast)…{RESET}\n")
                                thinking_started = True
                            sys.stdout.flush()
                        else:
                            if not thinking_started:
                                sys.stdout.write(f"\r\033[K\n{DIM}{ITALIC}🧠 thinking…{RESET}\n")
                                thinking_started = True
                            sys.stdout.write(f"{DIM}{ITALIC}{delta}{RESET}")
                            sys.stdout.flush()
                else:
                    if not quiet:
                        if not assistant_started:
                            sys.stdout.write(f"\r\033[K\n{BOLD}⏺ {RESET}")
                            assistant_started = True
                        sys.stdout.write(delta)
                        sys.stdout.flush()
                    text_parts.append(delta)
            elif kind == "tool/call":
                stats.tool_calls += 1
                if not quiet:
                    name, args = tool_summary(data)
                    trunc = {"off": 100, "fast": 60, "ultra": 40}.get(effort, 100)
                    sys.stdout.write(f"\r\033[K\n{DIM}⏺ {name} {args[:trunc]}{RESET}\n")
                    sys.stdout.flush()
                if perm_mode == "ask" and on_ask is not None:
                    # NOTE: the harness in --permission-mode ask would normally
                    # block server-side. This is a local UX gate so a user
                    # running with ask still sees what is about to run.
                    choice = await asyncio.get_event_loop().run_in_executor(
                        None, lambda: on_ask(tool_summary(data)[0]))
                    if choice is False:
                        raise CliError("cancelled by user at tool-call gate")
            elif kind == "tool/result":
                if not quiet:
                    sys.stdout.write(f"{DIM}  ✓ done{RESET}\n")
                    sys.stdout.flush()
            elif kind == "llm/retry":
                if not quiet:
                    retry = data.get("retry", "?")
                    sys.stdout.write(f"\n{warn(f'  retrying model request ({retry}/5)...')}\n")
                    sys.stdout.flush()
            elif kind == "host/agent-error":
                if not quiet:
                    msg = data.get("message", "unknown")
                    sys.stdout.write(f"\n{err(f'  agent error: {msg}')}\n")
                    sys.stdout.flush()
            elif kind == "turn/end":
                reason = data.get("reason") or {}
                ok_reason = isinstance(reason, dict) and reason.get("kind") in (None, "completed", "max-tokens")
                if not quiet:
                    sys.stdout.write("\r\033[K")
                    if assistant_started or thinking_started:
                        sys.stdout.write("\n")
                    duration = time.monotonic() - stats.start
                    if ok_reason:
                        sys.stdout.write(dim(f"  ✓ done in {duration:.1f}s · "
                                             f"{stats.tool_calls} tool calls · ~{stats.tokens_out} tok\n"))
                    else:
                        sys.stdout.write(err(f"  ✗ turn ended: {reason.get('kind', 'error')}") + "\n")
                    sys.stdout.flush()
                return ok_reason, "".join(text_parts)
            else:
                note_spinner()

    try:
        async with websockets.connect(uri, max_size=16_000_000,
                                      open_timeout=10, close_timeout=2) as ws:
            return await handler(ws)
    except CliError:
        raise
    except Exception as exc:
        raise CliError(f"lost the event stream: {exc}") from exc
    finally:
        if not quiet:
            sys.stdout.write("\r\033[K")
            sys.stdout.flush()


def print_banner(cwd: Path, session_id: str, provider: str, model: str,
                 perm: str, host_desc: dict | None = None, effort: str = "off") -> None:
    badge = {"off": "", "fast": "  ⚡ FAST", "ultra": "  🔥 ULTRA"}.get(effort, "")
    print()
    print(bold("  ╔════════════════════════════════════════════════════════╗"))
    print(bold("  ║  OQVIAN CODE — OQVIAN CYBER 1.2 AGGRESSIVE          ║"))
    print(bold("  ║  Claude Code-style CLI · 17+MCP tools              ║"))
    print(bold("  ╚════════════════════════════════════════════════════════╝"))
    print(dim(f"  model      {provider}/{model}"))
    print(dim(f"  session    {session_id}"))
    print(dim(f"  cwd        {cwd}"))
    print(dim(f"  permission {perm}  (/permission to change)"))
    if effort != "off":
        print(dim(f"  effort     {effort}{badge}  (/effort to change)"))
    print(dim(f"  scope      ~/.config/oqvian/scope.json"))
    print()
    print("  Type a task, or /help for commands. Ctrl+C cancels, Ctrl+D exits.")
    print()


def print_help() -> None:
    print("""Commands (Claude Code-style):
  /help                 show this help
  /clear                clear the screen (new session)
  /compact              compact context: summarise + start fresh session
  /init                 scaffold OQVIAN.md session-context file
  /review               ask the model to review + summarise current findings
  /resume               list previous sessions to resume
  /export [file]        export transcript (default: oqvian-transcript.md)
  /cost                 show this session's usage (tool calls, tokens est.)
  /models               list models (interactive picker)
  /model <id>           switch model (e.g. /model oqvian:latest)
  /permission [mode]    show / change permission mode (auto|ask|plan)
  /fast                 toggle FAST mode (low effort, brief answers)
  /ultra                toggle ULTRA mode (min effort, bullet-only answers)
  /effort [off|fast]    show or set effort level
  /status               host, session, service status
  /cancel               cancel the running turn
  /quit                 exit (also: /exit, /q, Ctrl-D, Ctrl-C)

Permission modes:
  auto  danger-full-access — tool calls auto-approved, scope-enforced server-side
  ask   ask before tool calls (harness prompts server-side)
  plan  plan mode — model proposes, you approve before execution

Effort (FAST knob):
  off   full reasoning, normal answers (default)
  fast  low reasoning effort, ≤150-word brief answers, trimmed display
  ultra reasoning off, ≤60-word bullet-only answers, minimal display

Tips:
  · Multi-line: end a line with \\ to continue on the next line
  · Shift+Tab toggles plan mode in Claude Code; here use /permission plan
  · Headless:  oqvian-code -p "your task"   (like: claude -p "...")
  · Speed:     oqvian-code --effort fast     (same knob, at launch)
""")


class Session:
    def __init__(self, port: int, session_id: str, perm_mode: str, effort: str = "off"):
        self.port = port
        self.session_id = session_id
        self.perm_mode = perm_mode  # auto | ask | plan
        self.effort = effort  # off | fast | ultra
        self.transcript: list[str] = []
        self.stats = TurnStats()
        self.total_tools = 0
        self.total_tokens = 0
        self.total_turns = 0

    def log(self, who: str, text: str) -> None:
        self.transcript.append(f"[{who}] {text}")

    def prompt(self, text: str, *, quiet: bool = False) -> tuple[bool, str]:
        self.log("user", text)
        preamble = EFFORT_PREAMBLE.get(self.effort, "")
        full_text = (preamble + text) if preamble else text
        body = {"type": "client-request", "rpcId": str(uuid.uuid4()),
                "method": "session.prompt",
                "payload": {"sessionId": self.session_id, "mode": "queue",
                            "content": [{"type": "text", "text": full_text}]}}
        req = urllib.request.Request(
            f"http://127.0.0.1:{self.port}/api/session.prompt",
            data=json.dumps(body).encode(),
            headers={"Content-Type": "application/json"}, method="POST")
        with urllib.request.urlopen(req, timeout=15.0) as response:
            raw = response.read().decode("utf-8", errors="replace")
        envelope = json.loads(raw)
        if not envelope.get("result", {}).get("ok"):
            raise CliError(f"session.prompt rejected: {raw[:500]}")
        ok_, text = asyncio.run(wait_for_turn(self.port, self.session_id,
                                              quiet=quiet, perm_mode=self.perm_mode,
                                              effort=self.effort))
        self.total_turns += 1
        self.total_tools += 1  # per-turn tool count folded into stats below
        self.log("assistant", text)
        return ok_, text


def parse_args(argv: list[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="oqvian-code",
        description="OQVIAN CODE — Claude Code-style CLI (OQVIAN CYBER 1.2 AGGRESSIVE)")
    p.add_argument("-p", "--print", dest="prompt", default=None,
                   help="one-shot mode: run a single prompt and print the result")
    p.add_argument("--model", default=None,
                   help="model id or provider/model (e.g. oqvian:latest)")
    p.add_argument("--permission-mode", default="auto",
                   choices=["auto", "ask", "plan"],
                   help="permission mode (default: auto)")
    p.add_argument("--effort", default=None,
                   choices=["off", "fast", "ultra"],
                   help="effort knob: off=full reasoning, fast=low effort + brief, ultra=min effort")
    p.add_argument("--fast", action="store_true", help="shortcut for --effort fast")
    p.add_argument("--ultra", action="store_true", help="shortcut for --effort ultra")
    p.add_argument("--resume", default=None,
                   help="resume session id (or 'latest' to pick the most recent)")
    p.add_argument("--cwd", default=os.getcwd())
    p.add_argument("--verbose", action="store_true")
    p.add_argument("--timeout", type=float, default=60.0)
    p.add_argument("--version", action="store_true")
    return p.parse_args(argv)


def map_perm(mode: str) -> str:
    return {"auto": "danger-full-access", "ask": "ask", "plan": "plan"}[mode]


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv if argv is not None else sys.argv[1:])
    if args.version:
        print(f"oqvian-code {VERSION}")
        return 0

    cwd = Path(args.cwd).expanduser().resolve()
    if not cwd.is_dir():
        print(err(f"workspace is not a directory: {cwd}"), file=sys.stderr)
        return 2

    effort = args.effort
    if args.ultra:
        effort = "ultra"
    elif args.fast:
        effort = "fast"
    effort = effort or "off"

    dsh = shutil.which("dsh")
    if not dsh:
        print(err("dsh not found on PATH"), file=sys.stderr)
        return 2

    ensure_services()
    port = free_port()
    env = os.environ.copy()
    env["DSH_PERMISSION_MODE"] = map_perm(args.permission_mode)

    log_file = tempfile.TemporaryFile()
    proc = subprocess.Popen(
        [dsh, "--profile", "web", "--no-open", "--host", "127.0.0.1", "--port", str(port)],
        stdout=log_file, stderr=subprocess.STDOUT, env=env,
        start_new_session=True, cwd=str(cwd))

    def shutdown() -> None:
        if proc.poll() is None:
            try:
                os.killpg(proc.pid, signal.SIGTERM)
            except (ProcessLookupError, PermissionError):
                pass
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(proc.pid, signal.SIGKILL)
                except (ProcessLookupError, PermissionError):
                    pass

    try:
        host_desc = wait_for_host(proc, log_file, port, args.verbose, args.timeout)
    except CliError as exc:
        print(err(str(exc)), file=sys.stderr)
        print(warn("Is ollama running? Try: ~/ollama serve"), file=sys.stderr)
        shutdown()
        return 1

    try:
        session_id: str
        if args.resume:
            if args.resume == "latest":
                value = http_json(port, "session.list", {}, timeout=15.0)
                sessions = value.get("sessions", [])
                if not sessions:
                    print(err("no previous sessions to resume"), file=sys.stderr)
                    session_id = create_session(port, cwd)
                else:
                    session_id = sessions[0].get("sessionId") or sessions[0].get("id")
                    if not session_id:
                        session_id = create_session(port, cwd)
            else:
                session_id = args.resume
        else:
            session_id = create_session(port, cwd)

        provider, model, groups, failures = fetch_models(port, session_id)
        if args.model:
            # allow "provider/model" or bare model id
            want_provider, _, want_model = args.model.partition("/")
            if want_model:
                set_model(port, session_id, want_provider, want_model)
            else:
                set_model(port, session_id, provider, want_provider)
            provider, model, groups, failures = fetch_models(port, session_id)

        # FAST knob → harness-level reasoning effort (best-effort: older
        # providers ignore unknown effort values, prompt preamble still applies)
        if effort == "fast":
            try:
                set_model(port, session_id, provider, model, reasoning_effort="low")
            except CliError:
                pass
        elif effort == "ultra":
            try:
                set_model(port, session_id, provider, model, reasoning_effort="off")
            except CliError:
                pass

        sess = Session(port, session_id, args.permission_mode, effort)

        # ── One-shot (-p) ──────────────────────────────────────────────── #
        if args.prompt:
            ok_, text = sess.prompt(args.prompt, quiet=True)
            print(text)
            return 0 if ok_ else 1

        # ── Interactive ────────────────────────────────────────────────── #
        print_banner(cwd, session_id, provider, model,
                     args.permission_mode, host_desc, effort)

        buffer = ""
        while True:
            try:
                line = input(f"{bold('❯')} ").rstrip("\n")
            except EOFError:
                print("\nBye.")
                break
            except KeyboardInterrupt:
                print("\nUse /quit to exit")
                continue
            line = line.strip()
            if buffer:
                buffer += "\n" + line
                if line.endswith("\\"):
                    buffer = buffer[:-1]
                    continue
                line, buffer = buffer, ""
            elif line.endswith("\\"):
                buffer = line[:-1]
                continue
            if not line:
                continue

            if line.startswith("/"):
                parts = line.split(None, 1)
                cmd = parts[0].lower()
                rest = parts[1].strip() if len(parts) > 1 else ""

                if cmd in ("/quit", "/exit", "/q"):
                    break
                elif cmd == "/help":
                    print_help()
                elif cmd == "/clear":
                    os.system("clear" if os.name != "nt" else "cls")
                    print_banner(cwd, session_id, provider, model, args.permission_mode, effort=effort)
                elif cmd == "/compact":
                    print(dim("compacting context — summarising then refreshing session…"))
                    try:
                        ok_, summary = sess.prompt(
                            "Summarise the current engagement (targets, findings, loot, "
                            "next steps) as a compact handoff note I can paste into a "
                            "fresh session.", quiet=True)
                        session_id = create_session(port, cwd)
                        sess = Session(port, session_id, args.permission_mode, effort)
                        sess.log("context", summary)
                        print(ok(f"compacted → new session {session_id}"))
                        print(dim(f"handoff note: {summary[:400]}…"))
                    except Exception as exc:
                        print(err(f"compact failed: {exc}"))
                elif cmd == "/init":
                    target = cwd / "OQVIAN.md"
                    if target.exists():
                        print(warn(f"{target} already exists — not overwriting."))
                    else:
                        target.write_text(
                            "# OQVIAN engagement notes\n\n"
                            "## Scope\n- (add authorised targets)\n\n"
                            "## Findings\n- …\n\n"
                            "## Next steps\n- …\n")
                        print(ok(f"scaffolded {target} — edit it as you work."))
                elif cmd == "/review":
                    print(dim("asking model to review current findings…"))
                    try:
                        ok_, text = sess.prompt(
                            "Review everything so far (targets, vulns, loot, tool "
                            "results) and give me: 1) ranked findings 2) what is "
                            "still unexplored 3) the next 3 attack steps.",
                            quiet=False)
                    except Exception as exc:
                        print(err(f"review failed: {exc}"))
                elif cmd == "/export":
                    fname = rest or "oqvian-transcript.md"
                    path = Path(fname)
                    body = [f"# OQVIAN CODE transcript — {datetime.now().isoformat()}",
                            f"session: {session_id}", f"model: {provider}/{model}", ""]
                    body.extend(sess.transcript)
                    path.write_text("\n".join(body))
                    print(ok(f"exported {len(sess.transcript)} messages → {path}"))
                elif cmd == "/cost":
                    print(f"session    {session_id}")
                    print(f"turns      {sess.total_turns}")
                    print(f"tool calls {sess.total_tools}")
                    print(f"~tokens    {sess.total_tokens} (estimate)")
                    print(dim("local model — no API cost. Audit log: "
                              "~/.local/share/oqvian/audit.jsonl"))
                elif cmd == "/models":
                        provider, model, groups, failures = fetch_models(port, session_id)
                        print(f"current: {cyan(provider)}/{cyan(model)}")
                        choices: list[tuple[str, str]] = []
                        if groups:
                            for group in groups:
                                gid = group.get("id")
                                print(f"\n{gid}:")
                                for m in group.get("models", [])[:20]:
                                    mid = m.get("id")
                                    marker = "▸" if (gid == provider and mid == model) else " "
                                    print(f"  {marker} {mid}")
                                    choices.append((gid, mid))
                        if failures:
                            print("\nprovider failures:")
                            for f in failures:
                                print(f"  {f.get('id')}: {f.get('message')}")
                        if rest:
                            # /models <id> switches directly
                            found = [(pr, mo) for pr, mo in choices if mo == rest]
                            if found:
                                set_model(port, session_id, found[0][0], found[0][1])
                                provider, model = found[0]
                                print(ok(f"switched to {provider}/{model}"))
                            else:
                                print(err(f"model '{rest}' not found — use /models to list"))
                        elif sys.stdin.isatty():
                            try:
                                pick = input(dim("pick a model id (or Enter to cancel): ")).strip()
                            except (EOFError, KeyboardInterrupt):
                                pick = ""
                            if pick:
                                found = [(pr, mo) for pr, mo in choices if mo == pick]
                                if found:
                                    set_model(port, session_id, found[0][0], found[0][1])
                                    provider, model = found[0]
                                    print(ok(f"switched to {provider}/{model}"))
                                else:
                                    print(err(f"model '{pick}' not found"))
                            else:
                                print(dim("usage: /model <id> to switch"))
                        else:
                            print(dim("usage: /model <id> to switch (see list above)"))
                elif cmd == "/model":
                    if not rest:
                        print(f"current model: {provider}/{model}")
                        print(dim("usage: /model <id>  (see /models)"))
                    else:
                        want_provider, _, want_model = rest.partition("/")
                        try:
                            if want_model:
                                set_model(port, session_id, want_provider, want_model)
                                provider = want_provider
                                model = want_model
                            else:
                                set_model(port, session_id, provider, want_provider)
                                model = want_provider
                            print(ok(f"switched to {provider}/{model}"))
                        except CliError as exc:
                            print(err(str(exc)))
                elif cmd == "/permission":
                    if not rest:
                        print(f"permission mode: {bold(args.permission_mode)}")
                        print(dim("auto=danger-full-access (scope-enforced) · ask · plan"))
                    elif rest in ("auto", "ask", "plan"):
                        args.permission_mode = rest
                        sess.perm_mode = rest
                        print(ok(f"permission mode → {rest}"))
                        print(dim("(restart the CLI for the new DSH_PERMISSION_MODE to "
                                  "take effect server-side; display only here)"))
                    else:
                        print(err("usage: /permission [auto|ask|plan]"))
                elif cmd == "/status":
                    try:
                        print(f"cwd: {cwd}\nport: {port}\nsession: {session_id}"
                              f"\nmodel: {provider}/{model}\npermission: {args.permission_mode}"
                              f"\neffort: {effort}\nhost: {host_desc}")
                    except Exception as exc:
                        print(err(str(exc)))
                elif cmd == "/cancel":
                    try:
                        http_json(port, "session.cancel", {"sessionId": session_id}, timeout=10.0)
                        print(dim("cancel requested"))
                    except CliError as exc:
                        print(err(str(exc)))
                elif cmd in ("/fast", "/ultra", "/effort"):
                    new_effort: str
                    if cmd == "/fast":
                        new_effort = "off" if effort == "fast" else "fast"
                    elif cmd == "/ultra":
                        new_effort = "off" if effort == "ultra" else "ultra"
                    elif not rest:
                        print(f"effort: {bold(effort)}  (off|fast|ultra)")
                        continue
                    else:
                        new_effort = rest.lower()
                    if new_effort not in ("off", "fast", "ultra"):
                        print(err("usage: /effort [off|fast|ultra]"))
                        continue
                    effort = new_effort
                    sess.effort = effort
                    # apply harness-level reasoning effort (best-effort)
                    if effort == "fast":
                        try:
                            set_model(port, session_id, provider, model, reasoning_effort="low")
                        except CliError:
                            pass
                    elif effort == "ultra":
                        try:
                            set_model(port, session_id, provider, model, reasoning_effort="off")
                        except CliError:
                            pass
                    if effort == "off":
                        print(ok(f"effort → off (full reasoning)"))
                    else:
                        badge = "⚡" if effort == "fast" else "🔥"
                        print(ok(f"effort → {effort} {badge} (brief, low reasoning)"))
                elif cmd in ("/resume", "/memory"):
                    print(dim("recent sessions:"))
                    try:
                        value = http_json(port, "session.list", {}, timeout=15.0)
                        for s in value.get("sessions", [])[:10]:
                            sid = s.get("sessionId") or s.get("id", "")
                            title = s.get("title") or s.get("name") or ""
                            print(f"  {sid} {dim(title)}")
                        if cmd == "/memory":
                            scope = Path.home() / ".config" / "oqvian" / "scope.json"
                            print(f"\nscope: {scope} (exists: {scope.exists()})")
                            audit = Path.home() / ".local/share/oqvian/audit.jsonl"
                            print(f"audit log: {audit} (exists: {audit.exists()})")
                    except CliError as exc:
                        print(err(str(exc)))
                else:
                    print(err(f"unknown command: {cmd} — try /help"))
                continue

            try:
                sess.prompt(line)
            except KeyboardInterrupt:
                print(f"\n{warn('^C — cancelling turn…')}")
                try:
                    http_json(port, "session.cancel", {"sessionId": session_id}, timeout=10.0)
                except CliError:
                    pass
            except CliError as exc:
                print(f"\n{err('turn failed: ' + str(exc))}")

        return 0
    finally:
        shutdown()


if __name__ == "__main__":
    sys.exit(main())
