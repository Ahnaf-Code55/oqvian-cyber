#!/usr/bin/env python3
"""Interactive OQVIAN terminal REPL backed by the local DSH agent.

Unlike `oqvian-cli`, this keeps one persistent DSH session alive while you chat.
It talks to the regular `dsh web` host over loopback HTTP + WebSocket, so the
same tool composition, scope checks, and audit log as the web UI apply.

This process sets DSH_PERMISSION_MODE=danger-full-access by default. That is the
explicit danger-bypass mode requested for the terminal client: the harness will
not stop to ask approval before tool calls. The scope file and audit log still
apply.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import os
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
from pathlib import Path

try:
    import websockets
except ImportError:
    print("Missing dependency: websockets (required by oqvian-repl)", file=sys.stderr)
    print("Install it with: python3 -m pip install 'websockets>=13'", file=sys.stderr)
    raise SystemExit(2)

ROOT = Path(__file__).resolve().parent.parent
RED = "\033[31m"
YELLOW = "\033[33m"
GREEN = "\033[32m"
DIM = "\033[2m"
BOLD = "\033[1m"
RESET = "\033[0m"


class ReplError(RuntimeError):
    pass


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        sock.listen(1)
        return int(sock.getsockname()[1])


def http_json(port: int, method: str, payload: dict | None = None, timeout: float = 15.0) -> dict:
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
        raise ReplError(f"HTTP {exc.code} from {method}: {raw}") from exc
    except Exception as exc:
        raise ReplError(f"could not call {method}: {exc}") from exc

    try:
        envelope = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ReplError(f"invalid JSON from {method}: {raw[:500]}") from exc

    if envelope.get("type") != "server-response":
        raise ReplError(f"unexpected response from {method}: {raw[:500]}")
    result = envelope.get("result", {})
    if not result.get("ok"):
        err = result.get("error", {})
        code = err.get("code", "unknown")
        msg = err.get("message", raw)
        raise ReplError(f"{method} failed ({code}): {msg}")
    return result.get("value", {})


def wait_for_host(proc: subprocess.Popen, log_file, port: int, verbose: bool, timeout: float) -> dict:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            log_file.flush()
            log_file.seek(0)
            log = log_file.read().decode("utf-8", errors="replace")
            raise ReplError(f"dsh web exited during startup (code {proc.returncode}):\n{log[-5000:]}")
        try:
            return http_json(port, "host.describe", {}, timeout=2.0)
        except ReplError:
            if verbose:
                print(dim("waiting for dsh web to become ready…"), flush=True)
            time.sleep(0.4)
    raise ReplError(f"timed out waiting for dsh web on 127.0.0.1:{port}")


def create_session(port: int, cwd: Path, verbose: bool) -> str:
    value = http_json(port, "session.create", {"cwd": str(cwd)}, timeout=20.0)
    session_id = value.get("sessionId")
    if not session_id:
        raise ReplError(f"session.create did not return a session id: {value!r}")
    if verbose:
        print(dim(f"session {session_id}"))
    return str(session_id)


def current_model(port: int, session_id: str, verbose: bool = False) -> str:
    try:
        value = http_json(port, "session.models", {"sessionId": session_id}, timeout=20.0)
        current = value.get("current", {})
        provider, model = current.get("provider", "?"), current.get("model", "?")
        return f"{provider}/{model}"
    except ReplError as exc:
        if verbose:
            print(dim(f"could not read session.models: {exc}"))
        return "unknown"


def bold(s: str) -> str:
    return f"{BOLD}{s}{RESET}"


def dim(s: str) -> str:
    return f"{DIM}{s}{RESET}"


def ok(s: str) -> str:
    return f"{GREEN}{s}{RESET}"


def err(s: str) -> str:
    return f"{RED}{s}{RESET}"


def warn(s: str) -> str:
    return f"{YELLOW}{s}{RESET}"


def tool_call_summary(payload: object) -> str:
    if not isinstance(payload, dict):
        return "tool"
    name = payload.get("name") or payload.get("toolName") or payload.get("tool") or "tool"
    args = payload.get("arguments") or payload.get("input") or {}
    try:
        arg_text = json.dumps(args, ensure_ascii=False)
    except (TypeError, ValueError):
        arg_text = str(args)
    if len(arg_text) > 96:
        arg_text = arg_text[:93] + "..."
    return f"{name}({arg_text})"


def chunk_text(chunk: object) -> str:
    if not isinstance(chunk, dict):
        return ""
    if chunk.get("type") == "text-delta":
        value = chunk.get("text", "")
        return value if isinstance(value, str) else ""
    content = chunk.get("content")
    if isinstance(content, str):
        return content
    return ""


def print_event_status(event: dict) -> None:
    kind = event.get("type")
    data = event.get("data") or {}
    if not isinstance(data, dict):
        return
    if kind == "llm/retry":
        retry = data.get("retry")
        print(f"\n{warn('↻ retrying model request (')}{retry}{warn('/5)…')}", flush=True)
    elif kind == "turn/end":
        reason = data.get("reason") or {}
        if isinstance(reason, dict) and reason.get("kind") not in (None, "completed"):
            error = reason.get("error") or {}
            if isinstance(error, dict):
                print(f"\n{err('turn ended: ')}{error.get('message', reason.get('kind'))}", flush=True)
            else:
                print(f"\n{err('turn ended: ')}{reason.get('kind')}", flush=True)
        elif isinstance(reason, dict) and reason.get("kind") == "max-tokens":
            print(f"\n{warn('turn ended at max tokens')}", flush=True)
    elif kind == "host/agent-error":
        print(f"\n{err('agent error: ')}{data.get('message', 'unknown')}", flush=True)


async def wait_for_turn(port: int, session_id: str, quiet: bool, verbose: bool) -> tuple[bool, str]:
    """Return (ok, assistant_text). Time out after 75 minutes."""
    uri = f"ws://127.0.0.1:{port}/api/events.mux"
    text_parts: list[str] = []
    tool_count = 0
    assistant_started = False
    deadline = time.monotonic() + 4500

    async def handler(websocket):
        nonlocal assistant_started, tool_count
        while True:
            try:
                raw = await asyncio.wait_for(websocket.recv(), timeout=max(0.0, deadline - time.monotonic()))
            except TimeoutError:
                raise ReplError("timed out after 75 minutes waiting for the turn to end")
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
                raise ReplError(f"mux stream error: {error.get('message', payload.get('error'))}")
            if frame_type == "session/subscribed":
                continue
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
                delta = chunk_text(data.get("chunk"))
                if delta:
                    if not quiet:
                        if not assistant_started:
                            print(f"\n{BOLD}oqvian ▸{RESET} ", end="", flush=True)
                            assistant_started = True
                        print(delta, end="", flush=True)
                    text_parts.append(delta)
            elif kind == "tool/call":
                tool_count += 1
                if not quiet:
                    print(f"\n{DIM}  ▶ {tool_call_summary(data)}{RESET}", flush=True)
            elif kind == "tool/result":
                if not quiet:
                    print(f"{DIM}  ✓ done{RESET}", flush=True)
            elif kind == "llm/retry":
                if not quiet:
                    retry = data.get("retry", "?")
                    print(f"\n{warn('  ↻ retrying model request (')}{retry}/5{warn(')')}", flush=True)
            elif kind == "host/agent-error":
                if not quiet:
                    print(f"\n{err('  agent error: ')}{data.get('message', 'unknown')}", flush=True)
            elif kind == "turn/end":
                reason = data.get("reason") or {}
                ok_reason = isinstance(reason, dict) and reason.get("kind") in (None, "completed", "max-tokens")
                if not quiet:
                    print_event_status(event)
                    if assistant_started:
                        print()
                    if ok_reason:
                        print(dim(f"[turn complete · {tool_count} tool call{'s' if tool_count != 1 else ''}]"), flush=True)
                    else:
                        print(dim("[turn ended with an error]"), flush=True)
                return ok_reason, "".join(text_parts)

    try:
        async with websockets.connect(uri, max_size=16_000_000, open_timeout=10, close_timeout=2) as ws:
            return await handler(ws)
    except ReplError:
        raise
    except Exception as exc:
        raise ReplError(f"lost the event stream: {exc}") from exc


def print_banner(descriptor: dict, cwd: Path, session_id: str, verbose: bool) -> None:
    print()
    print(bold("  OQVIAN REPL"))
    print(dim(f"  cwd      {cwd}"))
    print(dim(f"  host     127.0.0.1 (loopback only) · danger bypass enabled"))
    print(dim(f"  session  {session_id}"))
    print(dim(f"  scope    ~/.config/oqvian/scope.json"))
    print()
    print("  Type your message. Commands: /help /models /status /reset /cancel /quit")
    print()


def print_help() -> None:
    print("""Commands:
  /help                 show this help
  /models               show current and available models
  /status               show host and session status
  /reset                start a new session in this terminal
  /cancel               cancel the currently running turn (if supported)
  /quit                 exit (also: /exit, /q, Ctrl-D, Ctrl-C)

This REPL launches a local DSH web host. Tools still run through the same
authorization policy as the web UI; in danger bypass, tool calls are not prompted.""")


def print_models(port: int, session_id: str) -> None:
    value = http_json(port, "session.models", {"sessionId": session_id}, timeout=15.0)
    current = value.get("current", {})
    print(f"current: {current.get('provider')}/{current.get('model')}")
    for group in value.get("groups", []):
        print(f"\n{group.get('id')}:")
        for model in group.get("models", [])[:20]:
            print(f"  {model.get('id')}")
    failures = value.get("failures", [])
    if failures:
        print("\nprovider failures:")
        for failure in failures:
            print(f"  {failure.get('id')}: {failure.get('message')}")


def main() -> int:
    parser = argparse.ArgumentParser(description="Interactive OQVIAN terminal REPL")
    parser.add_argument("--cwd", default=os.getcwd(), help="workspace directory (default: current directory)")
    parser.add_argument("--verbose", action="store_true", help="show extra startup and parse details")
    parser.add_argument("--timeout", type=float, default=60.0, help="seconds to wait for DSH host startup (default: 60)")
    parser.add_argument("--version", action="store_true", help="print version and exit")
    args = parser.parse_args()

    if args.version:
        print("oqvian-repl 1.0.0")
        return 0

    cwd = Path(args.cwd).expanduser().resolve()
    if not cwd.is_dir():
        print(err(f"workspace is not a directory: {cwd}"), file=sys.stderr)
        return 2

    dsh = shutil.which("dsh")
    if not dsh:
        print(err("dsh not found on PATH"), file=sys.stderr)
        return 2

    port = free_port()
    env = os.environ.copy()
    env["DSH_PERMISSION_MODE"] = "danger-full-access"

    log_file = tempfile.TemporaryFile()
    proc = subprocess.Popen(
        [dsh, "--profile", "web", "--no-open", "--host", "127.0.0.1", "--port", str(port)],
        stdout=log_file,
        stderr=subprocess.STDOUT,
        env=env,
        start_new_session=True,
        cwd=str(cwd),
    )

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
        descriptor = wait_for_host(proc, log_file, port, args.verbose, args.timeout)
        session_id = create_session(port, cwd, args.verbose)
        current = current_model(port, session_id, args.verbose)
        print_banner(descriptor, cwd, session_id, args.verbose)
        print(f"  model    {current}\n")

        while True:
            try:
                prompt = input(f"{BOLD}you ▸ {RESET}").strip()
            except EOFError:
                print()
                break
            except KeyboardInterrupt:
                print("\nUse /quit to exit")
                continue

            if not prompt:
                continue
            if prompt.startswith("/"):
                command = prompt.split(None, 1)[0].lower()
                if command in ("/quit", "/exit", "/q"):
                    break
                if command == "/help":
                    print_help()
                    continue
                if command == "/status":
                    print(f"cwd: {cwd}\nport: {port}\nsession: {session_id}\nhost: {descriptor}")
                    continue
                if command == "/models":
                    print_models(port, session_id)
                    continue
                if command == "/reset":
                    session_id = create_session(port, cwd, args.verbose)
                    print(dim(f"new session {session_id}"))
                    continue
                if command == "/cancel":
                    try:
                        http_json(port, "session.cancel", {"sessionId": session_id}, timeout=10.0)
                        print(dim("cancel requested"))
                    except ReplError as exc:
                        print(err(str(exc)))
                    continue
                print(err(f"unknown command: {command}"))
                continue

            body = {"type": "client-request", "rpcId": str(uuid.uuid4()), "method": "session.prompt",
                    "payload": {"sessionId": session_id, "mode": "queue",
                                "content": [{"type": "text", "text": prompt}]}}
            req = urllib.request.Request(
                f"http://127.0.0.1:{port}/api/session.prompt",
                data=json.dumps(body).encode(),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            try:
                with urllib.request.urlopen(req, timeout=15.0) as response:
                    raw = response.read().decode("utf-8", errors="replace")
                envelope = json.loads(raw)
                if not envelope.get("result", {}).get("ok"):
                    raise ReplError(f"session.prompt rejected: {raw[:500]}")
            except Exception as exc:
                if isinstance(exc, urllib.error.HTTPError):
                    raw = exc.read().decode("utf-8", errors="replace")
                    print(err(f"prompt failed ({exc.code}): {raw[:500]}"))
                else:
                    print(err(f"prompt failed: {exc}"))
                continue

            try:
                asyncio.run(wait_for_turn(port, session_id, quiet=False, verbose=args.verbose))
            except KeyboardInterrupt:
                print(f"\n{warn('^C — cancelling turn…')}")
                try:
                    http_json(port, "session.cancel", {"sessionId": session_id}, timeout=10.0)
                except ReplError:
                    pass
            except ReplError as exc:
                print(f"\n{err('turn failed: ')}{exc}")

        return 0
    except ReplError as exc:
        print(err(str(exc)), file=sys.stderr)
        print(warn("is `ollama` running? starting it may help: systemctl --user start ollama.service"), file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("\nBye.")
        return 0
    finally:
        shutdown()
        log_file.close()


if __name__ == "__main__":
    sys.exit(main())
