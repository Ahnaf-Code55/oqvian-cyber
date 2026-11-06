#!/usr/bin/env python3
"""OQVIAN tool-call bridge.

Sits between an OpenAI-compatible client (the operator's harness) and Ollama.

It does two jobs, and is otherwise transparent:

1. **Retry the empty turn.** Ollama intermittently ends a turn with
   ``finish_reason: stop`` and an empty assistant message -- a few tokens were
   generated, then dropped by its tool parser -- instead of the tool call the
   model actually emitted. A blank turn reaches the agent as "the model did
   nothing". The bridge re-issues the request up to ``OQVIAN_PROXY_RETRIES``
   times (default 3), nudging sampling each time, before giving up.

2. **Normalise text-form tool calls.** Some abliterated bases emit a tool call
   as a markdown-fenced JSON object rather than a native call::

       ```json
       {"name": "kb", "arguments": {"action": "cve", "query": "CVE-2021-44228"}}
       ```

   Ollama hands that back as ordinary assistant *text*, so the harness never
   runs a tool. The bridge converts fenced/bare/keyed JSON back into a real
   OpenAI ``tool_calls`` array. Native calls pass through untouched.

Requests that carry ``tools`` are buffered, re-issued and (if needed) rewritten,
for streaming and non-streaming alike; everything else is a byte-for-byte
passthrough. A streaming tool turn gets its response headers, and then an SSE
comment keepalive every ``OQVIAN_PROXY_KEEPALIVE`` seconds, *before* the upstream
call is made -- see the ``_KEEPALIVE`` comment. Stdlib only. Configuration (env):
    OQVIAN_PROXY_UPSTREAM      default http://127.0.0.1:11434   (Ollama)
    OQVIAN_PROXY_UPSTREAM_API  chat (default, native /api/chat) | v1 (OpenAI shim)
    OQVIAN_PROXY_HOST          default 127.0.0.1
    OQVIAN_PROXY_PORT          default 11435
    OQVIAN_PROXY_RETRIES       default 3
    OQVIAN_PROXY_TIMEOUT       default 1800  upstream seconds; raise it (e.g. 3600)
                               on a CPU-only box where one turn can exceed 30 min
    OQVIAN_PROXY_KEEPALIVE     default 20    SSE keepalive seconds

Run:  python3 mcp/toolcall_proxy.py
"""
from __future__ import annotations

import json
import os
import re
import sys
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib import error as urlerr
from urllib import request as urlreq

UPSTREAM = os.environ.get("OQVIAN_PROXY_UPSTREAM", "http://127.0.0.1:11434").rstrip("/")
HOST = os.environ.get("OQVIAN_PROXY_HOST", "127.0.0.1")
PORT = int(os.environ.get("OQVIAN_PROXY_PORT", "11435"))
# Upstream dialect for tool-bearing requests:
#   "chat" (default) -> native /api/chat, translated to OpenAI shape. Reliable:
#                       Ollama returns tool calls here even when its OpenAI shim
#                       drops them.
#   "v1"             -> Ollama's /v1/chat/completions shim, passed through.
UPSTREAM_API = os.environ.get("OQVIAN_PROXY_UPSTREAM_API", "chat").lower()
# How tool calls are handled for /api/chat:
#   "render" (default) -> fold the tool schemas into the system message, let the
#                         model emit <tool_call> text, and parse it here. This
#                         bypasses Ollama's tool parser, which intermittently
#                         drops a valid call and returns an empty turn.
#   "ollama"           -> pass `tools` to Ollama and rely on its parser.
TOOL_MODE = os.environ.get("OQVIAN_PROXY_TOOL_MODE", "render").lower()

_FENCE = re.compile(r"```(?:json|JSON)?\s*(\{.*?\})\s*```", re.DOTALL)
# Qwen's tool template wraps each call in <tool_call>...</tool_call>.
_TOOLCALL = re.compile(r"<tool_call>\s*(\{.*?\})\s*</tool_call>", re.DOTALL)
# Upstream patience: how long the bridge will wait on Ollama for one attempt.
# A tool turn is buffered (upstream stream=False), and one attempt on a CPU-only
# box can run 25-30 min (prompt eval over ~10k tokens), so this must exceed the
# harness's streamIdleTimeoutMs. A client is never left waiting blind, though --
# _KEEPALIVE below keeps its stream open meanwhile.
_TIMEOUT = int(os.environ.get("OQVIAN_PROXY_TIMEOUT", "1800"))  # seconds
_RETRIES = int(os.environ.get("OQVIAN_PROXY_RETRIES", "3"))  # empty-completion retries
# While a tool turn is buffered upstream, a streaming client gets SSE comment
# keepalives this often. Two timeouts make this necessary. The OpenAI SDK clears
# its per-request timeout as soon as response *headers* arrive (client.js
# ``fetchWithTimeout`` clears the timer in ``finally``), so the headers must be
# sent before the upstream wait -- otherwise a turn longer than the SDK's default
# (~5 min) dies as "Request timed out." no matter how large streamIdleTimeoutMs
# is. And pi-ai's idle watchdog restarts on every chunk, so a comment every N
# seconds keeps a 25-minute CPU turn alive under a 60-minute idle window.
_KEEPALIVE = max(1, int(os.environ.get("OQVIAN_PROXY_KEEPALIVE", "20")))  # seconds


# --------------------------------------------------------------------------- #
# extraction: fenced/bare JSON -> [(name, arguments), ...]
# --------------------------------------------------------------------------- #
def _balanced_json(text: str) -> str | None:
    """First brace-balanced ``{...}`` in *text*, string-aware. None if absent."""
    start = text.find("{")
    while start != -1:
        depth = 0
        in_str = False
        esc = False
        for i in range(start, len(text)):
            c = text[i]
            if in_str:
                if esc:
                    esc = False
                elif c == "\\":
                    esc = True
                elif c == '"':
                    in_str = False
            elif c == '"':
                in_str = True
            elif c == "{":
                depth += 1
            elif c == "}":
                depth -= 1
                if depth == 0:
                    return text[start:i + 1]
        start = text.find("{", start + 1)
    return None


def _one(obj, names):
    """Normalise a single candidate object to ``(name, arguments)`` or None."""
    if not isinstance(obj, dict):
        return None
    fn = obj.get("function")
    if isinstance(fn, dict) and fn.get("name"):
        return fn.get("name"), fn.get("arguments", {})
    if obj.get("name"):
        return obj.get("name"), obj.get("arguments", {})
    keys = list(obj.keys())
    if len(keys) == 1 and keys[0] in names and isinstance(obj[keys[0]], dict):
        return keys[0], obj[keys[0]]
    return None


def _normalise(obj, names):
    if isinstance(obj, dict) and isinstance(obj.get("tool_calls"), list):
        items = obj["tool_calls"]
    elif isinstance(obj, list):
        items = obj
    else:
        items = [obj]
    out = []
    for it in items:
        got = _one(it, names)
        if got and got[0] in names:
            out.append(got)
    if not out and isinstance(obj, dict):
        picked = {k: v for k, v in obj.items() if k in names and isinstance(v, dict)}
        if picked and len(picked) == len(obj):
            out = list(picked.items())
    return out


def _extract(content, names):
    """Return ``(pairs, leftover_text)``; leftover is '' when calls were found."""
    if not content or not names:
        return [], content
    texts = [m.group(1) for m in _TOOLCALL.finditer(content)]
    texts += [m.group(1) for m in _FENCE.finditer(content)]
    if "{" in content:
        bal = _balanced_json(content)
        if bal:
            texts.append(bal)
    for t in texts:
        try:
            obj = json.loads(t)
        except Exception:
            bal = _balanced_json(t)
            if not bal:
                continue
            try:
                obj = json.loads(bal)
            except Exception:
                continue
        pairs = _normalise(obj, names)
        if pairs:
            return pairs, ""
    return [], content


def _args_str(v) -> str:
    return v if isinstance(v, str) else json.dumps(v)


def _tool_calls(pairs):
    return [
        {
            "id": "call_" + uuid.uuid4().hex[:8],
            "index": i,
            "type": "function",
            "function": {"name": n, "arguments": _args_str(a)},
        }
        for i, (n, a) in enumerate(pairs)
    ]


def _parse(resp, names):
    """Return ``(calls, leftover)`` from an OpenAI-shaped upstream response.

    Prefers a native ``tool_calls`` array; falls back to extracting a
    fenced/bare JSON call from the text. ``calls`` is None when neither is
    present, and ``leftover`` may still be '' — which is how an *empty*
    completion shows up.
    """
    try:
        msg = resp["choices"][0].get("message", {})
    except Exception:
        return None, ""
    native = msg.get("tool_calls")
    if native:
        return native, (msg.get("content") or "")
    pairs, _rest = _extract(msg.get("content") or "", names)
    if pairs:
        return _tool_calls(pairs), ""
    return None, (msg.get("content") or "")


def _tools_block(tools):
    """Reproduce the Qwen template's ``# Tools`` section verbatim.

    Byte-identical to what Ollama emits when it renders ``tools`` itself, so the
    model sees exactly the same prompt -- we just parse the reply ourselves
    instead of relying on Ollama's (intermittently failing) tool parser.
    """
    lines = []
    for t in tools or []:
        fn = (t or {}).get("function")
        if isinstance(fn, dict):
            lines.append(
                '{"type": "function", "function": %s}'
                % json.dumps(fn, separators=(",", ":"))
            )
    if not lines:
        return ""
    return (
        "\n\n# Tools\n\n"
        "You may call one or more functions to assist with the user query.\n\n"
        "You are provided with function signatures within <tools></tools> XML tags:\n"
        "<tools>\n" + "\n".join(lines) + "\n</tools>\n\n"
        "For each function call, return a json object with function name and "
        "arguments within <tool_call></tool_call> XML tags:\n"
        '<tool_call>\n{"name": <function-name>, "arguments": <args-json-object>}\n'
        "</tool_call>"
    )


def _inject_tools(messages, tools):
    """Append the tools block to the system turn (creating one if absent)."""
    block = _tools_block(tools)
    if not block:
        return list(messages or [])
    out = []
    injected = False
    for m in messages or []:
        if not isinstance(m, dict):
            continue
        if not injected and m.get("role") == "system":
            nm = dict(m)
            nm["content"] = (m.get("content") or "") + block
            out.append(nm)
            injected = True
        else:
            out.append(m)
    if not injected:
        out.insert(0, {"role": "system", "content": block.lstrip("\n")})
    return out


def _ollama_request(req, mode="ollama"):
    """OpenAI chat request -> native Ollama ``/api/chat`` body.

    ``mode='render'`` folds the tool schemas into the system message and drops
    the ``tools`` field, so Ollama does no tool parsing -- the caller parses the
    ``<tool_call>`` text itself. ``mode='ollama'`` passes ``tools`` through.
    """
    msgs = list(req.get("messages") or [])
    render = mode == "render" and req.get("tools")
    if render:
        msgs = _inject_tools(msgs, req.get("tools"))

    body = {"model": req.get("model"), "messages": [], "stream": False}
    for m in msgs:
        if not isinstance(m, dict):
            continue
        nm = {"role": m.get("role") or "user", "content": m.get("content") or ""}
        tcs = []
        for t in m.get("tool_calls") or []:
            fn = (t or {}).get("function", {}) or {}
            args = fn.get("arguments")
            if isinstance(args, str):
                try:
                    args = json.loads(args)
                except Exception:
                    args = {}
            tcs.append({"function": {"name": fn.get("name", ""), "arguments": args}})
        if tcs:
            nm["tool_calls"] = tcs
        body["messages"].append(nm)

    if req.get("tools") and not render:
        body["tools"] = req["tools"]

    opts = {}
    for src, dst in (
        ("temperature", "temperature"),
        ("top_p", "top_p"),
        ("max_tokens", "num_predict"),
        ("seed", "seed"),
        ("stop", "stop"),
    ):
        if req.get(src) is not None:
            opts[dst] = req[src]
    if isinstance(req.get("options"), dict):
        opts.update(req["options"])
    if opts:
        body["options"] = opts
    return body


def _ollama_response(resp, model):
    """Native Ollama ``/api/chat`` reply -> OpenAI chat-completion shape."""
    if isinstance(resp, dict) and resp.get("error"):
        return {"error": {"message": str(resp["error"])}}
    msg = (resp or {}).get("message", {}) or {}
    content = msg.get("content") or ""
    calls = []
    for tc in msg.get("tool_calls") or []:
        fn = (tc or {}).get("function", {}) or {}
        calls.append(
            {
                "id": "call_" + uuid.uuid4().hex[:8],
                "index": len(calls),
                "type": "function",
                "function": {
                    "name": fn.get("name", ""),
                    "arguments": _args_str(fn.get("arguments", {})),
                },
            }
        )
    out_msg = {"role": "assistant", "content": content}
    if calls:
        out_msg["tool_calls"] = calls
    if calls:
        finish = "tool_calls"
    elif (resp or {}).get("done_reason") == "length":
        finish = "length"
    else:
        finish = "stop"
    p = (resp or {}).get("prompt_eval_count") or 0
    c = (resp or {}).get("eval_count") or 0
    return {
        "id": "chatcmpl-" + uuid.uuid4().hex[:12],
        "object": "chat.completion",
        "created": int(time.time()),
        "model": (resp or {}).get("model") or model or "",
        "choices": [
            {"index": 0, "message": out_msg, "finish_reason": finish}
        ],
        "usage": {
            "prompt_tokens": p,
            "completion_tokens": c,
            "total_tokens": p + c,
        },
    }


# --------------------------------------------------------------------------- #
# http bridge
# --------------------------------------------------------------------------- #
_HOP = {"host", "content-length", "accept-encoding", "connection", "transfer-encoding"}


class _Upstream(Exception):
    """The upstream call failed and the client has not been answered yet."""

    def __init__(self, payload: bytes, status: int = 502):
        super().__init__(status)
        self.payload = payload
        self.status = status


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "oqvian-toolcall-bridge"

    def log_message(self, fmt, *args):
        sys.stderr.write("[toolcall-proxy] " + (fmt % args) + "\n")

    def do_GET(self):
        self._handle("GET")

    def do_POST(self):
        self._handle("POST")

    def _handle(self, method):
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            length = 0
        raw = self.rfile.read(length) if length else b""
        hdrs = {k: v for k, v in self.headers.items() if k.lower() not in _HOP}

        if method == "POST" and self.path.rstrip("/").endswith("/chat/completions"):
            try:
                req = json.loads(raw or b"{}")
            except Exception:
                req = {}
            if req.get("tools"):
                _dump = os.environ.get("OQVIAN_PROXY_DUMP")
                if _dump:
                    try:
                        with open(_dump, "w") as _fh:
                            json.dump(req, _fh, indent=1)
                    except Exception as _e:
                        sys.stderr.write(f"[toolcall-proxy] dump failed: {_e}\n")
                return self._buffered(req, hdrs)
        return self._passthrough(method, raw, hdrs)

    # -- transparent ------------------------------------------------------- #
    def _passthrough(self, method, raw, hdrs):
        req = urlreq.Request(
            UPSTREAM + self.path,
            data=raw if method == "POST" else None,
            headers=hdrs,
            method=method,
        )
        try:
            up = urlreq.urlopen(req, timeout=_TIMEOUT)
        except urlerr.HTTPError as e:
            up = e
        try:
            self.send_response(getattr(up, "status", 502))
            for k, v in up.headers.items():
                if k.lower() in ("transfer-encoding", "connection", "content-length",
                                 "content-encoding"):
                    continue
                self.send_header(k, v)
            self.send_header("Connection", "close")
            self.end_headers()
            while True:
                chunk = up.read(8192)
                if not chunk:
                    break
                self.wfile.write(chunk)
                self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError):
            # Client cancelled (e.g. the harness abandons its title request when the
            # main turn starts). Nobody is listening; do not dump a traceback.
            return

    # -- tools present: buffer upstream, rewrite, re-emit ------------------ #
    def _buffered(self, req, hdrs):
        want_stream = bool(req.get("stream"))
        names = {
            t.get("function", {}).get("name")
            for t in req.get("tools", [])
            if isinstance(t, dict)
        }
        names = {n for n in names if n}
        sys.stderr.write(
            "[toolcall-proxy] tool turn: "
            f"{len(names)} tools, tools_json={len(json.dumps(req.get('tools', [])))}B, "
            f"messages={len(req.get('messages', []))}, "
            f"prompt_chars={sum(len(str(m.get('content') or '')) for m in req.get('messages', []))}, "
            f"stream={want_stream}\n"
        )

        if want_stream:
            # Answer *before* doing the work: the client's request timeout starts
            # when it sends, and the OpenAI SDK clears it as soon as the response
            # headers land. Waiting for the upstream first (25 min on CPU) is what
            # produced "Request timed out." regardless of streamIdleTimeoutMs.
            self._stream_buffered(req, hdrs, names)
            return

        try:
            resp, calls, leftover = self._run_upstream(req, hdrs, names)
        except _Upstream as e:
            self._send_json(raw_body=e.payload, status=e.status)
            return
        self._emit_nonstream(resp, calls, leftover)

    def _run_upstream(self, req, hdrs, names):
        """Buffer one tool turn upstream. Returns ``(resp, calls, leftover)``.

        Raises ``_Upstream`` when the upstream itself failed, so each caller can
        report it in its own wire form (a JSON body, or an SSE chunk).
        """
        up_req = dict(req)
        up_req["stream"] = False
        h = dict(hdrs)
        h["Content-Type"] = "application/json"

        if UPSTREAM_API == "v1":
            url = UPSTREAM + "/v1/chat/completions"
        else:
            url = UPSTREAM + "/api/chat"

        # Both Ollama endpoints intermittently return an *empty* assistant turn
        # (no tool_call, no text, ``done_reason: stop``) -- a sampling artefact,
        # not a refusal. Re-issue the same request a few times rather than
        # handing the agent a blank turn; each retry nudges sampling so it does
        # not replay the same degenerate path.
        resp = None
        calls = None
        leftover = ""
        attempts = max(1, _RETRIES)
        for attempt in range(attempts):
            if UPSTREAM_API == "v1":
                body = dict(up_req)
                if attempt:
                    base = float(body.get("temperature", 0.2) or 0.2)
                    body["temperature"] = min(base + 0.25 * attempt, 1.0)
                    opts = dict(body.get("options") or {})
                    opts["temperature"] = body["temperature"]
                    body["options"] = opts
            else:
                body = _ollama_request(req, TOOL_MODE)
                if attempt:
                    opts = dict(body.get("options") or {})
                    base = float(opts.get("temperature", 0.2) or 0.2)
                    opts["temperature"] = min(base + 0.25 * attempt, 1.0)
                    body["options"] = opts

            r = urlreq.Request(
                url,
                data=json.dumps(body).encode(),
                headers=h,
                method="POST",
            )
            _t0 = time.time()
            try:
                up = urlreq.urlopen(r, timeout=_TIMEOUT)
                raw_resp = json.loads(up.read())
            except urlerr.HTTPError as e:
                raise _Upstream(e.read().decode(errors="replace").encode(), e.code)
            except Exception as e:  # upstream unreachable / timed out
                raise _Upstream(
                    json.dumps({"error": {"message": str(e)}}).encode(), 502
                )

            resp = (
                raw_resp
                if UPSTREAM_API == "v1"
                else _ollama_response(raw_resp, req.get("model"))
            )
            if resp.get("error"):  # upstream refused the request outright
                raise _Upstream(json.dumps(resp).encode(), 502)

            calls, leftover = _parse(resp, names)
            # _parse returns calls=None for a plain-text turn (no tool call), which is
            # the normal final answer. len(None) here would abort the turn -- and did.
            n_calls = len(calls) if calls else 0
            sys.stderr.write(
                f"[toolcall-proxy] attempt {attempt + 1}/{attempts}: "
                f"{time.time() - _t0:.1f}s, "
                f"prompt_eval={raw_resp.get('prompt_eval_count') if isinstance(raw_resp, dict) else None}, "
                f"eval={raw_resp.get('eval_count') if isinstance(raw_resp, dict) else None}, "
                f"done={raw_resp.get('done_reason') if isinstance(raw_resp, dict) else None}, "
                f"calls={n_calls}, text={len((leftover or '').strip())}\n"
            )
            if calls or (leftover or "").strip():
                break  # got a usable turn (tool call or real text)
            try:
                _m = (raw_resp.get("message") or {}) if isinstance(raw_resp, dict) else {}
                _dbg = {
                    "done_reason": raw_resp.get("done_reason") if isinstance(raw_resp, dict) else None,
                    "eval_count": raw_resp.get("eval_count") if isinstance(raw_resp, dict) else None,
                    "content": (_m.get("content") or "")[:120],
                    "has_tool_calls": bool(_m.get("tool_calls")),
                    "raw": (json.dumps(raw_resp)[:200] if isinstance(raw_resp, dict) else str(raw_resp)[:200]),
                }
            except Exception:
                _dbg = {}
            sys.stderr.write(
                f"[toolcall-proxy] empty completion, retry "
                f"{attempt + 1}/{attempts}  {_dbg}\n"
            )

        if calls:
            sys.stderr.write(
                f"[toolcall-proxy] rewrote {len(calls)} tool call(s): "
                f"{[c['function']['name'] for c in calls]}\n"
            )
        elif not (leftover or "").strip():
            sys.stderr.write(
                "[toolcall-proxy] WARNING: upstream returned empty after "
                f"{attempts} attempt(s)\n"
            )
        return resp, calls, leftover

    def _stream_buffered(self, req, hdrs, names):
        """Stream a buffered tool turn without letting the client time out.

        The headers go out immediately; an SSE comment every ``_KEEPALIVE``
        seconds keeps the socket warm while the upstream evaluates a long prompt.
        An SSE comment (``: ...``) is ignored by every spec-compliant parser, so
        it costs the client nothing.
        """
        self._sse_headers()
        box: dict = {}

        def work():
            try:
                box["ok"] = self._run_upstream(req, hdrs, names)
            except _Upstream as e:
                box["err"] = e
            except Exception as e:  # never let the worker die without a trace
                box["err"] = _Upstream(
                    json.dumps({"error": {"message": str(e)}}).encode(), 502
                )

        t = threading.Thread(target=work, daemon=True)
        t.start()
        try:
            while t.is_alive():
                t.join(_KEEPALIVE)
                if t.is_alive():
                    self.wfile.write(b": keepalive\n\n")
                    self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError):
            # Client gave up (cancelled turn, Ctrl-C). Stop feeding a dead socket;
            # the worker is a daemon thread and is reaped with the process.
            return

        if "ok" in box:
            resp, calls, leftover = box["ok"]
            try:
                self._emit_stream_chunks(resp, calls, leftover)
            except (BrokenPipeError, ConnectionResetError):
                pass
            return

        err = box.get("err")
        msg = ""
        try:
            msg = (json.loads(err.payload.decode(errors="replace")).get("error") or {}).get("message", "")
        except Exception:
            msg = ""
        msg = msg or "bridge could not reach the model"
        sys.stderr.write(f"[toolcall-proxy] streaming upstream failed: {msg}\n")
        try:
            self._emit_stream_error(msg)
        except (BrokenPipeError, ConnectionResetError):
            pass

    # -- emitters ---------------------------------------------------------- #
    def _send_json(self, raw_body, status=200):
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw_body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(raw_body)

    def _emit_nonstream(self, resp, calls, leftover):
        resp = json.loads(json.dumps(resp))
        choice = resp["choices"][0]
        msg = choice.setdefault("message", {})
        if calls:
            msg["role"] = "assistant"
            msg["tool_calls"] = calls
            msg["content"] = leftover if leftover.strip() else ""
            choice["finish_reason"] = "tool_calls"
        self._send_json(json.dumps(resp).encode())

    def _sse_headers(self):
        """Open the event stream before the upstream call is made."""
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.flush()

    def _emit_stream_chunks(self, resp, calls, leftover):
        cid = resp.get("id", "chatcmpl-proxy")
        model = resp.get("model", "")
        created = resp.get("created", 0)
        finish = resp.get("choices", [{}])[0].get("finish_reason") or "stop"

        def send(delta, finish_reason=None):
            chunk = {
                "id": cid,
                "object": "chat.completion.chunk",
                "created": created,
                "model": model,
                "choices": [{"index": 0, "delta": delta, "finish_reason": finish_reason}],
            }
            self.wfile.write(b"data: " + json.dumps(chunk).encode() + b"\n\n")
            self.wfile.flush()

        send({"role": "assistant", "content": ""})
        if calls:
            send({"tool_calls": calls})
            if leftover.strip():
                send({"content": leftover})
            send({}, "tool_calls")
        else:
            if leftover:
                send({"content": leftover})
            send({}, finish)
        self.wfile.write(b"data: [DONE]\n\n")
        self.wfile.flush()

    def _emit_stream_error(self, message):
        """Close out an already-open stream with an error as assistant text.

        The headers are long gone by now, so the status cannot be changed; a text
        delta plus ``stop`` is what a stream parser can still consume cleanly.
        """
        cid = "chatcmpl-proxy"
        created = int(time.time())

        def send(delta, finish_reason=None):
            chunk = {
                "id": cid,
                "object": "chat.completion.chunk",
                "created": created,
                "model": "",
                "choices": [{"index": 0, "delta": delta, "finish_reason": finish_reason}],
            }
            self.wfile.write(b"data: " + json.dumps(chunk).encode() + b"\n\n")
            self.wfile.flush()

        send({"role": "assistant", "content": f"[bridge error] {message}"})
        send({}, "stop")
        self.wfile.write(b"data: [DONE]\n\n")
        self.wfile.flush()


def main():
    srv = ThreadingHTTPServer((HOST, PORT), Handler)
    sys.stderr.write(
        f"[toolcall-proxy] listening on http://{HOST}:{PORT}  ->  {UPSTREAM} "
        f"(upstream: {UPSTREAM_API}, tool-mode: {TOOL_MODE}, retries: {_RETRIES})\n"
    )
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
