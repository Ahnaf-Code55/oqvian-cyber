#!/usr/bin/env python3
"""OQVIAN tool-call bridge.

Sits between an OpenAI-compatible client (the operator's harness) and Ollama.

Ollama only recognises a tool call when the model emits it inside
``<tool_call>...</tool_call>`` tags. Some abliterated bases instead emit the
same payload as a markdown-fenced JSON object::

    ```json
    {"name": "kb", "arguments": {"action": "cve", "query": "CVE-2021-44228"}}
    ```

Ollama then hands that back as ordinary assistant *text*, so the harness never
runs a tool. This bridge is transparent for all normal traffic and, only when a
request carries ``tools``, converts that fenced JSON back into a real OpenAI
``tool_calls`` array -- streaming and non-streaming alike. If the model already
emits native tool calls (e.g. an Instruct base), the response is passed through
untouched, so the bridge is safe under any base.

Stdlib only. Configuration (env):
    OQVIAN_PROXY_UPSTREAM   default http://127.0.0.1:11434   (Ollama)
    OQVIAN_PROXY_HOST       default 127.0.0.1
    OQVIAN_PROXY_PORT       default 11435

Run:  python3 mcp/toolcall_proxy.py
"""
from __future__ import annotations

import json
import os
import re
import sys
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib import error as urlerr
from urllib import request as urlreq

UPSTREAM = os.environ.get("OQVIAN_PROXY_UPSTREAM", "http://127.0.0.1:11434").rstrip("/")
HOST = os.environ.get("OQVIAN_PROXY_HOST", "127.0.0.1")
PORT = int(os.environ.get("OQVIAN_PROXY_PORT", "11435"))

_FENCE = re.compile(r"```(?:json|JSON)?\s*(\{.*?\})\s*```", re.DOTALL)
_TIMEOUT = 1800  # CPU-only generation can be slow


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
    texts = [m.group(1) for m in _FENCE.finditer(content)]
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


# --------------------------------------------------------------------------- #
# http bridge
# --------------------------------------------------------------------------- #
_HOP = {"host", "content-length", "accept-encoding", "connection", "transfer-encoding"}


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

    # -- tools present: buffer upstream, rewrite, re-emit ------------------ #
    def _buffered(self, req, hdrs):
        want_stream = bool(req.get("stream"))
        names = {
            t.get("function", {}).get("name")
            for t in req.get("tools", [])
            if isinstance(t, dict)
        }
        names = {n for n in names if n}

        up_req = dict(req)
        up_req["stream"] = False
        h = dict(hdrs)
        h["Content-Type"] = "application/json"
        r = urlreq.Request(
            UPSTREAM + "/v1/chat/completions",
            data=json.dumps(up_req).encode(),
            headers=h,
            method="POST",
        )
        try:
            up = urlreq.urlopen(r, timeout=_TIMEOUT)
            resp = json.loads(up.read())
        except urlerr.HTTPError as e:
            body = e.read().decode(errors="replace")
            self._send_json(raw_body=body.encode(), status=e.code)
            return
        except Exception as e:  # upstream unreachable
            self._send_json(
                raw_body=json.dumps({"error": {"message": str(e)}}).encode(), status=502
            )
            return

        calls = None
        leftover = ""
        try:
            choice = resp["choices"][0]
            msg = choice.get("message", {})
            native = msg.get("tool_calls")
            if native:  # base already calls tools -> pass through unchanged
                calls = native
                leftover = msg.get("content") or ""
            else:
                pairs, rest = _extract(msg.get("content") or "", names)
                if pairs:
                    calls = _tool_calls(pairs)
                else:
                    leftover = msg.get("content") or ""
        except Exception:
            calls = None

        if calls:
            sys.stderr.write(
                f"[toolcall-proxy] rewrote {len(calls)} tool call(s): "
                f"{[c['function']['name'] for c in calls]}\n"
            )
        if want_stream:
            self._emit_stream(resp, calls, leftover)
        else:
            self._emit_nonstream(resp, calls, leftover)

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

    def _emit_stream(self, resp, calls, leftover):
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "close")
        self.end_headers()

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


def main():
    srv = ThreadingHTTPServer((HOST, PORT), Handler)
    sys.stderr.write(
        f"[toolcall-proxy] listening on http://{HOST}:{PORT}  ->  {UPSTREAM}\n"
    )
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
