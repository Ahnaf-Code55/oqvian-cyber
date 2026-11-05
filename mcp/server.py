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
MAX_OUTPUT = 100_000

STATE.mkdir(parents=True, exist_ok=True)
LOOT.mkdir(parents=True, exist_ok=True)

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
    version="1.0.0",
    instructions=(
        "OQVIAN cyber-operations toolserver. Call kb before answering any "
        "security question so answers are grounded in ATT&CK/CWE/KEV/Sigma/atomics. "
        "Call recon for live DNS/HTTP/TLS/port evidence and execute to run "
        "installed security tools. Every target must be in "
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

if __name__ == "__main__":
    _audit("server", "start", detail=str(INDEX))
    mcp.run()
