#!/usr/bin/env python3
"""Build OQVIAN's local security knowledge index.

Sources are normalized into text documents, embedded with Ollama
(nomic-embed-text), and stored as docs.jsonl + embeddings.npy.
"""
import json
import os
import re
import sys
import time
import urllib.request
import zipfile
from pathlib import Path

import numpy as np
import yaml

ROOT = Path(__file__).resolve().parent
RAW = ROOT / "corpus" / "raw"
INDEX = ROOT / "index"
OLLAMA = os.environ.get("OLLAMA_HOST", "127.0.0.1:11434")
EMBED_MODEL = os.environ.get("OQVIAN_EMBED_MODEL", "nomic-embed-text")
MAX_CHARS = 1400
OVERLAP = 180

docs = []


def add(source, title, text, **meta):
    text = re.sub(r"\s+", " ", (text or "")).strip()
    if len(text) < 40:
        return
    for i, piece in enumerate(chunk(text)):
        docs.append({
            "id": f"{source}:{len(docs)}",
            "source": source,
            "title": title,
            "text": piece,
            "part": i,
            **meta,
        })


def chunk(text):
    if len(text) <= MAX_CHARS:
        return [text]
    out, start = [], 0
    while start < len(text):
        end = min(start + MAX_CHARS, len(text))
        if end < len(text):
            cut = text.rfind(". ", start + MAX_CHARS // 2, end)
            if cut > 0:
                end = cut + 1
        out.append(text[start:end])
        if end >= len(text):
            break
        start = max(end - OVERLAP, start + 1)
    return out


def load_attack():
    path = RAW / "enterprise-attack.json"
    if not path.exists():
        return
    data = json.loads(path.read_text())
    for obj in data.get("objects", []):
        t = obj.get("type")
        if t == "attack-pattern":
            ext = next((r.get("external_id") for r in obj.get("external_references", [])
                        if r.get("source_name") == "mitre-attack"), "")
            tactics = [p.get("phase_name", "") for p in obj.get("kill_chain_phases", [])]
            body = " ".join(filter(None, [
                obj.get("description", ""),
                "Tactics: " + ", ".join(filter(None, tactics)) if tactics else "",
                "Platforms: " + ", ".join(obj.get("x_mitre_platforms", [])),
                "Detection: " + (obj.get("x_mitre_detection") or ""),
            ]))
            add("attack", f"{ext} {obj.get('name','')}", body, ref=ext,
                tactics=tactics, kind="technique")
        elif t == "course-of-action":
            ext = next((r.get("external_id") for r in obj.get("external_references", [])
                        if r.get("source_name") == "mitre-attack"), "")
            add("attack", f"{ext} {obj.get('name','')}", obj.get("description", ""),
                ref=ext, kind="mitigation")
    print(f"  attack: {len(docs)}")


def load_cwe():
    z = RAW / "cwec_latest.xml.zip"
    xmls = sorted(RAW.glob("cwec*.xml"))
    if z.exists() and not xmls:
        with zipfile.ZipFile(z) as f:
            f.extractall(RAW)
        xmls = sorted(RAW.glob("cwec*.xml"))
    if not xmls:
        return
    import xml.etree.ElementTree as ET
    tree = ET.parse(xmls[0])
    root = tree.getroot()

    def local(tag):
        return tag.rpartition("}")[2] if "}" in tag else tag

    def text_of(el, *path):
        cur = el
        for name in path:
            nxt = next((c for c in cur if local(c.tag) == name), None)
            if nxt is None:
                return ""
            cur = nxt
        return (cur.text or "").strip()

    for w in (e for e in root.iter() if local(e.tag) == "Weakness"):
        wid, name = w.get("ID"), w.get("Name")
        txt = [text_of(w, "Description"), text_of(w, "ExtendedDescription")]
        for el in w.iter():
            if local(el.tag) == "Mitigation":
                t = text_of(el, "Description")
                if t:
                    txt.append("Mitigation: " + t)
            if local(el.tag) == "Consequence":
                scope, impact = text_of(el, "Scope"), text_of(el, "Impact")
                if scope or impact:
                    txt.append(f"Consequence: {scope} / {impact}")
        add("cwe", f"CWE-{wid} {name}", " ".join(txt), ref=f"CWE-{wid}", kind="weakness")
    print(f"  cwe: {len(docs)}")


def load_kev():
    path = RAW / "kev.json"
    if not path.exists():
        return
    data = json.loads(path.read_text())
    for v in data.get("vulnerabilities", []):
        body = " ".join(filter(None, [
            f"CVE: {v.get('cveID')}", f"Vendor: {v.get('vendorProject')}",
            f"Product: {v.get('product')}", f"Name: {v.get('vulnerabilityName')}",
            v.get("shortDescription", ""), f"Required action: {v.get('requiredAction')}",
            f"Added: {v.get('dateAdded')}",
            f"Ransomware use: {v.get('knownRansomwareCampaignUse')}",
            f"Notes: {v.get('notes','')}",
        ]))
        add("kev", f"{v.get('cveID')} {v.get('vulnerabilityName','')}", body,
            ref=v.get("cveID"), kind="exploited-cve")
    print(f"  kev: {len(docs)}")


def load_sigma():
    base = RAW / "sigma"
    if not base.exists():
        return
    for p in base.rglob("*.yml"):
        if "rules" not in p.parts:
            continue
        try:
            rule = yaml.safe_load(p.read_text(errors="ignore"))
        except Exception:
            continue
        if not isinstance(rule, dict) or "title" not in rule:
            continue
        det = rule.get("detection") or {}
        body = "\n".join(filter(None, [
            rule.get("description", ""),
            "Logsource: " + json.dumps(rule.get("logsource") or {}, ensure_ascii=False),
            "Detection: " + yaml.safe_dump(det, sort_keys=False, allow_unicode=True)[:2500],
            "Level: " + str(rule.get("level", "")),
            "Tags: " + ", ".join(rule.get("tags") or []),
            "False positives: " + ", ".join(map(str, rule.get("falsepositives") or [])),
        ]))
        add("sigma", rule.get("title", p.stem), body, ref=str(rule.get("id", "")), kind="detection-rule")
    print(f"  sigma: {len(docs)}")


def load_atomics():
    base = RAW / "atomic-red-team" / "atomics"
    if not base.exists():
        return
    for p in base.rglob("*.yaml"):
        try:
            a = yaml.safe_load(p.read_text(errors="ignore"))
        except Exception:
            continue
        if not isinstance(a, dict) or "atomic_tests" not in a:
            continue
        tests = []
        for t in a.get("atomic_tests", []):
            tests.append(" | ".join(filter(None, [
                t.get("name", ""), t.get("description", ""),
                "Executor: " + str((t.get("executor") or {}).get("name", "")),
                "Command: " + str((t.get("executor") or {}).get("command", ""))[:400],
            ])))
        body = "\n".join([a.get("display_name", ""), a.get("description", "")] + tests)
        add("atomic", f"{a.get('attack_technique','')} {a.get('display_name','')}", body,
            ref=a.get("attack_technique"), kind="atomic-test")
    print(f"  atomic: {len(docs)}")


def load_lolbas():
    path = RAW / "lolbas.json"
    if not path.exists():
        return
    data = json.loads(path.read_text())
    for e in data:
        cmds = []
        for c in e.get("Commands", []) or []:
            cmds.append(f"{c.get('Command','')} :: {c.get('Description','')}")
        body = "\n".join(filter(None, [e.get("Description", "")] + cmds +
                                 ["Detections: " + str(e.get("Detections", ""))]))
        add("lolbas", e.get("Name", ""), body, kind="lolbin")
    print(f"  lolbas: {len(docs)}")


def load_markdown(source, base, title_prefix=""):
    if not base.exists():
        return
    for p in sorted(base.rglob("*.md")):
        rel = p.relative_to(base)
        if any(x in rel.parts for x in ("node_modules", ".git")):
            continue
        text = p.read_text(errors="ignore")
        if len(text) < 200:
            continue
        add(source, f"{title_prefix}{rel.with_suffix('')}", text, kind="doc")
    print(f"  {source}: {len(docs)}")


def load_gtfobins():
    base = RAW / "GTFOBins.github.io" / "_gtfobins"
    if not base.exists():
        return
    for p in sorted(base.iterdir()):
        if not p.is_file() or p.name.startswith("."):
            continue
        text = p.read_text(errors="ignore")
        if len(text) < 60:
            continue
        add("gtfobins", p.name, text, kind="lolbin")
    print(f"  gtfobins: {len(docs)}")


def embed(texts):
    req = urllib.request.Request(
        f"http://{OLLAMA}/api/embed",
        data=json.dumps({"model": EMBED_MODEL, "input": texts}).encode(),
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=600) as r:
        return json.load(r)["embeddings"]


def build_fts(path):
    import sqlite3
    if path.exists():
        path.unlink()
    con = sqlite3.connect(path)
    con.execute("PRAGMA journal_mode=WAL")
    con.execute("PRAGMA synchronous=OFF")
    con.execute(
        "CREATE VIRTUAL TABLE docs USING fts5("
        "docid UNINDEXED, source, title, ref, kind, text, "
        "tokenize='unicode61 remove_diacritics 2', prefix='2 3')"
    )
    con.executemany(
        "INSERT INTO docs(docid, source, title, ref, kind, text) VALUES (?,?,?,?,?,?)",
        [(i, d.get("source", ""), d.get("title", ""), d.get("ref", ""),
          d.get("kind", ""), d.get("text", "")) for i, d in enumerate(docs)],
    )
    con.commit()
    con.execute("INSERT INTO docs(docs) VALUES('optimize')")
    con.commit()
    con.close()


def main():
    t0 = time.time()
    print("loading corpora...", flush=True)
    load_attack()
    load_cwe()
    load_kev()
    load_sigma()
    load_atomics()
    load_lolbas()
    load_gtfobins()
    load_markdown("wstg", RAW / "wstg" / "document", "WSTG ")
    print(f"documents: {len(docs)}", flush=True)

    INDEX.mkdir(parents=True, exist_ok=True)
    with (INDEX / "docs.jsonl").open("w") as f:
        for d in docs:
            f.write(json.dumps(d, ensure_ascii=False) + "\n")

    print("building FTS5 index...", flush=True)
    build_fts(INDEX / "fts.db")

    meta = {
        "count": len(docs),
        "built": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "sources": sorted({d["source"] for d in docs}),
        "search": "fts5-bm25",
        "vectors": False,
    }

    if "--embed" in sys.argv:
        print("building embeddings (slow on CPU)...", flush=True)
        vectors = np.zeros((len(docs), 768), dtype=np.float32)
        batch = 16
        for start in range(0, len(docs), batch):
            part = docs[start:start + batch]
            for attempt in range(3):
                try:
                    embs = embed([d["text"] for d in part])
                    break
                except Exception:
                    if attempt == 2:
                        raise
                    time.sleep(2)
            for i, e in enumerate(embs):
                v = np.asarray(e, dtype=np.float32)
                n = np.linalg.norm(v)
                vectors[start + i] = v / n if n else v
            if start % 160 == 0:
                rate = (start + len(part)) / max(time.time() - t0, 1)
                print(f"  embedded {start + len(part)}/{len(docs)} ({rate:.1f}/s)",
                      flush=True)
        np.save(INDEX / "embeddings.npy", vectors)
        meta.update({"vectors": True, "dim": 768, "model": EMBED_MODEL})

    (INDEX / "meta.json").write_text(json.dumps(meta, indent=2))
    print(f"done: {len(docs)} docs in {time.time()-t0:.1f}s -> {INDEX}", flush=True)


if __name__ == "__main__":
    main()
