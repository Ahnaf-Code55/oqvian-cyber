#!/usr/bin/env python3
"""Offline smoke test for the OQVIAN tool server (no LLM involved).

Run:  cd ~/oqvian-cyber && .venv/bin/python mcp/smoke_test.py
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import server  # noqa: E402

fails = 0


def check(name, cond, detail=""):
    global fails
    mark = "ok  " if cond else "FAIL"
    if not cond:
        fails += 1
    print(f"[{mark}] {name}" + (f" — {detail}" if detail and not cond else ""))


print("== scope ==")
check("private cidr allowed", server.check_scope("10.0.0.5")[0])
check("localhost allowed", server.check_scope("localhost")[0])
check("public denied", not server.check_scope("example.com")[0])
check("public ip denied", not server.check_scope("8.8.8.8")[0])

print("== transform ==")
check("base64", server.transform("abc", "base64") == "YWJj")
check("base64d", server.transform("YWJj", "base64d") == "abc")
check("sha256", server.transform("abc", "sha256").startswith("ba7816bf"))

print("== governance ==")
check("scope json", '"mode"' in server.governance("scope"))
check("audit call", isinstance(server.governance("audit", 3), str))

print("== index ==")
meta = server._load_index()
if not meta:
    print("[skip] index not built yet")
else:
    check("kb count", meta["meta"].get("count", 0) > 5000,
          str(meta["meta"].get("count")))
    r = server.kb("attack", "T1059", 3)
    check("attack T1059", "T1059" in r, r[:120])
    r = server.kb("search", "kerberoasting", 3)
    check("search kerberoasting", "No matches" not in r, r[:120])
    r = server.kb("kev", "vpn", 3)
    check("kev search", len(r) > 20)
    r = server.kb("cve", "CVE-2021-44228")
    check("cve lookup", "CVE-2021-44228" in r)

print("== recon (loopback) ==")
r = server.recon("dns", "localhost", "A")
check("dns localhost", "127.0.0.1" in r, r[:120])
r = server.recon("ports", "127.0.0.1", "22,80,443,11434")
check("port scan", "11434" in r, r[:200])
r = server.recon("http", "http://127.0.0.1:11434/")
check("http probe", "status:" in r, r[:120])

print()
print(f"{'FAILURES: ' + str(fails) if fails else 'all checks passed'}")
sys.exit(1 if fails else 0)
