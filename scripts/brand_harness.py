#!/usr/bin/env python3
"""Rename the harness's user-visible product strings to OQVIAN HARNESS.

The harness (dsh) hard-codes its product name in nine places that a user or the
model can actually see: the browser tab, the PWA manifest, the CLI help, the web
startup description, and two system-prompt sections. Everything else is a
package.json description or a source comment and is left alone.

Order matters — replacements are exact substrings, so re-running is safe (the
new strings no longer match the old ones).

    python scripts/brand_harness.py            # patch the installed harness
    python scripts/brand_harness.py --check    # report, change nothing
    python scripts/brand_harness.py --root DIR # explicit node_modules

An npm upgrade of dsh replaces these files, so run this again afterwards. The
installer calls it as its last harness step for exactly that reason.
"""
from __future__ import annotations

import argparse
import os
import subprocess
import sys
from pathlib import Path

OLD = "DeepSeek Harness"
NEW = "OQVIAN HARNESS"

# (path relative to node_modules, old, new)
PATCHES: list[tuple[str, str, str]] = [
    # Browser tab and installed-PWA identity.
    (
        "@deepseek-ai/dsh-web-frontend/dist/index.html",
        f"<title>{OLD}</title>",
        f"<title>{NEW}</title>",
    ),
    (
        "@deepseek-ai/dsh-web-frontend/dist/manifest.webmanifest",
        f'"name": "{OLD}"',
        f'"name": "{NEW}"',
    ),
    (
        "@deepseek-ai/dsh-web-frontend/dist/manifest.webmanifest",
        '"short_name": "DSH"',
        '"short_name": "OQVIAN"',
    ),
    # Tab title set at runtime, which wins over <title> once the app boots.
    (
        "@deepseek-ai/dsh-client-ui-renderer/lib/client.js",
        f'const productTitle = "{OLD}";',
        f'const productTitle = "{NEW}";',
    ),
    # CLI help text.
    (
        "@deepseek-ai/dsh/lib/bin.js",
        f'description("dsh: boot a {OLD} profile',
        f'description("dsh: boot an {NEW} profile',
    ),
    (
        "@deepseek-ai/dsh-web-app/lib/startup.js",
        f'description("Serve the {OLD} browser UI.")',
        f'description("Serve the {NEW} browser UI.")',
    ),
    # Model-visible system prompt sections.
    (
        "@deepseek-ai/dsh-web-app/lib/index.js",
        f"through the {OLD} Web GUI at ${{webUrl}}",
        f"through the {NEW} Web GUI at ${{webUrl}}",
    ),
    (
        "@deepseek-ai/dsh-app-boot/lib/index.js",
        f"The {OLD} implementation checkout is at ${{sourceRoot}}",
        f"The {NEW} implementation checkout is at ${{sourceRoot}}",
    ),
    (
        "@deepseek-ai/dsh-system-prompt/lib/index.js",
        f"You are an AI agent powered by {OLD}.",
        f"You are an AI agent powered by {NEW}.",
    ),
]


def candidates() -> list[Path]:
    """Plausible node_modules roots, most specific first."""
    out: list[Path] = []
    env = os.environ.get("DSH_NODE_MODULES")
    if env:
        out.append(Path(env))
    try:
        res = subprocess.run(
            ["npm", "root", "-g"], capture_output=True, text=True, timeout=30
        )
        if res.returncode == 0 and res.stdout.strip():
            out.append(Path(res.stdout.strip()))
    except (OSError, subprocess.SubprocessError):
        pass
    home = Path.home()
    out.append(home / ".npm-global" / "lib" / "node_modules")
    # Harness runtimes installed by a host app rather than npm.
    for base in (
        home / ".local/share/open-design/toolchains/dsh",
        home / "Library/Application Support/open-design/toolchains/dsh",
    ):
        if base.is_dir():
            for runtime in sorted(base.glob("runtime-*/node_modules")):
                out.append(runtime)
    return out


def find_root(explicit: str | None) -> Path | None:
    pool = [Path(explicit)] if explicit else candidates()
    for root in pool:
        if (root / "@deepseek-ai" / "dsh-web-frontend").is_dir():
            return root
    return None


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--root", help="node_modules directory containing @deepseek-ai/*")
    ap.add_argument("--check", action="store_true", help="report only")
    args = ap.parse_args()

    root = find_root(args.root)
    if root is None:
        print("harness not found: no node_modules with @deepseek-ai/dsh-web-frontend")
        print("pass --root /path/to/node_modules, or install the harness first:")
        print("  npm i -g @deepseek-ai/dsh@0.1.1-rc.2")
        return 2

    print(f"harness   {root}")
    changed = already = missing = 0
    for rel, old, new in PATCHES:
        path = root / rel
        if not path.is_file():
            print(f"  skip  {rel} (absent)")
            missing += 1
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as exc:
            print(f"  FAIL  {rel}: {exc}")
            return 1
        if new in text and old not in text:
            print(f"  ok    {rel} (already {NEW})")
            already += 1
            continue
        if old not in text:
            print(f"  ?     {rel} (string not found — upstream changed?)")
            missing += 1
            continue
        if args.check:
            print(f"  todo  {rel}")
            changed += 1
            continue
        path.write_text(text.replace(old, new), encoding="utf-8")
        print(f"  patch {rel}")
        changed += 1

    verb = "would patch" if args.check else "patched"
    print(f"\n{verb}: {changed}   already branded: {already}   unmatched: {missing}")
    if args.check and changed:
        print("run without --check to apply")
        return 1
    if missing and not changed and not already:
        print("nothing matched — is this the pinned version, 0.1.1-rc.2?")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
