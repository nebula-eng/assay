#!/usr/bin/env python3
"""Check every relative link and anchor in the Markdown files.

A README whose table of contents jumps nowhere is a small thing that reads as a
large thing: it says nobody opened the document after writing it. This script
checks the mechanical part so review can spend its attention on the prose.

Anchors follow GitHub's slug rules, which are narrower than they look:

* lowercase;
* drop everything that is not a letter, digit, space, hyphen or underscore — an
  em dash is dropped while the spaces around it stay, which is why
  `## Part 4 — The signature boundary` becomes `part-4--the-signature-boundary`
  with **two** hyphens;
* turn each space into one hyphen, without collapsing runs.

Getting that wrong in a checker produces false alarms on correct links, so the
rule is implemented once, here, rather than eyeballed.

Usage:
    python scripts/linkcheck.py            # check
    python scripts/linkcheck.py --verbose  # list every link

Exit code 0 when every link resolves, 1 otherwise.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# Markdown files that carry internal links. Anything else in the tree is either
# generated, vendored or a changelog fragment with no cross-references.
SOURCES = [
    "README.md",
    "README.zh-CN.md",
    "CHANGELOG.md",
    "CONTRIBUTING.md",
    "SECURITY.md",
    "CODE_OF_CONDUCT.md",
    "docs/ARCHITECTURE.md",
    "docs/CLI.md",
    "docs/FORMATS.md",
    "docs/RULES.md",
    "docs/SCORING.md",
    "docs/THREAT-MODEL.md",
]

LINK = re.compile(r"\[[^\]]*\]\(([^)\s]+)(?:\s+\"[^\"]*\")?\)")
HEADING = re.compile(r"^(#{1,6})\s+(.*?)\s*$")
FENCE = re.compile(r"^\s*(```|~~~)")
INLINE_CODE = re.compile(r"`[^`]*`")
HTML_TAG = re.compile(r"<[^>]+>")


def slug(title: str) -> str:
    """GitHub's heading anchor for `title`."""
    text = INLINE_CODE.sub(lambda m: m.group(0).replace("`", ""), title)
    text = HTML_TAG.sub("", text)
    text = text.strip().lower()
    out = []
    for ch in text:
        if ch.isalnum() or ch in " -_":
            out.append(ch)
        # Everything else — em dash, colon, comma, brackets — is dropped.
    return "".join(out).replace(" ", "-")


def anchors(path: Path) -> set[str]:
    """Every anchor a reader could land on in `path`."""
    found: set[str] = set()
    in_fence = False
    for line in path.read_text(encoding="utf-8").splitlines():
        if FENCE.match(line):
            in_fence = not in_fence
            continue
        if in_fence:
            continue
        match = HEADING.match(line)
        if match:
            found.add(slug(match.group(2)))
    return found


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--verbose", action="store_true", help="print every link checked")
    args = parser.parse_args()

    cache: dict[Path, set[str]] = {}
    broken: list[tuple[str, str, str]] = []
    checked = 0

    for name in SOURCES:
        source = ROOT / name
        if not source.exists():
            continue
        text = source.read_text(encoding="utf-8")
        in_fence = False
        for lineno, line in enumerate(text.splitlines(), 1):
            if FENCE.match(line):
                in_fence = not in_fence
                continue
            if in_fence:
                continue
            for target in LINK.findall(line):
                if target.startswith(("http://", "https://", "mailto:", "file:")):
                    continue
                checked += 1
                path_part, _, anchor = target.partition("#")
                dest = source if not path_part else (source.parent / path_part).resolve()
                if not dest.exists():
                    broken.append((f"{name}:{lineno}", target, "no such file"))
                    continue
                if anchor and dest.suffix == ".md":
                    if dest not in cache:
                        cache[dest] = anchors(dest)
                    if anchor not in cache[dest]:
                        broken.append((f"{name}:{lineno}", target, "no such anchor"))
                        continue
                if args.verbose:
                    print(f"  ok  {name}:{lineno}  {target}")

    print(f"checked {checked} links in {len([s for s in SOURCES if (ROOT / s).exists()])} files")
    for where, target, why in broken:
        print(f"  BROKEN  {where}  {target}  ({why})")
    if broken:
        return 1
    print("all relative links and anchors resolve")
    return 0


if __name__ == "__main__":
    sys.exit(main())
