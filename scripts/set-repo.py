#!/usr/bin/env python3
"""Point every repository URL at the real GitHub owner.

The source tree ships with `assay-tools/assay` as the owner/repo pair, because a
project that has not been published yet does not have one. That placeholder
appears in the Cargo manifest, the badges, the issue templates, the security
policy and the changelog's compare links — 20 places in 7 files, which is
exactly the kind of set that gets half-updated by hand and leaves a dead badge
behind.

This script rewrites all of them in one pass and then prints what changed.

Usage:
    python scripts/set-repo.py my-org/assay
    python scripts/set-repo.py my-org/assay --dry-run

`--dry-run` prints the files and line counts without writing. Exit code is 0
when the rewrite succeeds, 1 when the argument is not an `owner/repo` pair or
nothing matched.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

DEFAULT_SLUG = "assay-tools/assay"

# Files that carry the slug. Globs are resolved from the repository root; the
# generated and vendored trees are never touched.
TARGETS = [
    "Cargo.toml",
    "README.md",
    "README.zh-CN.md",
    "CHANGELOG.md",
    "CONTRIBUTING.md",
    "SECURITY.md",
    ".github/ISSUE_TEMPLATE/bug_report.yml",
    ".github/ISSUE_TEMPLATE/config.yml",
    ".github/ISSUE_TEMPLATE/feature_request.yml",
    ".github/PULL_REQUEST_TEMPLATE.md",
    ".github/workflows/ci.yml",
    ".github/workflows/release.yml",
]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("slug", help="GitHub owner/repo, e.g. `acme/assay`")
    parser.add_argument("--dry-run", action="store_true", help="report without writing")
    parser.add_argument(
        "--from",
        dest="source",
        default=DEFAULT_SLUG,
        help=f"slug to replace (default: {DEFAULT_SLUG})",
    )
    args = parser.parse_args()

    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", args.slug):
        print(f"error: `{args.slug}` is not an owner/repo pair", file=sys.stderr)
        return 1

    total = 0
    for name in TARGETS:
        path = ROOT / name
        if not path.exists():
            continue
        text = path.read_text(encoding="utf-8")
        count = text.count(args.source)
        if not count:
            continue
        total += count
        print(f"  {count:2}  {name}")
        if not args.dry_run:
            path.write_text(text.replace(args.source, args.slug), encoding="utf-8", newline="")

    if not total:
        print(f"error: `{args.source}` does not appear in any tracked document", file=sys.stderr)
        return 1

    verb = "would rewrite" if args.dry_run else "rewrote"
    print(f"\n{verb} {total} occurrence(s) of `{args.source}` -> `{args.slug}`")
    if not args.dry_run:
        print("Next: `cargo check -p assay-core` to confirm the manifest still parses,")
        print("then `python scripts/linkcheck.py` for the internal links.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
