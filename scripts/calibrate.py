#!/usr/bin/env python3
"""Re-measure the false-positive calibration corpus.

`docs/SCORING.md` §9 quotes a distribution over 643 Microsoft-signed binaries in
`C:\\Windows\\System32`, before and after the string-hygiene work. A number in a
document is a claim about the software, so this script exists to make that claim
reproducible on any Windows host rather than trusting the one machine it was
first measured on.

The corpus is the operating system itself: every file there is signed or
catalog-signed by Microsoft, so any verdict above `low` is either a true positive
(the Settings UI really can disable Defender) or a bug — no judgement call to
hide behind.

Usage:
    python scripts/calibrate.py
    python scripts/calibrate.py --corpus C:\\Windows\\System32 --binary target/release/assay
    python scripts/calibrate.py --recursive --top 25

Exit code is 0 when the measurement completed, 1 when the binary or corpus is
missing. The verdict distribution is printed, not asserted: this is a measuring
instrument, not a gate. `tests/e2e.py` holds the gate.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from collections import Counter
from pathlib import Path

GRADES = ["clean", "low", "medium", "high", "critical"]


def find_binary(path: Path) -> Path | None:
    """Accept `target/release/assay` and `target/release/assay.exe` alike."""
    for candidate in (path, Path(f"{path}.exe")):
        if candidate.is_file():
            return candidate
    return None


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--binary",
        default="target/release/assay",
        help="path to the assay binary (default: target/release/assay)",
    )
    parser.add_argument(
        "--corpus",
        default=r"C:\Windows\System32",
        help=r"directory to measure (default: C:\Windows\System32)",
    )
    parser.add_argument(
        "--recursive",
        action="store_true",
        help="descend into subdirectories (default: the directory only, which is the documented corpus)",
    )
    parser.add_argument("--top", type=int, default=15, help="how many top-scoring files to list")
    args = parser.parse_args()

    binary = find_binary(Path(args.binary))
    if binary is None:
        print(f"error: binary not found at {args.binary}", file=sys.stderr)
        print("       build it first: cargo build --release -p assay-cli", file=sys.stderr)
        return 1

    corpus = Path(args.corpus)
    if not corpus.is_dir():
        print(f"error: corpus not found at {corpus}", file=sys.stderr)
        return 1

    command = [str(binary), "batch", str(corpus), "--format", "json", "--quiet"]
    if not args.recursive:
        command.append("--no-recursive")

    # `batch` exits 1 or 2 when the worst grade reaches the threshold, which is
    # exactly what a corpus containing real positives does. The verdict is in the
    # JSON; the exit code is not an error condition here.
    result = subprocess.run(command, capture_output=True, text=True, encoding="utf-8")
    if not result.stdout.strip():
        print("error: assay produced no output", file=sys.stderr)
        print(result.stderr.strip(), file=sys.stderr)
        return 1

    try:
        rows = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        print(f"error: could not parse batch output: {exc}", file=sys.stderr)
        return 1

    counts = Counter(row["grade"] for row in rows)
    total = len(rows)

    print(f"corpus: {corpus}{'' if args.recursive else ' (this directory only)'}")
    print(f"binary: {binary}")
    print()
    print("| | " + " | ".join(GRADES) + " | total |")
    print("|---|" + "---|" * (len(GRADES) + 1))
    print("| measured | " + " | ".join(str(counts.get(g, 0)) for g in GRADES) + f" | {total} |")
    print()

    above_low = [row for row in rows if GRADES.index(row["grade"]) >= 2]
    if not above_low:
        print("Nothing reached medium. That is the expected shape for signed system binaries.")
        return 0

    above_low.sort(key=lambda row: (-row["score"], row["path"]))
    print(f"{len(above_low)} file(s) at medium or above — each one is either a true positive or a bug:")
    print()
    print("| score | grade | file | findings | techniques | indicators |")
    print("|---|---|---|---|---|---|")
    for row in above_low[: args.top]:
        # `batch` reports counts, not the full evidence; rerun a single file with
        # `analyze --format json` when one of these needs explaining.
        print(
            f"| {row['score']} | {row['grade']} | `{row['name']}` "
            f"| {row['findings']} | {row['techniques']} | {row['indicators']} |"
        )
    if len(above_low) > args.top:
        print(f"| … | | {len(above_low) - args.top} more | | | |")

    return 0


if __name__ == "__main__":
    sys.exit(main())
