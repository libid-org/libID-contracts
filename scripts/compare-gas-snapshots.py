#!/usr/bin/env python3
"""Print the change in forge's gas snapshots against a revision, as Markdown.

solidity/snapshots/ holds one JSON file per snapshot group, each an object of
name -> gas. The numbers now are the files in the working tree, as the run that
measured them left them. The base is the same files at REV. CI appends the
output to the gas job's summary, so a pull request shows what it does to each
number beside the diff of the committed files.

Run: ./scripts/compare-gas-snapshots.py REV    # e.g. origin/main, HEAD^1
"""
from __future__ import annotations

import argparse
import json
import pathlib
import subprocess
import sys

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
SNAPSHOTS = "solidity/snapshots"


def git(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(["git", *args], cwd=REPO_ROOT, capture_output=True, text=True)


def numbers(snapshot: dict[str, str]) -> dict[str, int]:
    # forge writes every value as a decimal string.
    return {name: int(value) for name, value in snapshot.items()}


def at_revision(rev: str) -> dict[str, dict[str, int]]:
    listing = git("ls-tree", "--name-only", f"{rev}:{SNAPSHOTS}")
    if listing.returncode != 0:
        return {}  # no snapshots at REV yet
    groups = {}
    for name in listing.stdout.split():
        if name.endswith(".json"):
            groups[name.removesuffix(".json")] = numbers(json.loads(git("show", f"{rev}:{SNAPSHOTS}/{name}").stdout))
    return groups


def in_working_tree() -> dict[str, dict[str, int]]:
    return {path.stem: numbers(json.loads(path.read_text())) for path in (REPO_ROOT / SNAPSHOTS).glob("*.json")}


def cell(gas: int | None) -> str:
    return "—" if gas is None else f"{gas:,}"


def change(base: int | None, now: int | None) -> str:
    if base is None:
        return "new"
    if now is None:
        return "removed"
    delta = now - base
    if delta == 0 or base == 0:
        return f"{delta:+,}" if delta else "0"
    return f"{delta:+,} ({delta / base:+.2%})"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("rev", help="the revision whose committed snapshots are the base")
    rev = parser.parse_args().rev
    resolved = git("rev-parse", "--verify", "--quiet", "--short", f"{rev}^{{commit}}")
    if resolved.returncode != 0:
        print(f"unknown revision {rev}", file=sys.stderr)
        return 1
    short = resolved.stdout.strip()

    base, now = at_revision(rev), in_working_tree()
    print(f"## Gas snapshots against {short}")
    for group in sorted(base.keys() | now.keys()):
        old, new = base.get(group, {}), now.get(group, {})
        print(f"\n### {group}\n")
        print(f"| | {short} | now | change |")
        print("|---|---:|---:|---:|")
        for name in sorted(old.keys() | new.keys()):
            print(f"| `{name}` | {cell(old.get(name))} | {cell(new.get(name))} | {change(old.get(name), new.get(name))} |")
    return 0


if __name__ == "__main__":
    sys.exit(main())
