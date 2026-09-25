#!/usr/bin/env python3
"""Check HandleEscrow's storage layout against the committed snapshot.

A UUPS upgrade keeps the proxy's storage and swaps the code that reads it. A
field reordered, removed or retyped in `HandleEscrowStorage` makes every
balance read out of the wrong bytes, and a balance read from the wrong bytes
does not revert: it answers. The snapshot beside the contract records what a
deployment's storage holds; this script regenerates the layout from source and
compares.

What is compared:

    root      the ERC-7201 namespace in the `@custom:storage-location`
              annotation, and the `HANDLE_ESCROW_STORAGE` constant, which must
              be `cast index-erc7201` of that namespace;
    contract  `HandleEscrow`'s own (non-namespaced) state variables -- none;
    field     each field of `HandleEscrowStorage`: slot and offset relative to
              the root, name, and type, read through the
              `HandleEscrowStorageLayout` probe contract.

Types are compared by their label (`mapping(bytes32 => uint256)`), not by the
compiler's `t_...` ids, which embed AST ids that move on unrelated edits.

Exit status is 0 only when the layout equals the snapshot. A change that only
appends fields at the end of a section is reported as an append to record; any
other change is reported as INCOMPATIBLE.

Updating it deliberately: append the new field at the END of the struct, run

    ./scripts/check-storage-layout.py --update

and commit the snapshot with the change. `--update` refuses to record anything
but an exact match or a pure append; a layout break is not something to
record, it is something to undo.

Needs `forge` and `cast` on PATH. It runs `forge inspect --no-cache` in
solidity/, which compiles what it needs and leaves the build cache alone.
"""
from __future__ import annotations

import argparse
import json
import pathlib
import re
import subprocess
import sys

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
SOLIDITY_ROOT = REPO_ROOT / "solidity"
SOURCE = SOLIDITY_ROOT / "contracts" / "escrow" / "HandleEscrow.sol"
SNAPSHOT = SOLIDITY_ROOT / "contracts" / "escrow" / "HandleEscrow.storage-layout"
CONTRACT = "HandleEscrow"
PROBE = "HandleEscrowStorageLayout"
STRUCT = "HandleEscrowStorage"
CONSTANT = "HANDLE_ESCROW_STORAGE"

HEADER = [
    "# HandleEscrow storage layout. Checked in CI by scripts/check-storage-layout.py.",
    "# Fields may only be APPENDED. Record an append with --update; see the script.",
]


def run(*args: str) -> str:
    return subprocess.run(args, cwd=SOLIDITY_ROOT, check=True, capture_output=True, text=True).stdout


def inspect(contract: str) -> dict:
    # --no-cache: a cached artifact from `forge build` carries no storage
    # layout, and inspect refuses it. Without the cache, forge compiles just
    # this contract's sources for the layout, in well under a second.
    return json.loads(run("forge", "inspect", contract, "storageLayout", "--json", "--no-cache"))


def entry(section: str, item: dict, types: dict) -> str:
    return f"{section} slot={item['slot']} offset={item['offset']} {item['label']}: {types[item['type']]['label']}"


def current() -> list[str]:
    source = SOURCE.read_text()
    namespaces = re.findall(r"@custom:storage-location erc7201:(\S+)", source)
    if len(namespaces) != 1:
        sys.exit(f"expected one @custom:storage-location in {SOURCE}, found {namespaces}")
    namespace = namespaces[0]
    constant = re.search(rf"{CONSTANT}\s*=\s*(0x[0-9a-fA-F]{{64}})", source)
    if not constant:
        sys.exit(f"no {CONSTANT} constant in {SOURCE}")
    derived = run("cast", "index-erc7201", namespace).strip()
    if int(derived, 16) != int(constant.group(1), 16):
        sys.exit(f"{CONSTANT} is {constant.group(1)}, but erc7201:{namespace} is {derived}")

    lines = [f"root erc7201:{namespace} {derived.lower()}"]

    own = inspect(CONTRACT)
    lines += [entry("contract", item, own["types"]) for item in own["storage"]]

    probe = inspect(PROBE)
    types = probe["types"]
    (root,) = probe["storage"]
    struct = types[root["type"]]
    if not struct["label"].endswith(f".{STRUCT}"):
        sys.exit(f"{PROBE} does not hold {STRUCT}: {struct['label']}")
    lines += [entry("field", member, types) for member in struct["members"]]
    return lines


def recorded() -> list[str]:
    if not SNAPSHOT.exists():
        return []
    return [line for line in SNAPSHOT.read_text().splitlines() if line and not line.startswith("#")]


def sections(lines: list[str]) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {"root": [], "contract": [], "field": []}
    for line in lines:
        out[line.split(" ", 1)[0]].append(line)
    return out


def classify(old: list[str], new: list[str]) -> str:
    """'same', 'append' or 'incompatible'."""
    if old == new:
        return "same"
    before, after = sections(old), sections(new)
    if before["root"] != after["root"]:
        return "incompatible"
    for name in ("contract", "field"):
        if after[name][: len(before[name])] != before[name]:
            return "incompatible"
    return "append"


def diff(old: list[str], new: list[str]) -> str:
    return "\n".join([f"  - {line}" for line in old if line not in new] + [f"  + {line}" for line in new if line not in old])


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--update", action="store_true", help="record an exact match or a pure append")
    args = parser.parse_args()

    old, new = recorded(), current()
    verdict = classify(old, new) if old else "append"

    if verdict == "incompatible":
        print(f"INCOMPATIBLE: {CONTRACT}'s storage layout was reordered, removed or retyped.", file=sys.stderr)
        print(diff(old, new), file=sys.stderr)
        print("Undo the change; fields may only be appended at the end of the struct.", file=sys.stderr)
        return 1

    if verdict == "append":
        if args.update:
            SNAPSHOT.write_text("\n".join(HEADER + new) + "\n")
            print(f"recorded {SNAPSHOT.relative_to(REPO_ROOT)}")
            return 0
        print(f"{CONTRACT}'s storage layout has appended fields the snapshot does not record:", file=sys.stderr)
        print(diff(old, new), file=sys.stderr)
        print("Record them with ./scripts/check-storage-layout.py --update and commit the snapshot.", file=sys.stderr)
        return 1

    print(f"{CONTRACT} storage layout matches {SNAPSHOT.relative_to(REPO_ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
