#!/usr/bin/env python3
"""Check every upgradeable contract's storage layout against its snapshot.

A UUPS upgrade keeps the proxy's storage and swaps the code that reads it. A
field reordered, removed or retyped in a contract's storage struct makes every
value read out of the wrong bytes, and a value read from the wrong bytes does
not revert: it answers. The snapshot beside each contract records what a
deployment's storage holds; this script regenerates the layout from source and
compares.

Each entry of LAYOUTS below is one source file and its snapshot, the file's
name with `.storage-layout` in place of `.sol`. What is compared:

    root      the ERC-7201 namespace in the file's `@custom:storage-location`
              annotation, and the storage-root constant, which must be
              `cast index-erc7201` of that namespace;
    contract  the ordinary (non-namespaced) state variables of each concrete
              contract the entry names -- none, for every contract today;
    field     each field of the namespaced struct: slot and offset relative
              to the root, name, and type, read through the
              `StorageLayoutProbe` contract;
    struct    each member of every struct those reach, directly or as a
              mapping's value or an array's element: slot and offset
              relative to the struct, name, and type. A struct's label alone
              would not change when its members are reordered.

An entry with no namespace (LibidFactory) records only its `contract` lines.

Types are compared by their label (`mapping(bytes32 => uint256)`), not by the
compiler's `t_...` ids, which embed AST ids that move on unrelated edits.

Exit status is 0 only when every layout equals its snapshot. A change that
only appends fields at the end of a section is reported as an append to
record; any other change is reported as INCOMPATIBLE.

Updating it deliberately: append the new field at the END of the struct, run

    ./scripts/check-storage-layout.py --update

and commit the snapshot with the change. `--update` refuses to record anything
but an exact match or a pure append; a layout break is not something to
record, it is something to undo. A new upgradeable contract gets an entry in
LAYOUTS, a field in `StorageLayoutProbe` if it has a namespace, and a first
snapshot from `--update`.

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
from dataclasses import dataclass

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
SOLIDITY_ROOT = REPO_ROOT / "solidity"
CONTRACTS_ROOT = SOLIDITY_ROOT / "contracts"
PROBE = "StorageLayoutProbe"
SECTIONS = ("root", "contract", "field", "struct")


@dataclass(frozen=True)
class Layout:
    source: str
    """The file, relative to solidity/contracts."""
    contracts: tuple[str, ...]
    """The concrete contracts deployed behind a proxy whose storage this is."""
    struct: str | None = None
    """The namespaced struct, as `Contract.Struct`; None for no namespace."""
    constant: str | None = None
    """The constant that holds the struct's ERC-7201 root."""

    @property
    def path(self) -> pathlib.Path:
        return CONTRACTS_ROOT / self.source

    @property
    def snapshot(self) -> pathlib.Path:
        return self.path.with_suffix(".storage-layout")

    @property
    def name(self) -> str:
        return self.path.stem


LAYOUTS = (
    Layout(
        "ceremony/CeremonyProofVerifier.sol",
        ("CeremonyProofVerifier",),
        "CeremonyProofVerifier.ProofVerifierStorage",
        "PROOF_VERIFIER_STORAGE",
    ),
    Layout(
        "ceremony/GoogleJwtRoots.sol",
        ("GoogleJwtRoots",),
        "GoogleJwtRoots.GoogleJwtRootsStorage",
        "GOOGLE_JWT_ROOTS_STORAGE",
    ),
    Layout(
        "ceremony/GooglePlatformVerifier.sol",
        ("GooglePlatformVerifier",),
        "GooglePlatformVerifier.GoogleStorage",
        "GOOGLE_STORAGE",
    ),
    Layout(
        "ceremony/NotaryService.sol",
        ("NotaryService",),
        "NotaryService.NotaryServiceStorage",
        "NOTARY_SERVICE_STORAGE",
    ),
    # Shared by every Platform Verifier. Google adds a namespace of its own,
    # above; X and GitHub have only this one.
    Layout(
        "ceremony/PlatformVerifierBase.sol",
        ("XPlatformVerifier", "GitHubPlatformVerifier"),
        "PlatformVerifierBase.PlatformVerifierStorage",
        "PLATFORM_VERIFIER_STORAGE",
    ),
    Layout(
        "escrow/HandleEscrow.sol",
        ("HandleEscrow",),
        "HandleEscrow.HandleEscrowStorage",
        "HANDLE_ESCROW_STORAGE",
    ),
    Layout("factory/LibidFactory.sol", ("LibidFactory",)),
    Layout(
        "identity/IdentityNames.sol",
        ("IdentityNames",),
        "IdentityNames.IdentityNamesStorage",
        "IDENTITY_NAMES_STORAGE",
    ),
)


def header(layout: Layout) -> list[str]:
    return [
        f"# {layout.name} storage layout. Checked in CI by scripts/check-storage-layout.py.",
        "# Fields may only be APPENDED. Record an append with --update; see the script.",
    ]


def run(*args: str) -> str:
    try:
        return subprocess.run(args, cwd=SOLIDITY_ROOT, check=True, capture_output=True, text=True).stdout
    except subprocess.CalledProcessError as failed:
        sys.exit(f"`{' '.join(args)}` exited {failed.returncode}:\n{failed.stderr.strip() or failed.stdout.strip()}")


def inspect(contract: str) -> dict:
    # --no-cache: a cached artifact from `forge build` carries no storage
    # layout, and inspect refuses it. Without the cache, forge compiles just
    # this contract's sources for the layout, in about a second.
    return json.loads(run("forge", "inspect", contract, "storageLayout", "--json", "--no-cache"))


def entry(section: str, item: dict, types: dict, owner: str | None = None) -> str:
    who = f" {owner}" if owner else ""
    return f"{section}{who} slot={item['slot']} offset={item['offset']} {item['label']}: {types[item['type']]['label']}"


def root(layout: Layout) -> str:
    source = layout.path.read_text()
    namespaces = re.findall(r"@custom:storage-location erc7201:(\S+)", source)
    if len(namespaces) != 1:
        sys.exit(f"expected one @custom:storage-location in {layout.path}, found {namespaces}")
    namespace = namespaces[0]
    constant = re.search(rf"{layout.constant}\s*=\s*(0x[0-9a-fA-F]{{64}})", source)
    if not constant:
        sys.exit(f"no {layout.constant} constant in {layout.path}")
    derived = run("cast", "index-erc7201", namespace).strip()
    if int(derived, 16) != int(constant.group(1), 16):
        sys.exit(f"{layout.constant} is {constant.group(1)}, but erc7201:{namespace} is {derived}")
    return f"root erc7201:{namespace} {derived.lower()}"


def nested(items: list[dict], types: dict) -> list[str]:
    """`struct` lines for every struct `items` reach, in first-reached order."""
    lines: list[str] = []
    seen: set[str] = set()
    pending = [item["type"] for item in items]
    while pending:
        type_id = pending.pop(0)
        kind = types[type_id]
        # A mapping's value, an array's element: `value` and `base`.
        pending += [kind[key] for key in ("value", "base") if key in kind]
        if "members" not in kind or type_id in seen:
            continue
        seen.add(type_id)
        name = kind["label"].removeprefix("struct ")
        lines += [entry("struct", member, types, name) for member in kind["members"]]
        pending += [member["type"] for member in kind["members"]]
    return lines


def fields(struct: str, probe: dict) -> list[str]:
    types = probe["types"]
    held = [types[item["type"]] for item in probe["storage"] if types[item["type"]]["label"] == f"struct {struct}"]
    if len(held) != 1:
        sys.exit(f"{PROBE} holds {struct} {len(held)} times; it must hold it once")
    members = held[0]["members"]
    return [entry("field", member, types) for member in members] + nested(members, types)


def current(layout: Layout, probe: dict) -> list[str]:
    lines = [root(layout)] if layout.struct else []
    plain: list[str] = []
    for contract in layout.contracts:
        own = inspect(contract)
        lines += [entry("contract", item, own["types"], contract) for item in own["storage"]]
        plain += nested(own["storage"], own["types"])
    if layout.struct:
        lines += fields(layout.struct, probe)
    return lines + [line for line in dict.fromkeys(plain) if line not in lines]


def recorded(layout: Layout) -> list[str] | None:
    """The snapshot's lines, or None when there is no snapshot yet."""
    if not layout.snapshot.exists():
        return None
    return [line for line in layout.snapshot.read_text().splitlines() if line and not line.startswith("#")]


def sections(lines: list[str], where: pathlib.Path) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {name: [] for name in SECTIONS}
    for line in lines:
        section = line.split(" ", 1)[0]
        if section not in out:
            sys.exit(f"{where}: {line!r} is not a snapshot line; each starts with one of {', '.join(SECTIONS)}")
        out[section].append(line)
    return out


def classify(old: list[str], new: list[str], where: pathlib.Path) -> str:
    """'same', 'append' or 'incompatible'."""
    if old == new:
        return "same"
    before, after = sections(old, where), sections(new, where)
    if before["root"] != after["root"]:
        return "incompatible"
    for name in ("contract", "field"):
        if after[name][: len(before[name])] != before[name]:
            return "incompatible"
    # Each struct may only grow at its own end. A struct that grew where it
    # sits inline shifts the fields after it, which the checks above catch.
    for struct, members in by_struct(before["struct"]).items():
        grown = by_struct(after["struct"]).get(struct, [])
        if grown[: len(members)] != members:
            return "incompatible"
    return "append"


def by_struct(lines: list[str]) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for line in lines:
        out.setdefault(line.split(" ", 2)[1], []).append(line)
    return out


def diff(old: list[str], new: list[str]) -> str:
    return "\n".join([f"  - {line}" for line in old if line not in new] + [f"  + {line}" for line in new if line not in old])


def check(layout: Layout, probe: dict, update: bool) -> bool:
    old, new = recorded(layout), current(layout, probe)
    snapshot = layout.snapshot.relative_to(REPO_ROOT)
    verdict = "append" if old is None else classify(old, new, snapshot)

    if verdict == "incompatible":
        print(f"INCOMPATIBLE: {layout.name}'s storage layout was reordered, removed or retyped.", file=sys.stderr)
        print(diff(old or [], new), file=sys.stderr)
        print("Undo the change; fields may only be appended at the end of the struct.", file=sys.stderr)
        return False

    if verdict == "append":
        if update:
            layout.snapshot.write_text("\n".join(header(layout) + new) + "\n")
            print(f"recorded {snapshot}")
            return True
        print(f"{layout.name}'s storage layout has appended fields {snapshot} does not record:", file=sys.stderr)
        print(diff(old or [], new), file=sys.stderr)
        print("Record them with ./scripts/check-storage-layout.py --update and commit the snapshot.", file=sys.stderr)
        return False

    print(f"{layout.name} storage layout matches {snapshot}")
    return True


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--update", action="store_true", help="record an exact match or a pure append")
    args = parser.parse_args()

    probe = inspect(PROBE)
    results = [check(layout, probe, args.update) for layout in LAYOUTS]
    return 0 if all(results) else 1


if __name__ == "__main__":
    sys.exit(main())
