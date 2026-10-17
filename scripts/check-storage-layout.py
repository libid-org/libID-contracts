#!/usr/bin/env python3
"""Check every upgradeable contract's storage layout against its snapshot.

A UUPS upgrade keeps the proxy's storage and swaps the code that reads it, so a
field reordered, removed or retyped reads the wrong bytes without reverting.
The snapshot beside each contract records what a deployment's storage holds.
This script regenerates the layout from source and compares.

Each entry of LAYOUTS is one source file and its snapshot, the file's name with
`.storage-layout` in place of `.sol`. What is compared:

    root      the ERC-7201 namespace in the file's `@custom:storage-location`
              annotation, and the storage-root constant, which must be
              `cast index-erc7201` of that namespace;
    contract  the ordinary (non-namespaced) state variables of each concrete
              contract the entry names;
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

Exit status is 0 only when every layout equals its snapshot and LAYOUTS covers
every concrete UUPS contract under solidity/contracts. A difference is one of:

    append        lines added only at the end of a section: each contract's
                  own `contract` lines, the `field` lines, each struct's
                  members;
    rename        every line keeps its slot, offset and type, a renamed struct
                  or contract type counting as the same type, and no label
                  both layouts keep has moved, so two swapped fields of one
                  type are not a rename;
    INCOMPATIBLE  anything else, including growth of a struct stored as an
                  array element or inline in one, which changes the stride.

To change a layout, append the new field at the END of the struct or rename in
place, run

    ./scripts/check-storage-layout.py --update

and commit the snapshot with the change. `--update` records only an exact
match, a pure append or a pure rename. A new upgradeable contract gets an
entry in LAYOUTS, a field in `StorageLayoutProbe` if it has a namespace, and a
first snapshot from `--update`.

A contract that ships as a fresh deployment, never as an upgrade of a live
proxy, may have its snapshot reset to the current layout:

    ./scripts/check-storage-layout.py --redeploy PlatformVerifierBase --why "..."

This rewrites that one snapshot and stamps it with the reason. The stamp stays
through later `--update`s, and appends are checked against the reset layout.

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
from typing import Any

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
    # Shared by every Platform Verifier. Google also has its own, above.
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
        "identity/IdentityRegistry.sol",
        ("IdentityRegistry",),
        "IdentityRegistry.IdentityRegistryStorage",
        "IDENTITY_REGISTRY_STORAGE",
    ),
)


@dataclass(frozen=True)
class StorageItem:
    """A state variable or struct member of a forge `storageLayout`."""

    label: str
    slot: str
    offset: int
    type: str
    """The compiler's type id, a key of the layout's `types`."""

    @classmethod
    def from_json(cls, raw: dict[str, Any]) -> StorageItem:
        return cls(label=raw["label"], slot=raw["slot"], offset=raw["offset"], type=raw["type"])


@dataclass(frozen=True)
class StorageType:
    """A type of a forge `storageLayout`."""

    label: str
    members: list[StorageItem] | None
    """A struct's members; None for any other type."""
    value: str | None
    """A mapping's value type id."""
    base: str | None
    """An array's element type id."""

    @classmethod
    def from_json(cls, raw: dict[str, Any]) -> StorageType:
        members = raw.get("members")
        return cls(
            label=raw["label"],
            members=None if members is None else [StorageItem.from_json(m) for m in members],
            value=raw.get("value"),
            base=raw.get("base"),
        )


@dataclass(frozen=True)
class StorageLayout:
    """`forge inspect <contract> storageLayout --json`."""

    storage: list[StorageItem]
    types: dict[str, StorageType]
    """By type id; forge writes null for a contract without storage."""

    @classmethod
    def from_json(cls, raw: dict[str, Any]) -> StorageLayout:
        return cls(
            storage=[StorageItem.from_json(item) for item in raw["storage"]],
            types={type_id: StorageType.from_json(kind) for type_id, kind in (raw["types"] or {}).items()},
        )


RESET = "# Reset for a redeploy, not an upgrade: "


def header(layout: Layout) -> list[str]:
    return [
        f"# {layout.name} storage layout. Checked in CI by scripts/check-storage-layout.py.",
        "# Fields may only be APPENDED. Record an append with --update; see the script.",
    ]


def stamp(layout: Layout) -> list[str]:
    """The snapshot's redeploy stamp, if it has one."""
    if not layout.snapshot.exists():
        return []
    return [line for line in layout.snapshot.read_text().splitlines() if line.startswith(RESET)]


def write(layout: Layout, lines: list[str], reset: list[str]) -> None:
    layout.snapshot.write_text("\n".join(header(layout) + reset + lines) + "\n")


def shown(path: pathlib.Path) -> pathlib.Path:
    return path.relative_to(REPO_ROOT) if path.is_relative_to(REPO_ROOT) else path


def run(*args: str) -> str:
    try:
        return subprocess.run(args, cwd=SOLIDITY_ROOT, check=True, capture_output=True, text=True).stdout
    except subprocess.CalledProcessError as failed:
        sys.exit(f"`{' '.join(args)}` exited {failed.returncode}:\n{failed.stderr.strip() or failed.stdout.strip()}")


def inspect(contract: str) -> StorageLayout:
    # --no-cache: a `forge build` artifact carries no storage layout, and
    # inspect refuses it. Without the cache forge compiles just this contract.
    return StorageLayout.from_json(json.loads(run("forge", "inspect", contract, "storageLayout", "--json", "--no-cache")))


def entry(section: str, item: StorageItem, types: dict[str, StorageType], owner: str | None = None) -> str:
    who = f" {owner}" if owner else ""
    return f"{section}{who} slot={item.slot} offset={item.offset} {item.label}: {types[item.type].label}"


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


def nested(items: list[StorageItem], types: dict[str, StorageType]) -> list[str]:
    """`struct` lines for every struct `items` reach, in first-reached order."""
    lines: list[str] = []
    seen: set[str] = set()
    pending = [item.type for item in items]
    while pending:
        type_id = pending.pop(0)
        kind = types[type_id]
        # A mapping's value, an array's element.
        pending += [inner for inner in (kind.value, kind.base) if inner is not None]
        if kind.members is None or type_id in seen:
            continue
        seen.add(type_id)
        name = kind.label.removeprefix("struct ")
        lines += [entry("struct", member, types, name) for member in kind.members]
        pending += [member.type for member in kind.members]
    return lines


def fields(struct: str, probe: StorageLayout) -> list[str]:
    types = probe.types
    held = [types[item.type] for item in probe.storage if types[item.type].label == f"struct {struct}"]
    if len(held) != 1:
        sys.exit(f"{PROBE} holds {struct} {len(held)} times; it must hold it once")
    members = held[0].members or []
    return [entry("field", member, types) for member in members] + nested(members, types)


def current(layout: Layout, probe: StorageLayout) -> list[str]:
    lines = [root(layout)] if layout.struct else []
    plain: list[str] = []
    for contract in layout.contracts:
        own = inspect(contract)
        lines += [entry("contract", item, own.types, contract) for item in own.storage]
        plain += nested(own.storage, own.types)
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
    """'same', 'append', 'rename' or 'incompatible'."""
    if old == new:
        return "same"
    before, after = sections(old, where), sections(new, where)
    if shape(old) == shape(new):
        return "incompatible" if moved(old, new) else "rename"
    if before["root"] != after["root"]:
        return "incompatible"
    if after["field"][: len(before["field"])] != before["field"]:
        return "incompatible"
    # Each contract's own variables, and each struct's members, may only grow
    # at their own end. A struct that grew where it sits inline shifts what
    # follows it, which these checks catch; one that is an array element
    # changes the stride, which they do not.
    strided = array_elements(old + new)
    for name in ("contract", "struct"):
        grown = by_owner(after[name])
        for owner, members in by_owner(before[name]).items():
            now = grown.get(owner, [])
            if now[: len(members)] != members:
                return "incompatible"
            if name == "struct" and owner in strided and len(now) != len(members):
                return "incompatible"
    return "append"


def shape(lines: list[str]) -> list[str]:
    """The lines with their names taken out: each field's and member's label
    dropped, and each struct or contract type named by the order it first
    appears in. Two layouts of one shape keep every type at the same slot and
    offset."""
    order: dict[str, str] = {}

    def anonymous(match: re.Match[str]) -> str:
        return match.group(1) + " #" + order.setdefault(match.group(0), str(len(order)))

    out = []
    for line in lines:
        head, colon, kind = line.partition(": ")
        if colon:
            line = head.rsplit(" ", 1)[0] + colon + kind
        out.append(re.sub(r"\b(struct|contract) ([\w.]+)", anonymous, line))
    return out


def moved(old: list[str], new: list[str]) -> bool:
    """Whether a label both layouts of one shape keep sits at another line in
    `new`. A rename brings a label in and takes one out; a label that moves
    is a reorder."""

    def labels(lines: list[str]) -> list[tuple[str, str] | None]:
        out: list[tuple[str, str] | None] = []
        for line, anonymous in zip(lines, shape(lines)):
            head, colon, _ = line.partition(": ")
            out.append((anonymous.split(" slot=", 1)[0], head.rsplit(" ", 1)[1]) if colon else None)
        return out

    before, after = labels(old), labels(new)
    kept = (set(before) & set(after)) - {None}
    return any(a != b and (a in kept or b in kept) for a, b in zip(before, after))


def by_owner(lines: list[str]) -> dict[str, list[str]]:
    """`contract` or `struct` lines grouped by the contract or struct named."""
    out: dict[str, list[str]] = {}
    for line in lines:
        out.setdefault(line.split(" ", 2)[1], []).append(line)
    return out


def array_elements(lines: list[str]) -> set[str]:
    """Structs whose size is an array's stride: stored as an array element,
    or inline (not behind a mapping or array) in one that is."""
    types = [line.split(": ", 1)[1] for line in lines if ": " in line]
    found = {name for label in types for name in re.findall(r"struct ([\w.]+)\[", label)}
    inline = [
        (line.split(" ", 2)[1], line.split(": ", 1)[1].removeprefix("struct "))
        for line in lines
        if line.startswith("struct ") and re.fullmatch(r"struct [\w.]+", line.split(": ", 1)[1])
    ]
    while True:
        more = {inner for outer, inner in inline if outer in found} - found
        if not more:
            return found
        found |= more


def upgradeable_contracts() -> set[str]:
    """Concrete contracts under solidity/contracts (tests and scripts aside)
    that inherit UUPSUpgradeable, directly or through the repository's own
    abstract bases."""
    declaration = re.compile(r"\b(abstract\s+)?contract\s+(\w+)\s+is\s+([^{]+)\{")
    bases: dict[str, list[str]] = {}
    concrete: set[str] = set()
    for path in CONTRACTS_ROOT.rglob("*.sol"):
        if "test" in path.relative_to(CONTRACTS_ROOT).parts or path.name.endswith((".t.sol", ".s.sol")):
            continue
        for match in declaration.finditer(path.read_text()):
            bases[match.group(2)] = [b.split("(")[0].strip() for b in match.group(3).split(",") if b.strip()]
            if not match.group(1):
                concrete.add(match.group(2))

    def uups(name: str, seen: frozenset[str]) -> bool:
        return any(
            base == "UUPSUpgradeable" or (base not in seen and uups(base, seen | {name}))
            for base in bases.get(name, [])
        )

    return {name for name in concrete if uups(name, frozenset())}


def diff(old: list[str], new: list[str]) -> str:
    return "\n".join([f"  - {line}" for line in old if line not in new] + [f"  + {line}" for line in new if line not in old])


def renames(old: list[str], new: list[str]) -> str:
    """Each renamed line beside the line it replaces: a rename keeps them in
    one order."""
    return "\n".join(f"  - {a}\n  + {b}" for a, b in zip(old, new) if a != b)


def check(layout: Layout, probe: StorageLayout, update: bool, why: str | None = None) -> bool:
    return settle(layout, recorded(layout), current(layout, probe), update, why)


def settle(layout: Layout, old: list[str] | None, new: list[str], update: bool, why: str | None) -> bool:
    """Compare and, when allowed, record. `why` resets the snapshot for a redeploy."""
    snapshot = shown(layout.snapshot)
    if why is not None:
        write(layout, new, [RESET + why])
        print(f"reset {snapshot} for a redeploy")
        return True

    verdict = "append" if old is None else classify(old, new, snapshot)

    if verdict == "incompatible":
        print(f"INCOMPATIBLE: {layout.name}'s storage layout was reordered, removed or retyped.", file=sys.stderr)
        print(diff(old or [], new), file=sys.stderr)
        print("Undo the change; fields may only be appended at the end of the struct.", file=sys.stderr)
        print(f"Only for a fresh deployment, never a live proxy: --redeploy {layout.name} --why ...", file=sys.stderr)
        return False

    if verdict in ("append", "rename"):
        if update:
            write(layout, new, stamp(layout))
            print(f"recorded {snapshot}")
            return True
        if verdict == "append":
            print(f"{layout.name}'s storage layout has appended fields {snapshot} does not record:", file=sys.stderr)
            print(diff(old or [], new), file=sys.stderr)
        else:
            print(f"{layout.name}'s storage layout renames what {snapshot} records, in place:", file=sys.stderr)
            print(renames(old or [], new), file=sys.stderr)
        print("Record them with ./scripts/check-storage-layout.py --update and commit the snapshot.", file=sys.stderr)
        return False

    print(f"{layout.name} storage layout matches {snapshot}")
    return True


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--update", action="store_true", help="record an exact match, a pure append or a pure rename")
    parser.add_argument(
        "--redeploy",
        metavar="NAME",
        choices=[layout.name for layout in LAYOUTS],
        help="reset this snapshot to the current layout, for a contract that ships as a fresh deployment",
    )
    parser.add_argument("--why", help="with --redeploy: the reason, stamped into the snapshot")
    args = parser.parse_args()
    if (args.redeploy is None) != (args.why is None) or (args.why is not None and not args.why.strip()):
        parser.error("--redeploy and --why go together, and --why needs a reason")
    if args.why is not None and "\n" in args.why:
        parser.error("--why is one line")

    covered = {contract for layout in LAYOUTS for contract in layout.contracts}
    missing = sorted(upgradeable_contracts() - covered)
    if missing:
        print(f"UNCHECKED: {', '.join(missing)} can be upgraded but has no entry in LAYOUTS.", file=sys.stderr)
        return 1

    probe = inspect(PROBE)
    results = [check(layout, probe, args.update, args.why if layout.name == args.redeploy else None) for layout in LAYOUTS]
    return 0 if all(results) else 1


if __name__ == "__main__":
    sys.exit(main())
