#!/usr/bin/env bash
# Vendor the forge artifacts the Rust crate embeds.
#
# Runs `forge build` in solidity/ (submodules must be initialized), then copies
# the artifact JSONs the crate needs from solidity/out into
# rust/contracts/artifacts/<File>.sol/<Name>.json, pruned to the fields the
# crate reads: bytecode.object, methodIdentifiers and, for the *HonkVerifier
# artifacts only, deployedBytecode.object (the runtime code a deployed copy's
# code hash is checked against). No abi: the binding
# drift tests (rust/contracts/src/bindings/mod.rs) read it from solidity/out,
# so the published crate carries none. The circuits pin rides along as
# circuits.json, so the crate can say which libid-circuits release its
# verifiers came from.
#
# The result is NOT committed: rust/contracts/artifacts is gitignored and
# regenerated on demand. Run this before any cargo command in rust/ — the
# crate embeds the directory with include_dir!, so a missing one is a compile
# error. CI runs it in every job that touches the crate, publishing included.
#
# solc is pinned (0.8.33) and its builds are deterministic, so two runs of
# this script over the same contracts produce byte-identical output.
#
# Usage:
#   scripts/vendor-artifacts.sh           # regenerate rust/contracts/artifacts
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="$REPO_ROOT/solidity/out"
DEST="$REPO_ROOT/rust/contracts/artifacts"
CIRCUITS_PIN="$REPO_ROOT/solidity/contracts/circuits/circuits.json"

# "<File>:<Contract>" — the artifact lives at out/<File>.sol/<Contract>.json.
# Keep in sync with the covered-contract list in rust/contracts/src/artifacts.rs.
ARTIFACTS=(
    # ceremony
    "NotaryService:NotaryService"
    "CeremonyProofVerifier:CeremonyProofVerifier"
    "ERC1967Proxy:ERC1967Proxy"
    "GoogleJwtRoots:GoogleJwtRoots"
    # ceremony: the launch Platform Verifiers (one per profile)
    "XPlatformVerifier:XPlatformVerifier"
    "GitHubPlatformVerifier:GitHubPlatformVerifier"
    "GooglePlatformVerifier:GooglePlatformVerifier"
    # circuits: the UltraHonk verifiers the Platform Verifiers pin, vendored
    # from the libid-circuits release by scripts/vendor-circuit-verifiers.sh
    "BearerLinkXHonkVerifier:BearerLinkXHonkVerifier"
    "BearerLinkGithubHonkVerifier:BearerLinkGithubHonkVerifier"
    "OidcGoogleHonkVerifier:OidcGoogleHonkVerifier"
    # identity
    "IdentityRegistry:IdentityRegistry"
    # ens (deployed once per network, not CREATE3-canonical; embedded so a
    # consumer can deploy it without a checkout of this repository)
    "HandleResolver:HandleResolver"
    # escrow: value held against a handle nobody holds yet
    "HandleEscrow:HandleEscrow"
    # factory
    "LibidFactory:LibidFactory"
    "WTIA9:WTIA9"
)

if [[ $# -gt 0 ]]; then
    echo "unknown argument: $1" >&2
    exit 2
fi

command -v jq >/dev/null || { echo "jq is required" >&2; exit 1; }

# The Honk verifiers are vendored, not committed, and a build without them
# fails in the test that imports them; name the missing step instead.
while read -r contract; do
    [[ -f "$REPO_ROOT/solidity/contracts/circuits/$contract.sol" ]] ||
        { echo "no $contract.sol under solidity/contracts/circuits; run scripts/vendor-circuit-verifiers.sh first" >&2; exit 1; }
done < <(jq -r '.circuits[].contract' "$CIRCUITS_PIN")

echo "==> forge build"
(cd "$REPO_ROOT/solidity" && forge build)

STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT

for entry in "${ARTIFACTS[@]}"; do
    file="${entry%%:*}"
    contract="${entry##*:}"
    src="$OUT/$file.sol/$contract.json"
    if [[ ! -f "$src" ]]; then
        echo "missing artifact: $src (did forge build succeed?)" >&2
        exit 1
    fi
    mkdir -p "$STAGE/$file.sol"
    jq -S --arg contract "$contract" '{
        bytecode: { object: .bytecode.object },
        methodIdentifiers: .methodIdentifiers
    } + if ($contract | endswith("HonkVerifier"))
        then { deployedBytecode: { object: .deployedBytecode.object } } else {} end' \
        "$src" > "$STAGE/$file.sol/$contract.json"
done

cp "$CIRCUITS_PIN" "$STAGE/circuits.json"

rm -rf "$DEST"
mkdir -p "$(dirname "$DEST")"
cp -R "$STAGE" "$DEST"
echo "==> vendored $(find "$DEST" -name '*.json' | wc -l | tr -d ' ') artifacts into rust/contracts/artifacts"
