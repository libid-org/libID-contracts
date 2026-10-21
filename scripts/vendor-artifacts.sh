#!/usr/bin/env bash
# Vendor the forge artifacts the Rust crate embeds.
#
# Runs `forge build` in solidity/ (submodules must be initialized), then copies
# what the crate needs from solidity/out:
#
#   rust/contracts/artifacts/<File>.sol/<Name>.json  the deployable contracts,
#       pruned to bytecode.object and, for the *HonkVerifier artifacts,
#       deployedBytecode.object, the runtime code a deployed copy's code hash
#       is checked against. The circuits pin is copied as circuits.json,
#       naming the libid-circuits release the verifiers came from.
#   rust/contracts/abi/<Name>.json  the ABI of every contract the crate binds,
#       which `alloy::sol!` reads at compile time.
#   rust/contracts/artifacts-testing/<File>.sol/<Name>.json  test stand-ins,
#       pruned like the deployable contracts. Only the crate's `testing`
#       feature embeds them.
#
# All three directories are gitignored. Run this before any cargo command in rust/:
# the crate embeds them, so a missing one is a compile error.
#
# solc is pinned in solidity/foundry.toml and builds deterministically, so two
# runs over the same contracts produce byte-identical output.
#
# Usage:
#   scripts/vendor-artifacts.sh
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="$REPO_ROOT/solidity/out"
DEST="$REPO_ROOT/rust/contracts/artifacts"
ABI_DEST="$REPO_ROOT/rust/contracts/abi"
TESTING_DEST="$REPO_ROOT/rust/contracts/artifacts-testing"
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
    "BearerLinkHonkVerifier:BearerLinkHonkVerifier"
    "OidcGoogleHonkVerifier:OidcGoogleHonkVerifier"
    # identity
    "IdentityRegistry:IdentityRegistry"
    # ens: deployed once per network, outside the CREATE3 canonical set
    "HandleResolver:HandleResolver"
    # escrow
    "HandleEscrow:HandleEscrow"
    # factory
    "LibidFactory:LibidFactory"
    "WTIA9:WTIA9"
)

# "<File>:<Contract>" for the test stand-ins.
# Keep in sync with TESTING_COVERED in rust/contracts/src/artifacts.rs.
TESTING_ARTIFACTS=(
    # identity: stands in for a Platform Verifier's proof check
    "StubPlatformVerifier:StubPlatformVerifier"
)

# "<File>:<Contract>" for every ABI the bindings in rust/contracts/src/bindings
# read, written to abi/<Contract>.json.
ABIS=(
    "NotaryService:NotaryService"
    "CeremonyProofVerifier:CeremonyProofVerifier"
    "GoogleJwtRoots:GoogleJwtRoots"
    "IPlatformVerifier:IPlatformVerifier"
    "PlatformVerifierBase:PlatformVerifierBase"
    "XPlatformVerifier:XPlatformVerifier"
    "GitHubPlatformVerifier:GitHubPlatformVerifier"
    "GooglePlatformVerifier:GooglePlatformVerifier"
    "ICeremonyPayloads:ICeremonyPayloads"
    # bb's verifiers share the IVerifier interface the vendor script requires.
    "BearerLinkHonkVerifier:IVerifier"
    "IHonkVerifierErrors:IHonkVerifierErrors"
    "IdentityRegistry:IdentityRegistry"
    "HandleResolver:HandleResolver"
    "HandleEscrow:HandleEscrow"
    "LibidFactory:LibidFactory"
    "ERC1967Proxy:ERC1967Proxy"
    "UUPSUpgradeable:UUPSUpgradeable"
    "StubPlatformVerifier:StubPlatformVerifier"
)

if [[ $# -gt 0 ]]; then
    echo "unknown argument: $1" >&2
    exit 2
fi

command -v jq >/dev/null || { echo "jq is required" >&2; exit 1; }

# The Honk verifiers are vendored, not committed. Name the missing step before
# forge build fails on the test that imports them.
while read -r contract; do
    [[ -f "$REPO_ROOT/solidity/contracts/circuits/$contract.sol" ]] ||
        { echo "no $contract.sol under solidity/contracts/circuits; run scripts/vendor-circuit-verifiers.sh first" >&2; exit 1; }
done < <(jq -r '.circuits[].contract' "$CIRCUITS_PIN")

echo "==> forge build"
(cd "$REPO_ROOT/solidity" && forge build)

STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT

# Prune each "<File>:<Contract>" in the arguments after the first into the
# directory named first.
prune() {
    local stage="$1" entry file contract src
    shift
    for entry in "$@"; do
        file="${entry%%:*}"
        contract="${entry##*:}"
        src="$OUT/$file.sol/$contract.json"
        if [[ ! -f "$src" ]]; then
            echo "missing artifact: $src (did forge build succeed?)" >&2
            exit 1
        fi
        mkdir -p "$stage/$file.sol"
        jq -S --arg contract "$contract" '{
            bytecode: { object: .bytecode.object }
        } + if ($contract | endswith("HonkVerifier"))
            then { deployedBytecode: { object: .deployedBytecode.object } } else {} end' \
            "$src" > "$stage/$file.sol/$contract.json"
    done
}

prune "$STAGE" "${ARTIFACTS[@]}"

cp "$CIRCUITS_PIN" "$STAGE/circuits.json"

TESTING_STAGE="$(mktemp -d)"
ABI_STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE" "$TESTING_STAGE" "$ABI_STAGE"' EXIT
prune "$TESTING_STAGE" "${TESTING_ARTIFACTS[@]}"

for entry in "${ABIS[@]}"; do
    file="${entry%%:*}"
    contract="${entry##*:}"
    src="$OUT/$file.sol/$contract.json"
    [[ -f "$src" ]] || { echo "missing artifact: $src (did forge build succeed?)" >&2; exit 1; }
    jq '.abi' "$src" > "$ABI_STAGE/$contract.json"
done

rm -rf "$DEST" "$TESTING_DEST" "$ABI_DEST"
mkdir -p "$(dirname "$DEST")"
cp -R "$STAGE" "$DEST"
cp -R "$TESTING_STAGE" "$TESTING_DEST"
cp -R "$ABI_STAGE" "$ABI_DEST"
echo "==> vendored $(find "$DEST" -name '*.json' | wc -l | tr -d ' ') artifacts into rust/contracts/artifacts"
echo "==> vendored ${#TESTING_ARTIFACTS[@]} test artifacts into rust/contracts/artifacts-testing"
echo "==> vendored ${#ABIS[@]} ABIs into rust/contracts/abi"
