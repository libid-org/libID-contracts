#!/usr/bin/env bash
# Vendor the forge artifacts the Rust crate embeds.
#
# Runs `forge build` in solidity/ (submodules must be initialized), then copies
# the artifact JSONs the crate needs from solidity/out into
# rust/contracts/artifacts/<File>.sol/<Name>.json, pruned to the fields the
# crate reads: bytecode.object, bytecode.linkReferences, methodIdentifiers.
# Libraries referenced through linkReferences are followed transitively and
# vendored too: the two Honk verifiers link RelationsLib and ZKTranscriptLib,
# and both are listed below as well so the list and the crate's COVERED agree
# line for line. The circuits pin rides along as circuits.json, so the crate
# can say which libid-circuits release its verifiers came from.
#
# The result is NOT committed: rust/contracts/artifacts is gitignored and
# regenerated on demand. Run this before any cargo command in rust/ — the
# crate embeds the directory with include_dir!, so a missing one is a compile
# error. CI runs it in every job that touches the crate, publishing included.
#
# solc is pinned (0.8.33) and via_ir builds are deterministic, so two runs of
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
    # from the libid-circuits release by scripts/vendor-circuit-verifiers.sh,
    # each with the two libraries it links (bb emits them as external
    # libraries, so they are deployed contracts the verifier is linked to)
    "BearerLinkHonkVerifier:BearerLinkHonkVerifier"
    "BearerLinkHonkVerifier:RelationsLib"
    "BearerLinkHonkVerifier:ZKTranscriptLib"
    "OidcGoogleHonkVerifier:OidcGoogleHonkVerifier"
    "OidcGoogleHonkVerifier:RelationsLib"
    "OidcGoogleHonkVerifier:ZKTranscriptLib"
    # identity
    "IdentityNames:IdentityNames"
    # ens (deployed once per network, not CREATE3-canonical; embedded so a
    # consumer can deploy it without a checkout of this repository)
    "HandleResolver:HandleResolver"
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

# prune <src> <file> <contract>: write the pruned artifact into the stage.
prune() {
    local src="$1" file="$2" contract="$3"
    mkdir -p "$STAGE/$file.sol"
    jq -S '{
        bytecode: {
            object: .bytecode.object,
            linkReferences: .bytecode.linkReferences
        },
        methodIdentifiers: .methodIdentifiers
    }' "$src" > "$STAGE/$file.sol/$contract.json"
}

# Vendor the listed artifacts, then follow linkReferences transitively so every
# library the crate's linker needs ships too.
queue=("${ARTIFACTS[@]}")
seen=""
while [[ ${#queue[@]} -gt 0 ]]; do
    entry="${queue[0]}"
    queue=("${queue[@]:1}")
    case " $seen " in *" $entry "*) continue ;; esac
    seen="$seen $entry"

    file="${entry%%:*}"
    contract="${entry##*:}"
    src="$OUT/$file.sol/$contract.json"
    if [[ ! -f "$src" ]]; then
        echo "missing artifact: $src (did forge build succeed?)" >&2
        exit 1
    fi
    prune "$src" "$file" "$contract"

    # linkReferences: { "path/to/LibFile.sol": { "LibName": [...] } } — the
    # library artifact lives at out/<LibFile>.sol/<LibName>.json.
    while IFS=: read -r lib_path lib_name; do
        [[ -n "$lib_path" ]] || continue
        lib_file="$(basename "$lib_path" .sol)"
        queue+=("$lib_file:$lib_name")
    done < <(jq -r '.bytecode.linkReferences // {}
                    | to_entries[]
                    | .key as $p
                    | .value | keys[]
                    | "\($p):\(.)"' "$src")
done

cp "$CIRCUITS_PIN" "$STAGE/circuits.json"

rm -rf "$DEST"
mkdir -p "$(dirname "$DEST")"
cp -R "$STAGE" "$DEST"
echo "==> vendored $(find "$DEST" -name '*.json' | wc -l | tr -d ' ') artifacts into rust/contracts/artifacts"
