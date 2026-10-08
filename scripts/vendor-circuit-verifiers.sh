#!/usr/bin/env bash
# Vendor the ceremony circuits' UltraHonk verifiers from the pinned
# libid-circuits release.
#
# A Honk verifier is not written here: bb derives it from a circuit's
# verification key, and libid-circuits runs bb and ships the result in each
# circuit's release tarball beside the vk. This script downloads those
# tarballs, checks them, formats the Solidity under solidity/foundry.toml and
# writes it to solidity/contracts/circuits/<Contract>.sol:
#
#   bearer-link-x       ->  BearerLinkXHonkVerifier.sol       (the x profile)
#   bearer-link-github  ->  BearerLinkGithubHonkVerifier.sol  (the github profile)
#   oidc-google  ->  OidcGoogleHonkVerifier.sol   (the google profile)
#
# THE PIN is solidity/contracts/circuits/circuits.json: the release version
# and, per circuit, the contract name and the tarball's sha256. The digests
# are committed literals, so a download is checked against what this
# repository says, never against a manifest that came down with it. The
# release's manifest.json is fetched too, but only to be held to the pin —
# it must name the same version and the same tarball digests — and then to
# check every file inside a tarball the pin has already vouched for.
#
# What ships is bb's optimized zero-knowledge verifier plus the one rewrite
# libid-circuits makes, the rename off bb's fixed `HonkVerifier`; `forge fmt`
# is the consumer's. So the written file is fmt(shipped) plus the banner
# below. solidity/foundry.toml compiles it on the legacy pipeline: solc
# cannot compile it via IR.
#
# The sources are NOT committed: they are gitignored like the forge
# artifacts and the npm ABIs, because they are another repository's release
# asset and the pin already says which bytes they must be. CI's forge-build
# action runs this script before every `forge build` — tests, dry-runs and
# publishes included — and a clone runs it once before its first build. So
# every build starts from a download the pin has just checked, and there is
# no committed copy for a hand edit or a stale vendor to live in.
#
# Moving the pin: download the new release's tarballs, read their sha256
# with `shasum -a 256` (compare against the release page, not against a
# manifest fetched by a script), write the version and the digests into
# circuits.json, run this script, commit circuits.json.
#
# Usage:
#   scripts/vendor-circuit-verifiers.sh                    # write the verifiers from the pin
#   scripts/vendor-circuit-verifiers.sh --local <artifacts>
#
# --local takes the verifiers from a libid-circuits `scripts/build.sh --out
# <artifacts>` instead of a release. Nothing vouches for those bytes but the
# build you ran, so it is for developing against an unreleased circuit, never
# for a deploy; the written files say so.
#
# Either way, each circuit ships the Noir table its rules and tags were
# compiled from (`handles-table.nr`), and it must be the table this
# repository's contracts/handles/handles.json generates: a circuit built from
# another table keys handles differently from the registry that stores them.
# The comparison is the generator's (`--compare-noir`), so a hand edit of the
# shipped table is caught, not only a stale label.
#
# Requires curl, jq, tar, forge, python3 and shasum or sha256sum.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SOLIDITY="$REPO_ROOT/solidity"
DEST_REL="contracts/circuits"
DEST="$SOLIDITY/$DEST_REL"
PIN="$DEST/circuits.json"
RELEASES="https://github.com/libid-org/libID-circuits/releases/download"

LOCAL=""
if [[ "${1:-}" == "--local" ]]; then
    LOCAL="${2:?--local needs an artifacts directory}"
    shift 2
fi
if [[ $# -gt 0 ]]; then
    echo "unknown argument: $1" >&2
    exit 2
fi

for tool in curl jq tar forge; do
    command -v "$tool" >/dev/null || { echo "$tool is required" >&2; exit 1; }
done
sha256() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | cut -d' ' -f1
    else
        shasum -a 256 "$1" | cut -d' ' -f1
    fi
}

[[ -f "$PIN" ]] || { echo "no pin at $PIN" >&2; exit 1; }

# The circuit in `$1` was compiled from this repository's handle table.
require_table() {
    local dir="$1" circuit="$2"
    [[ -f "$dir/handles-table.nr" ]] ||
        { echo "$circuit: no handles-table.nr; it predates the shipped handle table, or the build is not libid-circuits'" >&2; exit 1; }
    python3 "$REPO_ROOT/scripts/regen-identity-handles.py" --compare-noir "$dir/handles-table.nr" >/dev/null || {
        echo "$circuit was built from another handle table than contracts/handles/handles.json" >&2
        echo "  regenerate: scripts/regen-identity-handles.py --noir-out <libid-circuits>/lib/identity/src/table.nr, then rebuild" >&2
        exit 1
    }
}

# The interchange-format checks and the formatting, shared by both modes.
write_verifier() {
    local src="$1" contract="$2" banner="$3" contracts
    [[ -f "$src" ]] || { echo "no $contract.sol at $src" >&2; exit 1; }
    contracts="$(grep -c '^contract ' "$src" || true)"
    [[ "$contracts" == 1 ]] ||
        { echo "$contract.sol: expected one contract, found $contracts" >&2; exit 1; }
    grep -q "^contract $contract is IVerifier" "$src" ||
        { echo "$contract.sol: its contract is not '$contract is IVerifier'" >&2; exit 1; }
    if grep -q '^library ' "$src"; then
        echo "$contract.sol: declares a library; the crate deploys verifiers unlinked" >&2
        exit 1
    fi
    awk -v banner="$banner" '
        !done && /^pragma / { print banner; done = 1 }
        { print }
    ' "$src" | (cd "$SOLIDITY" && forge fmt --raw - | forge fmt --raw -) > "$STAGE/$contract.sol"
}

if [[ -n "$LOCAL" ]]; then
    LOCAL="$(cd "$LOCAL" && pwd)"
    STAGE="$(mktemp -d)"
    trap 'rm -rf "$STAGE"' EXIT
    while IFS=$'\t' read -r circuit contract; do
        require_table "$LOCAL/$circuit" "$circuit"
        write_verifier "$LOCAL/$circuit/$contract.sol" "$contract" \
            "// UNRELEASED: from a local libid-circuits build ($LOCAL/$circuit) by scripts/vendor-circuit-verifiers.sh --local.\n// Not pinned by circuits.json. Develop against it; never deploy it."
        echo "==> $circuit -> $DEST_REL/$contract.sol (local, unpinned)"
    done < <(jq -r '.circuits | to_entries[] | "\(.key)\t\(.value.contract)"' "$PIN")
    cp "$STAGE"/*.sol "$DEST/"
    exit 0
fi

unreleased="$(jq -r '[.circuits | to_entries[] | select(.value.sha256 == null) | .key] | join(" ")' "$PIN")"
[[ -z "$unreleased" ]] || {
    echo "circuits.json pins no release for: $unreleased" >&2
    echo "  build libid-circuits and run: scripts/vendor-circuit-verifiers.sh --local <artifacts>" >&2
    exit 1
}
VERSION="$(jq -r '.version' "$PIN")"
[[ -n "$VERSION" && "$VERSION" != "null" ]] || { echo "no version in $PIN" >&2; exit 1; }
TAG="v$VERSION"
echo "==> libid-circuits $TAG"

WORK="$(mktemp -d)"
STAGE="$(mktemp -d)"
trap 'rm -rf "$WORK" "$STAGE"' EXIT

# The release's own manifest: held to the pin, then used for the per-file
# check inside each tarball.
curl -fsSL -o "$WORK/manifest.json" "$RELEASES/$TAG/manifest.json"
released="$(jq -r '.version' "$WORK/manifest.json")"
[[ "$released" == "$VERSION" ]] ||
    { echo "the $TAG manifest declares version '$released', the pin says $VERSION" >&2; exit 1; }

while IFS=$'\t' read -r circuit contract want; do
    tarball="libid-circuits-$VERSION-$circuit.tar.gz"
    curl -fsSL -o "$WORK/$tarball" "$RELEASES/$TAG/$tarball"

    # The integrity check: the committed digest, nothing downloaded.
    got="$(sha256 "$WORK/$tarball")"
    [[ "$got" == "$want" ]] ||
        { echo "$tarball: sha256 $got, the pin says $want" >&2; exit 1; }
    declared="$(jq -r --arg t "$tarball" '.tarballs[$t].sha256' "$WORK/manifest.json")"
    [[ "$declared" == "$want" ]] ||
        { echo "$tarball: the $TAG manifest declares sha256 '$declared', the pin says $want" >&2; exit 1; }

    mkdir -p "$WORK/$circuit"
    tar xzf "$WORK/$tarball" -C "$WORK/$circuit"
    # Every file the manifest lists is in the tarball at the digest it
    # names; the tarball is trusted, so this catches a release that was
    # assembled wrong, not an attacker.
    while IFS=$'\t' read -r name file_want; do
        [[ -f "$WORK/$circuit/$name" ]] ||
            { echo "$tarball: the manifest lists $name, the tarball lacks it" >&2; exit 1; }
        file_got="$(sha256 "$WORK/$circuit/$name")"
        [[ "$file_got" == "$file_want" ]] ||
            { echo "$tarball: $name sha256 $file_got, the manifest says $file_want" >&2; exit 1; }
    done < <(jq -r --arg t "$tarball" '.tarballs[$t].files | to_entries[] | "\(.key)\t\(.value)"' "$WORK/manifest.json")

    require_table "$WORK/$circuit" "$circuit"
    write_verifier "$WORK/$circuit/$contract.sol" "$contract" \
        "// Vendored from libid-circuits $TAG ($tarball) by scripts/vendor-circuit-verifiers.sh. Do not edit.\n// The pin is $DEST_REL/circuits.json; \`forge fmt\` is the only change to what shipped."
    echo "==> $circuit -> $DEST_REL/$contract.sol"
done < <(jq -r '.circuits | to_entries[] | "\(.key)\t\(.value.contract)\t\(.value.sha256)"' "$PIN")

cp "$STAGE"/*.sol "$DEST/"
