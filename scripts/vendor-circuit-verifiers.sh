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
#   bearer-link  ->  BearerLinkHonkVerifier.sol   (the x and github profiles)
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
# What ships is bb's output plus exactly two rewrites libid-circuits makes
# (`assembly ("memory-safe")` on every assembly block, for via_ir, and the
# rename off bb's fixed `HonkVerifier`); `forge fmt` is deliberately left to
# the consumer, because libid-circuits carries no Foundry toolchain. So the
# written file is fmt(shipped) plus the banner below.
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
#   scripts/vendor-circuit-verifiers.sh   # write the verifiers from the pin
#
# Requires curl, jq, tar, forge and shasum or sha256sum.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SOLIDITY="$REPO_ROOT/solidity"
DEST_REL="contracts/circuits"
DEST="$SOLIDITY/$DEST_REL"
PIN="$DEST/circuits.json"
RELEASES="https://github.com/libid-org/libID-circuits/releases/download"

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

    src="$WORK/$circuit/$contract.sol"
    [[ -f "$src" ]] || { echo "$tarball: no $contract.sol inside" >&2; exit 1; }
    # The interchange format, as libid-circuits' scripts/gen-verifier.sh
    # promises it: one concrete contract under the pinned name, every
    # assembly block annotated. A file that breaks either would compile to
    # something the crate looks up under the wrong name, or not at all.
    concrete="$(grep -c '^contract .* is BaseZKHonkVerifier' "$src" || true)"
    [[ "$concrete" == 1 ]] && grep -q "^contract $contract is BaseZKHonkVerifier" "$src" ||
        { echo "$contract.sol: expected exactly one 'contract $contract is BaseZKHonkVerifier', found $concrete" >&2; exit 1; }
    if grep -qE 'assembly[[:space:]]*\{' "$src"; then
        echo "$contract.sol: an assembly block is not annotated memory-safe" >&2
        exit 1
    fi

    # The banner goes after bb's license header, before the first pragma.
    # Then forge fmt under this project's foundry.toml, which is the one
    # step libid-circuits leaves to the consumer.
    awk -v banner="// Vendored from libid-circuits $TAG ($tarball) by scripts/vendor-circuit-verifiers.sh. Do not edit.\n// The pin is $DEST_REL/circuits.json; \`forge fmt\` is the only change to what shipped." '
        !done && /^pragma / { print banner; done = 1 }
        { print }
    ' "$src" | (cd "$SOLIDITY" && forge fmt --raw -) > "$STAGE/$contract.sol"
    echo "==> $circuit -> $DEST_REL/$contract.sol"
done < <(jq -r '.circuits | to_entries[] | "\(.key)\t\(.value.contract)\t\(.value.sha256)"' "$PIN")

cp "$STAGE"/*.sol "$DEST/"
