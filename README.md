# libID-contracts

Smart contracts for libID, laid out per chain. `solidity/` is a self-contained
Foundry project holding the EVM contracts: the ceremony verification path
(Notary Service, Proof Verifier, Platform Verifiers, and the Google JWT root
list the Google verifier reads), the identity registry, and the
deterministic deployment factory. `rust/` and `ts/` hold the ABI wrapper packages; room is reserved
for `solana/` and other networks.

## Layout

```
solidity/            # Foundry project root
  contracts/
    ceremony/        # NotaryService, CeremonyProofVerifier, Platform Verifiers,
                     # GoogleJwtRoots
    circuits/        # the UltraHonk verifiers the Platform Verifiers pin:
                     # circuits.json pins a libid-circuits release, the
                     # Solidity is vendored from it and not committed
    identity/        # IdentityRegistry, handle normalization
    factory/         # LibidFactory: deterministic CREATE3 deployment
    WTIA9.sol        # wrapped TIA
  script/Deploy.s.sol
  lib/               # git submodules (openzeppelin, forge-std)
rust/contracts/      # libid-contracts crate: alloy bindings + embedded artifacts
ts/packages/contracts/  # @libid/contracts: viem ABIs, call builders, identity helpers
scripts/
  vendor-artifacts.sh
  vendor-circuit-verifiers.sh
  regen-identity-handles.py
```

## Build and test

```sh
git submodule update --init --recursive
scripts/vendor-circuit-verifiers.sh   # -> solidity/contracts/circuits/*HonkVerifier.sol
cd solidity
forge build
forge test
```

Nothing generated is committed. The Honk verifiers are downloaded from the
pinned [libID-circuits](https://github.com/libid-org/libID-circuits) release
(see [Circuit verifiers](#circuit-verifiers)), so a fresh clone vendors them
before its first `forge build`, which needs curl, jq, tar and forge. `forge
build` is in turn the input to the two generated trees. Generate them once
after cloning, and again after any change to a contract they cover:

```sh
scripts/vendor-artifacts.sh   # -> rust/contracts/artifacts (the crate embeds
                              #    this with include_dir!, so cargo commands
                              #    fail at macro expansion without it)
pnpm -C ts codegen            # -> ts/packages/contracts/src/abis (tsc reads
                              #    these, so `pnpm -C ts build` needs them)
```

CI runs all three before every build, test, dry-run and publish: the
forge-build action vendors the verifiers before it builds, and every job that
compiles the crate or the package regenerates its tree — the published crate
and npm package carry the generated output even though git does not.

## Handle vectors

`solidity/contracts/handles/handles.json` is the source of truth for platform
handle rules and the shared normalization vector table. After editing it:

```sh
python3 scripts/regen-identity-handles.py          # rewrite generated outputs
python3 scripts/regen-identity-handles.py --check  # verify nothing drifted
```

This generates `solidity/contracts/handles/HandleVectors.sol`,
`rust/identity/src/handle_vectors.rs` and
`ts/packages/contracts/src/identity/handleVectors.ts`; CI's handle-tables job
fails when any of them drifts from `handles.json`.

## Circuit verifiers

The ceremony circuits' UltraHonk verifiers are not written here. `bb` derives
each from its circuit's verification key, and
[libID-circuits](https://github.com/libid-org/libID-circuits) runs `bb` and
ships the Solidity in its release tarballs. `scripts/vendor-circuit-verifiers.sh`
downloads it into `solidity/contracts/circuits/`, formatted, where `forge
build` compiles it and the crate embeds it, so no consumer runs `bb`. The
files are gitignored: they are another repository's release asset, and the
pin says which bytes they must be. `solidity/foundry.toml` compiles them on
the legacy pipeline and everything else via IR: solc cannot compile bb's
optimized verifier via IR.

`solidity/contracts/circuits/circuits.json` is the pin — the release version
and each tarball's sha256, committed here and checked against every download.
To move it, download the new release's tarballs, take their digests with
`shasum -a 256`, write the version and the digests into `circuits.json`, then:

```sh
scripts/vendor-circuit-verifiers.sh   # rewrite the verifiers from the pin
```

CI's forge-build action runs the same script before every build, test,
dry-run and publish, refusing any tarball whose digest is not the pin's; a
release cannot ship a verifier that is not what the pinned circuits release
shipped.

## Deploying hashed identities

The registry keys identities by the nodes the circuits output, and each
Platform Verifier decodes a payload that carries those nodes. Neither reads
what an earlier deployment stored or accepts what an earlier client sent, so
this stack ships only as a new deployment under new canonical names. Never
upgrade a live proxy onto it:

- `IdentityRegistry` keeps the storage namespace `libid.storage.IdentityRegistry`,
  and its slots hold nodes. A proxy upgraded from a registry that held other
  keys would read every stored entry as a node it never was, and answer.
- The `x`, `github` and `google` ceremonies stay at ceremony version 1. Their
  payload shapes are this release's, so a client built against an earlier
  deployment is refused at decode.
- `HandleEscrow` is redeployed against the new registry, never upgraded or
  re-pointed: its deposits are keyed by handle node, and a node means nothing
  to the registry before it. `initialize` probes `resolveId(bytes32)`, which
  only the new registry has, and reverts `RegistryLacks` against the old one.

## Releasing

The Rust crate ([`libid-contracts`](https://crates.io/crates/libid-contracts))
and the npm package
([`@libid/contracts`](https://www.npmjs.com/package/@libid/contracts)) release
together under a single version number. A release is cut by publishing a
GitHub Release tagged `v<version>`; nothing publishes from pushes or PRs.

```sh
./scripts/bump-version.sh 0.2.0        # sets Cargo.toml, Cargo.lock, package.json
git checkout -b release/v0.2.0
git commit -sam "chore: release v0.2.0"
# open a PR, get it merged, then:
gh release create v0.2.0 --title "v0.2.0" --generate-notes
```

Publishing the release triggers CI's release jobs:

1. `verify-tag` — the tag must equal the version in both manifests (the tag
   is a pointer, never a source; the `versions` job also enforces crate/npm
   equality on every PR).
2. `publish-crates` — after the Solidity, Rust and publish dry-run jobs pass,
   `cargo publish` with `CARGO_REGISTRY_TOKEN`. If the version is already on
   crates.io (a re-run after a partial release), it skips with a notice.
3. `publish-npm` — after `publish-crates`, builds and publishes
   `@libid/contracts` via npm OIDC trusted publishing (no token secret), with
   provenance. A prerelease publishes under its first prerelease identifier
   as the dist-tag (`1.2.0-rc.1` → `rc`); a plain version under `latest`.

## License

Dual-licensed under MIT and Apache-2.0; see `LICENSE-MIT`, `LICENSE-APACHE`
and `CONTRIBUTING.md`.
