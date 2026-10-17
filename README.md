# libID-contracts

Smart contracts for libID, laid out per chain. `solidity/` is a self-contained
Foundry project holding the EVM contracts: the ceremony verification path
(Notary Service, Proof Verifier, Platform Verifiers, and the Google JWT root
list the Google verifier reads), the identity registry, the handle escrow, the
ENS resolver and the deterministic deployment factory. `rust/` and `ts/` hold
the bindings and the off-chain identity helpers.

## Layout

```
solidity/            # Foundry project root
  contracts/
    ceremony/        # NotaryService, CeremonyProofVerifier, Platform Verifiers,
                     # GoogleJwtRoots, CeremonyProfile
    circuits/        # the UltraHonk verifiers the Platform Verifiers pin:
                     # circuits.json pins a libid-circuits release; the
                     # Solidity and the platform table (platforms.json,
                     # handles.json) are vendored from it and not committed
    handles/         # HandleNode: the A-Z fold and the node hash
    identity/        # IdentityRegistry
    escrow/          # HandleEscrow: value sent to a handle before it is proved
    ens/             # HandleResolver
    factory/         # LibidFactory: deterministic CREATE3 deployment
    WTIA9.sol        # wrapped TIA
  script/Deploy.s.sol
  lib/               # git submodules (openzeppelin, forge-std)
rust/contracts/      # libid-contracts: alloy bindings + embedded artifacts
rust/identity/       # libid-identity: handle normalization, id rules, nodes
rust/profiles/       # libid-profiles: the ceremony profile constants
ts/packages/contracts/  # @libid/contracts: viem ABIs, call builders, identity helpers
scripts/             # vendoring, generators, release and CI helpers
```

## Build and test

```sh
git submodule update --init --recursive
scripts/vendor-circuit-verifiers.sh   # -> solidity/contracts/circuits/*HonkVerifier.sol
cd solidity
forge build
forge test
```

The Honk verifiers and the platform table are gitignored and downloaded from
the pinned [libID-circuits](https://github.com/libid-org/libID-circuits)
release (see [Circuit verifiers](#circuit-verifiers)). The vendor script needs
curl, jq, tar, forge, cast, cmp and shasum or sha256sum. Two more gitignored trees are generated from
`forge build`; regenerate them after any change to a contract they cover:

```sh
scripts/vendor-artifacts.sh   # -> rust/contracts/artifacts (the crate embeds
                              #    it with include_dir!; cargo fails without it)
pnpm -C ts codegen            # -> ts/packages/contracts/src/{abis,calls}
                              #    (`pnpm -C ts build` needs them)
```

CI's forge-build action vendors the verifiers before every build, and every
job that compiles the crate or the package regenerates its tree, so the
published crate and npm package carry the generated output.

## Handle vectors

libID-circuits' `lib/identity/platforms.json` holds each platform's node tags,
the circuits' buffers and its id shape; its `lib/identity/handles.json` holds
the shared vector table. `scripts/vendor-circuit-verifiers.sh` vendors both
into `solidity/contracts/circuits/`. After the pin moves:

```sh
python3 scripts/regen-identity-handles.py          # rewrite generated outputs
python3 scripts/regen-identity-handles.py --check  # verify nothing drifted
python3 scripts/regen-ceremony-profiles.py         # the ceremony profile constants
```

`regen-identity-handles.py` writes the platform tables and refusals
(`rust/identity/src/platforms.rs`, `ts/packages/contracts/src/platforms/platforms.ts`)
and the vector tables beside them (`vectors.rs`, `vectors.ts`).
`regen-ceremony-profiles.py` writes `CeremonyProfile.sol` and its Rust and
TypeScript mirrors from `profiles.json`, taking the node tags from
`platforms.json`. Both outputs are committed, and CI's Generated tables job
fails when either drifts. On chain a handle is only folded, by `HandleNode`,
and forge runs the vectors from the vendored `handles.json`.

## Circuit verifiers

`bb` derives each ceremony circuit's UltraHonk verifier from its verification
key. [libID-circuits](https://github.com/libid-org/libID-circuits) runs `bb`
and ships the Solidity, with the platform table, in its release tarballs.
`scripts/vendor-circuit-verifiers.sh` downloads them into
`solidity/contracts/circuits/`, formatted, where `forge build` compiles them
and the crate embeds them, so no consumer runs `bb`.

`solidity/contracts/circuits/circuits.json` is the pin: the release version
and each tarball's sha256, checked against every download. To move it, write
the new release's version and tarball digests into `circuits.json`, then:

```sh
scripts/vendor-circuit-verifiers.sh   # rewrite the verifiers from the pin
```

A change spanning both repositories lands circuits first: libID-circuits tags
a release, then `circuits.json` pins it here and the tables are regenerated.

Each Platform Verifier pins its circuit's verifier on chain by runtime code
hash: `initialize`, `setTrustRoots` and `verify` revert `WrongCircuit` for any
other code. The hashes are constants in
`solidity/contracts/circuits/CircuitCodehashes.sol`, which the vendor script
writes and which is committed. `forge test` compares it with the verifiers on
disk; the forge-build action's `git diff --exit-code` after vendoring guards
the committed file. Locally:

```sh
scripts/vendor-circuit-verifiers.sh
git diff --exit-code solidity/contracts/circuits/CircuitCodehashes.sol \
  solidity/contracts/circuits/IHonkVerifierErrors.sol
```

Commit both generated files with `circuits.json` whenever the pin moves. A new circuit release
is a new Platform Verifier implementation, not a trust-root rotation.

## Deploying hashed identities

The registry keys identities by the nodes the circuits output, and each
Platform Verifier decodes a payload that carries those nodes. This stack ships
only as a fresh deployment under new canonical names; never upgrade a live
proxy onto it:

- `IdentityRegistry` uses the storage namespace `libid.storage.IdentityRegistry`
  and its slots hold nodes: a proxy upgraded from a registry keyed otherwise
  would read stored entries as nodes.
- The `x`, `github` and `google` ceremonies are at ceremony version 1 with
  node-carrying payloads, so a client built for another payload shape is
  refused at decode.
- `HandleEscrow` is deployed against this registry, never upgraded or
  re-pointed: its deposits are keyed by handle node, and `initialize` reverts
  unless the registry's `nodeKeyed()` returns true.

## Releasing

The Rust crates ([`libid-contracts`](https://crates.io/crates/libid-contracts),
`libid-identity`, `libid-profiles`) and the npm package
([`@libid/contracts`](https://www.npmjs.com/package/@libid/contracts)) release
together under one version. A release is cut by publishing a GitHub Release
tagged `v<version>`; nothing publishes from pushes or PRs.

```sh
./scripts/bump-version.sh 0.2.0        # sets the Cargo.toml files, Cargo.lock, package.json
git checkout -b release/v0.2.0
git commit -sam "chore: release v0.2.0"
# open a PR, get it merged, then:
gh release create v0.2.0 --title "v0.2.0" --generate-notes
```

Publishing the release triggers CI's release jobs:

1. `verify-tag`: the tag must equal the version in every manifest. The
   `versions` job checks the manifests agree on every PR.
2. `publish-crates`: after the Solidity, Rust, Generated tables and publish
   dry-run jobs pass, `cargo publish` of `libid-identity`, `libid-profiles`
   and `libid-contracts` with `CARGO_REGISTRY_TOKEN`. A crate already on
   crates.io at this version is skipped, so a re-run finishes a partial
   release.
3. `publish-npm`: after `publish-crates`, builds and publishes
   `@libid/contracts` with provenance, authenticated by `NPM_TOKEN` when set,
   else by npm OIDC trusted publishing. A prerelease publishes under its first
   prerelease identifier as the dist-tag (`1.2.0-rc.1` → `rc`); a plain
   version under `latest`.

## License

Dual-licensed under MIT and Apache-2.0; see `LICENSE-MIT`, `LICENSE-APACHE`
and `CONTRIBUTING.md`.
