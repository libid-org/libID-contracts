# libid-contracts

Typed [alloy](https://github.com/alloy-rs/alloy) bindings, embedded forge
artifacts, and deploy/upgrade helpers for the libid identity stack: the
ceremony verification path (`NotaryService`, `CeremonyProofVerifier`, the
three launch Platform Verifiers it routes to, the two UltraHonk verifiers
they pin, and `GoogleJwtRoots`, the signing keys the `google/v1` verifier
trusts), the naming system (`IdentityNames`), and the deterministic
deployment factory (`LibidFactory`).

The compiled artifacts are vendored into the crate, so a consumer can deploy
or upgrade the whole stack against a live network with **zero filesystem
dependencies at runtime**. They are generated, not committed:
`scripts/vendor-artifacts.sh` produces `artifacts/` from `solidity/` and CI
runs it before every build, test and publish. Working in this repo, run it
once after cloning — the crate embeds the directory with `include_dir!`, so
until it exists `cargo build` fails at macro expansion. Signing stays on the
consumer's side: every helper is generic over an alloy `Provider` you have
already wired with a wallet.

## Example: deploy the Notary Service and the Google JWT root list

```rust,no_run
use alloy::{primitives::{Address, U256}, providers::ProviderBuilder};
use libid_contracts::{
    bindings::ceremony::{GoogleJwtRoots, NotaryService},
    deploy::deploy_behind_proxy,
    Artifacts,
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Any alloy provider with a wallet: HTTP + your signer of choice.
    let provider = ProviderBuilder::new()
        .wallet(/* your signer */ todo!())
        .connect_http("https://rpc.example.org".parse()?);
    let artifacts = Artifacts::embedded();
    let (owner, notary_key): (Address, Address) = todo!();

    // The Notary Service first: every notarized session is verified through
    // it, and it charges the Notary Fee for doing so.
    let notary = deploy_behind_proxy(
        &provider,
        &artifacts,
        "NotaryService",
        &NotaryService::initializeCall {
            owner_: owner,
            notary_: notary_key,
            fee_: U256::from(1_000),
        },
        None,
    )
    .await?;

    // The Google JWT root list pays that fee on every rotation. It starts empty:
    // a keeper submits a notarized reading of Google's JWKS to seed it.
    let roots = deploy_behind_proxy(
        &provider,
        &artifacts,
        "GoogleJwtRoots",
        &GoogleJwtRoots::initializeCall {
            owner_: owner,
            notary_: notary,
        },
        None,
    )
    .await?;

    let fee = GoogleJwtRoots::new(roots, &provider)
        .quoteRotation()
        .call()
        .await?;
    println!("roots {roots:#x} verify through {notary:#x}; a rotation costs {fee} wei");
    Ok(())
}
```

## Example: deploy a Platform Verifier on its circuit's Honk verifier

A Platform Verifier pins the bb-generated UltraHonk verifier for its circuit
by address and by code hash, holds a Notary Service only if its profile
notarizes anything, and caps its parameters. `platform_verifier::Initializer`
knows those rules: it reads the code hash off the chain, refuses what the
contract would refuse, and builds the exact `initialize` call.

The Honk verifier is vendored here too, from the pinned `libid-circuits`
release. `circuits::deploy_honk_verifier` deploys the two libraries it links
(`RelationsLib`, `ZKTranscriptLib`), links them in and deploys the verifier —
three transactions — and returns the address the initializer pins.

```rust,no_run
use alloy::{primitives::Address, providers::ProviderBuilder};
use libid_contracts::{
    bindings::ceremony::{CeremonyProofVerifier, XPlatformVerifier},
    circuits::deploy_honk_verifier,
    platform_verifier::{deploy_platform_verifier, Initializer, PlatformVerifier, TlsNotaryRoots},
    Artifacts,
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let provider = ProviderBuilder::new()
        .wallet(/* your signer */ todo!())
        .connect_http("https://rpc.example.org".parse()?);
    let artifacts = Artifacts::embedded();
    let (owner, notary, proof_verifier): (Address, Address, Address) = todo!();

    // The circuit `x/v1` proves under is `bearer-link`; `PlatformVerifier::circuit`
    // says so, and this deploys its verifier with the libraries linked.
    let honk_verifier =
        deploy_honk_verifier(&provider, &artifacts, PlatformVerifier::X.circuit(), None).await?;

    // `x/v1`: two notarized sessions, so a Notary Service is required.
    // `Initializer::Google` takes `GoogleRoots` instead — no Notary Service
    // (the profile notarizes nothing) and the JWT root list in its place.
    let verifier = deploy_platform_verifier(
        &provider,
        &artifacts,
        &Initializer::X(TlsNotaryRoots {
            owner,
            notary_service: notary,
            honk_verifier,
            proof_lifetime: 3600,
            max_future_attestation_skew: 300,
            future_observation_allowance: 300,
        }),
        None,
    )
    .await?;

    // Register it for the platform's launch slot.
    let platform_id = XPlatformVerifier::new(verifier, &provider).platformId().call().await?;
    CeremonyProofVerifier::new(proof_verifier, &provider)
        .setVerifier(platform_id, 1, verifier)
        .send()
        .await?
        .get_receipt()
        .await?;
    Ok(())
}
```

For a factory (CREATE3) deploy, `Initializer::call` returns the typed
`initialize` call; `abi_encode` it into the proxy's init data.

Other entry points:

- `deploy::upgrade_uups` — deploy a fresh implementation and
  `upgradeToAndCall` a UUPS proxy onto it.
- `factory::ensure_factory` / `factory::factory_deploy` — install the
  canonical cross-network factory where missing and deploy protocol proxies
  through it at name-derived CREATE3 addresses.
- `deploy::load_linked_bytecode` (or `Artifacts::linked_bytecode`) — deploys
  and links external libraries before returning the creation bytecode; what
  `circuits::deploy_honk_verifier` goes through.
- `circuits::version` — the `libid-circuits` release the vendored verifiers
  came from, for a consumer that names a deployment after its artifact.
- `platform_verifier::codehash_at` — the code hash `setTrustRoots` wants
  when a Platform Verifier is rotated onto a new circuit release.
- `Artifacts::method_identifiers` — selector extraction from the vendored
  `methodIdentifiers`.

## Testing

Unit tests run everywhere; the integration tests in `tests/anvil.rs` spawn
`anvil` (foundry) and deploy the stack for real. From `rust/`:

```sh
cargo +nightly fmt --all      # nightly only — stable rustfmt mangles imports
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all
```
