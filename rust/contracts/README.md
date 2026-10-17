# libid-contracts

Typed [alloy](https://github.com/alloy-rs/alloy) bindings, embedded forge
artifacts, and deploy/upgrade helpers for the libid identity stack: the
ceremony verification path (`NotaryService`, `CeremonyProofVerifier`, the
three launch Platform Verifiers it routes to, the two UltraHonk verifiers
they pin, and `GoogleJwtRoots`, the signing keys the `google/v1` verifier
trusts), the identity registry (`IdentityRegistry`), and the deterministic
deployment factory (`LibidFactory`).

The compiled artifacts are embedded in the crate, so a consumer deploys or
upgrades the stack with no filesystem access at runtime. The bindings are
`alloy::sol!` over the compiled ABIs. Every helper is generic over an alloy
`Provider` you have already wired with a wallet.

`artifacts/` and `abi/` are generated from `solidity/`, not committed. After
cloning, run `scripts/vendor-circuit-verifiers.sh` then
`scripts/vendor-artifacts.sh`; until then `cargo build` fails at
`include_dir!`. CI runs both before every build, test and publish.

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

    // Every notarized session is verified through the Notary Service, for
    // the Notary Fee.
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

    // The Google JWT root list pays that fee on every rotation. It starts
    // empty until a keeper submits a notarized reading of Google's JWKS.
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

A Platform Verifier wires the UltraHonk verifier for its circuit, and a
Notary Service only if its profile notarizes. Its validity window is
compiled in from its profile. `platform_verifier::Initializer` refuses what
the contract would refuse and builds the `initialize` call.

The contract reverts `WrongCircuit` for a Honk verifier whose code hash is
not its `circuitCodehash()`. `deploy_platform_verifier` reads the code hash
on chain and returns `Error::WrongCircuit` before any transaction.

The Honk verifiers are vendored from the pinned `libid-circuits` release,
one contract per circuit. `circuits::deploy_honk_verifier` deploys one in a
single transaction and returns the address the initializer wires.

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
    // says so, and this deploys its verifier.
    let honk_verifier =
        deploy_honk_verifier(&provider, &artifacts, PlatformVerifier::X.circuit(), None).await?;

    // `x/v1` notarizes two sessions, so it needs a Notary Service.
    // `Initializer::Google` takes `GoogleRoots`: the JWT root list instead.
    let verifier = deploy_platform_verifier(
        &provider,
        &artifacts,
        &Initializer::X(TlsNotaryRoots {
            owner,
            notary_service: notary,
            honk_verifier,
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

For a factory (CREATE3) deploy, `Initializer::call()` returns the typed
`initialize` call; `abi_encode` it into the proxy's init data, after
`PlatformVerifier::circuit_codehash_at` if the deploy should fail off chain.

Other entry points:

- `deploy::upgrade_uups` — deploy a fresh implementation and
  `upgradeToAndCall` a UUPS proxy onto it.
- `factory::FactoryGenesis::ensure` / `factory::factory_deploy` — install the
  canonical cross-network factory where missing and deploy protocol proxies
  through it at name-derived CREATE3 addresses.
- `circuits::version` — the `libid-circuits` release the vendored verifiers
  came from.
- `PlatformVerifier::rotation_codehash_at` — the code hash `setTrustRoots`
  wants, or `Error::WrongCircuit` unless the address holds the verifier the
  proxy's `circuitCodehash()` pins. `platform_verifier::codehash_at` reads
  any address's code hash, unchecked.
- `BindError::decode` — a refused `bind` by name (`HandleNotProved`,
  `NotYourHandle`, `SumcheckFailed`, …), from every contract on the route
  and bb's Honk verifiers. A revert does not say which contract raised it,
  so `contracts()` lists every one that declares the error.
- `bindings::ceremony::{TlsNotaryProof, GoogleProof}` — the payload a Platform
  Verifier decodes; its `SolValue::abi_encode` is the `payload` `bind` takes.

## Testing

Unit tests run everywhere; the integration tests in `tests/anvil.rs` spawn
`anvil` (foundry) and deploy the stack for real. From `rust/`:

```sh
cargo +nightly-2026-08-10 fmt --all   # CI's pin; rustfmt.toml needs nightly
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all
```
