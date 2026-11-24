# libid-contracts

Typed [alloy](https://github.com/alloy-rs/alloy) bindings, embedded forge
artifacts, and deploy/upgrade helpers for the libid identity stack: the
ceremony verification path (`NotaryService`, `CeremonyProofVerifier`, the
four launch Platform Verifiers it routes to, the three UltraHonk verifiers
they pin, and `GoogleJwtRoots` and `TelegramJwtRoots`, the signing keys the
`google/v1` and `telegram/v1` verifiers trust), the identity registry
(`IdentityRegistry`), the handle escrow (`HandleEscrow`), the referral splitter
(`ReferralSplitter`), and the deterministic deployment factory (`LibidFactory`).

The compiled artifacts are embedded in the crate, so a consumer deploys or
upgrades the stack with no filesystem access at runtime. The bindings are
`alloy::sol!` over the compiled ABIs. Every helper is generic over an alloy
`Provider` you have already wired with a wallet.

`artifacts/`, `artifacts-testing/` and `abi/` are generated from `solidity/`, not committed. After
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
    // `TelegramJwtRoots` deploys the same way.
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
    deploy::Mined,
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
    // `Initializer::Google` takes `OidcRoots`: the JWT root list instead.
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
    // A reverted transaction is mined too: `succeeded` refuses its receipt.
    CeremonyProofVerifier::new(proof_verifier, &provider)
        .setVerifier(platform_id, 1, verifier)
        .send()
        .await?
        .get_receipt()
        .await?
        .succeeded("CeremonyProofVerifier.setVerifier")?;
    Ok(())
}
```

For a factory (CREATE3) deploy, `Initializer::call()` returns the typed
`initialize` call; `abi_encode` it into the proxy's init data, after
`PlatformVerifier::circuit_codehash_at` if the deploy should fail off chain.

Other entry points:

- `deploy::upgrade_uups` — deploy a fresh implementation and
  `upgradeToAndCall` a UUPS proxy onto it, then read the proxy's EIP-1967
  slot at the receipt's block: `Error::NotUpgraded` unless it names the new
  implementation. With a `sender`, it sends through `send_with_nonce_retry!`.
- `deploy::ProxyReads::implementation_of` — the implementation a proxy runs
  at a block, from its EIP-1967 slot (`IMPLEMENTATION_SLOT`).
- `deploy::Mined` — `succeeded` turns a reverted receipt into
  `Error::Reverted`; `block` names the block it was mined in.
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
  so `contracts()` lists every one that declares the error. For
  `telegram/v1`, `AttestationAhead` and `ProofExpired` date the signed
  token's `iat`, not an attestation.
- `bindings::ceremony::{TlsNotaryProof, OidcProof}` — the payload a Platform
  Verifier decodes; its `SolValue::abi_encode` is the `payload` `bind` takes.
- `operation_list::{Operation, OPERATIONS_DOMAIN}` — a ceremony's transaction
  data: `vec![Operation::bind(target)].abi_encode()` under `OPERATIONS_DOMAIN`
  is a bind, beside the single form `abi.encode(target)` under `BIND_DOMAIN`;
  one list can carry other Consumers' entries beside the bind.
- `WalletRegistryError::decode` — a refused wallet link or login by name,
  from `WalletRegistry`, the same proof route, the wallet's own errors
  (`IWebWallet`: `AppNotListed`, `FirstSessionRefused`, …) and an onboarding
  batch's bind, its fee and claim (`IdentityRegistry`, `ReferralSplitter`,
  `HandleEscrow`).
- `bindings::wallet` — `IWebWallet`, the whole ABI of a wallet, and what its
  signers sign: `ExecuteMessage`, `user_operation_digest`,
  `below_quorum_hash`, `encode_authorization` (a UserOperation's signature
  and ERC-1271's inner signature, with no prefix), and
  `Policy::policy_hash` with `Rules::sort_allowances`; the link
  and login operation domains (`LINK_IDENTITY_DOMAIN`, `ADD_SESSION_DOMAIN`,
  `REMOVE_SESSIONS_DOMAIN`) and the `transaction_data` their proofs commit,
  naming the submitter that calls the wallet with them. `encode_executions`
  and `decode_executions` are the ERC-7579 batch codec; the decoder refuses
  a batch the wallet would refuse as non-canonical.
  `ExecuteMessage::from_authorized_data` decodes `data` leniently: compare
  `authorized_data` of the result with the bytes to know they are canonical.
- `gas::WalletGas` — what a simulation of a batch with dummy signatures
  leaves out: `verify(KeyKind)` per further signer, its iteration of the
  wallet's signature loop, `verify_tail()` once, the run after a valid
  signature check less the dummy run's revert, and `rules(n_calls)`, the
  rules check below quorum in its costly case (a native refund, then an
  ERC-20 `transfer` per further call, each a first spend), from the wallet's gas
  snapshot; `gas::CALL_OVERHEAD`.
- `wallet_target::check_target` — whether the factory and forwarder vouch
  for an address as a factory wallet or an EIP-7702 account, and its
  `Release`; `None` for anything else, `Err` when the node cannot tell.

## Example: sign and send a wallet batch directly

A web wallet's signers can sign a batch that anyone then sends as
`execute(AUTHORIZED_MODE, data)`, with no UserOperation. `ExecuteMessage` is
the message: `digest` is what the signers sign, under the domain of the
release the wallet runs and its salt, and `authorized_data` builds `data` from the same
message. The batch consumes EntryPoint nonce key `DIRECT_NONCE_KEY` (0):

```rust,no_run
use alloy::{
    primitives::{aliases::U48, Address, Bytes, U256},
    providers::ProviderBuilder,
    signers::{local::PrivateKeySigner, SignerSync},
};
use libid_contracts::bindings::wallet::{
    ExecuteAuthorization, ExecuteMessage, IWebWallet, SessionSignature, AUTHORIZED_MODE,
    DIRECT_NONCE_KEY,
};

alloy::sol! {
    #[sol(rpc)]
    interface IEntryPoint {
        function getNonce(address sender, uint192 key) external view returns (uint256);
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let relayer: PrivateKeySigner = todo!();
    let provider = ProviderBuilder::new()
        .wallet(relayer)
        .connect_http("https://rpc.example.org".parse()?);
    let (wallet, entry_point, chain_id): (Address, Address, u64) = todo!();
    let session: PrivateKeySigner = todo!();
    // An ERC-7579 batch: `abi.encode(Execution[])`.
    let execution_calldata: Bytes = todo!();

    let account = IWebWallet::new(wallet, &provider);
    let version = account.release().call().await?.version;
    // The domain's salt: `reset`, revoking an admin, removing or unlinking an
    // identity, and a threshold change move it. Read it from `eip712Domain()`,
    // or as `wallet_salt(epoch(), rootEpoch())`. A wallet without code signs
    // with `wallet_salt(B256::ZERO, 0)`.
    let salt = account.eip712Domain().call().await?.salt;
    let nonce = IEntryPoint::new(entry_point, &provider)
        .getNonce(wallet, DIRECT_NONCE_KEY)
        .call()
        .await?;
    // `value` is the `msg.value` the batch is sent with.
    let execute = ExecuteMessage {
        execution_calldata,
        value: U256::ZERO,
        at: U48::ZERO,
        nonce,
        deadline: U48::from(2_000_000_000),
        call_gas: U256::from(500_000),
    };
    // At quorum a session key signs the digest; below quorum,
    // `below_quorum_hash` of it.
    let signature = session.sign_hash_sync(&execute.digest(chain_id, wallet, version, salt))?;
    let data = execute.authorized_data(ExecuteAuthorization {
        signatures: vec![SessionSignature {
            key: session.address().to_vec().into(),
            signature: signature.as_bytes().to_vec().into(),
        }],
        ..Default::default()
    });
    account
        .execute(AUTHORIZED_MODE, data)
        .value(execute.value)
        .send()
        .await?
        .get_receipt()
        .await?;
    Ok(())
}
```

## Feature `testing`

Off by default. It embeds `StubPlatformVerifier`, a Platform Verifier that
checks no proof, and adds `testing::{deploy_stub_platform_verifier,
stub_payload, StubPayload, StubPlatformVerifier}`, so a consumer's tests can
bind through `IdentityRegistry` without a ceremony. `deploy_wallet_stack`
deploys the wallet stack on it to an anvil node, with EntryPoint v0.9 at its
canonical address. Enable it in
`[dev-dependencies]` only.

## Testing

Unit tests run everywhere; the integration tests in `tests/anvil.rs` spawn
`anvil` (foundry) and deploy the stack for real. From `rust/`:

```sh
cargo +nightly-2026-08-10 fmt --all   # CI's pin; rustfmt.toml needs nightly
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all
cargo test -p libid-contracts --features testing
```
