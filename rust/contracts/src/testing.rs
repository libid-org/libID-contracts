//! Test stand-ins, behind the `testing` feature: a Platform Verifier that
//! checks no proof and reports the nodes it is told to, so a consumer's tests
//! can bind through `IdentityRegistry` without a ceremony, and the wallet
//! stack on it.

use alloy::{
    primitives::{
        Address,
        Bytes,
        B256,
        U256,
    },
    providers::Provider,
    sol_types::{
        SolCall,
        SolConstructor,
        SolValue,
    },
};

use serde::Deserialize;

use crate::{
    artifacts::Artifacts,
    bindings::{
        ceremony::CeremonyProofVerifier,
        escrow::HandleEscrow,
        identity::IdentityRegistry,
        wallet::{
            WalletFactory,
            WalletRegistry,
        },
    },
    deploy::{
        deploy_behind_proxy,
        deploy_proxy,
        deploy_with_ctor,
        Mined,
    },
    error::{
        Error,
        Result,
    },
    platform_verifier::PlatformVerifier,
    wallet_target::Release,
};

/// Runtime code of EntryPoint v0.9 and its SenderCreator, read from Base
/// mainnet; vendored from `solidity/contracts/wallet/test/fixtures/`.
const ENTRY_POINT: &str = include_str!("../artifacts-testing/entrypoint-v0.9.json");

/// Send a contract call and require that it landed.
macro_rules! confirm {
    ($call:expr, $label:expr) => {
        $call
            .send()
            .await
            .map_err(|e| Error::Rpc {
                detail: format!("{} send failed: {e}", $label),
            })?
            .get_receipt()
            .await
            .map_err(|e| Error::Rpc {
                detail: format!("{} confirmation failed: {e}", $label),
            })?
            .succeeded($label)?
    };
}

#[allow(
    clippy::too_many_arguments,
    missing_docs,
    non_camel_case_types,
    unused_attributes
)]
mod inner {
    alloy::sol!(
        #[sol(rpc, all_derives)]
        StubPlatformVerifier,
        "abi/StubPlatformVerifier.json"
    );

    // `StubPlatformVerifier.StubPayload`, which its ABI leaves out. The anvil
    // suite binds through the stub with it, so a drift fails there.
    alloy::sol! {
        #[derive(Debug, PartialEq, Eq)]
        struct StubPayload {
            uint16 ceremonyVersion;
            bytes32 operationDomain;
            bytes32 authorizationNonce;
            bytes transactionData;
        }
    }
}

/// The digest inputs the stub's payload carries.
pub use inner::StubPayload;
/// `identity/test/StubPlatformVerifier.sol`: reports `set`'s id and handle
/// as nodes under its platform's tags (X's for an unknown platform), or
/// `setNodes`' nodes as given, for any payload it decodes.
pub use inner::StubPlatformVerifier;

/// The `payload` `bind` carries to the stub.
pub fn stub_payload(payload: &StubPayload) -> Bytes {
    payload.abi_encode().into()
}

/// Deploy a stub answering for `platform` at `fee` wei, and return its
/// address. `sender` opts into explicit nonces
/// ([`deploy_contract_from`](crate::deploy::deploy_contract_from)).
pub async fn deploy_stub_platform_verifier<P: Provider>(
    provider: &P,
    artifacts: &Artifacts,
    platform: B256,
    fee: U256,
    sender: Option<Address>,
) -> Result<Address> {
    deploy_with_ctor(
        provider,
        &artifacts.bytecode("StubPlatformVerifier")?,
        &StubPlatformVerifier::constructorCall {
            platform,
            fee_: fee,
        }
        .abi_encode(),
        "StubPlatformVerifier",
        sender,
    )
    .await
}

/// The wallet stack [`deploy_wallet_stack`] deploys, every contract behind
/// its own proxy where it has one.
#[derive(Clone, Copy, Debug)]
pub struct WalletStack {
    /// EntryPoint v0.9, at its canonical address.
    pub entry_point: Address,
    /// `WalletFactory`, with release 1 published.
    pub factory: Address,
    /// `WalletForwarder` of the factory.
    pub forwarder: Address,
    /// The platform the stub proves, X's.
    pub platform: B256,
    /// The factory's release 1.
    pub release: Release,
    /// `WalletRegistry`.
    pub wallet_registry: Address,
    /// `CeremonyProofVerifier`, with the stub as the platform's verifier 1.
    pub proof_verifier: Address,
    /// The [`StubPlatformVerifier`], at no fee.
    pub stub: Address,
    /// `IdentityRegistry` on the Proof Verifier.
    pub identities: Address,
    /// `HandleEscrow` on the identity registry.
    pub escrow: Address,
}

/// One code the EntryPoint fixture installs.
#[derive(Deserialize)]
struct Installed {
    address: Address,
    code: Bytes,
}

/// `entrypoint-v0.9.json`.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct EntryPointFixture {
    entry_point: Installed,
    sender_creator: Installed,
}

/// Install EntryPoint v0.9 and its SenderCreator through `anvil_setCode`,
/// and return the EntryPoint's address.
async fn install_entry_point<P: Provider>(provider: &P) -> Result<Address> {
    let fixture: EntryPointFixture =
        serde_json::from_str(ENTRY_POINT).map_err(|e| Error::Artifact {
            detail: format!("entrypoint-v0.9.json: {e}"),
        })?;
    for Installed { address, code } in [&fixture.sender_creator, &fixture.entry_point] {
        provider
            .raw_request::<_, ()>("anvil_setCode".into(), (address, code))
            .await
            .map_err(|e| Error::Rpc {
                detail: format!("anvil_setCode at {address}: {e}"),
            })?;
    }
    Ok(fixture.entry_point.address)
}

/// Deploy the wallet stack on an anvil node, owned by `owner`, which must be
/// the provider's sender: EntryPoint v0.9, the stub as X's verifier, and the
/// factory with release 1.
pub async fn deploy_wallet_stack<P: Provider>(
    provider: &P,
    artifacts: &Artifacts,
    owner: Address,
) -> Result<WalletStack> {
    let entry_point = install_entry_point(provider).await?;
    let platform = PlatformVerifier::X.platform_id();
    let proof_verifier = deploy_behind_proxy(
        provider,
        artifacts,
        "CeremonyProofVerifier",
        &CeremonyProofVerifier::initializeCall { owner_: owner },
        None,
    )
    .await?;
    let stub =
        deploy_stub_platform_verifier(provider, artifacts, platform, U256::ZERO, None)
            .await?;
    confirm!(
        CeremonyProofVerifier::new(proof_verifier, provider)
            .setVerifier(platform, 1, stub),
        "CeremonyProofVerifier.setVerifier"
    );
    let identities = deploy_behind_proxy(
        provider,
        artifacts,
        "IdentityRegistry",
        &IdentityRegistry::initializeCall { owner_: owner },
        None,
    )
    .await?;
    confirm!(
        IdentityRegistry::new(identities, provider).setProofVerifier(proof_verifier),
        "IdentityRegistry.setProofVerifier"
    );
    let escrow = deploy_behind_proxy(
        provider,
        artifacts,
        "HandleEscrow",
        &HandleEscrow::initializeCall {
            owner_: owner,
            registry_: identities,
        },
        None,
    )
    .await?;
    let wallet_registry = deploy_behind_proxy(
        provider,
        artifacts,
        "WalletRegistry",
        &WalletRegistry::initializeCall {
            owner_: owner,
            verifier: proof_verifier,
        },
        None,
    )
    .await?;

    let deploy = |contract: &'static str, args: Vec<u8>| async move {
        deploy_with_ctor(
            provider,
            &artifacts.bytecode(contract)?,
            &args,
            contract,
            None,
        )
        .await
    };
    let factory_impl = deploy("WalletFactory", wallet_registry.abi_encode()).await?;
    let factory = deploy_proxy(
        provider,
        &artifacts.bytecode("ERC1967Proxy")?,
        factory_impl,
        WalletFactory::initializeCall { owner_: owner }
            .abi_encode()
            .into(),
        "WalletFactory (proxy)",
        None,
    )
    .await?;
    let identity_admin = deploy("IdentityAdmin", vec![]).await?;
    let session_rules = deploy("SessionRules", vec![]).await?;
    let args = (
        factory,
        wallet_registry,
        1u64,
        identity_admin,
        session_rules,
    );
    let implementation = deploy("WebWallet", args.abi_encode_params()).await?;
    let wallet_factory = WalletFactory::new(factory, provider);
    confirm!(
        wallet_factory.publish(implementation),
        "WalletFactory.publish"
    );
    let forwarder = deploy("WalletForwarder", factory.abi_encode()).await?;
    let latest = wallet_factory
        .latest()
        .call()
        .await
        .map_err(|e| Error::Rpc {
            detail: format!("WalletFactory.latest: {e}"),
        })?;

    Ok(WalletStack {
        entry_point,
        factory,
        forwarder,
        platform,
        release: Release {
            implementation: latest.implementation,
            version: latest.version,
        },
        wallet_registry,
        proof_verifier,
        stub,
        identities,
        escrow,
    })
}
