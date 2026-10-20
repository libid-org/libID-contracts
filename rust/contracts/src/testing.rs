//! Test stand-ins, behind the `testing` feature: a Platform Verifier that
//! checks no proof and reports the nodes it is told to, so a consumer's tests
//! can bind through `IdentityRegistry` without a ceremony.

use alloy::{
    primitives::{
        Address,
        Bytes,
        B256,
        U256,
    },
    providers::Provider,
    sol_types::{
        SolConstructor,
        SolValue,
    },
};

use crate::{
    artifacts::Artifacts,
    deploy::deploy_with_ctor,
    error::Result,
};

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
