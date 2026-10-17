//! Bindings for the identity registry (`solidity/contracts/identity/`), read
//! from the compiled artifact. Nodes are `SHA256(tag || value)`;
//! `libid_identity` computes them off chain.

#[allow(
    clippy::too_many_arguments,
    missing_docs,
    non_camel_case_types,
    unused_attributes
)]
mod inner {
    alloy::sol!(
        #[sol(rpc, all_derives, extra_derives(serde::Serialize, serde::Deserialize))]
        IdentityRegistry,
        "abi/IdentityRegistry.json"
    );
}

/// `identity/IdentityRegistry.sol`.
pub use inner::IdentityRegistry;
