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

/// `identity/IIdentityRegistry.sol`'s types: `Identity`, as `identitiesOf`
/// returns it.
pub use inner::IIdentityRegistry;
/// `identity/IdentityRegistry.sol`, with `Identity` still at its old path.
#[allow(non_snake_case)]
pub mod IdentityRegistry {
    pub use super::inner::{
        IIdentityRegistry::Identity,
        IdentityRegistry::*,
    };
}

#[cfg(test)]
mod tests {
    #[test]
    fn identity_keeps_its_registry_path() {
        let id: super::IdentityRegistry::Identity =
            super::IIdentityRegistry::Identity::default();
        assert_eq!(id, super::IdentityRegistry::Identity::default());
    }
}
