//! Bindings for the ENS resolver (`solidity/contracts/ens/`), read from the
//! compiled artifact.

#[allow(
    clippy::too_many_arguments,
    missing_docs,
    non_camel_case_types,
    unused_attributes
)]
mod inner {
    alloy::sol!(
        #[sol(rpc, all_derives)]
        HandleResolver,
        "abi/HandleResolver.json"
    );
}

/// `ens/HandleResolver.sol`: the wildcard resolver for `handles.link`. Not a
/// proxy: the owner, the gateway endpoints and the signer set arrive in the
/// constructor; deploy it with `deploy_with_ctor` and the ABI-encoded
/// constructor tuple.
pub use inner::HandleResolver;
