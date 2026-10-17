//! Bindings for the deterministic deployment factory
//! (`solidity/contracts/factory/`), read from the compiled artifact.

#[allow(
    clippy::too_many_arguments,
    missing_docs,
    non_camel_case_types,
    unused_attributes
)]
mod inner {
    alloy::sol!(
        #[sol(rpc, all_derives)]
        LibidFactory,
        "abi/LibidFactory.json"
    );
}

/// `factory/LibidFactory.sol`. Every protocol proxy is deployed through it via
/// CREATE3 with `salt = keccak256(bytes(name))`, so its address is a function
/// of (factory address, name) only; the factory lives at the same address on
/// every chain (see [`crate::factory`]).
pub use inner::LibidFactory;
