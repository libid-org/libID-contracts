//! Bindings for the handle escrow (`solidity/contracts/escrow/`), read from the
//! compiled artifact: value held against a handle node until its holder claims
//! it, refundable by its sender from its `refundableAt` until then.

#[allow(
    clippy::too_many_arguments,
    missing_docs,
    non_camel_case_types,
    unused_attributes
)]
mod inner {
    alloy::sol!(
        #[sol(rpc, all_derives)]
        HandleEscrow,
        "abi/HandleEscrow.json"
    );
}

/// `escrow/HandleEscrow.sol`.
pub use inner::HandleEscrow;
