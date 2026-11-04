//! Bindings for the referral splitter (`solidity/contracts/referral/`), read
//! from the compiled artifact: the fee receiver a referred bind pays, which
//! sends a share of the fee to the referrer's handle through the escrow and the
//! rest to the treasury.

#[allow(
    clippy::too_many_arguments,
    missing_docs,
    non_camel_case_types,
    unused_attributes
)]
mod inner {
    alloy::sol!(
        #[sol(rpc, all_derives)]
        ReferralSplitter,
        "abi/ReferralSplitter.json"
    );
}

/// `referral/ReferralSplitter.sol`.
pub use inner::ReferralSplitter;
