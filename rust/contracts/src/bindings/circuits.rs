//! Bindings for the bb-generated UltraHonk verifiers in
//! `solidity/contracts/circuits`, read from the compiled artifacts.

#[allow(
    clippy::too_many_arguments,
    missing_docs,
    non_camel_case_types,
    unused_attributes
)]
mod honk_verifier {
    alloy::sol!(
        #[sol(rpc, all_derives)]
        HonkVerifier,
        "abi/IVerifier.json"
    );
}

#[allow(
    clippy::too_many_arguments,
    missing_docs,
    non_camel_case_types,
    unused_attributes
)]
mod honk_verifier_errors {
    alloy::sol!(
        #[sol(all_derives)]
        IHonkVerifierErrors,
        "abi/IHonkVerifierErrors.json"
    );
}

/// bb's `IVerifier`, which every vendored Honk verifier implements: the one
/// call a Platform Verifier makes of it.
pub use honk_verifier::HonkVerifier;
/// `circuits/IHonkVerifierErrors.sol`, generated from the vendored verifiers'
/// `*_SELECTOR` constants: what a Honk verifier reverts with.
/// [`BindError::decode`](crate::BindError::decode) uses these.
pub use honk_verifier_errors::IHonkVerifierErrors;
