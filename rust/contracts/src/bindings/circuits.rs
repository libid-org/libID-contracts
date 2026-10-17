//! Bindings for the bb-generated UltraHonk verifiers in
//! `solidity/contracts/circuits`: the one call a Platform Verifier makes of
//! them, and the error that says which circuit a deployed one answers for.

/// Bindings for a bb-generated UltraHonk verifier, one interface for the
/// three circuits' verifiers. A wrong-length proof's `logN` is how a test
/// identifies the circuit, since the verifier exposes no getter.
#[allow(unused_attributes)]
mod honk_verifier_inner {
    use alloy::sol;

    sol! {
        #[sol(rpc)]
        interface HonkVerifier {
            function verify(bytes calldata proof, bytes32[] calldata publicInputs)
                external
                view
                returns (bool);

            /// Raised by `verify` before anything else when the proof is
            /// not the length the circuit's `logN` implies.
            error ProofLengthWrongWithLogN(uint256 logN, uint256 actualLength, uint256 expectedLength);
        }
    }
}

pub use honk_verifier_inner::HonkVerifier;

/// Bindings for `circuits/IHonkVerifierErrors.sol`: what a vendored Honk
/// verifier reverts with, under bb's names. bb's artifact declares none of
/// them; [`BindError::decode`](crate::BindError::decode) uses these.
#[allow(non_camel_case_types, unused_attributes)]
mod honk_verifier_errors_inner {
    use alloy::sol;

    sol! {
        #[sol(abi)]
        interface IHonkVerifierErrors {
            error ValueGeLimbMax();
            error ValueGeGroupOrder();
            error ValueGeFieldOrder();
            error SumcheckFailed();
            error ShpleminiFailed();
            /// Raised before anything else when the proof is not the length
            /// the circuit's `logN` implies.
            error ProofLengthWrongWithLogN(uint256 logN, uint256 actualLength, uint256 expectedLength);
            error PublicInputsLengthWrong();
            /// bb's name, which the selector is the hash of.
            error MODEXP_FAILED();
            error ConsistencyCheckFailed();
            error GeminiChallengeInSubgroup();
        }
    }
}

pub use honk_verifier_errors_inner::IHonkVerifierErrors;

#[cfg(test)]
mod tests {
    use alloy::sol_types::SolCall;

    use super::*;
    use crate::{
        circuits::Circuit,
        Artifacts,
    };

    /// `verify` is what a Platform Verifier calls; a vendored verifier
    /// without that selector would be pinned and revert at the first
    /// user's proof.
    #[test]
    fn every_circuit_verifier_answers_verify() {
        let artifacts = Artifacts::embedded();
        for circuit in Circuit::ALL {
            let methods = artifacts.method_identifiers(circuit.contract()).unwrap();
            let found = methods
                .get(HonkVerifier::verifyCall::SIGNATURE)
                .unwrap_or_else(|| panic!("{} has no verify", circuit.contract()));
            assert_eq!(
                *found,
                alloy::hex::encode(HonkVerifier::verifyCall::SELECTOR),
                "{}.verify",
                circuit.contract()
            );
        }
    }

    /// The binding is the compiled interface, item for item.
    #[test]
    fn honk_verifier_errors_binding_matches_artifact() {
        crate::bindings::drift::assert_binding_matches_artifact(
            "IHonkVerifierErrors",
            "IHonkVerifierErrors",
            &IHonkVerifierErrors::abi::contract(),
            &[],
        );
    }
}
