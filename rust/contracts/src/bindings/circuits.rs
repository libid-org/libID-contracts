//! Bindings for the bb-generated UltraHonk verifiers in
//! `solidity/contracts/circuits`: the one call a Platform Verifier makes of
//! them, and the error that says which circuit a deployed one answers for.

/// Bindings for a bb-generated UltraHonk verifier — `BearerLinkHonkVerifier`
/// and `OidcGoogleHonkVerifier`, one interface for both.
///
/// `verify` is the whole surface a Platform Verifier uses
/// (`IHonkVerifier` in `PlatformVerifierBase.sol`). The error is the one
/// thing a deployed verifier says about itself: it embeds its verification
/// key as code constants and exposes no getter, so `logN` from a
/// wrong-length proof is how a test tells a real verifier over the right
/// circuit from a contract that merely has code.
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
}
