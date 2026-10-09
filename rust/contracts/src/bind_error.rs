//! A refused `bind`, decoded by name.
//!
//! A revert passes unchanged through every contract on the `bind` route, so
//! [`BindError::decode`] tries each one's error set in call order, the Honk
//! verifier (`IHonkVerifierErrors`) last. TypeScript's `bindErrorsAbi` has
//! the same sets.

use alloy::sol_types::SolInterface;

use crate::bindings::{
    ceremony::{
        CeremonyProofVerifier::CeremonyProofVerifierErrors,
        GooglePlatformVerifier::GooglePlatformVerifierErrors,
        NotaryService::NotaryServiceErrors,
        TlsNotaryPlatformVerifier::TlsNotaryPlatformVerifierErrors,
    },
    circuits::IHonkVerifierErrors::IHonkVerifierErrorsErrors,
    identity::IdentityRegistry::IdentityRegistryErrors,
};

/// A `bind` revert, decoded by the first contract on the route whose error
/// set declares its selector.
pub enum BindError {
    /// `IdentityRegistry`.
    Registry(IdentityRegistryErrors),
    /// `CeremonyProofVerifier`.
    ProofVerifier(CeremonyProofVerifierErrors),
    /// `XPlatformVerifier` or `GitHubPlatformVerifier`.
    TlsNotaryVerifier(TlsNotaryPlatformVerifierErrors),
    /// `GooglePlatformVerifier`.
    GoogleVerifier(GooglePlatformVerifierErrors),
    /// `NotaryService`.
    NotaryService(NotaryServiceErrors),
    /// The platform's Honk verifier.
    HonkVerifier(IHonkVerifierErrorsErrors),
}

impl BindError {
    /// The error `revert_data` encodes, or `None` when no contract on the
    /// route declares its selector or its fields do not decode.
    pub fn decode(revert_data: &[u8]) -> Option<Self> {
        if let Ok(e) = IdentityRegistryErrors::abi_decode(revert_data) {
            return Some(Self::Registry(e));
        }
        if let Ok(e) = CeremonyProofVerifierErrors::abi_decode(revert_data) {
            return Some(Self::ProofVerifier(e));
        }
        if let Ok(e) = TlsNotaryPlatformVerifierErrors::abi_decode(revert_data) {
            return Some(Self::TlsNotaryVerifier(e));
        }
        if let Ok(e) = GooglePlatformVerifierErrors::abi_decode(revert_data) {
            return Some(Self::GoogleVerifier(e));
        }
        if let Ok(e) = NotaryServiceErrors::abi_decode(revert_data) {
            return Some(Self::NotaryService(e));
        }
        if let Ok(e) = IHonkVerifierErrorsErrors::abi_decode(revert_data) {
            return Some(Self::HonkVerifier(e));
        }
        None
    }

    /// The error's Solidity name, e.g. `NotYourHandle`.
    pub fn name(&self) -> &'static str {
        let signature = self.signature();
        signature
            .split_once('(')
            .map_or(signature, |(name, _)| name)
    }

    /// The error's Solidity signature: `HandleNotProved(bytes32,bytes32)`.
    pub fn signature(&self) -> &'static str {
        match self {
            Self::Registry(e) => {
                IdentityRegistryErrors::signature_by_selector(e.selector())
            }
            Self::ProofVerifier(e) => {
                CeremonyProofVerifierErrors::signature_by_selector(e.selector())
            }
            Self::TlsNotaryVerifier(e) => {
                TlsNotaryPlatformVerifierErrors::signature_by_selector(e.selector())
            }
            Self::GoogleVerifier(e) => {
                GooglePlatformVerifierErrors::signature_by_selector(e.selector())
            }
            Self::NotaryService(e) => {
                NotaryServiceErrors::signature_by_selector(e.selector())
            }
            Self::HonkVerifier(e) => {
                IHonkVerifierErrorsErrors::signature_by_selector(e.selector())
            }
        }
        .unwrap_or("unknown")
    }
}

impl BindError {
    /// The contract whose error set decoded it.
    pub fn contract(&self) -> &'static str {
        match self {
            Self::Registry(_) => "IdentityRegistry",
            Self::ProofVerifier(_) => "CeremonyProofVerifier",
            Self::TlsNotaryVerifier(_) => "TlsNotaryPlatformVerifier",
            Self::GoogleVerifier(_) => "GooglePlatformVerifier",
            Self::NotaryService(_) => "NotaryService",
            Self::HonkVerifier(_) => "HonkVerifier",
        }
    }
}

/// Contract and signature; the generated enums carry no `Debug`.
impl std::fmt::Debug for BindError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}::{}", self.contract(), self.signature())
    }
}

impl std::fmt::Display for BindError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}

#[cfg(test)]
mod tests {
    use alloy::{
        primitives::{
            keccak256,
            B256,
            U256,
        },
        sol_types::SolValue,
    };

    use super::*;
    use crate::bindings::{
        ceremony::TlsNotaryPlatformVerifier,
        identity::IdentityRegistry,
    };

    /// Revert data built from the signature, independent of the bindings.
    fn revert(signature: &str, params: Vec<u8>) -> Vec<u8> {
        let mut data = keccak256(signature.as_bytes())[..4].to_vec();
        data.extend(params);
        data
    }

    const DISCLOSED: B256 = B256::repeat_byte(0xd1);
    const BOUND: B256 = B256::repeat_byte(0xe2);

    #[test]
    fn names_a_platform_verifier_refusal() {
        let data = revert(
            "HandleNotProved(bytes32,bytes32)",
            (DISCLOSED, BOUND).abi_encode_params(),
        );
        let error = BindError::decode(&data).expect("decodes");
        assert_eq!(error.name(), "HandleNotProved");
        assert_eq!(error.signature(), "HandleNotProved(bytes32,bytes32)");
        match error {
            BindError::TlsNotaryVerifier(
                TlsNotaryPlatformVerifier::TlsNotaryPlatformVerifierErrors::HandleNotProved(e),
            ) => {
                assert_eq!((e.disclosed, e.proved), (DISCLOSED, BOUND));
            }
            other => panic!("decoded as {other}"),
        }
    }

    #[test]
    fn names_a_registry_refusal() {
        let data = revert("NotYourHandle(bytes32)", (BOUND,).abi_encode_params());
        let error = BindError::decode(&data).expect("decodes");
        assert_eq!(error.name(), "NotYourHandle");
        match error {
            BindError::Registry(
                IdentityRegistry::IdentityRegistryErrors::NotYourHandle(e),
            ) => {
                assert_eq!(e.handleNode, BOUND);
            }
            other => panic!("decoded as {other}"),
        }
    }

    #[test]
    fn names_the_errors_of_every_contract_on_the_route() {
        let cases = [
            (
                "UnknownVersion",
                revert(
                    "UnknownVersion(bytes32,uint16)",
                    (BOUND, 1u16).abi_encode_params(),
                ),
            ),
            ("NoFramedCommitment", revert("NoFramedCommitment()", vec![])),
            (
                "UntrustedModulus",
                revert("UntrustedModulus(bytes32)", BOUND.abi_encode()),
            ),
            ("MalformedSignature", revert("MalformedSignature()", vec![])),
            (
                "UnknownPlatform",
                revert("UnknownPlatform(bytes32)", BOUND.abi_encode()),
            ),
        ];
        for (name, data) in cases {
            assert_eq!(BindError::decode(&data).expect(name).name(), name);
        }
    }

    /// bb's errors decode by name, fields included.
    #[test]
    fn names_a_honk_verifier_refusal() {
        let error =
            BindError::decode(&revert("SumcheckFailed()", vec![])).expect("decodes");
        assert_eq!(error.contract(), "HonkVerifier");
        assert_eq!(error.name(), "SumcheckFailed");

        let data = revert(
            "ProofLengthWrongWithLogN(uint256,uint256,uint256)",
            (U256::from(17), U256::from(100), U256::from(200)).abi_encode_params(),
        );
        match BindError::decode(&data).expect("decodes") {
            BindError::HonkVerifier(
                IHonkVerifierErrorsErrors::ProofLengthWrongWithLogN(e),
            ) => {
                assert_eq!(
                    (e.logN, e.actualLength, e.expectedLength),
                    (U256::from(17), U256::from(100), U256::from(200))
                );
            }
            other => panic!("decoded as {other}"),
        }
        assert_eq!(
            BindError::decode(&revert("MODEXP_FAILED()", vec![]))
                .expect("decodes")
                .name(),
            "MODEXP_FAILED"
        );
    }

    /// A selector no contract on the route declares decodes to nothing.
    #[test]
    fn an_undeclared_selector_decodes_to_none() {
        assert!(BindError::decode(&revert("NoSuchError()", vec![])).is_none());
        assert!(BindError::decode(&[]).is_none());
    }
}
