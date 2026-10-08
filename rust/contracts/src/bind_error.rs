//! A refused `bind`, decoded by name.
//!
//! `IdentityRegistry.bind` reverts with whatever the contract on its route
//! that refused it raised: the registry, the Proof Verifier it dispatches to,
//! the Platform Verifier the version routes to, or the Notary Service a
//! notarized session is authenticated through. A revert passes through every
//! hop unchanged, so [`BindError::decode`] tries each one's error set, in the
//! order the call reaches them. TypeScript's `bindErrorsAbi` carries the same
//! sets.
//!
//! The Honk verifiers are not on the list: bb's generated code reverts from
//! assembly with selectors no ABI declares, so their failures decode to
//! `None`.

use alloy::sol_types::SolInterface;

use crate::bindings::{
    ceremony::{
        CeremonyProofVerifier::CeremonyProofVerifierErrors,
        GooglePlatformVerifier::GooglePlatformVerifierErrors,
        NotaryService::NotaryServiceErrors,
        TlsNotaryPlatformVerifier::TlsNotaryPlatformVerifierErrors,
    },
    identity::IdentityRegistry::IdentityRegistryErrors,
};

/// A `bind` revert, decoded by the first contract on the route whose error
/// set declares its selector. An error several contracts declare
/// (`UnknownPlatform`, `WrongValue`) decodes as the first one's; its name
/// and fields are the same whichever raised it.
pub enum BindError {
    /// `IdentityRegistry`: the binding rules, the disclosure check, an
    /// unknown platform.
    Registry(IdentityRegistryErrors),
    /// `CeremonyProofVerifier`: no verifier for the pair, the wrong value.
    ProofVerifier(CeremonyProofVerifierErrors),
    /// `XPlatformVerifier` or `GitHubPlatformVerifier`: the transcripts, the
    /// proof, the disclosed handle.
    TlsNotaryVerifier(TlsNotaryPlatformVerifierErrors),
    /// `GooglePlatformVerifier`: the ID token, the proof, the disclosed
    /// address.
    GoogleVerifier(GooglePlatformVerifierErrors),
    /// `NotaryService`: the attestation's encoding and signature, the fee.
    NotaryService(NotaryServiceErrors),
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
        None
    }

    /// The error's name, as Solidity declares it: `HandleNotProved`,
    /// `DisclosureMismatch`.
    pub fn name(&self) -> &'static str {
        // Every variant was decoded from a selector its set declares, so
        // the lookup always answers.
        match self {
            Self::Registry(e) => IdentityRegistryErrors::name_by_selector(e.selector()),
            Self::ProofVerifier(e) => {
                CeremonyProofVerifierErrors::name_by_selector(e.selector())
            }
            Self::TlsNotaryVerifier(e) => {
                TlsNotaryPlatformVerifierErrors::name_by_selector(e.selector())
            }
            Self::GoogleVerifier(e) => {
                GooglePlatformVerifierErrors::name_by_selector(e.selector())
            }
            Self::NotaryService(e) => NotaryServiceErrors::name_by_selector(e.selector()),
        }
        .unwrap_or("unknown")
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
        }
    }
}

/// The generated error enums carry no `Debug`, so this names the error by
/// its contract and signature; match the variant for its fields.
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
        },
        sol_types::SolValue,
    };

    use super::*;
    use crate::bindings::{
        ceremony::TlsNotaryPlatformVerifier,
        identity::IdentityRegistry,
    };

    /// Revert data built from the Solidity signature itself, not from the
    /// bindings under test, so the two cannot agree by sharing a mistake.
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
        let data = revert(
            "DisclosureMismatch(bytes32,bytes32)",
            (DISCLOSED, BOUND).abi_encode_params(),
        );
        let error = BindError::decode(&data).expect("decodes");
        assert_eq!(error.name(), "DisclosureMismatch");
        match error {
            BindError::Registry(
                IdentityRegistry::IdentityRegistryErrors::DisclosureMismatch(e),
            ) => {
                assert_eq!((e.disclosed, e.bound), (DISCLOSED, BOUND));
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

    /// A selector no contract on the route declares decodes to nothing,
    /// as bb's `SumcheckFailed()` does.
    #[test]
    fn an_undeclared_selector_decodes_to_none() {
        assert!(BindError::decode(&revert("SumcheckFailed()", vec![])).is_none());
        assert!(BindError::decode(&[]).is_none());
    }
}
