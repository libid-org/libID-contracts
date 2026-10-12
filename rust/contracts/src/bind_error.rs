//! A refused `bind`, decoded by name.
//!
//! A revert passes unchanged through every contract on the `bind` route, so
//! [`BindError::decode`] tries each one's error set in call order, the Honk
//! verifier (`IHonkVerifierErrors`) last, then a Solidity `Panic`.
//! TypeScript's `bindErrorsAbi` has the same sets.

use alloy::{
    primitives::U256,
    sol_types::{
        Panic,
        SolError,
        SolInterface,
    },
};

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

/// A `bind` revert, decoded by the first error set on the route that
/// declares its selector. Many selectors are declared by several contracts,
/// so the variant names the error set, not the contract that reverted;
/// [`BindError::contracts`] lists every contract that could have.
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
    /// A Solidity `Panic(uint256)`, with its code: a failed `assert`, an
    /// overflow, an index out of bounds, in any contract on the route.
    Panic(U256),
}

impl BindError {
    /// The error `revert_data` encodes, or `None` when no contract on the
    /// route declares its selector or its fields do not decode.
    pub fn decode(revert_data: &[u8]) -> Option<Self> {
        ROUTE
            .iter()
            .find_map(|(_, _, decode)| decode(revert_data))
            .or_else(|| {
                Panic::abi_decode(revert_data)
                    .ok()
                    .map(|p| Self::Panic(p.code))
            })
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
            Self::Panic(_) => Some(Panic::SIGNATURE),
        }
        .unwrap_or("unknown")
    }
}

/// Whether an error set declares a selector.
type Declares = fn([u8; 4]) -> bool;

/// Revert data as one error set's error, if that set declares it.
type Decode = fn(&[u8]) -> Option<BindError>;

/// The route's error sets, in the order `decode` tries them.
const ROUTE: [(&str, Declares, Decode); 6] = [
    (
        "IdentityRegistry",
        IdentityRegistryErrors::valid_selector,
        |d| {
            IdentityRegistryErrors::abi_decode(d)
                .ok()
                .map(BindError::Registry)
        },
    ),
    (
        "CeremonyProofVerifier",
        CeremonyProofVerifierErrors::valid_selector,
        |d| {
            CeremonyProofVerifierErrors::abi_decode(d)
                .ok()
                .map(BindError::ProofVerifier)
        },
    ),
    (
        "TlsNotaryPlatformVerifier",
        TlsNotaryPlatformVerifierErrors::valid_selector,
        |d| {
            TlsNotaryPlatformVerifierErrors::abi_decode(d)
                .ok()
                .map(BindError::TlsNotaryVerifier)
        },
    ),
    (
        "GooglePlatformVerifier",
        GooglePlatformVerifierErrors::valid_selector,
        |d| {
            GooglePlatformVerifierErrors::abi_decode(d)
                .ok()
                .map(BindError::GoogleVerifier)
        },
    ),
    ("NotaryService", NotaryServiceErrors::valid_selector, |d| {
        NotaryServiceErrors::abi_decode(d)
            .ok()
            .map(BindError::NotaryService)
    }),
    (
        "HonkVerifier",
        IHonkVerifierErrorsErrors::valid_selector,
        |d| {
            IHonkVerifierErrorsErrors::abi_decode(d)
                .ok()
                .map(BindError::HonkVerifier)
        },
    ),
];

impl BindError {
    /// Every contract on the route that declares this error, or for a
    /// `Panic` every contract on it. A revert does not say which one raised it.
    pub fn contracts(&self) -> Vec<&'static str> {
        let selector = self.selector();
        ROUTE
            .iter()
            .filter(|(_, declares, _)| {
                matches!(self, Self::Panic(_)) || declares(selector)
            })
            .map(|(name, ..)| *name)
            .collect()
    }

    fn selector(&self) -> [u8; 4] {
        match self {
            Self::Registry(e) => e.selector(),
            Self::ProofVerifier(e) => e.selector(),
            Self::TlsNotaryVerifier(e) => e.selector(),
            Self::GoogleVerifier(e) => e.selector(),
            Self::NotaryService(e) => e.selector(),
            Self::HonkVerifier(e) => e.selector(),
            Self::Panic(_) => Panic::SELECTOR,
        }
    }
}

/// Candidate contracts and signature; the generated enums carry no `Debug`.
impl std::fmt::Debug for BindError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}::{}", self.contracts().join("|"), self.signature())
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
        assert_eq!(error.contracts(), ["HonkVerifier"]);
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

    /// A selector several contracts declare names them all, not the first.
    #[test]
    fn a_shared_error_names_every_contract_that_declares_it() {
        let data = revert("UnknownPlatform(bytes32)", BOUND.abi_encode());
        let error = BindError::decode(&data).expect("decodes");
        assert_eq!(
            error.contracts(),
            [
                "IdentityRegistry",
                "TlsNotaryPlatformVerifier",
                "GooglePlatformVerifier"
            ]
        );
        let data = revert("NotYourHandle(bytes32)", BOUND.abi_encode());
        assert_eq!(
            BindError::decode(&data).expect("decodes").contracts(),
            ["IdentityRegistry"]
        );
    }

    /// A selector no contract on the route declares decodes to nothing.
    #[test]
    fn an_undeclared_selector_decodes_to_none() {
        assert!(BindError::decode(&revert("NoSuchError()", vec![])).is_none());
        assert!(BindError::decode(&[]).is_none());
    }

    /// TypeScript's `bindErrorsAbi` is built from `bindRoute` in
    /// `codegen.mjs`. It lists the same contracts in `ROUTE`'s order, which
    /// is the order `decode` tries, with X's and GitHub's verifiers under the
    /// one binding.
    #[test]
    fn the_typescript_bind_route_is_the_one_decode_tries() {
        let codegen = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../ts/packages/contracts/scripts/codegen.mjs"
        ))
        .expect("codegen.mjs");
        let (_, route) = codegen
            .split_once("const bindRoute = [")
            .expect("bindRoute");
        let (route, _) = route.split_once("\n]").expect("the end of bindRoute");
        let ts: Vec<&str> = route.lines().filter_map(|l| l.split('\'').nth(3)).collect();

        let rust: Vec<&str> = ROUTE
            .iter()
            .flat_map(|(name, ..)| match *name {
                "TlsNotaryPlatformVerifier" => {
                    vec!["XPlatformVerifier", "GitHubPlatformVerifier"]
                }
                "HonkVerifier" => vec!["IHonkVerifierErrors"],
                other => vec![other],
            })
            .collect();
        assert_eq!(rust, ts);
    }

    /// A compiler panic decodes with its code, whichever contract raised it.
    #[test]
    fn names_a_panic() {
        let data = revert("Panic(uint256)", U256::from(0x11).abi_encode());
        let error = BindError::decode(&data).expect("decodes");
        assert_eq!(error.name(), "Panic");
        assert_eq!(error.signature(), "Panic(uint256)");
        assert!(matches!(error, BindError::Panic(code) if code == U256::from(0x11)));
        assert_eq!(error.contracts().len(), ROUTE.len());
    }
}
