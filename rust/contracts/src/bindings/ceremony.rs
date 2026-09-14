//! Bindings for the ceremony verification path (`solidity/contracts/ceremony/`):
//! the Notary Service every notarized session is authenticated through, the
//! Proof Verifier that routes a claim to the Platform Verifier registered for
//! its version, the three launch Platform Verifiers it routes to, and the
//! Google JWT root list the `google/v1` verifier reads.
//!
//! `verify` is on none of the Platform Verifier interfaces, for the reason it
//! is on neither `NotaryService` nor `CeremonyProofVerifier`: a contract on
//! the route calls it with the fee attached, and the decoded claim comes back
//! to that contract. What an operator does from here is initialize, rotate
//! the trust roots and move the governance parameters — see
//! [`platform_verifier`](crate::platform_verifier) for the initializer that
//! checks the rules first.

/// Bindings for `ceremony/NotaryService.sol` (which implements
/// `INotaryService`).
///
/// Authenticates one attestation and charges one fee for it. The digest is
/// derived from the attested bytes on chain, never taken from the caller
/// (REQ-COMMON-33), which is why `verify` is not on this interface: a
/// consumer contract calls it with the fee attached, and the decoded record
/// comes back to that contract, not to an off-chain reader. What an operator
/// does from here is hold the trusted key set, set the fee and withdraw what
/// accrued.
#[allow(clippy::too_many_arguments, unused_attributes)]
mod notary_service_inner {
    use alloy::sol;

    sol! {
        #[sol(rpc)]
        interface NotaryService {
            /// `notary_` is the first trusted key; `fee_` may be zero (a
            /// deployment may meter at no charge, and the exact-value rule
            /// still applies).
            function initialize(address owner_, address notary_, uint256 fee_) external;
            /// What one verification costs, in the chain's native asset.
            /// Readable before a submission is built, so it can be bounded.
            function fee() external view returns (uint256);
            function setFee(uint256 fee_) external;
            /// Add or remove a trusted notary key. Several are held at once so
            /// a rotation can overlap: add the incoming key, remove the
            /// outgoing one once nothing can still present under it.
            function setNotary(address key, bool trusted_) external;
            function isTrustedNotary(address key) external view returns (bool);
            /// Fees accrue here rather than being forwarded per verification.
            function withdraw(address to, uint256 amount) external;

            function owner() external view returns (address);
            function pendingOwner() external view returns (address);
            function transferOwnership(address newOwner) external;
            function acceptOwnership() external;

            event FeeChanged(uint256 previousFee, uint256 newFee);
            event NotaryTrustChanged(address indexed key, bool trusted);
            event FeesWithdrawn(address indexed to, uint256 amount);
        }
    }
}

pub use notary_service_inner::NotaryService;

/// Bindings for `ceremony/CeremonyProofVerifier.sol` (which implements
/// `IProofVerifier`).
///
/// The Supported Version Set: which Platform Verifier answers for a
/// `(platformId, verifierVersion)` pair. Governance registers one with
/// `setVerifier`; `IdentityNames.claim` dispatches through `verify`, which is
/// not on this interface for the same reason `NotaryService.verify` is not —
/// it is called by the consumer contract with the fee attached.
#[allow(clippy::too_many_arguments, unused_attributes)]
mod proof_verifier_inner {
    use alloy::sol;

    sol! {
        #[sol(rpc)]
        interface CeremonyProofVerifier {
            function initialize(address owner_) external;
            /// Register (or, with the zero address, remove) the Platform
            /// Verifier for a pair. The verifier must serve `platformId`.
            function setVerifier(bytes32 platformId, uint16 verifierVersion, address verifier) external;
            /// The Platform Verifier registered for a pair, or zero.
            function verifierOf(bytes32 platformId, uint16 verifierVersion) external view returns (address);
            /// What one claim under this pair costs: the registered
            /// verifier's quote, forwarded whole.
            function quote(bytes32 platformId, uint16 verifierVersion) external view returns (uint256);
            /// Whether any version is registered for the platform at all.
            function verifiesPlatform(bytes32 platformId) external view returns (bool);
            /// This chain's identifier, as the digest construction takes it.
            function chainId() external view returns (bytes32);

            function owner() external view returns (address);
            function pendingOwner() external view returns (address);
            function transferOwnership(address newOwner) external;
            function acceptOwnership() external;

            event VerifierConfigured(bytes32 indexed platformId, uint16 indexed verifierVersion, address verifier);
        }
    }
}

pub use proof_verifier_inner::CeremonyProofVerifier;

/// Bindings for `ceremony/GoogleJwtRoots.sol` — the signing keys the
/// `google/v1` Platform Verifier trusts, and until when. Starts EMPTY:
/// Google names bind only once a notarized reading of Google's JWKS has
/// landed here.
///
/// The list is two generations of Google's key set and nothing else:
/// `current` is the latest reading applied, `previous` the reading before
/// it, kept for the tokens still in flight under a key Google has since
/// dropped. A newer reading of the same set restarts `current`'s clock
/// (`ReadingRefreshed`); a newer reading of a different set shifts `current`
/// into `previous` and drops what `previous` held (`KeysRotated`). A
/// generation is trusted until `READING_LIFETIME` after its reading's own
/// `createdAt`, so there is nothing to prune or untrust by hand.
///
/// A rotation is an ordinary notarized session: the keeper reveals the whole
/// `GET /oauth2/v3/certs` exchange, `rotate` hands the attested bytes and the
/// notary's proof to the Notary Service with the Notary Fee attached (read
/// it with `quoteRotation`, which is the service's `fee()`), and the contract
/// reads the JWKS out of the transcript it vouched for.
#[allow(clippy::too_many_arguments, unused_attributes)]
mod google_jwt_roots_inner {
    use alloy::sol;

    sol! {
        #[sol(rpc)]
        interface GoogleJwtRoots {
            /// One reading of Google's key set: the notary's clock, and the
            /// limb hash of every modulus it listed, in Google's order.
            #[derive(Debug, serde::Serialize, serde::Deserialize)]
            struct Generation {
                uint64 observedAt;
                bytes32[] moduli;
            }

            function initialize(address owner_, address notary_) external;
            /// The Notary Service a rotation is verified through.
            function notaryService() external view returns (address);
            function setNotaryService(address notary_) external;
            /// What one rotation costs beyond gas: the Notary Fee, forwarded
            /// whole. `rotate` must be sent with exactly this value.
            function quoteRotation() external view returns (uint256);
            /// Permissionless. `attestedData` is the ceremony-common section
            /// 9.1 record of the JWKS session, `proof` the notary's
            /// authentication of it (a 65-byte EIP-191 signature today). A
            /// reading dated no later than the current generation is refused
            /// with `NotNewer(createdAt, observedAt)`, and the revert hands
            /// the fee back.
            function rotate(bytes calldata attestedData, bytes calldata proof) external payable;

            /// What `GooglePlatformVerifier` reads: modulus hash -> when it
            /// stops being trusted, zero when neither generation lists it.
            function trustedHashExpiresAt(bytes32 modulusHash) external view returns (uint256);
            /// Both generations, as stored.
            function currentKeys() external view returns (Generation memory current, Generation memory previous);
            /// The current generation's `observedAt`: the notary's clock on
            /// the reading in force.
            function freshestObservedAt() external view returns (uint256);
            /// True until the current generation is guaranteed trusted
            /// `RENEWAL_MARGIN` from now; true on an empty list.
            function needsRotation() external view returns (bool);
            function READING_LIFETIME() external view returns (uint256);
            function RENEWAL_MARGIN() external view returns (uint256);
            function MAX_KEYS() external view returns (uint256);

            function owner() external view returns (address);
            function pendingOwner() external view returns (address);
            function transferOwnership(address newOwner) external;
            function acceptOwnership() external;

            event NotaryServiceChanged(address notary);
            /// A different set landed: `kids` and `moduli` in the order
            /// Google listed them, `observedAt` the notary's clock.
            event KeysRotated(uint64 observedAt, string[] kids, bytes32[] moduli);
            /// A newer reading of the set already current.
            event ReadingRefreshed(uint64 observedAt);
        }
    }
}

pub use google_jwt_roots_inner::GoogleJwtRoots;

/// Bindings for the two TLSNotary Platform Verifiers, `ceremony/XPlatformVerifier.sol`
/// and `ceremony/GitHubPlatformVerifier.sol`. One interface serves both: they
/// differ in the revealed layout they accept, not in the surface an operator
/// touches, and each answers for itself through `platformId()`. The same
/// module is exported as [`XPlatformVerifier`] and [`GitHubPlatformVerifier`],
/// so a consumer names the contract it means.
///
/// The initializer takes what `PlatformVerifierBase.__PlatformVerifierBase_init`
/// takes. `notary_` is required here (nonzero): a TLSNotary profile
/// authenticates two attestations through it, and the base refuses a zero
/// address for a profile whose Attestation Count is nonzero
/// (`WrongNotaryForProfile`). `honkVerifierCodehash_` must equal
/// `address(honkVerifier_).codehash` and be neither zero nor `keccak256("")`
/// (`WrongVerifierArtifact`); the three parameters are capped by the `MAX_*`
/// constants (`ParameterTooLarge`).
#[allow(clippy::too_many_arguments, unused_attributes)]
mod tls_notary_platform_verifier_inner {
    use alloy::sol;

    sol! {
        #[sol(rpc)]
        interface TlsNotaryPlatformVerifier {
            /// Derives so the built call can be compared and printed by the
            /// initializer that assembles it.
            #[derive(Debug, PartialEq, Eq)]
            function initialize(
                address owner_,
                address notary_,
                address honkVerifier_,
                bytes32 honkVerifierCodehash_,
                uint64 proofLifetime_,
                uint64 maxFutureAttestationSkew_,
                uint64 futureObservationAllowance_
            ) external;

            /// The identity platform this verifier serves: `keccak256` of the
            /// platform's bare name. The Proof Verifier refuses to register it
            /// under another platform.
            function platformId() external view returns (bytes32);
            /// What a submission must carry: one Notary Fee per attestation
            /// the profile requires — two, for a TLSNotary profile.
            function quote() external view returns (uint256);

            function notaryService() external view returns (address);
            function honkVerifier() external view returns (address);
            /// The code hash of the artifact wired: the only handle on WHICH
            /// circuit a deployed bb verifier answers for.
            function honkVerifierCodehash() external view returns (bytes32);
            function protocolParameters()
                external
                view
                returns (uint64 proofLifetime, uint64 maxFutureAttestationSkew, uint64 futureObservationAllowance);
            /// Rotate the trust roots. The same rules as `initialize`: the
            /// code hash names the artifact, and the call fails if the
            /// address does not hold it.
            function setTrustRoots(address notary_, address honkVerifier_, bytes32 honkVerifierCodehash_) external;
            function setProtocolParameters(
                uint64 proofLifetime_,
                uint64 maxFutureAttestationSkew_,
                uint64 futureObservationAllowance_
            ) external;

            /// Ceilings on the three parameters, in seconds.
            function MAX_PROOF_LIFETIME() external view returns (uint64);
            function MAX_FUTURE_ATTESTATION_SKEW() external view returns (uint64);
            function MAX_FUTURE_OBSERVATION_ALLOWANCE() external view returns (uint64);

            function owner() external view returns (address);
            function pendingOwner() external view returns (address);
            function transferOwnership(address newOwner) external;
            function acceptOwnership() external;

            event TrustRootsChanged(address notary, address honkVerifier, bytes32 honkVerifierCodehash);
            event ProtocolParametersChanged(
                uint64 proofLifetime, uint64 maxFutureAttestationSkew, uint64 futureObservationAllowance
            );

            /// A profile that verifies no attestation holds a Notary Service,
            /// or one that verifies some holds none.
            error WrongNotaryForProfile(bytes32 platformId, address notary);
            error ParameterTooLarge(uint64 provided, uint64 limit);
            error ZeroAddress();
            /// The verifier at that address is not the artifact named.
            error WrongVerifierArtifact(bytes32 expected, bytes32 found);
        }
    }
}

pub use tls_notary_platform_verifier_inner::{
    TlsNotaryPlatformVerifier,
    TlsNotaryPlatformVerifier as GitHubPlatformVerifier,
    TlsNotaryPlatformVerifier as XPlatformVerifier,
};

/// Bindings for `ceremony/GooglePlatformVerifier.sol` — the `google/v1`
/// profile.
///
/// A different shape from the other two: no notarized session, so no Notary
/// Service, no fee, no proof lifetime and no attestation skew. The evidence
/// is a signed ID Token whose `exp` is the whole validity ceiling, and the
/// signing keys it trusts are read from `GoogleJwtRoots`.
///
/// `notary_` must therefore be the ZERO address: the base refuses a Notary
/// Service for a profile whose Attestation Count is zero
/// (`WrongNotaryForProfile`), because `notaryService()` would otherwise
/// report a collaborator nothing on this path calls. `jwtRoots_` must be
/// nonzero (`ZeroAddress`). The code hash and the allowance follow the same
/// rules as the TLSNotary verifiers'; the lifetime and skew read back as
/// zero.
#[allow(clippy::too_many_arguments, unused_attributes)]
mod google_platform_verifier_inner {
    use alloy::sol;

    sol! {
        #[sol(rpc)]
        interface GooglePlatformVerifier {
            #[derive(Debug, PartialEq, Eq)]
            function initialize(
                address owner_,
                address notary_,
                address honkVerifier_,
                bytes32 honkVerifierCodehash_,
                uint64 futureObservationAllowance_,
                address jwtRoots_
            ) external;

            /// `keccak256("google")`.
            function platformId() external view returns (bytes32);
            /// Always zero: the profile verifies nothing that charges, and
            /// `verify` refuses any value sent.
            function quote() external view returns (uint256);

            /// The root list the trusted moduli are read through.
            function jwtRoots() external view returns (address);
            function setJwtRoots(address roots) external;

            function notaryService() external view returns (address);
            function honkVerifier() external view returns (address);
            function honkVerifierCodehash() external view returns (bytes32);
            function protocolParameters()
                external
                view
                returns (uint64 proofLifetime, uint64 maxFutureAttestationSkew, uint64 futureObservationAllowance);
            function setTrustRoots(address notary_, address honkVerifier_, bytes32 honkVerifierCodehash_) external;
            function setProtocolParameters(
                uint64 proofLifetime_,
                uint64 maxFutureAttestationSkew_,
                uint64 futureObservationAllowance_
            ) external;

            function MAX_PROOF_LIFETIME() external view returns (uint64);
            function MAX_FUTURE_ATTESTATION_SKEW() external view returns (uint64);
            function MAX_FUTURE_OBSERVATION_ALLOWANCE() external view returns (uint64);

            function owner() external view returns (address);
            function pendingOwner() external view returns (address);
            function transferOwnership(address newOwner) external;
            function acceptOwnership() external;

            event JwtRootsChanged(address roots);
            event TrustRootsChanged(address notary, address honkVerifier, bytes32 honkVerifierCodehash);
            event ProtocolParametersChanged(
                uint64 proofLifetime, uint64 maxFutureAttestationSkew, uint64 futureObservationAllowance
            );

            error WrongNotaryForProfile(bytes32 platformId, address notary);
            error ParameterTooLarge(uint64 provided, uint64 limit);
            error ZeroAddress();
            error WrongVerifierArtifact(bytes32 expected, bytes32 found);
        }
    }
}

pub use google_platform_verifier_inner::GooglePlatformVerifier;

#[cfg(test)]
mod tests {
    use alloy::sol_types::SolCall;

    use super::*;
    use crate::Artifacts;

    /// A Platform Verifier binding and its vendored artifact come from one
    /// tree, so every bound selector is one the compiled contract answers.
    /// The initializer is the one that matters: an `initialize` the proxy's
    /// implementation has no function for reaches its fallback, and the
    /// proxy is left uninitialized for anyone to claim.
    #[test]
    fn every_bound_platform_verifier_selector_exists_in_its_artifact() {
        let artifacts = Artifacts::embedded();
        let check = |contract: &str, sig: &str, selector: [u8; 4]| {
            let methods = artifacts.method_identifiers(contract).unwrap();
            let found = methods
                .get(sig)
                .unwrap_or_else(|| panic!("{contract} has no {sig}"));
            assert_eq!(*found, alloy::hex::encode(selector), "{contract}.{sig}");
        };

        macro_rules! bound {
            ($contract:expr, $iface:ident, [$($call:ident),* $(,)?]) => {
                $(check($contract, $iface::$call::SIGNATURE, $iface::$call::SELECTOR);)*
            };
        }

        for contract in ["XPlatformVerifier", "GitHubPlatformVerifier"] {
            bound!(
                contract,
                TlsNotaryPlatformVerifier,
                [
                    initializeCall,
                    platformIdCall,
                    quoteCall,
                    notaryServiceCall,
                    honkVerifierCall,
                    honkVerifierCodehashCall,
                    protocolParametersCall,
                    setTrustRootsCall,
                    setProtocolParametersCall,
                    MAX_PROOF_LIFETIMECall,
                    MAX_FUTURE_ATTESTATION_SKEWCall,
                    MAX_FUTURE_OBSERVATION_ALLOWANCECall,
                    ownerCall,
                    pendingOwnerCall,
                    transferOwnershipCall,
                    acceptOwnershipCall,
                ]
            );
        }
        bound!(
            "GooglePlatformVerifier",
            GooglePlatformVerifier,
            [
                initializeCall,
                platformIdCall,
                quoteCall,
                jwtRootsCall,
                setJwtRootsCall,
                notaryServiceCall,
                honkVerifierCall,
                honkVerifierCodehashCall,
                protocolParametersCall,
                setTrustRootsCall,
                setProtocolParametersCall,
                MAX_PROOF_LIFETIMECall,
                MAX_FUTURE_ATTESTATION_SKEWCall,
                MAX_FUTURE_OBSERVATION_ALLOWANCECall,
                ownerCall,
                pendingOwnerCall,
                transferOwnershipCall,
                acceptOwnershipCall,
            ]
        );

        // The two initializers differ in shape, and the artifacts say so:
        // the TLSNotary one is not on Google's contract, nor the reverse.
        assert_ne!(
            TlsNotaryPlatformVerifier::initializeCall::SELECTOR,
            GooglePlatformVerifier::initializeCall::SELECTOR
        );
        let google = artifacts
            .method_identifiers("GooglePlatformVerifier")
            .unwrap();
        assert!(
            !google.contains_key(TlsNotaryPlatformVerifier::initializeCall::SIGNATURE)
        );
        let x = artifacts.method_identifiers("XPlatformVerifier").unwrap();
        assert!(!x.contains_key(GooglePlatformVerifier::initializeCall::SIGNATURE));
    }
}
