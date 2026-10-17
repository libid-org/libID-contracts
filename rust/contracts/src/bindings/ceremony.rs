//! Bindings for the ceremony verification path (`solidity/contracts/ceremony/`):
//! the Notary Service every notarized session is authenticated through, the
//! Proof Verifier that routes a claim to the Platform Verifier registered for
//! its version, the three launch Platform Verifiers, and the Google JWT root
//! list the `google/v1` verifier reads.
//!
//! `verify` is on none of these interfaces: a contract on the route calls it
//! with the fee attached and receives the decoded claim.
//! [`platform_verifier`](crate::platform_verifier) checks a Platform Verifier
//! initializer before it is sent.

/// Bindings for `ceremony/NotaryService.sol`, an `INotaryService`.
///
/// Authenticates one attestation and charges one fee for it. The digest is
/// derived on chain from the attested bytes, never taken from the caller
/// (REQ-COMMON-33). The operator holds the trusted key set, sets the fee and
/// withdraws what accrued.
#[allow(clippy::too_many_arguments, unused_attributes)]
mod notary_service_inner {
    use alloy::sol;

    sol! {
        #[sol(rpc, abi)]
        interface NotaryService {
            /// `notary_` is the first trusted key. `fee_` may be zero; the
            /// exact-value rule still applies.
            function initialize(address owner_, address notary_, uint256 fee_) external;
            /// What one verification costs, in the chain's native asset.
            function fee() external view returns (uint256);
            function setFee(uint256 fee_) external;
            /// Add or remove a trusted notary key. To rotate, add the incoming
            /// key and remove the outgoing one once nothing presents under it.
            function setNotary(address key, bool trusted_) external;
            function isTrustedNotary(address key) external view returns (bool);
            /// Pay out fees, which accrue here per verification.
            function withdraw(address to, uint256 amount) external;

            function owner() external view returns (address);
            function pendingOwner() external view returns (address);
            function transferOwnership(address newOwner) external;
            function acceptOwnership() external;

            event FeeChanged(uint256 previousFee, uint256 newFee);
            event NotaryTrustChanged(address indexed key, bool trusted);
            event FeesWithdrawn(address indexed to, uint256 amount);

            // What `verify` and the operator calls can revert with.
            error WrongFee(uint256 required, uint256 provided);
            error UntrustedNotary(address recovered);
            error MalformedSignature();
            error Truncated();
            error TrailingBytes(uint256 extra);
            error EmptyRange(uint32 at);
            error OutOfOrder(uint32 start, uint32 previousEnd);
            error PastTranscriptEnd(uint32 end, uint32 length);
            error CommitmentOverlapsRevealed(uint32 start, uint32 end);
            error ZeroAddress();
            error NothingToWithdraw();
            error WithdrawalFailed(address to, uint256 amount);
            error OwnableUnauthorizedAccount(address account);
            error OwnableInvalidOwner(address owner);
        }
    }
}

pub use notary_service_inner::NotaryService;

/// Bindings for `ceremony/CeremonyProofVerifier.sol`, an `IProofVerifier`.
///
/// The Supported Version Set: which Platform Verifier answers for a
/// `(platformId, verifierVersion)` pair. Governance registers one with
/// `setVerifier`; `IdentityRegistry.bind` dispatches through `verify`.
#[allow(clippy::too_many_arguments, unused_attributes)]
mod proof_verifier_inner {
    use alloy::sol;

    sol! {
        #[sol(rpc, abi)]
        interface CeremonyProofVerifier {
            function initialize(address owner_) external;
            /// Register the Platform Verifier for a pair, or remove it with the
            /// zero address. The verifier must serve `platformId`.
            function setVerifier(bytes32 platformId, uint16 verifierVersion, address verifier) external;
            /// The Platform Verifier registered for a pair, or zero.
            function verifierOf(bytes32 platformId, uint16 verifierVersion) external view returns (address);
            /// What one claim under this pair costs: the registered
            /// verifier's quote, forwarded whole.
            function quote(bytes32 platformId, uint16 verifierVersion) external view returns (uint256);
            /// Whether any version is registered for the platform.
            function verifiesPlatform(bytes32 platformId) external view returns (bool);
            /// This chain's identifier, as the digest construction takes it.
            function chainId() external view returns (bytes32);

            function owner() external view returns (address);
            function pendingOwner() external view returns (address);
            function transferOwnership(address newOwner) external;
            function acceptOwnership() external;

            event VerifierConfigured(bytes32 indexed platformId, uint16 indexed verifierVersion, address verifier);

            /// No Platform Verifier is registered for the pair a `bind` named.
            error UnknownVersion(bytes32 platformId, uint16 verifierVersion);
            /// `setVerifier` was handed a verifier serving another platform.
            error VerifierPlatformMismatch(bytes32 expected, bytes32 found);
            /// The value attached is not the pair's quote.
            error WrongValue(uint256 required, uint256 provided);
            error OwnableUnauthorizedAccount(address account);
            error OwnableInvalidOwner(address owner);
        }
    }
}

pub use proof_verifier_inner::CeremonyProofVerifier;

/// Bindings for `ceremony/GoogleJwtRoots.sol`: the signing keys the
/// `google/v1` Platform Verifier trusts, and until when. It starts empty, so
/// Google bindings fail until the first notarized reading of Google's JWKS.
///
/// It holds two generations: `current`, the latest reading, and `previous`,
/// kept for tokens issued under a key Google has since dropped. A newer
/// reading of the same set restarts `current`'s clock (`ReadingRefreshed`).
/// A different set shifts `current` into `previous` (`KeysRotated`). A
/// generation is trusted until `READING_LIFETIME` after its reading's
/// `createdAt`, so nothing is pruned by hand.
///
/// `rotate` takes a notarized `GET /oauth2/v3/certs` exchange, verifies it
/// through the Notary Service with the fee `quoteRotation` returns, and reads
/// the JWKS from the transcript.
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
            /// Permissionless. `attestedData` is the platform-ceremonies
            /// section 4.1 record of the JWKS session, `proof` the notary's
            /// authentication of it. A reading no newer than the current
            /// generation reverts `NotNewer(createdAt, observedAt)`.
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
/// and `ceremony/GitHubPlatformVerifier.sol`. They differ only in the revealed
/// layout they accept, so one interface serves both, exported as
/// [`XPlatformVerifier`] and [`GitHubPlatformVerifier`].
///
/// The initializer takes what `PlatformVerifierBase.__PlatformVerifierBase_init`
/// takes. `notary_` must be nonzero, since a TLSNotary profile authenticates
/// two attestations (`WrongNotaryForProfile`). `honkVerifier_` must hold the
/// code hash `circuitCodehash()` names (`WrongCircuit`). The validity window
/// is the profile's, compiled in; `protocolParameters()` reads it.
#[allow(clippy::too_many_arguments, unused_attributes)]
mod tls_notary_platform_verifier_inner {
    use alloy::sol;

    sol! {
        #[sol(rpc, abi)]
        interface TlsNotaryPlatformVerifier {
            /// Comparable and printable, for the initializer that builds it.
            #[derive(Debug, PartialEq, Eq)]
            function initialize(address owner_, address notary_, address honkVerifier_) external;

            /// The identity platform this verifier serves: `keccak256` of the
            /// platform's bare name. The Proof Verifier refuses to register it
            /// under another platform.
            function platformId() external pure returns (bytes32);
            /// What a submission must carry: one Notary Fee per attestation
            /// the profile requires, two for a TLSNotary profile.
            function quote() external view returns (uint256);

            function notaryService() external view returns (address);
            function honkVerifier() external view returns (address);
            /// The runtime code hash of the one Honk verifier this contract
            /// accepts: its platform's circuit's, as compiled in.
            function circuitCodehash() external pure returns (bytes32);
            function protocolParameters()
                external
                pure
                returns (uint64 proofLifetime, uint64 maxFutureAttestationSkew, uint64 futureObservationAllowance);
            /// Rotate the trust roots, under the same rules as `initialize`.
            function setTrustRoots(address notary_, address honkVerifier_) external;

            function owner() external view returns (address);
            function pendingOwner() external view returns (address);
            function transferOwnership(address newOwner) external;
            function acceptOwnership() external;
            /// Always reverts.
            function renounceOwnership() external pure;

            event TrustRootsChanged(address notary, address honkVerifier);
            event OwnershipTransferStarted(address indexed previousOwner, address indexed newOwner);
            event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

            /// A profile that verifies no attestation holds a Notary Service,
            /// or one that verifies some holds none.
            error WrongNotaryForProfile(bytes32 platformId, address notary);
            error ZeroAddress();
            /// The Honk verifier is not this platform's circuit's: `expected`
            /// is `circuitCodehash()`, `found` the code hash at the address.
            error WrongCircuit(bytes32 expected, bytes32 found);
            // What `verify` can revert with.
            error WrongValue(uint256 required, uint256 provided);
            error WrongCeremonyVersion(uint16 expected, uint16 found);
            error WrongAuthority(bytes32 expected, bytes32 found);
            error TransactionDataTooLong(uint256 length);
            error AttestationAhead(uint64 createdAt, uint64 blockTime, uint64 allowance);
            error ProofExpired(uint64 validUntil, uint64 blockTime);
            error ObservedInTheFuture(uint64 observedAt, uint64 limit);
            /// The Honk verifier answered `false`.
            error BadProof();
            error UnknownPlatform(bytes32 platformId);
            error OwnableUnauthorizedAccount(address account);
            error OwnableInvalidOwner(address owner);
            // The transcript checks of the two notarized sessions.
            error CoverageGap(uint32 from, uint32 to);
            error SpansOverlap(uint32 at);
            error NotOneCommitment(uint256 count);
            error ObsoleteLineFold(uint256 at);
            error BareLineFeed(uint256 at);
            error BareCarriageReturn(uint256 at);
            error NotOneAuthorizationHeader(uint256 count);
            error BadBearerFraming();
            /// No commitment carries the framing the profile reads a value by.
            error NoFramedCommitment();
            /// The framing's prefix is revealed twice, or frames two
            /// commitments.
            error AmbiguousFraming();
            /// The identity request's revealed bytes hold `heads` head ends
            /// where one request holds exactly one.
            error NotOneRequest(uint256 heads);
            /// Bytes follow the identity request's head.
            error BytesAfterRequest(uint256 count);
            error AmbiguousField(string name);
            error FieldNotFound(string name);
            error MalformedForm(uint256 at);
            error EmptyFormValue(string name);
            error WrongRequestLine();
            error CodeVerifierMismatch();
            error ClientIdentifierNotSerializerSafe(bytes found);
            error RequestLineNotAtOrigin(uint32 start);
            error WrongTokenRequestLayout(uint256 revealedRanges, uint256 commitments);
            error NoHeadBoundary(uint256 occurrences);
            error WrongTokenRequestHead();
            error WrongIdentityRequestHead();
            error ForbiddenRequestHeader(bytes name);
            error WrongDeclaredBodyLength(uint256 declared, uint256 signed);
            error WrongGrantType(bytes found);
        }
    }
}

pub use tls_notary_platform_verifier_inner::{
    TlsNotaryPlatformVerifier,
    TlsNotaryPlatformVerifier as GitHubPlatformVerifier,
    TlsNotaryPlatformVerifier as XPlatformVerifier,
};

/// Bindings for `ceremony/GooglePlatformVerifier.sol`, the `google/v1`
/// profile.
///
/// The profile has no notarized session, so no Notary Service, fee, proof
/// lifetime or attestation skew. The evidence is a signed ID Token whose `exp`
/// is the validity ceiling, checked against keys read from `GoogleJwtRoots`.
///
/// `notary_` must be zero (`WrongNotaryForProfile`) and `jwtRoots_` nonzero
/// (`ZeroAddress`). The code hash rule is the TLSNotary verifiers'.
/// `protocolParameters()` returns the profile's allowance and a zero lifetime
/// and skew.
#[allow(clippy::too_many_arguments, unused_attributes)]
mod google_platform_verifier_inner {
    use alloy::sol;

    sol! {
        #[sol(rpc, abi)]
        interface GooglePlatformVerifier {
            #[derive(Debug, PartialEq, Eq)]
            function initialize(
                address owner_,
                address notary_,
                address honkVerifier_,
                address jwtRoots_
            ) external;

            /// `keccak256("google")`.
            function platformId() external pure returns (bytes32);
            /// Always zero: the profile verifies nothing that charges, and
            /// `verify` refuses any value sent.
            function quote() external pure returns (uint256);

            /// The root list the trusted moduli are read through.
            function jwtRoots() external view returns (address);
            function setJwtRoots(address roots) external;

            function notaryService() external view returns (address);
            function honkVerifier() external view returns (address);
            /// The runtime code hash of the one Honk verifier this contract
            /// accepts: its platform's circuit's, as compiled in.
            function circuitCodehash() external pure returns (bytes32);
            function protocolParameters()
                external
                pure
                returns (uint64 proofLifetime, uint64 maxFutureAttestationSkew, uint64 futureObservationAllowance);
            function setTrustRoots(address notary_, address honkVerifier_) external;

            function owner() external view returns (address);
            function pendingOwner() external view returns (address);
            function transferOwnership(address newOwner) external;
            function acceptOwnership() external;
            /// Always reverts.
            function renounceOwnership() external pure;

            event JwtRootsChanged(address roots);
            event TrustRootsChanged(address notary, address honkVerifier);
            event OwnershipTransferStarted(address indexed previousOwner, address indexed newOwner);
            event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

            error WrongNotaryForProfile(bytes32 platformId, address notary);
            error ZeroAddress();
            /// The Honk verifier is not this platform's circuit's: `expected`
            /// is `circuitCodehash()`, `found` the code hash at the address.
            error WrongCircuit(bytes32 expected, bytes32 found);
            // What `verify` can revert with.
            error WrongValue(uint256 required, uint256 provided);
            error WrongCeremonyVersion(uint16 expected, uint16 found);
            error WrongAuthority(bytes32 expected, bytes32 found);
            error TransactionDataTooLong(uint256 length);
            error AttestationAhead(uint64 createdAt, uint64 blockTime, uint64 allowance);
            error ProofExpired(uint64 validUntil, uint64 blockTime);
            error ObservedInTheFuture(uint64 observedAt, uint64 limit);
            /// The Honk verifier answered `false`.
            error BadProof();
            error UnknownPlatform(bytes32 platformId);
            error OwnableUnauthorizedAccount(address account);
            error OwnableInvalidOwner(address owner);
            // The ID token's checks.
            error MissingClientIdentifier();
            error TokenExpired(uint64 exp, uint64 blockTime);
            error UntrustedModulus(bytes32 modulusHash);
        }
    }
}

pub use google_platform_verifier_inner::GooglePlatformVerifier;

/// The payloads `IdentityRegistry.bind` carries to a Platform Verifier, from
/// `ceremony/ICeremonyPayloads.sol`. A payload is the struct's
/// [`SolValue::abi_encode`](alloy::sol_types::SolValue::abi_encode), never a
/// call to either function.
#[allow(clippy::too_many_arguments, unused_attributes)]
mod payloads_inner {
    use alloy::sol;

    sol! {
        #[sol(abi)]
        interface ICeremonyPayloads {
            /// `ICeremony.Attestation`: the notarized bytes and the Notary
            /// Service's authentication of them.
            #[derive(Debug, PartialEq, Eq)]
            struct Attestation {
                bytes attestedData;
                bytes proof;
            }

            /// `TlsNotaryVerifierBase.TlsNotaryProof`: the `x/v1` and
            /// `github/v1` payload.
            #[derive(Debug, PartialEq, Eq)]
            struct TlsNotaryProof {
                uint16 ceremonyVersion;
                bytes32 operationDomain;
                bytes32 authorizationNonce;
                bytes transactionData;
                Attestation tokenSession;
                Attestation identitySession;
                bytes32 idNode;
                bytes32 handleNode;
                bytes proof;
            }

            /// `GooglePlatformVerifier.GoogleProof`: the `google/v1` payload.
            #[derive(Debug, PartialEq, Eq)]
            struct GoogleProof {
                uint16 ceremonyVersion;
                bytes32 operationDomain;
                bytes32 authorizationNonce;
                bytes transactionData;
                bytes clientIdentifier;
                bytes32 idNode;
                bytes32 handleNode;
                uint64 exp;
                bytes32[18] modulus;
                bytes proof;
            }

            function tlsNotaryProof(TlsNotaryProof calldata payload) external pure;
            function googleProof(GoogleProof calldata payload) external pure;
        }
    }
}

pub use payloads_inner::ICeremonyPayloads::{
    self as ICeremonyPayloads,
    Attestation,
    GoogleProof,
    TlsNotaryProof,
};

#[cfg(test)]
mod tests {
    use std::fs;

    use alloy::{
        primitives::{
            keccak256,
            Bytes,
            B256,
        },
        sol_types::{
            SolCall,
            SolValue,
        },
    };
    use serde::{
        de::DeserializeOwned,
        Deserialize,
    };

    use super::*;
    use crate::{
        bindings::drift::{
            assert_binding_matches_artifact,
            assert_shared_binding_matches_artifact,
        },
        Artifacts,
    };

    /// Inherited upgrade and initializer ABI, left to `proxy::IUUPSUpgradeable`,
    /// and `verify`, which only a contract on the route calls.
    const OMITTED: &[&str] = &[
        "error AddressEmptyCode(address)",
        "error ERC1967InvalidImplementation(address)",
        "error ERC1967NonPayable()",
        "error FailedCall()",
        "error InvalidInitialization()",
        "error NotInitializing()",
        "error UUPSUnauthorizedCallContext()",
        "error UUPSUnsupportedProxiableUUID(bytes32)",
        "event Initialized(uint64)",
        "event Upgraded(address)",
        "function UPGRADE_INTERFACE_VERSION()",
        "function proxiableUUID()",
        "function upgradeToAndCall(address,bytes)",
        "function verify(bytes)",
    ];

    /// Every error `verify` can revert with is bound, for both the X and
    /// GitHub artifacts.
    #[test]
    fn the_platform_verifier_bindings_match_the_artifact_abis() {
        let tls = TlsNotaryPlatformVerifier::abi::contract();
        assert_binding_matches_artifact(
            "XPlatformVerifier",
            "XPlatformVerifier",
            &tls,
            OMITTED,
        );
        // GitHub's token request carries no `grant_type` to refuse.
        assert_shared_binding_matches_artifact(
            "GitHubPlatformVerifier",
            "GitHubPlatformVerifier",
            &tls,
            OMITTED,
            &["error WrongGrantType(bytes)"],
        );
        assert_binding_matches_artifact(
            "GooglePlatformVerifier",
            "GooglePlatformVerifier",
            &GooglePlatformVerifier::abi::contract(),
            OMITTED,
        );
    }

    /// The Notary Service and Proof Verifier bind every error `bind` surfaces.
    #[test]
    fn the_route_bindings_match_the_artifact_abis() {
        // `OMITTED` and ownership, with `verify` taking `verify`'s signature.
        let route_omitted = |verify: &'static str| -> Vec<&str> {
            OMITTED
                .iter()
                .copied()
                .filter(|item| *item != "function verify(bytes)")
                .chain([
                    "event OwnershipTransferStarted(address,address)",
                    "event OwnershipTransferred(address,address)",
                    "function renounceOwnership()",
                    verify,
                ])
                .collect()
        };
        assert_binding_matches_artifact(
            "NotaryService",
            "NotaryService",
            &NotaryService::abi::contract(),
            &route_omitted("function verify(bytes,bytes)"),
        );
        assert_binding_matches_artifact(
            "CeremonyProofVerifier",
            "CeremonyProofVerifier",
            &CeremonyProofVerifier::abi::contract(),
            &route_omitted("function verify(bytes32,uint16,bytes)"),
        );
    }

    /// The payload structs match the compiled interface's signatures.
    #[test]
    fn the_payload_bindings_match_the_artifact_abi() {
        assert_binding_matches_artifact(
            "ICeremonyPayloads",
            "ICeremonyPayloads",
            &ICeremonyPayloads::abi::contract(),
            &[],
        );
    }

    /// The notarized sessions in `x-ceremony-session.json`, read for the
    /// payload fields.
    #[derive(Deserialize)]
    struct SessionFixture {
        ceremony_version: u16,
        operation_domain: B256,
        authorization_nonce: B256,
        transaction_data: Bytes,
        token: AttestationFixture,
        identity: AttestationFixture,
    }

    /// One session's notarized bytes and the notary's signature over them.
    #[derive(Deserialize)]
    struct AttestationFixture {
        attested_data: Bytes,
        notary_signature: Bytes,
    }

    impl From<AttestationFixture> for Attestation {
        fn from(fixture: AttestationFixture) -> Self {
            Self {
                attestedData: fixture.attested_data,
                proof: fixture.notary_signature,
            }
        }
    }

    /// `x-ceremony-session-proof.json`, read for the proof.
    #[derive(Deserialize)]
    struct ProofFixture {
        proof: Bytes,
    }

    /// `x-ceremony-payload.json`: the nodes and the encoding solc pins.
    #[derive(Deserialize)]
    struct PayloadFixture {
        id_node: B256,
        handle_node: B256,
        keccak256: B256,
        length: usize,
    }

    /// A Solidity suite fixture.
    fn fixture<T: DeserializeOwned>(name: &str) -> T {
        let path = format!(
            "{}/../../solidity/contracts/ceremony/test/fixtures/{name}",
            env!("CARGO_MANIFEST_DIR")
        );
        let text = fs::read_to_string(&path).expect(&path);
        serde_json::from_str(&text).expect(&path)
    }

    /// The X fixture encodes to the hash `x-ceremony-payload.json` pins.
    #[test]
    fn the_x_fixture_payload_encodes_to_the_pinned_bytes() {
        let session: SessionFixture = fixture("x-ceremony-session.json");
        let proof: ProofFixture = fixture("x-ceremony-session-proof.json");
        let pinned: PayloadFixture = fixture("x-ceremony-payload.json");

        let payload = TlsNotaryProof {
            ceremonyVersion: session.ceremony_version,
            operationDomain: session.operation_domain,
            authorizationNonce: session.authorization_nonce,
            transactionData: session.transaction_data,
            tokenSession: session.token.into(),
            identitySession: session.identity.into(),
            idNode: pinned.id_node,
            handleNode: pinned.handle_node,
            proof: proof.proof,
        };

        let encoded = payload.abi_encode();
        assert_eq!(encoded.len(), pinned.length);
        assert_eq!(keccak256(&encoded), pinned.keccak256);
        assert_eq!(TlsNotaryProof::abi_decode(&encoded).unwrap(), payload);
    }

    #[test]
    fn a_google_payload_round_trips() {
        let payload = GoogleProof {
            ceremonyVersion: 1,
            operationDomain: B256::repeat_byte(0x11),
            authorizationNonce: B256::repeat_byte(0x22),
            transactionData: vec![1, 2].into(),
            clientIdentifier: b"aud".to_vec().into(),
            idNode: B256::repeat_byte(0x33),
            handleNode: B256::repeat_byte(0x44),
            exp: 1_800_000_000,
            modulus: [B256::repeat_byte(0x55); 18],
            proof: vec![0xde, 0xad].into(),
        };
        assert_eq!(
            GoogleProof::abi_decode(&payload.abi_encode()).unwrap(),
            payload
        );
    }

    /// Every bound Platform Verifier selector exists in its vendored artifact.
    /// An unknown `initialize` would leave the proxy uninitialized.
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
                    protocolParametersCall,
                    setTrustRootsCall,
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
                protocolParametersCall,
                setTrustRootsCall,
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
