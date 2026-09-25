//! Bindings for the identity-names stack (`solidity/contracts/identity/`):
//! `IdentityNames`.

/// Bindings for `identity/IdentityNames.sol`.
///
/// `Rules` mirrors `HandleNormalizer.Rules` — the normalization rules the
/// contract stores per platform. Platform ids are `keccak256` of the
/// platform's domain string.
#[allow(clippy::too_many_arguments, unused_attributes)]
mod names_inner {
    use alloy::sol;

    sol! {
        #[sol(rpc, abi)]
        interface IdentityNames {
            #[derive(Debug, serde::Serialize, serde::Deserialize)]
            struct Rules {
                uint16 maxLength;
                bool stripLeadingAt;
                bool isEmail;
                bool allowUnderscore;
                bool allowHyphen;
            }

            function initialize(address owner_) external;

            /// The wallet that proved an account id, and when.
            function byId(bytes32 idNode) external view returns (address owner, uint64 observedAt);
            /// The wallet that last proved a handle node, and when. A zero
            /// owner: nobody holds it.
            function byHandle(bytes32 handleNode) external view returns (address owner, uint64 observedAt);
            /// The operation domain a claim's authorization names.
            function CLAIM_IDENTITY_DOMAIN() external view returns (bytes32);

            function owner() external view returns (address);
            function pendingOwner() external view returns (address);
            function transferOwnership(address newOwner) external;
            function acceptOwnership() external;
            /// Always reverts; the contract declares it `pure`.
            function renounceOwnership() external pure;

            /// The keyspace half: what a handle on this platform means. It
            /// does not vary by proof version — two versions normalizing
            /// differently would put one handle on two nodes.
            function setPlatform(bytes32 platformId, Rules calldata rules) external;

            /// Which contract holds the Supported Version Set. Registering a
            /// version is that contract's call, not this one's.
            function setProofVerifier(address verifier) external;
            function proofVerifier() external view returns (address);

            /// The one write. The contract does not know what `payload` is:
            /// it names a platform and this chain's verifier version for it,
            /// and the Proof Verifier routes the bytes to the one contract
            /// that decodes them. The value attached must equal `quoteClaim`
            /// for the same pair exactly.
            function claim(bytes32 platformId, uint16 verifierVersion, bytes calldata payload, bool publishName) external payable;
            function quoteClaim(bytes32 platformId, uint16 verifierVersion) external view returns (uint256);
            function digestSpent(bytes32 digest) external view returns (bool);
            function unpublish(bytes32 platformId) external;
            function resolveId(bytes32 platformId, string calldata userId) external view returns (address);
            function resolveHandle(bytes32 platformId, string calldata handle) external view returns (address);
            /// The handle's current owner, and whether `userId` resolves to
            /// that same wallet.
            function resolvePair(bytes32 platformId, string calldata handle, string calldata userId) external view returns (address wallet, bool idAgrees);
            function reverseOf(address wallet, bytes32 platformId) external view returns (string memory);
            function primaryOf(address wallet, bytes32 platformId) external view returns (string memory);
            /// The platform's rules as configured now, for a client that
            /// normalizes locally rather than send a handle's text to `nodeOf`.
            /// Reverts for a platform that is not usable, like the resolvers.
            function rulesOf(bytes32 platformId) external view returns (Rules memory);
            /// Whether a new identity claim can bind a holder on this platform
            /// now: a keyspace, and a Proof Verifier that verifies it.
            function acceptsClaims(bytes32 platformId) external view returns (bool);
            /// The node a handle keys to under the platform's current rules.
            /// Needs only a keyspace; reverts `UnusableHandle` for text the
            /// rules refuse.
            function nodeOf(bytes32 platformId, string calldata handle) external view returns (bytes32 handleNode);

            /// Carries the ceremony version that proved the binding -- logged,
            /// never stored, because nothing on chain acts on it and an
            /// operator asking which bindings a version touched reads the log.
            /// What the ceremony authenticated beyond the binding rides on
            /// `CeremonyBound` instead.
            event IdentityBound(
                address indexed owner,
                bytes32 indexed idNode,
                bytes32 indexed handleNode,
                bytes32 platformId,
                string userId,
                string handle,
                uint64 observedAt,
                bool published,
                uint16 ceremonyVersion
            );
            /// A platform with no keyspace, or one nothing verifies and on
            /// which nothing was ever bound.
            error UnknownPlatform(bytes32 platformId);
            /// Text the platform's rules refuse; `problem` is a
            /// `HandleNormalizer.Problem`.
            error UnusableHandle(uint8 problem);

            event OwnershipTransferStarted(address indexed previousOwner, address indexed newOwner);
            event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

            // What `claim` can revert with: its own refusals, and the
            // normalizer's, for a proved handle the rules refuse.
            error ZeroAddress();
            error ForeignOperationDomain(bytes32 operationDomain);
            error DigestAlreadySpent(bytes32 digest);
            error BadTransactionData(uint256 length);
            error WrongClaimValue(uint256 required, uint256 provided);
            error WrongFeeValue(uint256 required, uint256 provided);
            error NoncanonicalFee(uint256 amount, address receiver);
            error FeeTransferFailed(address receiver, uint256 amount);
            error NotProofTarget(address proved, address caller);
            error NoObservationTime();
            error NoUserId();
            error StaleProof(uint64 observedAt, uint64 known);
            error EmptyHandle();
            error HandleTooLong();
            error BadCharacter();
            error BadShape();
            error OwnableUnauthorizedAccount(address account);
            error OwnableInvalidOwner(address owner);
            error ReentrancyGuardReentrantCall();

            event HandleRetired(bytes32 indexed platformId, bytes32 indexed handleNode, address indexed owner);
            event PlatformConfigured(bytes32 indexed platformId);
            event ProofVerifierConfigured(address verifier);
            /// The service fee a claim's own Authorized Transaction Data named
            /// was delivered. Emitted only when there is one.
            event ClaimFeePaid(bytes32 indexed authorizationDigest, address indexed receiver, uint256 amount);
            event NameUnpublished(address indexed owner, bytes32 indexed platformId);
            /// The OAuth client a ceremony authenticated. Nothing stores it, so
            /// "which application produced these bindings" is answerable only
            /// from this log.
            event CeremonyBound(
                bytes32 indexed authorizationDigest,
                address indexed owner,
                bytes32 indexed platformId,
                bytes clientIdentifier
            );
        }
    }
}

pub use names_inner::IdentityNames;

#[cfg(test)]
mod tests {
    use super::names_inner::IdentityNames;
    use crate::bindings::drift::assert_binding_matches_artifact;

    /// What the compiled contract has and the binding leaves out on purpose:
    /// the upgrade and initializer machinery it inherits, reached through
    /// `proxy::IUUPSUpgradeable`.
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
    ];

    #[test]
    fn the_binding_matches_the_artifact_abi() {
        assert_binding_matches_artifact(
            "IdentityNames",
            "IdentityNames",
            &IdentityNames::abi::contract(),
            OMITTED,
        );
    }
}
