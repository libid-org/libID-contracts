//! Bindings for the identity registry (`solidity/contracts/identity/`):
//! `IdentityNames`.

/// Bindings for `identity/IdentityNames.sol`.
///
/// `Rules` mirrors `HandleNormalizer.Rules` — the normalization rules the
/// contract stores per platform. Platform ids are `keccak256` of the
/// platform key.
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

            /// One identity a holder proved, as its list reports it. `handle`
            /// is the one the identity proved most recently, and
            /// `handleCurrent` says whether the handle node still points back
            /// at this identity: it stops doing so when another identity
            /// proves the same handle, and the string stays as the last thing
            /// the identity was known as.
            #[derive(Debug, serde::Serialize, serde::Deserialize)]
            struct Identity {
                bytes32 platformId;
                string id;
                string handle;
                bool handleCurrent;
            }

            function initialize(address owner_) external;

            /// The holder that proved an id, and when.
            function idBinding(bytes32 idNode) external view returns (address holder, uint64 observedAt);
            /// The holder that last proved a handle node, and when. A zero
            /// holder: nobody proved it, or it was retired.
            function handleBinding(bytes32 handleNode) external view returns (address holder, uint64 observedAt);
            /// The operation domain a binding's authorization names.
            function OPERATION_DOMAIN() external view returns (bytes32);

            function owner() external view returns (address);
            function pendingOwner() external view returns (address);
            function transferOwnership(address newOwner) external;
            function acceptOwnership() external;
            /// Always reverts; the contract declares it `pure`.
            function renounceOwnership() external pure;

            /// The rules half: what a handle on this platform means. It
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
            /// that decodes them. The value attached must equal `quoteBind`
            /// for the same pair exactly.
            function bind(bytes32 platformId, uint16 verifierVersion, bytes calldata payload, bool publish) external payable;
            function quoteBind(bytes32 platformId, uint16 verifierVersion) external view returns (uint256);
            function digestSpent(bytes32 digest) external view returns (bool);
            function unpublish(bytes32 platformId) external;
            function resolveId(bytes32 platformId, string calldata id) external view returns (address);
            function resolveHandle(bytes32 platformId, string calldata handle) external view returns (address);
            /// The handle's holder, and whether `id` resolves to that same
            /// holder.
            function resolveHandleAndId(bytes32 platformId, string calldata handle, string calldata id) external view returns (address holder, bool idAgrees);
            /// The handle a holder published, while it still resolves back to
            /// that holder; empty otherwise.
            function publishedHandleOf(address holder, bytes32 platformId) external view returns (string memory);
            /// The platform's rules as configured now, for local normalization.
            function rulesOf(bytes32 platformId) external view returns (Rules memory);
            /// Whether `bind` can bind a holder on this platform
            /// now: rules, and a Proof Verifier that verifies it.
            function acceptsBindings(bytes32 platformId) external view returns (bool);
            /// `keccak256` of the normalized handle: what `HandleEscrow.deposit`
            /// takes. Reverts `UnknownPlatform` or `UnusableHandle`.
            function handleHashOf(bytes32 platformId, string calldata handle) external view returns (bytes32 handleHash);
            /// The node a handle hashes to now; reverts as `handleHashOf` does.
            function handleNodeOf(bytes32 platformId, string calldata handle) external view returns (bytes32 handleNode);
            /// The node of a handle given as its hash, as `bind` binds it.
            function handleNodeOfHash(bytes32 platformId, bytes32 handleHash) external pure returns (bytes32);

            /// How many identities a holder has, on every platform together.
            function identityCount(address holder) external view returns (uint256);
            /// A page of a holder's identities, on every platform
            /// together: the indices `[from, from + limit)`, counted from
            /// zero and clipped to the list. Order is arbitrary and changes
            /// when an identity leaves the list, so a reader that needs every
            /// identity reads `identityCount` and the pages in one block.
            function identitiesOf(address holder, uint256 from, uint256 limit) external view returns (Identity[] memory);

            /// Carries the ceremony version that proved the binding -- logged,
            /// never stored, because nothing on chain acts on it and an
            /// operator asking which bindings a version touched reads the log.
            /// What the ceremony authenticated beyond the binding rides on
            /// `CeremonyBound` instead.
            event IdentityBound(
                address indexed holder,
                bytes32 indexed idNode,
                bytes32 indexed handleNode,
                bytes32 platformId,
                string id,
                string handle,
                uint64 observedAt,
                bool published,
                uint16 ceremonyVersion
            );
            /// A platform not configured, or one nothing verifies and on
            /// which nothing was ever bound.
            error UnknownPlatform(bytes32 platformId);
            /// Text the platform's rules refuse; `problem` is a
            /// `HandleNormalizer.Problem`.
            error UnusableHandle(uint8 problem);

            event OwnershipTransferStarted(address indexed previousOwner, address indexed newOwner);
            event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

            // What `bind` can revert with: its own refusals, and the
            // normalizer's, for a proved handle the rules refuse.
            error ZeroAddress();
            error ForeignOperationDomain(bytes32 operationDomain);
            error DigestAlreadySpent(bytes32 digest);
            error BadTransactionData(uint256 length);
            error WrongBindValue(uint256 required, uint256 provided);
            error WrongFeeValue(uint256 required, uint256 provided);
            error NoncanonicalFee(uint256 amount, address receiver);
            error FeeTransferFailed(address receiver, uint256 amount);
            error NotProofTarget(address proved, address caller);
            error NoObservationTime();
            error NoId();
            error StaleProof(uint64 observedAt, uint64 known);
            error EmptyHandle();
            error HandleTooLong();
            error BadCharacter();
            error BadShape();
            error OwnableUnauthorizedAccount(address account);
            error OwnableInvalidOwner(address owner);
            error ReentrancyGuardReentrantCall();

            event HandleRetired(bytes32 indexed platformId, bytes32 indexed handleNode, address indexed holder);
            event PlatformConfigured(bytes32 indexed platformId);
            event ProofVerifierConfigured(address verifier);
            /// The service fee a binding's own Authorized Transaction Data named
            /// was delivered. Emitted only when there is one.
            event BindFeePaid(bytes32 indexed authorizationDigest, address indexed receiver, uint256 amount);
            event HandleUnpublished(address indexed holder, bytes32 indexed platformId);
            /// The OAuth client a ceremony authenticated. Nothing stores it, so
            /// "which application produced these bindings" is answerable only
            /// from this log.
            event CeremonyBound(
                bytes32 indexed authorizationDigest,
                address indexed holder,
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

    /// Inherited upgrade and initializer ABI, left to `proxy::IUUPSUpgradeable`.
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
