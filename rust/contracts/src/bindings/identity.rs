//! Bindings for the identity registry (`solidity/contracts/identity/`):
//! `IdentityRegistry`.

/// Bindings for `identity/IdentityRegistry.sol`. Nodes are
/// `SHA256(tag || value)`; `libid_identity` computes them off chain.
#[allow(clippy::too_many_arguments, unused_attributes)]
mod registry_inner {
    use alloy::sol;

    sol! {
        #[sol(rpc, abi)]
        interface IdentityRegistry {
            /// One identity a holder proved. `handleCurrent` is whether
            /// `handleNode` still points back at this identity.
            #[derive(Debug, serde::Serialize, serde::Deserialize)]
            struct Identity {
                bytes32 platformId;
                bytes32 idNode;
                bytes32 handleNode;
                bool handleCurrent;
            }

            function initialize(address owner_) external;

            /// The holder that proved an id, and when.
            function idBinding(bytes32 idNode) external view returns (address holder, uint64 observedAt);
            /// The holder that last proved a handle node, and when. A zero
            /// holder: nobody proved it, or it was retired.
            function handleBinding(bytes32 handleNode) external view returns (address holder, uint64 observedAt);
            /// True: identities are keyed by the nodes a circuit outputs.
            function nodeKeyed() external pure returns (bool);
            /// The operation domain a binding's authorization names.
            function OPERATION_DOMAIN() external view returns (bytes32);

            function owner() external view returns (address);
            function pendingOwner() external view returns (address);
            function transferOwnership(address newOwner) external;
            function acceptOwnership() external;
            /// Always reverts.
            function renounceOwnership() external pure;

            /// Sets the Proof Verifier, which holds the Supported Version Set
            /// and registers versions.
            function setProofVerifier(address verifier) external;
            function proofVerifier() external view returns (address);

            /// Bind the caller to a proved identity. `payload` is routed
            /// opaque to the pair's Platform Verifier; the value must equal
            /// `quoteBind`. A nonempty `handle` is disclosed and must fold
            /// and hash to the proved handle node.
            function bind(bytes32 platformId, uint16 verifierVersion, bytes calldata payload, string calldata handle) external payable;
            /// `bind` disclosing nothing.
            function bindPrivately(bytes32 platformId, uint16 verifierVersion, bytes calldata payload) external payable;
            function quoteBind(bytes32 platformId, uint16 verifierVersion) external view returns (uint256);
            function digestSpent(bytes32 digest) external view returns (bool);
            /// Disclose the caller's handle; it must match the node it holds.
            function publish(bytes32 platformId, string calldata handle) external;
            function unpublish(bytes32 platformId) external;
            /// The holder of an id node.
            function resolveId(bytes32 idNode) external view returns (address);
            function resolveHandle(bytes32 platformId, string calldata handle) external view returns (address);
            /// The handle's holder, and whether `idNode` is the account that last proved it.
            function resolveHandleAndId(bytes32 platformId, string calldata handle, bytes32 idNode) external view returns (address holder, bool idAgrees);
            /// `resolveHandleAndId` for a handle node computed off chain.
            function resolveHandleNodeAndId(bytes32 platformId, bytes32 handleNode, bytes32 idNode) external view returns (address holder, bool idAgrees);
            /// The handle a holder published, while it still resolves back to
            /// that holder; empty otherwise.
            function publishedHandleOf(address holder, bytes32 platformId) external view returns (string memory);
            /// Whether `bind` accepts this platform now.
            function acceptsBindings(bytes32 platformId) external view returns (bool);
            /// The node a handle is bound under (`HandleEscrow.deposit` takes it).
            function handleNodeOf(bytes32 platformId, string calldata handle) external pure returns (bytes32 handleNode);

            /// How many identities a holder has, on every platform together.
            function identityCount(address holder) external view returns (uint256);
            /// A page of a holder's identities on every platform: indices
            /// `[from, from + limit)`, clipped to the list. Order changes when
            /// an identity leaves, so read `identityCount` and every page at
            /// one block.
            function identitiesOf(address holder, uint256 from, uint256 limit) external view returns (Identity[] memory);

            /// The two nodes a binding wrote, and the proving version.
            event IdentityBound(
                address indexed holder,
                bytes32 indexed idNode,
                bytes32 indexed handleNode,
                bytes32 platformId,
                uint64 observedAt,
                uint16 ceremonyVersion
            );
            /// A holder disclosed its handle on a platform as its name there.
            event HandlePublished(
                address indexed holder,
                bytes32 indexed platformId,
                bytes32 indexed handleNode,
                string handle
            );
            /// No ceremony profile names the platform.
            error UnknownPlatform(bytes32 platformId);

            event OwnershipTransferStarted(address indexed previousOwner, address indexed newOwner);
            event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

            // What `bind` can revert with.
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
            error NoHandle();
            error StaleProof(uint64 observedAt, uint64 known);
            /// The disclosed handle is not one the caller holds.
            error NotYourHandle(bytes32 handleNode);
            /// The handle a bind discloses hashes to `disclosed`, not the node
            /// the proof bound.
            error HandleNotProved(bytes32 disclosed, bytes32 proved);
            error OwnableUnauthorizedAccount(address account);
            error OwnableInvalidOwner(address owner);
            error ReentrancyGuardReentrantCall();

            event HandleRetired(bytes32 indexed platformId, bytes32 indexed handleNode, address indexed holder);
            event ProofVerifierConfigured(address verifier);
            /// The service fee a binding's Authorized Transaction Data named was
            /// delivered. Emitted only when there is one.
            event BindFeePaid(bytes32 indexed authorizationDigest, address indexed receiver, uint256 amount);
            event HandleUnpublished(address indexed holder, bytes32 indexed platformId);
            /// The OAuth client a ceremony authenticated. Only this log records it.
            event CeremonyBound(
                bytes32 indexed authorizationDigest,
                address indexed holder,
                bytes32 indexed platformId,
                bytes clientIdentifier
            );
        }
    }
}

pub use registry_inner::IdentityRegistry;

#[cfg(test)]
mod tests {
    use super::registry_inner::IdentityRegistry;
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
            "IdentityRegistry",
            "IdentityRegistry",
            &IdentityRegistry::abi::contract(),
            OMITTED,
        );
    }
}
