//! Bindings for the handle escrow (`solidity/contracts/escrow/`).
//!
//! Value held against a platform handle rather than against an account id, so
//! a sender who knows only a name can pay it before anybody has claimed it.
//! Whoever the naming system names as that handle's holder takes what is held;
//! until the holder claims it, each depositor can refund its own deposit.
//!
//! The escrow keys on the naming system's handle node,
//! `keccak256(abi.encode(keccak256("libid.identity.handle-node.v1"), platformId,
//! keccak256(normalized)))`, the node `IdentityNames` binds and emits as
//! `IdentityBound.handleNode`. `nodeOf` derives it from text under the
//! platform's current rules, by asking `IdentityNames.nodeOf`; a client that must keep a handle out of calldata
//! derives it itself from the normalized handle and pays with `depositToNode`.

/// Bindings for `escrow/HandleEscrow.sol`.
#[allow(clippy::too_many_arguments, unused_attributes)]
mod escrow_inner {
    use alloy::sol;

    sol! {
        #[sol(rpc)]
        interface HandleEscrow {
            function initialize(address owner_, address names_) external;

            /// Put `amount` of `token` against a handle, given as text.
            /// `address(0)` is the chain's own token, and then `amount` must
            /// equal the value sent. The text is normalized under the
            /// platform's current rules; text no rules accept is refused.
            ///
            /// A handle somebody holds is paid STRAIGHT THROUGH to its holder —
            /// the escrow is for the window before a handle is claimed. Only an
            /// unheld handle escrows, only on a platform that accepts claims,
            /// and then the depositor can `refund` it until the holder claims
            /// it. Watch `Deposited` against `Forwarded` to tell the two
            /// apart.
            function depositToHandle(
                bytes32 platformId,
                string calldata handle,
                address token,
                uint256 amount
            ) external payable;

            /// The same, against a handle node the caller derived. Nothing
            /// about the node can be checked: a wrong node funds a slot nothing
            /// can claim, and only its depositor's `refund` recovers it.
            function depositToNode(
                bytes32 platformId,
                bytes32 handleNode,
                address token,
                uint256 amount
            ) external payable;

            /// Take everything held for a handle node in one token. The caller
            /// has to be the node's holder in the naming system.
            function claim(bytes32 handleNode, address token, address recipient) external;

            /// Take back the caller's own contribution to a handle node in one
            /// token, whether or not the node has a holder yet. What a claim
            /// took is never refundable: a refund and a claim racing, the
            /// first to land wins.
            function refund(bytes32 handleNode, address token, address recipient) external;

            function escrowed(bytes32 handleNode, address token) external view returns (uint256);
            /// What `refund` would pay `depositor` now: its contribution since
            /// the last claim of the slot.
            function refundable(bytes32 handleNode, address token, address depositor) external view returns (uint256);
            /// The node a handle keys to under the platform's current rules:
            /// `IdentityNames.nodeOf`, asked through the escrow. Reverts with
            /// the naming system's `UnknownPlatform` or `UnusableHandle`,
            /// which `depositToHandle` bubbles up too.
            function nodeOf(bytes32 platformId, string calldata handle) external view returns (bytes32);
            function names() external view returns (address);
            function NATIVE() external view returns (address);

            function owner() external view returns (address);
            function pendingOwner() external view returns (address);
            function transferOwnership(address newOwner) external;
            function acceptOwnership() external;
            /// Always reverts `RenounceDisabled`.
            function renounceOwnership() external;

            event Deposited(
                bytes32 indexed handleNode,
                address indexed token,
                address indexed depositor,
                bytes32 platformId,
                uint256 amount
            );
            /// A deposit for a handle node somebody already held, paid to that
            /// holder and never booked. Nothing is claimable afterwards, which
            /// is what separates it from `Deposited`.
            event Forwarded(
                bytes32 indexed handleNode,
                address indexed token,
                address indexed depositor,
                address holder,
                bytes32 platformId,
                uint256 amount
            );
            event Claimed(
                bytes32 indexed handleNode,
                address indexed token,
                address indexed claimer,
                address recipient,
                uint256 amount
            );
            event OwnershipTransferStarted(address indexed previousOwner, address indexed newOwner);
            event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);
            event Refunded(
                bytes32 indexed handleNode,
                address indexed token,
                address indexed depositor,
                address recipient,
                uint256 amount
            );

            error ZeroAmount();
            /// The node's holder is the caller, so the deposit would pay the
            /// caller back to itself.
            error PayingYourself(address holder);
            error ValueMismatch(uint256 expected, uint256 provided);
            error NothingHeld(bytes32 handleNode, address token);
            /// The caller is not the node's holder.
            error NotTheHolder(address holder, address caller);
            /// The depositor has nothing refundable for this node and token.
            error NothingToRefund(bytes32 handleNode, address token, address depositor);
            error BadRecipient(address recipient);
            /// Nobody holds the node and no new claim can bind a holder on
            /// this platform.
            error PlatformAcceptsNoClaims(bytes32 platformId);
            error NativeTransferFailed(address recipient, uint256 amount);
            error NoNames();
            error RenounceDisabled();
            error OwnableUnauthorizedAccount(address account);
            error OwnableInvalidOwner(address owner);
            /// A deposit, claim or refund was entered again from inside one.
            error ReentrancyGuardReentrantCall();
            /// The token answered `false` to a transfer.
            error SafeERC20FailedOperation(address token);
        }
    }
}

pub use escrow_inner::HandleEscrow;

#[cfg(test)]
mod tests {
    use std::collections::{
        BTreeMap,
        BTreeSet,
    };

    use alloy::json_abi::JsonAbi;

    use super::escrow_inner::HandleEscrow::{
        HandleEscrowCalls,
        HandleEscrowErrors,
        HandleEscrowEvents,
    };
    use crate::Artifacts;

    /// What the compiled contract has and the binding leaves out on purpose:
    /// the upgrade and initializer machinery it inherits. A caller upgrades
    /// through `proxy::IUUPSUpgradeable`, not through this binding.
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

    /// The hand-written binding against the ABI of the contract it binds, as
    /// vendored: every function, event and error the artifact has is bound
    /// with the same selector or topic, or is listed in `OMITTED`; the binding
    /// has nothing the artifact lacks; and `OMITTED` lists nothing that is
    /// bound or gone. A selector is the whole signature, so a changed
    /// parameter type shows up as one item missing and one extra.
    #[test]
    fn the_binding_matches_the_artifact_abi() {
        let json = Artifacts::embedded()
            .raw("HandleEscrow", "HandleEscrow")
            .unwrap();
        let abi: JsonAbi = serde_json::from_value(json["abi"].clone())
            .expect("the vendored artifact has no ABI; run scripts/vendor-artifacts.sh");

        let mut compiled: BTreeMap<Vec<u8>, String> = BTreeMap::new();
        for f in abi.functions() {
            compiled.insert(f.selector().to_vec(), format!("function {}", f.signature()));
        }
        for e in abi.events() {
            compiled.insert(e.selector().to_vec(), format!("event {}", e.signature()));
        }
        for e in abi.errors() {
            compiled.insert(e.selector().to_vec(), format!("error {}", e.signature()));
        }

        let bound: BTreeSet<Vec<u8>> = HandleEscrowCalls::SELECTORS
            .iter()
            .map(|s| s.to_vec())
            .chain(HandleEscrowEvents::SELECTORS.iter().map(|s| s.to_vec()))
            .chain(HandleEscrowErrors::SELECTORS.iter().map(|s| s.to_vec()))
            .collect();

        let unbound: Vec<&str> = compiled
            .iter()
            .filter(|(selector, _)| !bound.contains(*selector))
            .map(|(_, name)| name.as_str())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        let mut omitted = OMITTED.to_vec();
        omitted.sort_unstable();
        assert_eq!(
            unbound, omitted,
            "the artifact has items the binding does not bind, or OMITTED is stale"
        );

        let extra: Vec<String> = bound
            .iter()
            .filter(|selector| !compiled.contains_key(*selector))
            .map(alloy::hex::encode)
            .collect();
        assert!(
            extra.is_empty(),
            "the binding has selectors the contract does not: {extra:?}"
        );
    }
}
