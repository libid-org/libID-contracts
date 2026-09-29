//! Bindings for the handle escrow (`solidity/contracts/escrow/`).
//!
//! Value held against a platform handle rather than against an account id, so
//! a sender who knows only a name can pay it before anybody has claimed it.
//! Whoever the naming system names as that handle's holder takes what is held;
//! until the holder claims it, the `refundTo` each deposit named can take it
//! back.
//!
//! The escrow keys on the naming system's handle node,
//! `keccak256(abi.encode(keccak256("libid.identity.handle-node.v1"), platformId,
//! keccak256(normalized)))`, the node `IdentityNames` binds and emits as
//! `IdentityBound.handleNode`. `deposit` takes the inner hash,
//! `keccak256(normalized)`: from `IdentityNames.handleHashOf`, or computed
//! locally from the normalized handle.

/// Bindings for `escrow/HandleEscrow.sol`.
#[allow(clippy::too_many_arguments, unused_attributes)]
mod escrow_inner {
    use alloy::sol;

    sol! {
        #[sol(rpc, abi)]
        interface HandleEscrow {
            function initialize(address owner_, address names_) external;

            /// Put `amount` of `token` against `keccak256` of the normalized
            /// handle. `address(0)` is the chain's own token, and then `amount`
            /// must equal the value sent. Nothing about the hash can be
            /// checked: a wrong hash funds a slot nothing can claim, and only
            /// its `refundTo`'s `refund` recovers it.
            ///
            /// A handle somebody holds is paid STRAIGHT THROUGH to its holder.
            /// Only an unheld handle escrows, only on a platform that accepts
            /// claims, and then `refundTo` (never zero) can `refund` it until
            /// the holder claims it. `Deposited` and `Forwarded` tell the two
            /// apart.
            function deposit(
                bytes32 platformId,
                bytes32 handleHash,
                address token,
                uint256 amount,
                address refundTo
            ) external payable;

            /// Take everything held for a handle node in one token. The caller
            /// has to be the node's holder in the naming system.
            function claim(bytes32 handleNode, address token, address recipient) external;

            /// Take back what deposits naming the caller as `refundTo` put
            /// into a handle node in one token, whether or not the node has a
            /// holder yet. What a claim
            /// took is never refundable: a refund and a claim racing, the
            /// first to land wins.
            function refund(bytes32 handleNode, address token, address recipient) external;

            function escrowed(bytes32 handleNode, address token) external view returns (uint256);
            /// What `refund` would pay `refundTo` now: what is booked under it
            /// since the last claim of the slot.
            function refundable(bytes32 handleNode, address token, address refundTo) external view returns (uint256);
            /// The node a handle keys to under the platform's current rules:
            /// `IdentityNames.nodeOf`, asked through the escrow. Reverts with
            /// the naming system's `UnknownPlatform` or `UnusableHandle`.
            function nodeOf(bytes32 platformId, string calldata handle) external view returns (bytes32);
            function names() external view returns (address);
            function NATIVE() external view returns (address);

            function owner() external view returns (address);
            function pendingOwner() external view returns (address);
            function transferOwnership(address newOwner) external;
            function acceptOwnership() external;
            /// Always reverts `RenounceDisabled`; the contract declares it
            /// `pure`.
            function renounceOwnership() external pure;

            /// Value held for a node nobody holds, booked under `refundTo`;
            /// `depositor` is the caller that paid.
            event Deposited(
                bytes32 indexed handleNode,
                address indexed token,
                address indexed refundTo,
                address depositor,
                bytes32 platformId,
                uint256 amount
            );
            /// A deposit for a handle node somebody already held, paid to that
            /// holder and never booked. Nothing is claimable afterwards, which
            /// is what separates it from `Deposited`. `amount` is what the
            /// deposit asked to move, `received` what the holder gained.
            event Forwarded(
                bytes32 indexed handleNode,
                address indexed token,
                address indexed depositor,
                address holder,
                bytes32 platformId,
                uint256 amount,
                uint256 received
            );
            /// `released` here and in `Refunded` is what the books released;
            /// `received` is what `recipient` gained — its balance gain for a
            /// token — which a fee on the payout makes less.
            event Claimed(
                bytes32 indexed handleNode,
                address indexed token,
                address indexed claimer,
                address recipient,
                uint256 released,
                uint256 received
            );
            event OwnershipTransferStarted(address indexed previousOwner, address indexed newOwner);
            event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);
            event Refunded(
                bytes32 indexed handleNode,
                address indexed token,
                address indexed refundTo,
                address recipient,
                uint256 released,
                uint256 received
            );

            error ZeroAmount();
            /// The node's holder is the caller, so the deposit would pay the
            /// caller back to itself.
            error PayingYourself(address holder);
            error ValueMismatch(uint256 expected, uint256 provided);
            error NothingHeld(bytes32 handleNode, address token);
            /// The caller is not the node's holder.
            error NotTheHolder(address holder, address caller);
            /// Nothing refundable is booked under `refundTo` for this node and
            /// token.
            error NothingToRefund(bytes32 handleNode, address token, address refundTo);
            /// A deposit named no `refundTo`.
            error NoRefundTo();
            error BadRecipient(address recipient);
            /// Nobody holds the node and no new claim can bind a holder on
            /// this platform.
            error PlatformAcceptsNoClaims(bytes32 platformId);
            error NativeTransferFailed(address recipient, uint256 amount);
            error NoNames();
            /// `initialize`: the naming contract does not answer `selector`,
            /// one of the functions the escrow calls.
            error NamesLacks(address names, bytes4 selector);
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
    use super::escrow_inner::HandleEscrow;
    use crate::bindings::drift::assert_binding_matches_artifact;

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

    #[test]
    fn the_binding_matches_the_artifact_abi() {
        assert_binding_matches_artifact(
            "HandleEscrow",
            "HandleEscrow",
            &HandleEscrow::abi::contract(),
            OMITTED,
        );
    }
}
