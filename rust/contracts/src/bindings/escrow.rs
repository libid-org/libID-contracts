//! Bindings for the handle escrow (`solidity/contracts/escrow/`): value held
//! against a handle node until its holder in `IdentityNames` claims it, and
//! refundable to each deposit's `refundTo` until then. `deposit` takes
//! `keccak256(normalized handle)`, from `IdentityNames.handleHashOf` or
//! computed locally.

/// Bindings for `escrow/HandleEscrow.sol`.
#[allow(clippy::too_many_arguments, unused_attributes)]
mod escrow_inner {
    use alloy::sol;

    sol! {
        #[sol(rpc, abi)]
        interface HandleEscrow {
            function initialize(address owner_, address registry_) external;

            /// Pay a handle by its hash. A held node is paid straight through
            /// (`Forwarded`); otherwise the value is escrowed (`Deposited`) and
            /// `refundTo` can `refund` it until the holder claims. An unchecked
            /// wrong hash funds a slot only `refund` recovers.
            function deposit(
                bytes32 platformId,
                bytes32 handleHash,
                address token,
                uint256 amount,
                address refundTo
            ) external payable;

            /// Take everything held for a node in each of `tokens`; holder
            /// only. Tokens with nothing held are skipped; reverts
            /// `NothingHeld` when none paid.
            function claim(bytes32 handleNode, address[] calldata tokens, address recipient) external;

            /// Take back the caller's contribution to a node in the current
            /// round, until the holder claims.
            function refund(bytes32 handleNode, address token, address recipient) external;

            function escrowed(bytes32 handleNode, address token) external view returns (uint256);
            /// What `refund` would pay `refundTo` now.
            function refundable(bytes32 handleNode, address token, address refundTo) external view returns (uint256);
            /// The identity registry the escrow resolves through.
            function registry() external view returns (address);
            /// The EIP-7528 native-token address, `0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE`.
            function NATIVE() external view returns (address);

            function owner() external view returns (address);
            function pendingOwner() external view returns (address);
            function transferOwnership(address newOwner) external;
            function acceptOwnership() external;
            /// Always reverts `RenounceDisabled`.
            function renounceOwnership() external pure;

            /// Value escrowed for a node nobody holds, booked under `refundTo`
            /// in `round`, which the next `Claimed` closes.
            event Deposited(
                bytes32 indexed handleNode,
                address indexed token,
                address indexed refundTo,
                address depositor,
                bytes32 platformId,
                uint256 round,
                uint256 amount
            );
            /// A deposit paid straight to the node's holder; `received` is
            /// what the holder gained.
            event Forwarded(
                bytes32 indexed handleNode,
                address indexed token,
                address indexed depositor,
                address holder,
                bytes32 platformId,
                uint256 amount,
                uint256 received
            );
            /// `released` (here and in `Refunded`) left the books; `received`
            /// is what `recipient` gained. `round` is the one this claim closed.
            event Claimed(
                bytes32 indexed handleNode,
                address indexed token,
                address indexed claimer,
                address recipient,
                uint256 round,
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
                uint256 round,
                uint256 released,
                uint256 received
            );

            error ZeroAmount();
            /// The caller holds the node it is paying.
            error PayingYourself(address holder);
            error ValueMismatch(uint256 expected, uint256 provided);
            error NothingHeld(bytes32 handleNode);
            /// The caller is not the node's holder.
            error NotTheHolder(address holder, address caller);
            /// Nothing refundable is booked under `refundTo`.
            error NothingToRefund(bytes32 handleNode, address token, address refundTo);
            /// `refundTo` is zero or the escrow: nobody could refund.
            error BadRefundTo(address refundTo);
            error BadRecipient(address recipient);
            /// Nobody holds the node and nothing new can bind on the platform.
            error PlatformAcceptsNoBindings(bytes32 platformId);
            error NativeTransferFailed(address recipient, uint256 amount);
            /// A payout took more of the escrow's balance than it booked.
            error OverDebited(address token, uint256 booked, uint256 debited);
            error NoRegistry();
            /// `initialize`: the registry does not answer `selector`.
            error RegistryLacks(address registry, bytes4 selector);
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
            "HandleEscrow",
            "HandleEscrow",
            &HandleEscrow::abi::contract(),
            OMITTED,
        );
    }
}
