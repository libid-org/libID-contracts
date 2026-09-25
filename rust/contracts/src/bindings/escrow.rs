//! Bindings for the handle escrow (`solidity/contracts/escrow/`).
//!
//! Value held against a platform handle rather than against an account id, so
//! a sender who knows only a name can pay it before anybody has claimed it.
//! Whoever the naming system names as that handle's holder takes what is held.
//!
//! The escrow keys on the naming system's handle node,
//! `keccak256(abi.encode(keccak256("libid.identity.handle-node.v1"), platformId,
//! keccak256(normalized)))`, the node `IdentityNames` binds and emits as
//! `IdentityBound.handleNode`. `nodeOf` derives it from text under the
//! platform's current rules; a client that must keep a handle out of calldata
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
            /// and then there is no way to take it back. Watch `Deposited`
            /// against `Forwarded` to tell the two apart.
            function depositToHandle(
                bytes32 platformId,
                string calldata handle,
                address token,
                uint256 amount
            ) external payable;

            /// The same, against a handle node the caller derived. Nothing
            /// about the node can be checked: a wrong node funds a slot nothing
            /// can claim, and there is no refund.
            function depositToNode(
                bytes32 platformId,
                bytes32 handleNode,
                address token,
                uint256 amount
            ) external payable;

            /// Take everything held for a handle node in one token. The caller
            /// has to be the node's holder in the naming system.
            function claim(bytes32 handleNode, address token, address recipient) external;

            function escrowed(bytes32 handleNode, address token) external view returns (uint256);
            /// The node a handle keys to under the platform's current rules.
            function nodeOf(bytes32 platformId, string calldata handle) external view returns (bytes32);
            function names() external view returns (address);
            function NATIVE() external view returns (address);

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

            error ZeroAmount();
            error ValueMismatch(uint256 expected, uint256 provided);
            error NothingHeld(bytes32 handleNode, address token);
            /// The caller is not the node's holder.
            error NotTheHolder(address holder, address caller);
            error BadRecipient(address recipient);
            /// `problem` is a `HandleNormalizer.Problem`.
            error UnusableHandle(uint8 problem);
            /// Nobody holds the node and no new claim can bind a holder on
            /// this platform.
            error PlatformAcceptsNoClaims(bytes32 platformId);
            error NativeTransferFailed(address recipient, uint256 amount);
            error NoNames();
        }
    }
}

pub use escrow_inner::HandleEscrow;
