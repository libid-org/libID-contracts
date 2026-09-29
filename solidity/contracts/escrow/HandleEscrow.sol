// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {Ownable2StepUpgradeable} from "@openzeppelin/contracts-upgradeable/access/Ownable2StepUpgradeable.sol";
import {ReentrancyGuardUpgradeable} from "@openzeppelin/contracts-upgradeable/utils/ReentrancyGuardUpgradeable.sol";

import {IIdentityNames} from "../identity/IIdentityNames.sol";
import {IdentityNodes} from "../identity/IdentityNodes.sol";

/// @title HandleEscrow - send to a platform handle before anybody claims it.
///
/// @notice Holds value against a handle node. The node's holder in
///         `IdentityNames` claims it; until then each deposit's `refundTo`
///         can take its own contribution back.
///
/// @dev - A slot is `IdentityNodes.handleNode(platformId, normalized)`, the
///        node `IdentityNames` binds and emits. `claim` is authorized by
///        `names.byHandle(node).owner` alone.
///      - A deposit for a held node is paid straight through; only an unheld
///        node on a platform that `acceptsClaims` escrows.
///      - Refunds have no delay and stay open until the holder claims; a claim
///        takes everything and moves the slot to a new round, which ends the
///        refunds of the old one. A refund and a claim racing: first wins.
///      - The handle is the whole key: a recycled handle, or a stale binding
///        (`byHandle` names whoever last proved it), receives what is paid or
///        left unrefunded. Wallets should show `byHandle(node).observedAt`.
///      - No pause. `refund` depends on neither the platform's rules nor
///        `acceptsClaims`, so it stays the way out when those change.
///      - Unsupported: rebasing tokens. Value arriving outside a deposit is
///        never swept. A token that blocklists this contract freezes its slots.
///      - Trust base: every key that can change what `byHandle` answers (the
///        `IdentityNames`, `CeremonyProofVerifier`, `NotaryService`,
///        Platform Verifier and `GoogleJwtRoots` owners, trusted notary keys,
///        the platforms themselves) can take held value through an ordinary
///        identity claim; this contract's owner can upgrade it.
contract HandleEscrow is Initializable, UUPSUpgradeable, Ownable2StepUpgradeable, ReentrancyGuardUpgradeable {
    using SafeERC20 for IERC20;

    /// @notice The native token of the chain, as a token address.
    address public constant NATIVE = address(0);

    /// @custom:storage-location erc7201:libid.storage.HandleEscrow
    struct HandleEscrowStorage {
        /// handle node -> token -> amount held.
        mapping(bytes32 => mapping(address => uint256)) held;
        IIdentityNames names;
        /// handle node -> token -> claims so far; contributions are booked
        /// under the current round.
        mapping(bytes32 => mapping(address => uint256)) round;
        /// handle node -> token -> round -> refundTo -> refundable amount. In
        /// the current round these sum to `held`.
        mapping(bytes32 => mapping(address => mapping(uint256 => mapping(address => uint256)))) contributions;
    }

    // keccak256(abi.encode(uint256(keccak256("libid.storage.HandleEscrow")) - 1)) & ~bytes32(uint256(0xff))
    bytes32 private constant HANDLE_ESCROW_STORAGE = 0xfcca8d7d2c66f78c2760f3fcd99e0bf938b0aeb0d0b471f481dd50b8aff6b400;

    /// @dev Fields may only be appended on upgrade.
    function _s() private pure returns (HandleEscrowStorage storage $) {
        assembly {
            $.slot := HANDLE_ESCROW_STORAGE
        }
    }

    // ─── Events ─────────────────────────────────────────────────────

    /// @notice Value was escrowed for a node nobody holds. `amount` is what
    ///         arrived; `depositor` paid, `refundTo` may refund.
    event Deposited(
        bytes32 indexed handleNode,
        address indexed token,
        address indexed refundTo,
        address depositor,
        bytes32 platformId,
        uint256 amount
    );

    /// @notice A deposit for a held node was paid straight to `holder`.
    ///         `amount` was asked for; `received` is what the holder gained.
    event Forwarded(
        bytes32 indexed handleNode,
        address indexed token,
        address indexed depositor,
        address holder,
        bytes32 platformId,
        uint256 amount,
        uint256 received
    );

    /// @notice The holder took what was held. `released` left the books;
    ///         `received` is what `recipient` gained.
    event Claimed(
        bytes32 indexed handleNode,
        address indexed token,
        address indexed claimer,
        address recipient,
        uint256 released,
        uint256 received
    );

    /// @notice `refundTo` took its contribution back. `released` left the
    ///         books; `received` is what `recipient` gained.
    event Refunded(
        bytes32 indexed handleNode,
        address indexed token,
        address indexed refundTo,
        address recipient,
        uint256 released,
        uint256 received
    );

    // ─── Errors ─────────────────────────────────────────────────────

    /// Nothing was asked for, or nothing arrived.
    error ZeroAmount();
    /// The caller holds the node it is paying.
    error PayingYourself(address holder);
    /// Native value must equal the amount, and a token deposit carries none.
    error ValueMismatch(uint256 expected, uint256 provided);
    /// Nothing is held for this handle node in this token.
    error NothingHeld(bytes32 handleNode, address token);
    /// The caller does not hold this handle node.
    error NotTheHolder(address holder, address caller);
    /// Nothing refundable is booked under this address in the current round.
    error NothingToRefund(bytes32 handleNode, address token, address refundTo);
    /// `refundTo` must be nonzero.
    error NoRefundTo();
    /// A payout may not go to the zero address or this contract.
    error BadRecipient(address recipient);
    /// Nobody holds the node and nothing new can bind on this platform.
    error PlatformAcceptsNoClaims(bytes32 platformId);
    /// The recipient refused the transfer.
    error NativeTransferFailed(address recipient, uint256 amount);
    /// The escrow needs a naming system to resolve through.
    error NoNames();
    /// The naming contract does not answer this function as expected.
    error NamesLacks(address names, bytes4 selector);
    /// Ownership cannot be renounced; see `renounceOwnership`.
    error RenounceDisabled();

    // ─── Setup ──────────────────────────────────────────────────────

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    /// @dev Reverts `NamesLacks` unless `names_` answers like `IdentityNames`.
    function initialize(address owner_, IIdentityNames names_) external initializer {
        if (address(names_) == address(0)) revert NoNames();
        _requireAnswers(names_);
        __Ownable_init(owner_);
        __Ownable2Step_init();
        __UUPSUpgradeable_init();
        __ReentrancyGuard_init();
        _s().names = names_;
    }

    /// @notice The naming system this escrow resolves through.
    function names() external view returns (IIdentityNames) {
        return _s().names;
    }

    // ─── Depositing ─────────────────────────────────────────────────

    /// @notice Pay `amount` of `token` to a handle, given as `keccak256` of its
    ///         normalized form (`IdentityNames.handleHashOf`).
    ///
    /// @dev - The hash cannot be checked: a wrong one funds a slot nobody can
    ///        claim, which `refundTo` can refund.
    ///      - A held node is paid straight through (`Forwarded`), and a holder
    ///        paying itself reverts `PayingYourself`. Otherwise the value is
    ///        escrowed under `refundTo` (`Deposited`).
    ///      - Both branches book what arrived, so fee-on-transfer tokens work.
    ///        A holder that sweeps tokens onward inside the transfer gains
    ///        nothing and the deposit reverts `ZeroAmount`.
    /// @param token    An ERC-20, or `NATIVE`, when `amount` must equal `msg.value`.
    /// @param refundTo Who may refund an escrowed deposit. Never zero.
    function deposit(bytes32 platformId, bytes32 handleHash, address token, uint256 amount, address refundTo)
        external
        payable
        nonReentrant
    {
        _deposit(platformId, IdentityNodes.handleNodeOfHash(platformId, handleHash), token, amount, refundTo);
    }

    function _deposit(bytes32 platformId, bytes32 node, address token, uint256 amount, address refundTo) private {
        if (amount == 0) revert ZeroAmount();
        if (refundTo == address(0)) revert NoRefundTo();

        if (token == NATIVE) {
            if (msg.value != amount) revert ValueMismatch(amount, msg.value);
        } else if (msg.value != 0) {
            revert ValueMismatch(0, msg.value);
        }

        (address holder,) = _s().names.byHandle(node);
        if (holder != address(0)) {
            if (holder == msg.sender) revert PayingYourself(holder);
            uint256 received = _move(token, msg.sender, holder, amount);
            if (received == 0) revert ZeroAmount();
            emit Forwarded(node, token, msg.sender, holder, platformId, amount, received);
            return;
        }

        if (!_s().names.acceptsClaims(platformId)) revert PlatformAcceptsNoClaims(platformId);

        uint256 credited = _move(token, msg.sender, address(this), amount);
        if (credited == 0) revert ZeroAmount();

        HandleEscrowStorage storage $ = _s();
        $.held[node][token] += credited;
        $.contributions[node][token][$.round[node][token]][refundTo] += credited;
        emit Deposited(node, token, refundTo, msg.sender, platformId, credited);
    }

    // ─── Claiming ───────────────────────────────────────────────────

    /// @notice Take everything held for a node in one token. The caller must
    ///         be `byHandle(handleNode).owner`; `recipient` is its choice.
    function claim(bytes32 handleNode, address token, address recipient) external nonReentrant {
        if (recipient == address(0) || recipient == address(this)) revert BadRecipient(recipient);

        (address holder,) = _s().names.byHandle(handleNode);
        if (holder != msg.sender) revert NotTheHolder(holder, msg.sender);

        HandleEscrowStorage storage $ = _s();
        uint256 amount = $.held[handleNode][token];
        if (amount == 0) revert NothingHeld(handleNode, token);
        $.held[handleNode][token] = 0;
        ++$.round[handleNode][token];

        emit Claimed(handleNode, token, msg.sender, recipient, amount, _move(token, address(this), recipient, amount));
    }

    // ─── Refunding ──────────────────────────────────────────────────

    /// @notice Take back what is booked under the caller for a node in the
    ///         current round, whether or not the node has a holder.
    function refund(bytes32 handleNode, address token, address recipient) external nonReentrant {
        if (recipient == address(0) || recipient == address(this)) revert BadRecipient(recipient);

        HandleEscrowStorage storage $ = _s();
        mapping(address => uint256) storage current = $.contributions[handleNode][token][$.round[handleNode][token]];
        uint256 amount = current[msg.sender];
        if (amount == 0) revert NothingToRefund(handleNode, token, msg.sender);
        current[msg.sender] = 0;
        $.held[handleNode][token] -= amount;

        emit Refunded(handleNode, token, msg.sender, recipient, amount, _move(token, address(this), recipient, amount));
    }

    // ─── Reading ────────────────────────────────────────────────────

    /// @notice How much is held for a node in one token.
    function escrowed(bytes32 handleNode, address token) external view returns (uint256) {
        return _s().held[handleNode][token];
    }

    /// @notice What `refund` would pay `refundTo` now.
    function refundable(bytes32 handleNode, address token, address refundTo) external view returns (uint256) {
        HandleEscrowStorage storage $ = _s();
        return $.contributions[handleNode][token][$.round[handleNode][token]][refundTo];
    }

    /// @notice `IdentityNames.nodeOf`: the node a handle keys to now, which
    ///         `claim`, `refund` and the reads take.
    function nodeOf(bytes32 platformId, string calldata handle) external view returns (bytes32) {
        return _s().names.nodeOf(platformId, handle);
    }

    /// @dev Moves value and returns what `to` gained (native: `amount`). Zero is
    ///      returned, not refused: deposits refuse it, payouts accept it.
    function _move(address token, address from, address to, uint256 amount) private returns (uint256 gained) {
        if (token == NATIVE) {
            if (to != address(this)) _sendNative(to, amount);
            return amount;
        }
        uint256 before = IERC20(token).balanceOf(to);
        if (from == address(this)) IERC20(token).safeTransfer(to, amount);
        else IERC20(token).safeTransferFrom(from, to, amount);
        uint256 afterwards = IERC20(token).balanceOf(to);
        return afterwards > before ? afterwards - before : 0;
    }

    function _sendNative(address to, uint256 amount) private {
        (bool ok,) = to.call{value: amount}("");
        if (!ok) revert NativeTransferFailed(to, amount);
    }

    /// @dev Requires the exact answers `IdentityNames` gives for the zero node
    ///      and platform: an empty binding, `false`, and `UnknownPlatform(0)`.
    function _requireAnswers(IIdentityNames names_) private view {
        bytes memory result;
        bool ok;
        (ok, result) = address(names_).staticcall(abi.encodeCall(IIdentityNames.byHandle, (bytes32(0))));
        if (!ok || keccak256(result) != keccak256(abi.encode(address(0), uint64(0)))) {
            revert NamesLacks(address(names_), IIdentityNames.byHandle.selector);
        }
        (ok, result) = address(names_).staticcall(abi.encodeCall(IIdentityNames.acceptsClaims, (bytes32(0))));
        if (!ok || keccak256(result) != keccak256(abi.encode(false))) {
            revert NamesLacks(address(names_), IIdentityNames.acceptsClaims.selector);
        }
        (ok, result) = address(names_).staticcall(abi.encodeCall(IIdentityNames.nodeOf, (bytes32(0), "")));
        if (ok || keccak256(result) != keccak256(abi.encodeWithSelector(IIdentityNames.UnknownPlatform.selector, 0))) {
            revert NamesLacks(address(names_), IIdentityNames.nodeOf.selector);
        }
    }

    // ─── Upgrade ────────────────────────────────────────────────────

    function _authorizeUpgrade(address) internal override onlyOwner {}

    /// @dev The upgrade is the only repair lever, so ownership stays.
    function renounceOwnership() public pure override {
        revert RenounceDisabled();
    }
}
