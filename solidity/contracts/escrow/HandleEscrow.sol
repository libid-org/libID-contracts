// SPDX-License-Identifier: MIT
pragma solidity ^0.8.22;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {Initializable} from "@openzeppelin/contracts/proxy/utils/Initializable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts/proxy/utils/UUPSUpgradeable.sol";
import {Ownable2StepUpgradeable} from "@openzeppelin/contracts-upgradeable/access/Ownable2StepUpgradeable.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {SafeCast} from "@openzeppelin/contracts/utils/math/SafeCast.sol";

import {HandleNode} from "../handles/HandleNode.sol";
import {IHandleReveal} from "../handles/IHandleReveal.sol";
import {IIdentityRegistry} from "../identity/IIdentityRegistry.sol";

// The EIP-7528 address that stands for the chain's native token.
address constant NATIVE_TOKEN = 0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE;

/// @title HandleEscrow - send to a platform handle before anybody holds it.
/// @notice Holds value against a handle node until its holder claims it. Until
///         then each sender can take its own contribution back from its
///         `refundableAt`, which each of its deposits sets `REFUND_GRACE` ahead.
/// @dev A deposit belongs to `msg.sender`. Deposits through a contract share its
///      contribution: whoever can make it call `refund` can take it, and whoever can
///      make it deposit can keep it locked. A claim empties the slot and opens a new
///      round, ending the old round's refunds.
///      Integration notes are in README.md beside this file.
contract HandleEscrow is IHandleReveal, Initializable, UUPSUpgradeable, Ownable2StepUpgradeable, ReentrancyGuard {
    using SafeERC20 for IERC20;

    /// @notice The native token of the chain, as a token address (EIP-7528).
    address public constant NATIVE = NATIVE_TOKEN;

    /// @notice How long a deposit stays claimable before its sender can refund it.
    uint256 public constant REFUND_GRACE = 30 days;

    /// @notice One sender's balance for a node and token in one round.
    struct Contribution {
        uint192 amount;
        /// When `refund` opens; each deposit sets it `REFUND_GRACE` ahead.
        uint64 refundableAt;
    }

    /// @custom:storage-location erc7201:libid.storage.HandleEscrow
    struct HandleEscrowStorage {
        /// handle node -> token -> amount held.
        mapping(bytes32 => mapping(address => uint256)) held;
        IIdentityRegistry registry;
        /// handle node -> token -> claims so far; contributions are booked
        /// under the current round.
        mapping(bytes32 => mapping(address => uint256)) round;
        /// handle node -> token -> round -> sender -> contribution. In the
        /// current round the amounts sum to `held`.
        mapping(bytes32 => mapping(address => mapping(uint256 => mapping(address => Contribution)))) contributions;
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

    /// @notice `sender` escrowed value for a node nobody holds, under `round`.
    ///         `amount` is what arrived; `sender`'s whole contribution is
    ///         refundable from `refundableAt` until the round's claim.
    event Deposited(
        bytes32 indexed handleNode,
        address indexed token,
        address indexed sender,
        uint256 round,
        uint256 amount,
        uint64 refundableAt
    );

    /// @notice `sender`'s deposit for a held node was paid straight to `holder`.
    ///         `amount` was asked for; `received` is what the holder gained.
    event Forwarded(
        bytes32 indexed handleNode,
        address indexed token,
        address indexed sender,
        address holder,
        uint256 amount,
        uint256 received
    );

    /// @notice The holder took what was held in one token, closing `round`.
    ///         `released` left the books; `received` is what `recipient`
    ///         gained.
    event Claimed(
        bytes32 indexed handleNode,
        address indexed token,
        address indexed claimer,
        address recipient,
        uint256 round,
        uint256 released,
        uint256 received
    );

    /// @notice `sender` took its `round` contribution back. `released` left
    ///         the books; `received` is what `recipient` gained.
    event Refunded(
        bytes32 indexed handleNode,
        address indexed token,
        address indexed sender,
        address recipient,
        uint256 round,
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
    /// Nothing is held for this handle node in any of the tokens asked for.
    error NothingHeld(bytes32 handleNode);
    /// The caller does not hold this handle node.
    error NotTheHolder(address holder, address caller);
    /// Nothing is booked under this sender in the current round.
    error NothingToRefund(bytes32 handleNode, address token, address sender);
    /// The sender's contribution is refundable from `refundableAt`.
    error RefundLocked(bytes32 handleNode, address token, address sender, uint64 refundableAt);
    /// The sender's contribution would not fit its 192 bits.
    error ContributionTooLarge(bytes32 handleNode, address token, address sender);
    /// A token other than `NATIVE` must have code.
    error BadToken(address token);
    /// A payout may not go to the zero address or this contract.
    error BadRecipient(address recipient);
    /// A payout took more of this contract's balance than it booked.
    error OverDebited(address token, uint256 booked, uint256 debited);
    /// The recipient refused the transfer.
    error NativeTransferFailed(address recipient, uint256 amount);
    /// The escrow needs an identity registry to resolve through.
    error NoRegistry();
    /// The registry does not key identities by handle node (`nodeKeyed()` is false).
    error RegistryNotNodeKeyed(address registry);
    /// Ownership cannot be renounced; see `renounceOwnership`.
    error RenounceDisabled();
    /// A deposit to an unheld node on a platform nobody can bind now, so nobody could claim.
    error PlatformAcceptsNoBindings(bytes32 platformId);

    // ─── Setup ──────────────────────────────────────────────────────

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    /// @dev Reverts `RegistryNotNodeKeyed` when `registry_.nodeKeyed()` is false, and on the call
    ///      itself when `registry_` has no `nodeKeyed`.
    function initialize(address owner_, IIdentityRegistry registry_) external initializer {
        if (address(registry_) == address(0)) revert NoRegistry();
        if (!registry_.nodeKeyed()) revert RegistryNotNodeKeyed(address(registry_));
        __Ownable_init(owner_);
        __Ownable2Step_init();
        _s().registry = registry_;
    }

    /// @notice The identity registry this escrow resolves through.
    function registry() external view returns (IIdentityRegistry) {
        return _s().registry;
    }

    // ─── Depositing ─────────────────────────────────────────────────

    /// @notice Pay `amount` of `token` to a handle node (`IdentityRegistry.handleNodeOf`):
    ///         to whoever holds it when the transaction executes, else into escrow.
    ///         Reverts `PlatformAcceptsNoBindings` when it would escrow on a platform nobody
    ///         can bind now, and the registry's `UnknownPlatform` when it would escrow on a
    ///         platform the registry does not know; a holder is still paid.
    ///         Reverts `ContributionTooLarge` when the sender's contribution would reach
    ///         2^192.
    /// @dev Books what arrived under `msg.sender`, and moves the date `refund` opens for
    ///      its whole contribution to `REFUND_GRACE` from now. A wrong node funds a slot
    ///      only the sender can recover, from its `refundableAt` like any other. A node of
    ///      another platform than `platformId` escrows until its own platform binds it;
    ///      then its holder can claim.
    /// @param platformId     The platform whose tag made `handleNode`.
    /// @param token          An ERC-20, or `NATIVE`, when `amount` must equal `msg.value`.
    function deposit(bytes32 platformId, bytes32 handleNode, address token, uint256 amount)
        external
        payable
        nonReentrant
    {
        _deposit(handleNode, platformId, token, amount);
    }

    /// @notice `deposit` to a handle given as text, which the calldata and the log
    ///         make public. Reverts the registry's `UnknownPlatform` for a platform
    ///         it does not know, even when the handle is held.
    /// @dev The node is the registry's `handleNodeOf`; `HandleRevealed` carries the handle folded.
    function depositToHandle(bytes32 platformId, string calldata handle, address token, uint256 amount)
        external
        payable
        nonReentrant
    {
        bytes32 handleNode = _s().registry.handleNodeOf(platformId, handle);
        _deposit(handleNode, platformId, token, amount);
        emit HandleRevealed(platformId, handleNode, HandleNode.fold(handle));
    }

    function _deposit(bytes32 handleNode, bytes32 platformId, address token, uint256 amount) private {
        if (amount == 0) revert ZeroAmount();
        if (token == NATIVE) {
            if (msg.value != amount) revert ValueMismatch(amount, msg.value);
        } else {
            if (token.code.length == 0) revert BadToken(token);
            if (msg.value != 0) revert ValueMismatch(0, msg.value);
        }

        HandleEscrowStorage storage $ = _s();
        (address holder,) = $.registry.handleBinding(handleNode);
        if (holder != address(0)) {
            if (holder == msg.sender) revert PayingYourself(holder);
            uint256 received = _move(token, msg.sender, holder, amount);
            if (received == 0) revert ZeroAmount();
            emit Forwarded(handleNode, token, msg.sender, holder, amount, received);
            return;
        }

        if (!$.registry.acceptsBindings(platformId)) revert PlatformAcceptsNoBindings(platformId);
        uint256 credited = _move(token, msg.sender, address(this), amount);
        if (credited == 0) revert ZeroAmount();

        uint256 round = $.round[handleNode][token];
        mapping(address => Contribution) storage current = $.contributions[handleNode][token][round];
        uint64 refundableAt = SafeCast.toUint64(block.timestamp + REFUND_GRACE);
        uint256 total = current[msg.sender].amount + credited;
        if (total > type(uint192).max) revert ContributionTooLarge(handleNode, token, msg.sender);
        // forge-lint: disable-next-line(unsafe-typecast)
        current[msg.sender] = Contribution(uint192(total), refundableAt);
        $.held[handleNode][token] += credited;
        emit Deposited(handleNode, token, msg.sender, round, credited, refundableAt);
    }

    // ─── Claiming ───────────────────────────────────────────────────

    /// @notice Take everything held for a node in each of `tokens`. The caller
    ///         must be `handleBinding(handleNode).holder`; `recipient` is its
    ///         choice.
    /// @dev Tokens with nothing held are skipped, so a list read from an
    ///      indexer survives a refund landing first; a repeated token pays
    ///      once. Reverts `NothingHeld` only when no token paid. One `Claimed`
    ///      per token paid.
    function claim(bytes32 handleNode, address[] calldata tokens, address recipient) external nonReentrant {
        if (recipient == address(0) || recipient == address(this)) revert BadRecipient(recipient);

        (address holder,) = _s().registry.handleBinding(handleNode);
        if (holder != msg.sender) revert NotTheHolder(holder, msg.sender);

        HandleEscrowStorage storage $ = _s();
        bool paid;
        for (uint256 i; i < tokens.length; ++i) {
            address token = tokens[i];
            uint256 amount = $.held[handleNode][token];
            if (amount == 0) continue;
            $.held[handleNode][token] = 0;
            uint256 round = $.round[handleNode][token]++;
            paid = true;
            emit Claimed(
                handleNode, token, msg.sender, recipient, round, amount, _move(token, address(this), recipient, amount)
            );
        }
        if (!paid) revert NothingHeld(handleNode);
    }

    // ─── Refunding ──────────────────────────────────────────────────

    /// @notice Pay `recipient` what is booked under the caller for a node in the
    ///         current round, once its `refundableAt` has come, whether or not the
    ///         node has a holder. Reverts `BadRecipient` for the zero address or this
    ///         contract, `NothingToRefund` when nothing is booked, `RefundLocked`
    ///         before `refundableAt`, and `NativeTransferFailed` or the token's own
    ///         error when the payout fails.
    function refund(bytes32 handleNode, address token, address recipient) external nonReentrant {
        if (recipient == address(0) || recipient == address(this)) revert BadRecipient(recipient);

        HandleEscrowStorage storage $ = _s();
        uint256 round = $.round[handleNode][token];
        mapping(address => Contribution) storage current = $.contributions[handleNode][token][round];
        Contribution memory mine = current[msg.sender];
        if (mine.amount == 0) revert NothingToRefund(handleNode, token, msg.sender);
        if (block.timestamp < mine.refundableAt) {
            revert RefundLocked(handleNode, token, msg.sender, mine.refundableAt);
        }
        uint256 amount = mine.amount;
        delete current[msg.sender];
        $.held[handleNode][token] -= amount;

        emit Refunded(
            handleNode, token, msg.sender, recipient, round, amount, _move(token, address(this), recipient, amount)
        );
    }

    // ─── Reading ────────────────────────────────────────────────────

    /// @notice How much is held for a node in one token.
    function escrowed(bytes32 handleNode, address token) external view returns (uint256) {
        return _s().held[handleNode][token];
    }

    /// @notice What is booked under `sender` for a node in the current round, and
    ///         when `refund` opens for it.
    function contribution(bytes32 handleNode, address token, address sender)
        external
        view
        returns (uint256 amount, uint64 refundableAt)
    {
        HandleEscrowStorage storage $ = _s();
        Contribution storage c = $.contributions[handleNode][token][$.round[handleNode][token]][sender];
        return (c.amount, c.refundableAt);
    }

    /// @dev Moves value and returns what `to` gained (native: `amount`). Zero is
    ///      returned, not refused: deposits refuse it, payouts accept it. A
    ///      payout may not take more of this contract's balance than `amount`.
    function _move(address token, address from, address to, uint256 amount) private returns (uint256 gained) {
        if (token == NATIVE) {
            if (to != address(this)) _sendNative(to, amount);
            return amount;
        }
        IERC20 erc20 = IERC20(token);
        uint256 before = erc20.balanceOf(to);
        if (from == address(this)) {
            uint256 poolBefore = erc20.balanceOf(address(this));
            erc20.safeTransfer(to, amount);
            uint256 poolAfter = erc20.balanceOf(address(this));
            if (poolAfter < poolBefore && poolBefore - poolAfter > amount) {
                revert OverDebited(token, amount, poolBefore - poolAfter);
            }
        } else {
            erc20.safeTransferFrom(from, to, amount);
        }
        uint256 afterwards = erc20.balanceOf(to);
        return afterwards > before ? afterwards - before : 0;
    }

    function _sendNative(address to, uint256 amount) private {
        (bool ok,) = to.call{value: amount}("");
        if (!ok) revert NativeTransferFailed(to, amount);
    }

    // ─── Upgrade ────────────────────────────────────────────────────

    function _authorizeUpgrade(address) internal override onlyOwner {}

    /// @dev The upgrade is the only repair lever, so ownership stays.
    function renounceOwnership() public pure override {
        revert RenounceDisabled();
    }
}
