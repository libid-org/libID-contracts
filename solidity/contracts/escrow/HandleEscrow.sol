// SPDX-License-Identifier: MIT
pragma solidity ^0.8.22;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {Ownable2StepUpgradeable} from "@openzeppelin/contracts-upgradeable/access/Ownable2StepUpgradeable.sol";
import {ReentrancyGuardUpgradeable} from "@openzeppelin/contracts-upgradeable/utils/ReentrancyGuardUpgradeable.sol";

import {IIdentityRegistry} from "../identity/IIdentityRegistry.sol";

// The EIP-7528 address that stands for the chain's native token.
address constant NATIVE_TOKEN = 0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE;

/// @title HandleEscrow - send to a platform handle before anybody holds it.
/// @notice Holds value against a handle node until its holder claims it; each
///         deposit's `refundTo` can take its own contribution back until then.
/// @dev - A held node is paid straight through; an unheld one escrows.
///      - A claim empties the slot and opens a new round, ending the old
///        round's refunds. Refunds have no delay and no pause gates them.
///      - Each token is one pool across all nodes; a payout that debits it by
///        more than it books reverts `OverDebited`, so a token that charges
///        its sender on `transfer` deposits but never pays out.
contract HandleEscrow is Initializable, UUPSUpgradeable, Ownable2StepUpgradeable, ReentrancyGuardUpgradeable {
    using SafeERC20 for IERC20;

    /// @notice The native token of the chain, as a token address (EIP-7528).
    address public constant NATIVE = NATIVE_TOKEN;

    /// @custom:storage-location erc7201:libid.storage.HandleEscrow
    struct HandleEscrowStorage {
        /// handle node -> token -> amount held.
        mapping(bytes32 => mapping(address => uint256)) held;
        IIdentityRegistry registry;
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

    /// @notice Value was escrowed for a node nobody holds, under `round`.
    ///         `amount` is what arrived; `depositor` paid, `refundTo` may
    ///         refund until the round's claim.
    event Deposited(
        bytes32 indexed handleNode,
        address indexed token,
        address indexed refundTo,
        address depositor,
        uint256 round,
        uint256 amount
    );

    /// @notice A deposit for a held node was paid straight to `holder`.
    ///         `amount` was asked for; `received` is what the holder gained.
    event Forwarded(
        bytes32 indexed handleNode,
        address indexed token,
        address indexed depositor,
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

    /// @notice `refundTo` took its `round` contribution back. `released` left
    ///         the books; `received` is what `recipient` gained.
    event Refunded(
        bytes32 indexed handleNode,
        address indexed token,
        address indexed refundTo,
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
    /// Nothing refundable is booked under this address in the current round.
    error NothingToRefund(bytes32 handleNode, address token, address refundTo);
    /// `refundTo` must be an address that can call `refund`: not zero, not
    /// this contract.
    error BadRefundTo(address refundTo);
    /// A payout may not go to the zero address or this contract.
    error BadRecipient(address recipient);
    /// A payout took more of this contract's balance than it booked.
    error OverDebited(address token, uint256 booked, uint256 debited);
    /// The recipient refused the transfer.
    error NativeTransferFailed(address recipient, uint256 amount);
    /// The escrow needs an identity registry to resolve through.
    error NoRegistry();
    /// The registry does not answer this function as expected.
    error RegistryLacks(address registry, bytes4 selector);
    /// Ownership cannot be renounced; see `renounceOwnership`.
    error RenounceDisabled();

    // ─── Setup ──────────────────────────────────────────────────────

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    /// @dev Reverts `RegistryLacks` unless `registry_` answers like the node-keyed `IdentityRegistry`.
    function initialize(address owner_, IIdentityRegistry registry_) external initializer {
        if (address(registry_) == address(0)) revert NoRegistry();
        _requireAnswers(registry_);
        __Ownable_init(owner_);
        __Ownable2Step_init();
        __UUPSUpgradeable_init();
        __ReentrancyGuard_init();
        _s().registry = registry_;
    }

    /// @notice The identity registry this escrow resolves through.
    function registry() external view returns (IIdentityRegistry) {
        return _s().registry;
    }

    // ─── Depositing ─────────────────────────────────────────────────

    /// @notice Pay `amount` of `token` to a handle node (`IdentityRegistry.handleNodeOf`).
    /// @dev Books what arrived. A wrong node funds a slot only `refundTo` can recover.
    /// @param token    An ERC-20, or `NATIVE`, when `amount` must equal `msg.value`.
    /// @param refundTo Who may refund an escrowed deposit; never zero or this contract.
    function deposit(bytes32 handleNode, address token, uint256 amount, address refundTo)
        external
        payable
        nonReentrant
    {
        if (amount == 0) revert ZeroAmount();
        if (refundTo == address(0) || refundTo == address(this)) revert BadRefundTo(refundTo);

        if (token == NATIVE) {
            if (msg.value != amount) revert ValueMismatch(amount, msg.value);
        } else if (msg.value != 0) {
            revert ValueMismatch(0, msg.value);
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

        uint256 credited = _move(token, msg.sender, address(this), amount);
        if (credited == 0) revert ZeroAmount();

        uint256 round = $.round[handleNode][token];
        $.held[handleNode][token] += credited;
        $.contributions[handleNode][token][round][refundTo] += credited;
        emit Deposited(handleNode, token, refundTo, msg.sender, round, credited);
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

    /// @notice Take back what is booked under the caller for a node in the
    ///         current round, whether or not the node has a holder.
    function refund(bytes32 handleNode, address token, address recipient) external nonReentrant {
        if (recipient == address(0) || recipient == address(this)) revert BadRecipient(recipient);

        HandleEscrowStorage storage $ = _s();
        uint256 round = $.round[handleNode][token];
        mapping(address => uint256) storage current = $.contributions[handleNode][token][round];
        uint256 amount = current[msg.sender];
        if (amount == 0) revert NothingToRefund(handleNode, token, msg.sender);
        current[msg.sender] = 0;
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

    /// @notice What `refund` would pay `refundTo` now.
    function refundable(bytes32 handleNode, address token, address refundTo) external view returns (uint256) {
        HandleEscrowStorage storage $ = _s();
        return $.contributions[handleNode][token][$.round[handleNode][token]][refundTo];
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

    /// @dev Probed once at initialization: only the node-keyed registry has `resolveId(bytes32)`.
    bytes4 private constant NODE_REGISTRY_PROBE = bytes4(keccak256("resolveId(bytes32)"));

    /// @dev Refuses a registry that does not answer `handleBinding` and `NODE_REGISTRY_PROBE` in shape.
    function _requireAnswers(IIdentityRegistry registry_) private view {
        (bool ok, bytes memory result) =
            address(registry_).staticcall(abi.encodeCall(IIdentityRegistry.handleBinding, (bytes32(0))));
        if (!ok || result.length != 64) {
            revert RegistryLacks(address(registry_), IIdentityRegistry.handleBinding.selector);
        }
        (ok, result) = address(registry_).staticcall(abi.encodeWithSelector(NODE_REGISTRY_PROBE, bytes32(0)));
        if (!ok || result.length != 32) revert RegistryLacks(address(registry_), NODE_REGISTRY_PROBE);
    }

    // ─── Upgrade ────────────────────────────────────────────────────

    function _authorizeUpgrade(address) internal override onlyOwner {}

    /// @dev The upgrade is the only repair lever, so ownership stays.
    function renounceOwnership() public pure override {
        revert RenounceDisabled();
    }
}
