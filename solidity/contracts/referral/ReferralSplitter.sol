// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {Ownable2Step} from "@openzeppelin/contracts/access/Ownable2Step.sol";

import {HandleEscrow, NATIVE_TOKEN} from "../escrow/HandleEscrow.sol";
import {IBindFeeReceiver} from "../identity/IBindFeeReceiver.sol";
import {IIdentityRegistry} from "../identity/IIdentityRegistry.sol";

/// @title ReferralSplitter - a bind's service fee, shared with the handle that referred it.
/// @notice The registry's `bindWithFeeCall` pays the fee here. With a referral in
///         `feeData`, `shareBps` of the fee goes to the referrer's handle node
///         through the escrow: to its holder, or held until somebody binds it. The
///         rest, and any share that cannot be delivered, goes to `treasury`.
/// @dev Holds no balance between transactions. Its escrow contributions are the
///      shares of nodes nobody held yet, held until each node's holder claims them.
contract ReferralSplitter is IBindFeeReceiver, Ownable2Step {
    /// @notice What happened to a referral's share.
    enum Outcome {
        /// Deposited with the escrow, which logs `Forwarded` or `Deposited` with this contract as `sender`.
        Paid,
        /// The binder holds the referrer's node; the treasury took the share.
        SelfReferral,
        /// The deposit reverted: the escrow or the holder refused the share, or the holder used up the gas; the treasury took the share.
        Refused
    }

    uint16 private constant WHOLE = 10_000;

    /// @notice The registry whose binds pay here. Only it may call `onBindFee`.
    IIdentityRegistry public immutable REGISTRY;

    /// @notice The escrow that holds a share for a node nobody holds.
    HandleEscrow public immutable ESCROW;

    /// @notice Where every part of a fee that is not a delivered share goes.
    address public treasury;

    /// @notice The referrer's part of a fee, in basis points.
    uint16 public shareBps;

    /// @notice A fee below this pays the treasury alone, referral or not, so a
    ///         one-wei bind cannot add to a referrer's history.
    uint256 public minReferralFee;

    // ─── Events ─────────────────────────────────────────────────────

    /// @notice A bind named a referrer. `share` is the referrer's part at the
    ///         current rate; `outcome` says whether it was delivered.
    event Referred(
        bytes32 indexed referrerNode,
        address indexed binder,
        bytes32 indexed sessionId,
        bytes32 referrerPlatformId,
        bytes32 platformId,
        bytes32 handleNode,
        uint256 fee,
        uint256 share,
        Outcome outcome
    );

    event ShareSet(uint16 shareBps);
    event TreasurySet(address treasury);
    event MinReferralFeeSet(uint256 minReferralFee);

    // ─── Errors ─────────────────────────────────────────────────────

    error ZeroAddress();
    /// The escrow resolves nodes through another registry.
    error EscrowOfAnotherRegistry(address escrowRegistry);
    /// `onBindFee` came from somebody other than the registry.
    error NotRegistry(address caller);
    /// `feeData` is neither empty nor `abi.encode(bytes32 referrerPlatformId, bytes32 referrerNode)`.
    error BadFeeData(uint256 length);
    /// The treasury refused its part, which reverts the bind.
    error TreasuryRefused(address treasury, uint256 amount);
    error BadTreasury(address treasury);
    error ShareAboveWhole(uint16 shareBps);
    error RenounceDisabled();

    // ─── Setup ──────────────────────────────────────────────────────

    /// @dev The owner is an argument, so a deploy through a factory names it.
    constructor(
        IIdentityRegistry registry,
        HandleEscrow escrow,
        address owner_,
        address treasury_,
        uint16 shareBps_,
        uint256 minReferralFee_
    ) Ownable(owner_) {
        if (address(registry) == address(0) || address(escrow) == address(0)) revert ZeroAddress();
        if (address(escrow.registry()) != address(registry)) {
            revert EscrowOfAnotherRegistry(address(escrow.registry()));
        }
        REGISTRY = registry;
        ESCROW = escrow;
        _setTreasury(treasury_);
        _setShare(shareBps_);
        _setMinReferralFee(minReferralFee_);
    }

    // ─── Settings ───────────────────────────────────────────────────

    function setTreasury(address treasury_) external onlyOwner {
        _setTreasury(treasury_);
    }

    /// @notice Up to 10,000, the whole fee.
    function setShare(uint16 shareBps_) external onlyOwner {
        _setShare(shareBps_);
    }

    function setMinReferralFee(uint256 minReferralFee_) external onlyOwner {
        _setMinReferralFee(minReferralFee_);
    }

    function _setTreasury(address treasury_) private {
        if (treasury_ == address(0) || treasury_ == address(this)) revert BadTreasury(treasury_);
        treasury = treasury_;
        emit TreasurySet(treasury_);
    }

    function _setShare(uint16 shareBps_) private {
        if (shareBps_ > WHOLE) revert ShareAboveWhole(shareBps_);
        shareBps = shareBps_;
        emit ShareSet(shareBps_);
    }

    function _setMinReferralFee(uint256 minReferralFee_) private {
        minReferralFee = minReferralFee_;
        emit MinReferralFeeSet(minReferralFee_);
    }

    /// @dev The treasury and the settings stay changeable.
    function renounceOwnership() public pure override {
        revert RenounceDisabled();
    }

    // ─── Splitting ──────────────────────────────────────────────────

    /// @inheritdoc IBindFeeReceiver
    /// @dev `feeData` is empty for no referral, or `abi.encode(referrerPlatformId,
    ///      referrerNode)`. A referral emits `Referred` only when it carries a share:
    ///      a fee of at least `minReferralFee` and a nonzero `shareBps`.
    function onBindFee(
        address binder,
        bytes32 platformId,
        bytes32 handleNode,
        bytes32 sessionId,
        bytes calldata feeData
    ) external payable returns (bytes4) {
        if (msg.sender != address(REGISTRY)) revert NotRegistry(msg.sender);
        if (feeData.length != 0 && feeData.length != 64) revert BadFeeData(feeData.length);

        uint256 fee = msg.value;
        uint256 share = feeData.length == 0 || fee < minReferralFee ? 0 : fee * shareBps / WHOLE;
        if (share == 0) {
            _payTreasury(fee);
            return IBindFeeReceiver.onBindFee.selector;
        }

        (bytes32 referrerPlatformId, bytes32 referrerNode) = abi.decode(feeData, (bytes32, bytes32));
        Outcome outcome = _deliver(binder, referrerPlatformId, referrerNode, share);
        emit Referred(referrerNode, binder, sessionId, referrerPlatformId, platformId, handleNode, fee, share, outcome);
        _payTreasury(outcome == Outcome.Paid ? fee - share : fee);
        return IBindFeeReceiver.onBindFee.selector;
    }

    /// @dev Deposits the share unless the binder holds the referrer's node. A
    ///      reverted deposit loses the share to the treasury and the bind goes on.
    ///      The deposit gets all the gas left but 1/64. When it runs out of gas
    ///      with less than about a million, that 1/64 cannot pay for the log and
    ///      the treasury, and the bind reverts: the lowest gas limit a bind
    ///      succeeds at pays a holder that accepts the share.
    function _deliver(address binder, bytes32 referrerPlatformId, bytes32 referrerNode, uint256 share)
        private
        returns (Outcome)
    {
        (address holder,) = REGISTRY.handleBinding(referrerNode);
        if (holder == binder) return Outcome.SelfReferral;

        try ESCROW.deposit{value: share}(referrerPlatformId, referrerNode, NATIVE_TOKEN, share) {
            return Outcome.Paid;
        } catch {
            return Outcome.Refused;
        }
    }

    function _payTreasury(uint256 amount) private {
        if (amount == 0) return;
        (bool paid,) = treasury.call{value: amount}("");
        if (!paid) revert TreasuryRefused(treasury, amount);
    }
}
