// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {ReentrancyGuardUpgradeable} from "@openzeppelin/contracts-upgradeable/utils/ReentrancyGuardUpgradeable.sol";

import {HandleEscrow} from "../HandleEscrow.sol";
import {one} from "./One.sol";
import {IdentityNodes} from "../../identity/IdentityNodes.sol";
import {IIdentityNames} from "../../identity/IIdentityNames.sol";
import {SettableNames} from "./HandleEscrowAccounting.t.sol";
import {
    BlocklistToken,
    FalseToken,
    HookToken,
    ITransferHooks,
    NoReturnToken,
    PayoutFeeToken,
    RebasingToken,
    SenderFeeToken,
    ShrinkingToken
} from "./HostileTokens.sol";
import {IERC20Errors} from "@openzeppelin/contracts/interfaces/draft-IERC6093.sol";

/// @notice The two calls a test makes on any of the mintable tokens.
interface IMintable {
    function mint(address to, uint256 amount) external;
    function approve(address spender, uint256 amount) external returns (bool);
}

/// @notice A depositor, holder and recipient in one, registered for the hook token's callbacks.
contract HookedParty is ITransferHooks {
    enum Reentry {
        None,
        Deposit,
        Claim,
        Refund
    }

    HandleEscrow private immutable ESCROW;
    HookToken private immutable TOKEN;
    bytes32 private immutable PLATFORM;
    bytes32 private immutable HASH;
    bytes32 private immutable NODE;

    Reentry public reentry;
    bool private entered;
    /// How many reentries were tried, and how many the escrow let through.
    uint256 public attempts;
    uint256 public admitted;
    /// Why the last reentry was refused.
    bytes public refusal;

    constructor(HandleEscrow escrow_, HookToken token_, bytes32 platformId_, bytes32 handleHash_) {
        ESCROW = escrow_;
        TOKEN = token_;
        PLATFORM = platformId_;
        HASH = handleHash_;
        NODE = IdentityNodes.handleNodeOfHash(platformId_, handleHash_);
        token_.register();
        token_.approve(address(escrow_), type(uint256).max);
    }

    function arm(Reentry reentry_) external {
        reentry = reentry_;
        entered = false;
    }

    function deposit(uint256 amount) external {
        ESCROW.deposit(PLATFORM, HASH, address(TOKEN), amount, address(this));
    }

    function claim() external {
        ESCROW.claim(NODE, one(address(TOKEN)), address(this));
    }

    function refund() external {
        ESCROW.refund(NODE, address(TOKEN), address(this));
    }

    function tokensToSend(address, address, uint256) external {
        _reenter();
    }

    function tokensReceived(address, address, uint256) external {
        _reenter();
    }

    function _reenter() private {
        if (entered || reentry == Reentry.None) return;
        entered = true;
        ++attempts;
        bytes memory call;
        if (reentry == Reentry.Deposit) {
            call = abi.encodeCall(HandleEscrow.deposit, (PLATFORM, HASH, address(TOKEN), 1, address(this)));
        } else if (reentry == Reentry.Claim) {
            call = abi.encodeCall(HandleEscrow.claim, (NODE, one(address(TOKEN)), address(this)));
        } else {
            call = abi.encodeCall(HandleEscrow.refund, (NODE, address(TOKEN), address(this)));
        }
        (bool ok, bytes memory reason) = address(ESCROW).call(call);
        if (ok) ++admitted;
        else refusal = reason;
    }
}

/// @notice A holder that moves every hook token it receives on to a vault from inside the transfer,
///         and takes native value as it comes.
contract SweepingHolder is ITransferHooks {
    HookToken private immutable TOKEN;
    address private immutable VAULT;

    constructor(HookToken token_, address vault_) {
        TOKEN = token_;
        VAULT = vault_;
        token_.register();
    }

    function tokensToSend(address, address, uint256) external {}

    function tokensReceived(address, address, uint256 amount) external {
        require(TOKEN.transfer(VAULT, amount), "the sweep failed");
    }

    receive() external payable {}
}

/// @notice Tokens that do what ERC-20 permits and a naive escrow does not expect: call back in,
///         answer `false`, answer nothing, or refuse an address.
contract HandleEscrowHostileTokensTest is Test {
    bytes32 internal constant PLATFORM = keccak256("x");
    bytes32 internal constant HASH = keccak256("node");
    bytes32 internal immutable NODE = IdentityNodes.handleNodeOfHash(PLATFORM, HASH);
    bytes32 internal constant HASH2 = keccak256("node 2");
    bytes32 internal immutable NODE2 = IdentityNodes.handleNodeOfHash(PLATFORM, HASH2);

    HandleEscrow internal escrow;
    SettableNames internal names;

    address internal depositor = makeAddr("depositor");
    address internal holder = makeAddr("holder");
    address internal elsewhere = makeAddr("elsewhere");
    address internal other = makeAddr("other");

    function setUp() public {
        names = new SettableNames();
        HandleEscrow impl = new HandleEscrow();
        escrow = HandleEscrow(
            address(
                new ERC1967Proxy(
                    address(impl),
                    abi.encodeCall(HandleEscrow.initialize, (address(this), IIdentityNames(address(names))))
                )
            )
        );
    }

    // ─── A token that calls back in ─────────────────────────────────

    /// A hook in the depositor, run while the escrow pulls its tokens, tries to deposit again.
    function test_aHookReenteringDepositIsRefused() public {
        (HookToken token, HookedParty party) = _hooked();
        token.mint(address(party), 10 ether);
        party.arm(HookedParty.Reentry.Deposit);

        party.deposit(10 ether);

        _assertRefusedByTheGuard(party);
        assertEq(escrow.escrowed(NODE, address(token)), 10 ether);
        assertEq(escrow.refundable(NODE, address(token), address(party)), 10 ether);
        assertEq(token.balanceOf(address(escrow)), 10 ether, "the books and the balance disagree");
    }

    /// A hook in the holder, run while the claim pays it, tries to claim again.
    function test_aHookReenteringClaimIsRefused() public {
        (HookToken token, HookedParty party) = _hooked();
        _fundWithHookToken(token, 10 ether);
        names.setHolder(NODE, address(party));
        party.arm(HookedParty.Reentry.Claim);

        party.claim();

        _assertRefusedByTheGuard(party);
        assertEq(token.balanceOf(address(party)), 10 ether, "the holder was paid other than once");
        assertEq(escrow.escrowed(NODE, address(token)), 0);
        assertEq(token.balanceOf(address(escrow)), 0);
    }

    /// A hook in the depositor, run while its refund pays it, tries to refund again.
    function test_aHookReenteringRefundIsRefused() public {
        (HookToken token, HookedParty party) = _hooked();
        token.mint(address(party), 10 ether);
        party.deposit(10 ether);
        _fundWithHookToken(token, 5 ether);
        party.arm(HookedParty.Reentry.Refund);

        party.refund();

        _assertRefusedByTheGuard(party);
        assertEq(token.balanceOf(address(party)), 10 ether, "the depositor was refunded other than once");
        assertEq(escrow.escrowed(NODE, address(token)), 5 ether, "somebody else's contribution moved");
        assertEq(token.balanceOf(address(escrow)), 5 ether);
    }

    /// KNOWN LIMITATION, pinned.
    function test_ACCEPTED_aHolderThatSweepsATokenCannotBePaidThroughInIt() public {
        HookToken token = new HookToken();
        SweepingHolder sweeper = new SweepingHolder(token, elsewhere);
        names.setHolder(NODE, address(sweeper));
        token.mint(depositor, 10 ether);

        vm.startPrank(depositor);
        token.approve(address(escrow), type(uint256).max);
        vm.expectRevert(HandleEscrow.ZeroAmount.selector);
        escrow.deposit(PLATFORM, HASH, address(token), 10 ether, depositor);
        vm.stopPrank();
        assertEq(token.balanceOf(depositor), 10 ether, "the refused deposit moved tokens");
        assertEq(token.balanceOf(elsewhere), 0);

        vm.deal(depositor, 1 ether);
        vm.prank(depositor);
        escrow.deposit{value: 1 ether}(PLATFORM, HASH, address(0), 1 ether, depositor);
        assertEq(address(sweeper).balance, 1 ether, "native value did not reach the holder");
    }

    // ─── A token that answers false ─────────────────────────────────

    /// `false` is a failure, whatever the balance says: the deposit reverts and nothing is booked.
    function test_aTokenAnsweringFalseFailsTheDeposit() public {
        FalseToken token = new FalseToken();
        token.mint(depositor, 10 ether);
        vm.prank(depositor);
        token.approve(address(escrow), type(uint256).max);
        token.setFailing(true);

        vm.prank(depositor);
        vm.expectRevert(abi.encodeWithSelector(SafeERC20.SafeERC20FailedOperation.selector, address(token)));
        escrow.deposit(PLATFORM, HASH, address(token), 10 ether, depositor);
        assertEq(escrow.escrowed(NODE, address(token)), 0);
    }

    /// A payout the token answers `false` to reverts the claim or refund whole: the books are as
    /// they were, and the value is still there to take once the token pays again.
    function test_aTokenAnsweringFalseFailsThePayoutAndLeavesTheBooks() public {
        FalseToken token = new FalseToken();
        token.mint(depositor, 10 ether);
        vm.startPrank(depositor);
        token.approve(address(escrow), type(uint256).max);
        escrow.deposit(PLATFORM, HASH, address(token), 10 ether, depositor);
        vm.stopPrank();
        token.setFailing(true);

        vm.prank(depositor);
        vm.expectRevert(abi.encodeWithSelector(SafeERC20.SafeERC20FailedOperation.selector, address(token)));
        escrow.refund(NODE, address(token), depositor);
        assertEq(escrow.refundable(NODE, address(token), depositor), 10 ether, "a failed refund spent the entry");

        names.setHolder(NODE, holder);
        vm.prank(holder);
        vm.expectRevert(abi.encodeWithSelector(SafeERC20.SafeERC20FailedOperation.selector, address(token)));
        escrow.claim(NODE, one(address(token)), holder);
        assertEq(escrow.escrowed(NODE, address(token)), 10 ether, "a failed claim emptied the slot");

        token.setFailing(false);
        vm.prank(holder);
        escrow.claim(NODE, one(address(token)), holder);
        assertEq(token.balanceOf(holder), 10 ether);
    }

    // ─── A token that answers nothing ───────────────────────────────

    /// USDT's shape: no return value anywhere.
    function test_aTokenAnsweringNothingMovesOnEveryPath() public {
        NoReturnToken token = new NoReturnToken();
        token.mint(depositor, 30 ether);
        vm.startPrank(depositor);
        token.approve(address(escrow), type(uint256).max);
        escrow.deposit(PLATFORM, HASH, address(token), 10 ether, depositor);
        escrow.refund(NODE, address(token), depositor);
        escrow.deposit(PLATFORM, HASH, address(token), 10 ether, depositor);
        vm.stopPrank();
        assertEq(token.balanceOf(depositor), 20 ether, "the refund did not return the deposit");

        names.setHolder(NODE, holder);
        vm.prank(holder);
        escrow.claim(NODE, one(address(token)), holder);
        assertEq(token.balanceOf(holder), 10 ether, "the claim did not pay");

        vm.prank(depositor);
        escrow.deposit(PLATFORM, HASH, address(token), 5 ether, depositor);
        assertEq(token.balanceOf(holder), 15 ether, "the pay-through did not pay");
        assertEq(token.balanceOf(address(escrow)), 0);
    }

    // ─── A token that shrinks the recipient ─────────────────────────

    /// A transfer into the escrow that leaves it holding LESS than before delivered nothing: the
    /// deposit is refused `ZeroAmount`, as a pay-through that delivers nothing is, not with an
    /// arithmetic panic, and the books are as they were.
    function test_aDepositThatLowersTheEscrowsBalanceDeliveredNothing() public {
        ShrinkingToken token = new ShrinkingToken();
        token.mint(depositor, 20 ether);
        vm.startPrank(depositor);
        token.approve(address(escrow), type(uint256).max);
        escrow.deposit(PLATFORM, HASH, address(token), 10 ether, depositor);
        vm.stopPrank();
        token.setShrinking(true);

        vm.prank(depositor);
        vm.expectRevert(HandleEscrow.ZeroAmount.selector);
        escrow.deposit(PLATFORM, HASH, address(token), 1 ether, depositor);

        assertEq(escrow.escrowed(NODE, address(token)), 10 ether, "the refused deposit moved the books");
        assertEq(escrow.refundable(NODE, address(token), depositor), 10 ether);
    }

    // ─── A token that takes a fee on the payout ─────────────────────

    /// `Claimed` reports what the books released and, beside it, what the recipient received: the
    /// slot empties by the whole amount held.
    function test_aClaimReportsWhatTheRecipientReceived() public {
        PayoutFeeToken token = _escrowPayoutFeeToken(100 ether);
        names.setHolder(NODE, holder);

        vm.expectEmit(true, true, true, true, address(escrow));
        emit HandleEscrow.Claimed(NODE, address(token), holder, elsewhere, 100 ether, 99 ether);
        vm.prank(holder);
        escrow.claim(NODE, one(address(token)), elsewhere);

        assertEq(token.balanceOf(elsewhere), 99 ether);
        assertEq(escrow.escrowed(NODE, address(token)), 0, "the books kept the fee");
        assertEq(token.balanceOf(address(escrow)), 0);
    }

    /// `Refunded` the same, and the contribution is spent whole.
    function test_aRefundReportsWhatTheRecipientReceived() public {
        PayoutFeeToken token = _escrowPayoutFeeToken(100 ether);

        vm.expectEmit(true, true, true, true, address(escrow));
        emit HandleEscrow.Refunded(NODE, address(token), depositor, elsewhere, 100 ether, 99 ether);
        vm.prank(depositor);
        escrow.refund(NODE, address(token), elsewhere);

        assertEq(token.balanceOf(elsewhere), 99 ether);
        assertEq(escrow.refundable(NODE, address(token), depositor), 0, "the fee stayed refundable");
        assertEq(escrow.escrowed(NODE, address(token)), 0);
        assertEq(token.balanceOf(address(escrow)), 0);
    }

    // ─── A token with a blocklist ───────────────────────────────────

    /// A claim to a recipient the token refuses reverts whole, and the holder can name another.
    function test_aClaimToABlockedRecipientRevertsAndLeavesTheBooks() public {
        BlocklistToken token = _escrowBlocklistToken(10 ether);
        names.setHolder(NODE, holder);
        token.setBlocked(holder, true);

        vm.prank(holder);
        vm.expectRevert(abi.encodeWithSelector(BlocklistToken.Blocked.selector, holder));
        escrow.claim(NODE, one(address(token)), holder);
        assertEq(escrow.escrowed(NODE, address(token)), 10 ether, "a failed claim emptied the slot");

        vm.prank(holder);
        escrow.claim(NODE, one(address(token)), elsewhere);
        assertEq(token.balanceOf(elsewhere), 10 ether);
    }

    /// A refund to a recipient the token refuses reverts whole, and the depositor can name another.
    function test_aRefundToABlockedRecipientRevertsAndLeavesTheBooks() public {
        BlocklistToken token = _escrowBlocklistToken(10 ether);
        token.setBlocked(depositor, true);

        vm.prank(depositor);
        vm.expectRevert(abi.encodeWithSelector(BlocklistToken.Blocked.selector, depositor));
        escrow.refund(NODE, address(token), depositor);
        assertEq(escrow.refundable(NODE, address(token), depositor), 10 ether, "a failed refund spent the entry");
        assertEq(escrow.escrowed(NODE, address(token)), 10 ether);

        vm.prank(depositor);
        escrow.refund(NODE, address(token), elsewhere);
        assertEq(token.balanceOf(elsewhere), 10 ether);
    }

    /// A pay-through to a holder the token refuses fails the deposit, and the depositor keeps its
    /// tokens.
    function test_aPayThroughToABlockedHolderReverts() public {
        BlocklistToken token = new BlocklistToken();
        token.mint(depositor, 10 ether);
        vm.prank(depositor);
        token.approve(address(escrow), type(uint256).max);
        names.setHolder(NODE, holder);
        token.setBlocked(holder, true);

        vm.prank(depositor);
        vm.expectRevert(abi.encodeWithSelector(BlocklistToken.Blocked.selector, holder));
        escrow.deposit(PLATFORM, HASH, address(token), 10 ether, depositor);
        assertEq(token.balanceOf(depositor), 10 ether);
    }

    /// The token blocklisting the escrow itself freezes every slot in that token: no deposit, claim
    /// or refund moves it.
    function test_ACCEPTED_aTokenBlockingTheEscrowFreezesEverySlotInIt() public {
        BlocklistToken token = _escrowBlocklistToken(10 ether);
        token.mint(depositor, 10 ether);
        token.setBlocked(address(escrow), true);

        vm.startPrank(depositor);
        vm.expectRevert(abi.encodeWithSelector(BlocklistToken.Blocked.selector, address(escrow)));
        escrow.deposit(PLATFORM, HASH, address(token), 1 ether, depositor);
        vm.expectRevert(abi.encodeWithSelector(BlocklistToken.Blocked.selector, address(escrow)));
        escrow.refund(NODE, address(token), depositor);
        vm.stopPrank();

        names.setHolder(NODE, holder);
        vm.prank(holder);
        vm.expectRevert(abi.encodeWithSelector(BlocklistToken.Blocked.selector, address(escrow)));
        escrow.claim(NODE, one(address(token)), holder);
        assertEq(escrow.escrowed(NODE, address(token)), 10 ether, "the frozen slot changed");

        token.setBlocked(address(escrow), false);
        vm.prank(holder);
        escrow.claim(NODE, one(address(token)), holder);
        assertEq(token.balanceOf(holder), 10 ether);
    }

    // ─── One pool per token ─────────────────────────────────────────

    /// A payout that would take more of the pool than it books is refused, so one node's claim
    /// cannot spend another node's backing.
    function test_aPayoutThatOverDebitsThePoolIsRefused() public {
        SenderFeeToken token = new SenderFeeToken();
        _escrowTwoNodes(address(token), 10 ether);

        names.setHolder(NODE, holder);
        vm.prank(holder);
        vm.expectRevert(abi.encodeWithSelector(HandleEscrow.OverDebited.selector, address(token), 10 ether, 10.1 ether));
        escrow.claim(NODE, one(address(token)), holder);

        vm.prank(depositor);
        vm.expectRevert(abi.encodeWithSelector(HandleEscrow.OverDebited.selector, address(token), 10 ether, 10.1 ether));
        escrow.refund(NODE, address(token), depositor);

        assertEq(escrow.escrowed(NODE, address(token)), 10 ether);
        assertEq(escrow.escrowed(NODE2, address(token)), 10 ether);
        assertEq(token.balanceOf(address(escrow)), 20 ether);
    }

    /// KNOWN LIMITATION, pinned: a negative rebase shrinks the shared pool, and whoever withdraws
    /// that token last cannot.
    function test_ACCEPTED_aNegativeRebaseStrandsTheLastWithdrawal() public {
        RebasingToken token = new RebasingToken();
        _escrowTwoNodes(address(token), 10 ether);
        token.slash(address(escrow), 5 ether);

        vm.prank(depositor);
        escrow.refund(NODE, address(token), depositor);
        assertEq(token.balanceOf(depositor), 10 ether, "the first refund was not whole");

        vm.prank(other);
        vm.expectRevert(
            abi.encodeWithSelector(IERC20Errors.ERC20InsufficientBalance.selector, address(escrow), 5 ether, 10 ether)
        );
        escrow.refund(NODE2, address(token), other);
        assertEq(escrow.escrowed(NODE2, address(token)), 10 ether, "the stranded slot changed");
    }

    // ─── Helpers ────────────────────────────────────────────────────

    /// `amount` escrowed for NODE by `depositor` and for NODE2 by `other`.
    function _escrowTwoNodes(address token, uint256 amount) internal {
        IMintable(token).mint(depositor, amount);
        IMintable(token).mint(other, amount);
        vm.startPrank(depositor);
        IMintable(token).approve(address(escrow), amount);
        escrow.deposit(PLATFORM, HASH, token, amount, depositor);
        vm.stopPrank();
        vm.startPrank(other);
        IMintable(token).approve(address(escrow), amount);
        escrow.deposit(PLATFORM, HASH2, token, amount, other);
        vm.stopPrank();
    }

    function _hooked() internal returns (HookToken token, HookedParty party) {
        token = new HookToken();
        party = new HookedParty(escrow, token, PLATFORM, HASH);
    }

    /// Another depositor's contribution, in the hook token, which has no hook.
    function _fundWithHookToken(HookToken token, uint256 amount) internal {
        token.mint(depositor, amount);
        vm.startPrank(depositor);
        token.approve(address(escrow), amount);
        escrow.deposit(PLATFORM, HASH, address(token), amount, depositor);
        vm.stopPrank();
    }

    function _escrowPayoutFeeToken(uint256 amount) internal returns (PayoutFeeToken token) {
        token = new PayoutFeeToken();
        token.mint(depositor, amount);
        vm.startPrank(depositor);
        token.approve(address(escrow), type(uint256).max);
        escrow.deposit(PLATFORM, HASH, address(token), amount, depositor);
        vm.stopPrank();
        assertEq(escrow.escrowed(NODE, address(token)), amount, "the deposit did not arrive whole");
    }

    function _escrowBlocklistToken(uint256 amount) internal returns (BlocklistToken token) {
        token = new BlocklistToken();
        token.mint(depositor, amount);
        vm.startPrank(depositor);
        token.approve(address(escrow), type(uint256).max);
        escrow.deposit(PLATFORM, HASH, address(token), amount, depositor);
        vm.stopPrank();
    }

    function _assertRefusedByTheGuard(HookedParty party) internal view {
        assertEq(party.attempts(), 1, "the hook never reentered");
        assertEq(party.admitted(), 0, "a reentry was let through");
        assertEq(
            party.refusal(),
            abi.encodeWithSelector(ReentrancyGuardUpgradeable.ReentrancyGuardReentrantCall.selector),
            "the reentry was not refused by the guard"
        );
    }
}
