// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {ReentrancyGuardUpgradeable} from "@openzeppelin/contracts-upgradeable/utils/ReentrancyGuardUpgradeable.sol";

import {HandleEscrow} from "../HandleEscrow.sol";
import {IIdentityNames} from "../IIdentityNames.sol";
import {SettableNames} from "./HandleEscrowAccounting.t.sol";
import {BlocklistToken, FalseToken, HookToken, ITransferHooks, NoReturnToken} from "./HostileTokens.sol";

/// @notice A depositor, holder and recipient in one, registered for the hook
///         token's callbacks. From inside a hook it makes one more escrow
///         call, catches the refusal and keeps it, so the outer call runs to
///         the end and what the guard did can be read afterwards.
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
    bytes32 private immutable NODE;

    Reentry public reentry;
    bool private entered;
    /// How many reentries were tried, and how many the escrow let through.
    uint256 public attempts;
    uint256 public admitted;
    /// Why the last reentry was refused.
    bytes public refusal;

    constructor(HandleEscrow escrow_, HookToken token_, bytes32 platformId_, bytes32 node_) {
        ESCROW = escrow_;
        TOKEN = token_;
        PLATFORM = platformId_;
        NODE = node_;
        token_.register();
        token_.approve(address(escrow_), type(uint256).max);
    }

    function arm(Reentry reentry_) external {
        reentry = reentry_;
        entered = false;
    }

    function deposit(uint256 amount) external {
        ESCROW.depositToNode(PLATFORM, NODE, address(TOKEN), amount);
    }

    function claim() external {
        ESCROW.claim(NODE, address(TOKEN), address(this));
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
            call = abi.encodeCall(HandleEscrow.depositToNode, (PLATFORM, NODE, address(TOKEN), 1));
        } else if (reentry == Reentry.Claim) {
            call = abi.encodeCall(HandleEscrow.claim, (NODE, address(TOKEN), address(this)));
        } else {
            call = abi.encodeCall(HandleEscrow.refund, (NODE, address(TOKEN), address(this)));
        }
        (bool ok, bytes memory reason) = address(ESCROW).call(call);
        if (ok) ++admitted;
        else refusal = reason;
    }
}

/// @notice Tokens that do what ERC-20 permits and a naive escrow does not
///         expect: call back in, answer `false`, answer nothing, or refuse an
///         address.
///
/// @dev Against the settable naming system, as the accounting suite runs:
///      what is under test is how the escrow moves value, not who holds a
///      node.
contract HandleEscrowHostileTokensTest is Test {
    bytes32 internal constant PLATFORM = keccak256("x");
    bytes32 internal constant NODE = keccak256("node");

    HandleEscrow internal escrow;
    SettableNames internal names;

    address internal depositor = makeAddr("depositor");
    address internal holder = makeAddr("holder");
    address internal elsewhere = makeAddr("elsewhere");

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

    /// A hook in the depositor, run while the escrow pulls its tokens, tries
    /// to deposit again. The guard refuses it, and the outer deposit books
    /// exactly what it brought.
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

    /// A hook in the depositor, run while its refund pays it, tries to refund
    /// again. Another depositor's contribution is held beside it, so a second
    /// payout would have something to take.
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

    // ─── A token that answers false ─────────────────────────────────

    /// `false` is a failure, whatever the balance says: the deposit reverts
    /// and nothing is booked.
    function test_aTokenAnsweringFalseFailsTheDeposit() public {
        FalseToken token = new FalseToken();
        token.mint(depositor, 10 ether);
        vm.prank(depositor);
        token.approve(address(escrow), type(uint256).max);
        token.setFailing(true);

        vm.prank(depositor);
        vm.expectRevert(abi.encodeWithSelector(SafeERC20.SafeERC20FailedOperation.selector, address(token)));
        escrow.depositToNode(PLATFORM, NODE, address(token), 10 ether);
        assertEq(escrow.escrowed(NODE, address(token)), 0);
    }

    /// A payout the token answers `false` to reverts the claim or refund
    /// whole: the books are as they were, and the value is still there to
    /// take once the token pays again.
    function test_aTokenAnsweringFalseFailsThePayoutAndLeavesTheBooks() public {
        FalseToken token = new FalseToken();
        token.mint(depositor, 10 ether);
        vm.startPrank(depositor);
        token.approve(address(escrow), type(uint256).max);
        escrow.depositToNode(PLATFORM, NODE, address(token), 10 ether);
        vm.stopPrank();
        token.setFailing(true);

        vm.prank(depositor);
        vm.expectRevert(abi.encodeWithSelector(SafeERC20.SafeERC20FailedOperation.selector, address(token)));
        escrow.refund(NODE, address(token), depositor);
        assertEq(escrow.refundable(NODE, address(token), depositor), 10 ether, "a failed refund spent the entry");

        names.setHolder(NODE, holder);
        vm.prank(holder);
        vm.expectRevert(abi.encodeWithSelector(SafeERC20.SafeERC20FailedOperation.selector, address(token)));
        escrow.claim(NODE, address(token), holder);
        assertEq(escrow.escrowed(NODE, address(token)), 10 ether, "a failed claim emptied the slot");

        token.setFailing(false);
        vm.prank(holder);
        escrow.claim(NODE, address(token), holder);
        assertEq(token.balanceOf(holder), 10 ether);
    }

    // ─── A token that answers nothing ───────────────────────────────

    /// USDT's shape: no return value anywhere. Every path that moves the token
    /// works: escrow, refund, claim and pay-through.
    function test_aTokenAnsweringNothingMovesOnEveryPath() public {
        NoReturnToken token = new NoReturnToken();
        token.mint(depositor, 30 ether);
        vm.startPrank(depositor);
        token.approve(address(escrow), type(uint256).max);
        escrow.depositToNode(PLATFORM, NODE, address(token), 10 ether);
        escrow.refund(NODE, address(token), depositor);
        escrow.depositToNode(PLATFORM, NODE, address(token), 10 ether);
        vm.stopPrank();
        assertEq(token.balanceOf(depositor), 20 ether, "the refund did not return the deposit");

        names.setHolder(NODE, holder);
        vm.prank(holder);
        escrow.claim(NODE, address(token), holder);
        assertEq(token.balanceOf(holder), 10 ether, "the claim did not pay");

        vm.prank(depositor);
        escrow.depositToNode(PLATFORM, NODE, address(token), 5 ether);
        assertEq(token.balanceOf(holder), 15 ether, "the pay-through did not pay");
        assertEq(token.balanceOf(address(escrow)), 0);
    }

    // ─── A token with a blocklist ───────────────────────────────────

    /// A claim to a recipient the token refuses reverts whole, and the holder
    /// can name another.
    function test_aClaimToABlockedRecipientRevertsAndLeavesTheBooks() public {
        BlocklistToken token = _escrowBlocklistToken(10 ether);
        names.setHolder(NODE, holder);
        token.setBlocked(holder, true);

        vm.prank(holder);
        vm.expectRevert(abi.encodeWithSelector(BlocklistToken.Blocked.selector, holder));
        escrow.claim(NODE, address(token), holder);
        assertEq(escrow.escrowed(NODE, address(token)), 10 ether, "a failed claim emptied the slot");

        vm.prank(holder);
        escrow.claim(NODE, address(token), elsewhere);
        assertEq(token.balanceOf(elsewhere), 10 ether);
    }

    /// A refund to a recipient the token refuses reverts whole, and the
    /// depositor can name another.
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

    /// A pay-through to a holder the token refuses fails the deposit, and the
    /// depositor keeps its tokens.
    function test_aPayThroughToABlockedHolderReverts() public {
        BlocklistToken token = new BlocklistToken();
        token.mint(depositor, 10 ether);
        vm.prank(depositor);
        token.approve(address(escrow), type(uint256).max);
        names.setHolder(NODE, holder);
        token.setBlocked(holder, true);

        vm.prank(depositor);
        vm.expectRevert(abi.encodeWithSelector(BlocklistToken.Blocked.selector, holder));
        escrow.depositToNode(PLATFORM, NODE, address(token), 10 ether);
        assertEq(token.balanceOf(depositor), 10 ether);
    }

    /// The token blocklisting the escrow itself freezes every slot in that
    /// token: no deposit, claim or refund moves it. Lifting the block restores
    /// all of them, with the books intact.
    function test_ACCEPTED_aTokenBlockingTheEscrowFreezesEverySlotInIt() public {
        BlocklistToken token = _escrowBlocklistToken(10 ether);
        token.mint(depositor, 10 ether);
        token.setBlocked(address(escrow), true);

        vm.startPrank(depositor);
        vm.expectRevert(abi.encodeWithSelector(BlocklistToken.Blocked.selector, address(escrow)));
        escrow.depositToNode(PLATFORM, NODE, address(token), 1 ether);
        vm.expectRevert(abi.encodeWithSelector(BlocklistToken.Blocked.selector, address(escrow)));
        escrow.refund(NODE, address(token), depositor);
        vm.stopPrank();

        names.setHolder(NODE, holder);
        vm.prank(holder);
        vm.expectRevert(abi.encodeWithSelector(BlocklistToken.Blocked.selector, address(escrow)));
        escrow.claim(NODE, address(token), holder);
        assertEq(escrow.escrowed(NODE, address(token)), 10 ether, "the frozen slot changed");

        token.setBlocked(address(escrow), false);
        vm.prank(holder);
        escrow.claim(NODE, address(token), holder);
        assertEq(token.balanceOf(holder), 10 ether);
    }

    // ─── Helpers ────────────────────────────────────────────────────

    function _hooked() internal returns (HookToken token, HookedParty party) {
        token = new HookToken();
        party = new HookedParty(escrow, token, PLATFORM, NODE);
    }

    /// Another depositor's contribution, in the hook token, which has no hook.
    function _fundWithHookToken(HookToken token, uint256 amount) internal {
        token.mint(depositor, amount);
        vm.startPrank(depositor);
        token.approve(address(escrow), amount);
        escrow.depositToNode(PLATFORM, NODE, address(token), amount);
        vm.stopPrank();
    }

    function _escrowBlocklistToken(uint256 amount) internal returns (BlocklistToken token) {
        token = new BlocklistToken();
        token.mint(depositor, amount);
        vm.startPrank(depositor);
        token.approve(address(escrow), type(uint256).max);
        escrow.depositToNode(PLATFORM, NODE, address(token), amount);
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
