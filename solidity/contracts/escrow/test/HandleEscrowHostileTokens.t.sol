// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {IERC20Errors} from "@openzeppelin/contracts/interfaces/draft-IERC6093.sol";
import {ReentrancyGuardUpgradeable} from "@openzeppelin/contracts-upgradeable/utils/ReentrancyGuardUpgradeable.sol";

import {HandleEscrow} from "../HandleEscrow.sol";
import {HandleVectors} from "../../identity/HandleVectors.sol";
import {IIdentityRegistry} from "../../identity/IIdentityRegistry.sol";
import {TestNodes} from "../../identity/test/TestNodes.sol";
import {
    BlocklistToken,
    FalseToken,
    HookToken,
    ITransferHooks,
    NoReturnToken,
    PayoutFeeToken,
    RebasingToken,
    SenderFeeToken,
    SettableRegistry,
    TestERC20,
    one
} from "./EscrowMocks.sol";

/// @notice Depositor and holder in one, re-entering the escrow from the hook token's callbacks.
contract HookedParty is ITransferHooks {
    HandleEscrow private immutable ESCROW;
    address private immutable TOKEN;
    bytes32 private immutable NODE;
    bytes public reentry;
    bytes public refusal;

    constructor(HandleEscrow escrow_, HookToken token_, bytes32 node_) {
        (ESCROW, TOKEN, NODE) = (escrow_, address(token_), node_);
        token_.register();
        token_.approve(address(escrow_), type(uint256).max);
    }

    function act(bytes calldata call, bytes calldata reentry_) external {
        reentry = reentry_;
        (bool ok, bytes memory reason) = address(ESCROW).call(call);
        require(ok, string(reason));
    }

    function tokensToSend(address, address, uint256) external {
        _reenter();
    }

    function tokensReceived(address, address, uint256) external {
        _reenter();
    }

    function _reenter() private {
        if (reentry.length == 0) return;
        bytes memory call = reentry;
        delete reentry;
        (bool ok, bytes memory reason) = address(ESCROW).call(call);
        require(!ok, "a reentry was let through");
        refusal = reason;
    }
}

/// @notice Tokens that call back in, answer `false` or nothing, charge fees, blocklist or rebase.
contract HandleEscrowHostileTokensTest is Test {
    bytes32 internal constant PLATFORM = HandleVectors.PLATFORM_X;
    bytes32 internal immutable NODE = TestNodes.handleNode(PLATFORM, "alice");
    bytes32 internal immutable NODE2 = TestNodes.handleNode(PLATFORM, "bob");

    HandleEscrow internal escrow;
    SettableRegistry internal registry;
    address internal depositor = makeAddr("depositor");
    address internal holder = makeAddr("holder");
    address internal other = makeAddr("other");

    function setUp() public {
        registry = new SettableRegistry();
        escrow = HandleEscrow(
            address(
                new ERC1967Proxy(
                    address(new HandleEscrow()),
                    abi.encodeCall(HandleEscrow.initialize, (address(this), IIdentityRegistry(address(registry))))
                )
            )
        );
    }

    /// A hook re-entering deposit, claim or refund from inside the transfer is refused by the guard.
    function test_aHookReenteringAnyEntryPointIsRefused() public {
        HookToken token = new HookToken();
        HookedParty party = new HookedParty(escrow, token, NODE);
        token.mint(address(party), 20 ether);
        bytes memory depositCall =
            abi.encodeCall(HandleEscrow.deposit, (PLATFORM, NODE, address(token), 10 ether, address(party)));
        bytes memory claimCall = abi.encodeCall(HandleEscrow.claim, (NODE, one(address(token)), address(party)));
        bytes memory refundCall = abi.encodeCall(HandleEscrow.refund, (NODE, address(token), address(party)));
        bytes memory guard = abi.encodeWithSelector(ReentrancyGuardUpgradeable.ReentrancyGuardReentrantCall.selector);

        party.act(depositCall, depositCall);
        assertEq(party.refusal(), guard);
        party.act(refundCall, refundCall);
        assertEq(party.refusal(), guard);
        assertEq(token.balanceOf(address(party)), 20 ether, "refunded other than once");

        party.act(depositCall, "");
        registry.setHolder(NODE, address(party));
        party.act(claimCall, claimCall);
        assertEq(party.refusal(), guard);
        assertEq(token.balanceOf(address(party)), 20 ether, "claimed other than once");
        assertEq(token.balanceOf(address(escrow)), 0);
    }

    /// `false` fails the deposit and each payout whole; the books wait until the token pays again.
    function test_aTokenAnsweringFalseFailsWholeAndLeavesTheBooks() public {
        FalseToken token = new FalseToken();
        _escrow(address(token), depositor, NODE, 10 ether);
        token.setFailing(true);
        bytes memory failed = abi.encodeWithSelector(SafeERC20.SafeERC20FailedOperation.selector, address(token));

        vm.startPrank(depositor);
        vm.expectRevert(failed);
        escrow.deposit(PLATFORM, NODE, address(token), 1, depositor);
        vm.expectRevert(failed);
        escrow.refund(NODE, address(token), depositor);
        vm.stopPrank();
        registry.setHolder(NODE, holder);
        vm.prank(holder);
        vm.expectRevert(failed);
        escrow.claim(NODE, one(address(token)), holder);
        assertEq(escrow.refundable(NODE, address(token), depositor), 10 ether);

        token.setFailing(false);
        vm.prank(holder);
        escrow.claim(NODE, one(address(token)), holder);
        assertEq(token.balanceOf(holder), 10 ether);
    }

    /// USDT's shape, no return value, works on every path.
    function test_aTokenAnsweringNothingMovesOnEveryPath() public {
        NoReturnToken token = new NoReturnToken();
        token.mint(depositor, 25 ether);
        vm.startPrank(depositor);
        token.approve(address(escrow), type(uint256).max);
        escrow.deposit(PLATFORM, NODE, address(token), 10 ether, depositor);
        escrow.refund(NODE, address(token), depositor);
        escrow.deposit(PLATFORM, NODE, address(token), 10 ether, depositor);
        vm.stopPrank();
        registry.setHolder(NODE, holder);
        vm.prank(holder);
        escrow.claim(NODE, one(address(token)), holder);
        vm.prank(depositor);
        escrow.deposit(PLATFORM, NODE, address(token), 5 ether, depositor);
        assertEq(token.balanceOf(holder), 15 ether);
        assertEq(token.balanceOf(depositor), 10 ether);
        assertEq(token.balanceOf(address(escrow)), 0);
    }

    /// A payout fee: the books release the whole amount, and the events report both.
    function test_aPayoutFeeIsReportedAsReleasedAndReceived() public {
        PayoutFeeToken token = new PayoutFeeToken();
        _escrow(address(token), depositor, NODE, 100 ether);
        _escrow(address(token), other, NODE2, 100 ether);

        vm.expectEmit(address(escrow));
        emit HandleEscrow.Refunded(NODE, address(token), depositor, depositor, 0, 100 ether, 99 ether);
        vm.prank(depositor);
        escrow.refund(NODE, address(token), depositor);

        registry.setHolder(NODE2, holder);
        vm.expectEmit(address(escrow));
        emit HandleEscrow.Claimed(NODE2, address(token), holder, holder, 0, 100 ether, 99 ether);
        vm.prank(holder);
        escrow.claim(NODE2, one(address(token)), holder);
        assertEq(token.balanceOf(address(escrow)), 0);
    }

    /// A blocked recipient or holder fails the call whole; another recipient works.
    function test_aBlockedPartyFailsTheCallAndLeavesTheBooks() public {
        BlocklistToken token = new BlocklistToken();
        _escrow(address(token), depositor, NODE, 10 ether);
        token.setBlocked(holder, true);
        token.setBlocked(depositor, true);

        vm.prank(depositor);
        vm.expectRevert(abi.encodeWithSelector(BlocklistToken.Blocked.selector, depositor));
        escrow.refund(NODE, address(token), depositor);
        registry.setHolder(NODE, holder);
        vm.prank(holder);
        vm.expectRevert(abi.encodeWithSelector(BlocklistToken.Blocked.selector, holder));
        escrow.claim(NODE, one(address(token)), holder);

        token.mint(other, 1 ether);
        vm.startPrank(other);
        token.approve(address(escrow), 1 ether);
        vm.expectRevert(abi.encodeWithSelector(BlocklistToken.Blocked.selector, holder));
        escrow.deposit(PLATFORM, NODE, address(token), 1 ether, other);
        vm.stopPrank();

        vm.prank(holder);
        escrow.claim(NODE, one(address(token)), other);
        assertEq(token.balanceOf(other), 11 ether);
    }

    /// KNOWN LIMITATION: a token blocking the escrow freezes every slot in it until it stops.
    function test_ACCEPTED_aTokenBlockingTheEscrowFreezesItsSlots() public {
        BlocklistToken token = new BlocklistToken();
        _escrow(address(token), depositor, NODE, 10 ether);
        token.setBlocked(address(escrow), true);
        bytes memory blocked = abi.encodeWithSelector(BlocklistToken.Blocked.selector, address(escrow));

        vm.prank(depositor);
        vm.expectRevert(blocked);
        escrow.refund(NODE, address(token), depositor);
        registry.setHolder(NODE, holder);
        vm.prank(holder);
        vm.expectRevert(blocked);
        escrow.claim(NODE, one(address(token)), holder);

        token.setBlocked(address(escrow), false);
        vm.prank(holder);
        escrow.claim(NODE, one(address(token)), holder);
        assertEq(token.balanceOf(holder), 10 ether);
    }

    /// KNOWN LIMITATION: a token charging its sender on `transfer` deposits but never pays out. Every
    /// claim and refund would take more of the pool than it books and is refused, which is what keeps
    /// one node from spending another's; only an upgrade can release the value.
    function test_ACCEPTED_aSenderFeeTokenDepositsButNeverPaysOut() public {
        SenderFeeToken token = new SenderFeeToken();
        _escrow(address(token), depositor, NODE, 10 ether);
        _escrow(address(token), other, NODE2, 10 ether);
        bytes memory over =
            abi.encodeWithSelector(HandleEscrow.OverDebited.selector, address(token), 10 ether, 10.1 ether);

        vm.prank(depositor);
        vm.expectRevert(over);
        escrow.refund(NODE, address(token), depositor);
        registry.setHolder(NODE, holder);
        vm.prank(holder);
        vm.expectRevert(over);
        escrow.claim(NODE, one(address(token)), holder);
        assertEq(token.balanceOf(address(escrow)), 20 ether);
        assertEq(escrow.escrowed(NODE, address(token)), 10 ether);
        assertEq(escrow.refundable(NODE, address(token), depositor), 10 ether);
    }

    /// KNOWN LIMITATION: a negative rebase shrinks the shared pool; the last withdrawal fails.
    function test_ACCEPTED_aNegativeRebaseStrandsTheLastWithdrawal() public {
        RebasingToken token = new RebasingToken();
        _escrow(address(token), depositor, NODE, 10 ether);
        _escrow(address(token), other, NODE2, 10 ether);
        token.slash(address(escrow), 5 ether);

        vm.prank(depositor);
        escrow.refund(NODE, address(token), depositor);
        assertEq(token.balanceOf(depositor), 10 ether);
        vm.prank(other);
        vm.expectRevert(
            abi.encodeWithSelector(IERC20Errors.ERC20InsufficientBalance.selector, address(escrow), 5 ether, 10 ether)
        );
        escrow.refund(NODE2, address(token), other);
    }

    function _escrow(address token, address from, bytes32 node, uint256 amount) internal {
        TestERC20(token).mint(from, amount);
        vm.startPrank(from);
        TestERC20(token).approve(address(escrow), type(uint256).max);
        escrow.deposit(PLATFORM, node, token, amount, from);
        vm.stopPrank();
    }
}
