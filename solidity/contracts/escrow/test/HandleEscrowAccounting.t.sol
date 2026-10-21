// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {CommonBase} from "forge-std/Base.sol";
import {StdCheats} from "forge-std/StdCheats.sol";
import {StdUtils} from "forge-std/StdUtils.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeCast} from "@openzeppelin/contracts/utils/math/SafeCast.sol";

import {HandleEscrow, NATIVE_TOKEN} from "../HandleEscrow.sol";
import {CeremonyProfile} from "../../ceremony/CeremonyProfile.sol";
import {IIdentityRegistry} from "../../identity/IIdentityRegistry.sol";
import {TestNodes} from "../../identity/test/TestNodes.sol";
import {EscrowHelpers, FeeToken, NoReturnToken, SettableRegistry, TestERC20, one} from "./EscrowMocks.sol";

// The native token as the escrow names it.
address constant NATIVE = NATIVE_TOKEN;

/// @notice Drives random deposits, refunds, waits, joins, retirements and claims, and models
///         each sender's contribution.
contract EscrowHandler is CommonBase, StdCheats, StdUtils, EscrowHelpers {
    bytes32 internal constant PLATFORM = CeremonyProfile.PLATFORM_X;
    uint256 internal constant TOKENS = 4;

    HandleEscrow public immutable ESCROW;
    SettableRegistry public immutable REGISTRY;
    address[3] public depositors;
    address[TOKENS] public tokens;
    bytes32[2] public nodes;
    address[2] public holders;

    /// Escrowed deposits, paid refunds and claims that took something, per run.
    uint256 public depositsMade;
    uint256 public refundsPaid;
    uint256 public claimsPaid;

    /// node -> token -> sender -> contribution, as modelled.
    mapping(bytes32 => mapping(address => mapping(address => HandleEscrow.Contribution))) public modelled;

    constructor(HandleEscrow escrow_, SettableRegistry registry_) {
        (ESCROW, REGISTRY) = (escrow_, registry_);
        depositors = [makeAddr("depositor 1"), makeAddr("depositor 2"), makeAddr("depositor 3")];
        tokens = [NATIVE, address(new TestERC20()), address(new FeeToken()), address(new NoReturnToken())];
        nodes = [TestNodes.handleNode(PLATFORM, "alice"), TestNodes.handleNode(PLATFORM, "bob")];
        holders = [makeAddr("holder 1"), makeAddr("holder 2")];
    }

    function deposit(uint256 fromSeed, uint256 tokenSeed, uint256 nodeSeed, uint256 amount) external {
        address from = depositors[fromSeed % 3];
        address token = tokens[tokenSeed % TOKENS];
        bytes32 node = nodes[nodeSeed % 2];
        amount = bound(amount, 1, 1e24);
        uint256 delivered = token == tokens[2] ? amount - (amount * FeeToken(token).FEE_BPS()) / 10_000 : amount;

        if (token == NATIVE) {
            vm.deal(from, amount);
        } else {
            TestERC20(token).mint(from, amount);
            // `NoReturnToken.approve` returns nothing, so no `IERC20` cast here.
            vm.prank(from);
            NoReturnToken(token).approve(address(ESCROW), amount);
        }
        vm.prank(from);
        ESCROW.deposit{value: token == NATIVE ? amount : 0}(PLATFORM, node, token, amount);
        if (REGISTRY.holderOf(node) != address(0)) return;
        ++depositsMade;
        HandleEscrow.Contribution storage model = modelled[node][token][from];
        model.amount = SafeCast.toUint192(model.amount + delivered);
        model.refundableAt = graceEnd(ESCROW);
    }

    function refund(uint256 fromSeed, uint256 tokenSeed, uint256 nodeSeed) public {
        address from = depositors[fromSeed % 3];
        address token = tokens[tokenSeed % TOKENS];
        bytes32 node = nodes[nodeSeed % 2];
        HandleEscrow.Contribution memory model = modelled[node][token][from];
        uint256 before = _balanceOf(token, from);

        bool paid;
        if (model.amount == 0) {
            vm.expectRevert(abi.encodeWithSelector(HandleEscrow.NothingToRefund.selector, node, token, from));
        } else if (vm.getBlockTimestamp() < model.refundableAt) {
            vm.expectRevert(
                abi.encodeWithSelector(HandleEscrow.RefundLocked.selector, node, token, from, model.refundableAt)
            );
        } else {
            paid = true;
        }
        vm.prank(from);
        ESCROW.refund(node, token, from);
        uint256 expected = paid ? model.amount : 0;
        require(_balanceOf(token, from) - before == expected, "the refund paid other than the contribution");
        if (paid) {
            delete modelled[node][token][from];
            ++refundsPaid;
        }
    }

    /// Refund the open contribution with the earliest date, the first from `seed` on among
    /// equals, waiting for its date if it has not come; nothing when none is open.
    function refundDue(uint256 seed) public {
        uint256 slots = 3 * TOKENS * 2;
        uint256 earliest = type(uint256).max;
        uint256 pick;
        for (uint256 i = 0; i < slots; i++) {
            uint256 at = (seed % slots + i) % slots;
            HandleEscrow.Contribution memory model =
                modelled[nodes[at / (3 * TOKENS)]][tokens[at / 3 % TOKENS]][depositors[at % 3]];
            if (model.amount != 0 && model.refundableAt < earliest) (earliest, pick) = (model.refundableAt, at);
        }
        if (earliest == type(uint256).max) return;
        if (vm.getBlockTimestamp() < earliest) vm.warp(earliest);
        refund(pick % 3, pick / 3 % TOKENS, pick / (3 * TOKENS));
    }

    function wait(uint256 seconds_) external {
        vm.warp(vm.getBlockTimestamp() + bound(seconds_, 0, 60 days));
    }

    function join(uint256 nodeSeed, uint256 holderSeed) external {
        REGISTRY.setHolder(nodes[nodeSeed % 2], holders[holderSeed % 2]);
    }

    function retire(uint256 nodeSeed) external {
        REGISTRY.setHolder(nodes[nodeSeed % 2], address(0));
    }

    function claim(uint256 tokenSeed, uint256 nodeSeed) external {
        address token = tokens[tokenSeed % TOKENS];
        bytes32 node = nodes[nodeSeed % 2];
        address holder = REGISTRY.holderOf(node);
        uint256 held = ESCROW.escrowed(node, token);
        if (holder == address(0) || held == 0) return;
        uint256 before = _balanceOf(token, holder);

        vm.prank(holder);
        ESCROW.claim(node, one(token), holder);
        require(_balanceOf(token, holder) - before == held, "the claim paid other than what was held");
        ++claimsPaid;
        for (uint256 i = 0; i < 3; i++) {
            delete modelled[node][token][depositors[i]];
        }
    }

    function _balanceOf(address token, address who) internal view returns (uint256) {
        return token == NATIVE ? who.balance : IERC20(token).balanceOf(who);
    }
}

/// @notice The books against the balances and the model, under random interleavings.
contract HandleEscrowAccountingTest is Test {
    HandleEscrow internal escrow;
    EscrowHandler internal handler;

    function setUp() public {
        SettableRegistry registry = new SettableRegistry();
        escrow = HandleEscrow(
            address(
                new ERC1967Proxy(
                    address(new HandleEscrow()),
                    abi.encodeCall(HandleEscrow.initialize, (address(this), IIdentityRegistry(address(registry))))
                )
            )
        );
        handler = new EscrowHandler(escrow, registry);
        targetContract(address(handler));
    }

    /// A run ends with a refund of whatever is still open, and the books still add up. A run
    /// that escrowed anything paid it out by refund or by claim.
    function afterInvariant() public {
        handler.refundDue(0);
        invariant_theBooksAddUp();
        if (handler.depositsMade() > 0) {
            assertGt(handler.refundsPaid() + handler.claimsPaid(), 0, "an escrowed deposit was never paid out");
        }
    }

    /// A handler call that reverts, its own checks included, fails the run.
    /// forge-config: default.invariant.fail-on-revert = true
    function invariant_theBooksAddUp() public view {
        for (uint256 t = 0; t < 4; t++) {
            address token = handler.tokens(t);
            uint256 heldTotal;
            for (uint256 n = 0; n < 2; n++) {
                bytes32 node = handler.nodes(n);
                uint256 sum;
                for (uint256 d = 0; d < 3; d++) {
                    address sender = handler.depositors(d);
                    (uint192 model, uint64 modelAt) = handler.modelled(node, token, sender);
                    (uint256 amount, uint64 refundableAt) = escrow.contribution(node, token, sender);
                    assertEq(amount, model, "the amount departs from the model");
                    assertEq(refundableAt, modelAt, "the refund date departs from the model");
                    sum += model;
                }
                assertEq(escrow.escrowed(node, token), sum, "held is not the sum of the open contributions");
                heldTotal += sum;
            }
            uint256 balance = token == NATIVE ? address(escrow).balance : IERC20(token).balanceOf(address(escrow));
            assertEq(heldTotal, balance, "the books and the balance disagree");
        }
    }
}
