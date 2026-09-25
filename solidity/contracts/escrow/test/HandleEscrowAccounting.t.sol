// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {CommonBase} from "forge-std/Base.sol";
import {StdCheats} from "forge-std/StdCheats.sol";
import {StdUtils} from "forge-std/StdUtils.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

import {HandleNormalizer} from "../../identity/HandleNormalizer.sol";
import {HandleEscrow} from "../HandleEscrow.sol";
import {IIdentityNames} from "../IIdentityNames.sol";
import {FeeToken, TestERC20} from "./HandleEscrow.t.sol";

/// @notice A naming system whose holders are set directly.
///
/// @dev The escrow reads `byHandle`, `acceptsClaims` and `rulesOf` and nothing
///      else. The accounting under test depends only on whether `byHandle`
///      names a holder, so the handler flips that directly instead of
///      staging identity claims; `HandleEscrow.t.sol` runs the real naming
///      system.
contract SettableNames is IIdentityNames {
    mapping(bytes32 => address) public holderOf;

    function setHolder(bytes32 handleNode, address holder) external {
        holderOf[handleNode] = holder;
    }

    function byHandle(bytes32 handleNode) external view returns (address owner, uint64 observedAt) {
        return (holderOf[handleNode], 0);
    }

    function rulesOf(bytes32) external pure returns (HandleNormalizer.Rules memory rules) {
        return rules;
    }

    function acceptsClaims(bytes32) external pure returns (bool) {
        return true;
    }
}

/// @notice Drives the escrow through random deposits, refunds, joins, claims
///         and retirements, and keeps its own model of each depositor's
///         refundable contribution.
///
/// @dev The model is deliberately simpler than the contract: a deposit to a
///      node with no holder adds what the token delivers, computed from the
///      token's own fee rule; a refund zeroes the caller's entry; a claim
///      zeroes every entry for the slot. It knows nothing of rounds.
contract EscrowHandler is CommonBase, StdCheats, StdUtils {
    bytes32 internal constant PLATFORM = keccak256("x");

    HandleEscrow public immutable ESCROW;
    SettableNames public immutable NAMES;

    address[3] public depositors;
    address[3] public tokens;
    bytes32[2] public nodes;
    address[2] public holders;

    /// node -> token -> depositor -> the model's refundable contribution.
    mapping(bytes32 => mapping(address => mapping(address => uint256))) public modelContribution;

    constructor(HandleEscrow escrow_, SettableNames names_, address plain, address fee) {
        ESCROW = escrow_;
        NAMES = names_;
        depositors = [makeAddr("depositor 1"), makeAddr("depositor 2"), makeAddr("depositor 3")];
        tokens = [address(0), plain, fee];
        nodes = [keccak256("node a"), keccak256("node b")];
        holders = [makeAddr("holder 1"), makeAddr("holder 2")];
    }

    function deposit(uint256 depositorSeed, uint256 tokenSeed, uint256 nodeSeed, uint256 amount) external {
        address depositor = depositors[depositorSeed % 3];
        address token = tokens[tokenSeed % 3];
        bytes32 node = nodes[nodeSeed % 2];
        amount = bound(amount, 1, 1e24);

        uint256 delivered = amount;
        if (token == address(0)) {
            vm.deal(depositor, amount);
            vm.prank(depositor);
            ESCROW.depositToNode{value: amount}(PLATFORM, node, token, amount);
        } else {
            TestERC20(token).mint(depositor, amount);
            vm.prank(depositor);
            IERC20(token).approve(address(ESCROW), amount);
            if (token == tokens[2]) delivered = amount - (amount * FeeToken(token).FEE_BPS()) / 10_000;
            vm.prank(depositor);
            ESCROW.depositToNode(PLATFORM, node, token, amount);
        }
        if (NAMES.holderOf(node) == address(0)) modelContribution[node][token][depositor] += delivered;
    }

    function refund(uint256 depositorSeed, uint256 tokenSeed, uint256 nodeSeed) external {
        address depositor = depositors[depositorSeed % 3];
        address token = tokens[tokenSeed % 3];
        bytes32 node = nodes[nodeSeed % 2];
        address holder = NAMES.holderOf(node);
        uint256 expected = modelContribution[node][token][depositor];
        uint256 before = _balanceOf(token, depositor);

        if (holder != address(0)) {
            vm.expectRevert(abi.encodeWithSelector(HandleEscrow.PayeeHasJoined.selector, node, holder));
        } else if (expected == 0) {
            vm.expectRevert(abi.encodeWithSelector(HandleEscrow.NothingToRefund.selector, node, token, depositor));
        }
        vm.prank(depositor);
        ESCROW.refund(node, token, depositor);

        if (holder == address(0) && expected != 0) {
            require(_balanceOf(token, depositor) - before == expected, "the refund paid other than the contribution");
            modelContribution[node][token][depositor] = 0;
        }
    }

    function join(uint256 nodeSeed, uint256 holderSeed) external {
        NAMES.setHolder(nodes[nodeSeed % 2], holders[holderSeed % 2]);
    }

    function retire(uint256 nodeSeed) external {
        NAMES.setHolder(nodes[nodeSeed % 2], address(0));
    }

    function claim(uint256 tokenSeed, uint256 nodeSeed) external {
        address token = tokens[tokenSeed % 3];
        bytes32 node = nodes[nodeSeed % 2];
        address holder = NAMES.holderOf(node);
        if (holder == address(0) || ESCROW.escrowed(node, token) == 0) return;

        vm.prank(holder);
        ESCROW.claim(node, token, holder);
        for (uint256 i = 0; i < 3; i++) {
            modelContribution[node][token][depositors[i]] = 0;
        }
    }

    function _balanceOf(address token, address who) internal view returns (uint256) {
        return token == address(0) ? who.balance : IERC20(token).balanceOf(who);
    }
}

/// @notice The escrow's books against its balances and against a model, under
///         random interleavings of every entry point that moves them.
///
/// @dev Contributions are read straight out of storage with `vm.load`, at
///      slots computed here from the ERC-7201 root, not through the contract:
///      `refundable` answers zero while a node has a holder, and the books
///      still have to add up then.
contract HandleEscrowAccountingTest is Test {
    bytes32 internal constant ROOT = 0xfcca8d7d2c66f78c2760f3fcd99e0bf938b0aeb0d0b471f481dd50b8aff6b400;
    uint256 internal constant ROUND_FIELD = 2;
    uint256 internal constant CONTRIBUTIONS_FIELD = 3;

    HandleEscrow internal escrow;
    SettableNames internal names;
    EscrowHandler internal handler;

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
        handler = new EscrowHandler(escrow, names, address(new TestERC20("Token", "TKN")), address(new FeeToken()));
        targetContract(address(handler));
        bytes4[] memory selectors = new bytes4[](5);
        selectors[0] = EscrowHandler.deposit.selector;
        selectors[1] = EscrowHandler.refund.selector;
        selectors[2] = EscrowHandler.join.selector;
        selectors[3] = EscrowHandler.retire.selector;
        selectors[4] = EscrowHandler.claim.selector;
        targetSelector(FuzzSelector({addr: address(handler), selectors: selectors}));
    }

    /// A handler call that reverts unexpectedly — including its own check on
    /// what a refund paid — fails the run rather than being skipped.
    ///
    /// forge-config: default.invariant.runs = 128
    /// forge-config: default.invariant.depth = 128
    /// forge-config: default.invariant.fail-on-revert = true
    function invariant_theBooksAddUp() public view {
        for (uint256 t = 0; t < 3; t++) {
            address token = handler.tokens(t);
            uint256 heldTotal;
            for (uint256 n = 0; n < 2; n++) {
                bytes32 node = handler.nodes(n);
                uint256 held = escrow.escrowed(node, token);
                heldTotal += held;
                bool hasHolder = names.holderOf(node) != address(0);

                uint256 round = uint256(vm.load(address(escrow), _roundSlot(node, token)));
                uint256 stored;
                uint256 modelled;
                for (uint256 d = 0; d < 3; d++) {
                    address depositor = handler.depositors(d);
                    uint256 contribution =
                        uint256(vm.load(address(escrow), _contributionSlot(node, token, round, depositor)));
                    uint256 model = handler.modelContribution(node, token, depositor);
                    assertEq(contribution, model, "a stored contribution departs from the model");
                    assertEq(escrow.refundable(node, token, depositor), hasHolder ? 0 : model, "refundable is wrong");
                    stored += contribution;
                    modelled += model;
                }
                assertEq(held, stored, "held is not the sum of the current round's contributions");
                assertEq(held, modelled, "held departs from the model");
            }
            uint256 balance = token == address(0) ? address(escrow).balance : IERC20(token).balanceOf(address(escrow));
            assertLe(heldTotal, balance, "the books promise more than the escrow holds");
            assertEq(heldTotal, balance, "the escrow holds value no slot accounts for");
        }
    }

    /// The layout the invariant reads through, pinned on a known state so a
    /// wrong slot formula cannot make the invariant vacuous.
    function test_theSlotFormulaReadsTheBooks() public {
        address depositor = handler.depositors(0);
        bytes32 node = handler.nodes(0);
        handler.deposit(0, 0, 0, 5 ether);

        assertEq(uint256(vm.load(address(escrow), _roundSlot(node, address(0)))), 0);
        assertEq(uint256(vm.load(address(escrow), _contributionSlot(node, address(0), 0, depositor))), 5 ether);

        handler.join(0, 0);
        handler.claim(0, 0);
        assertEq(uint256(vm.load(address(escrow), _roundSlot(node, address(0)))), 1, "a claim did not close the round");
    }

    function _field(uint256 index) internal pure returns (bytes32) {
        return bytes32(uint256(ROOT) + index);
    }

    function _roundSlot(bytes32 node, address token) internal pure returns (bytes32) {
        return keccak256(abi.encode(token, keccak256(abi.encode(node, _field(ROUND_FIELD)))));
    }

    function _contributionSlot(bytes32 node, address token, uint256 round, address depositor)
        internal
        pure
        returns (bytes32)
    {
        bytes32 byNode = keccak256(abi.encode(node, _field(CONTRIBUTIONS_FIELD)));
        bytes32 byToken = keccak256(abi.encode(token, byNode));
        bytes32 byRound = keccak256(abi.encode(round, byToken));
        return keccak256(abi.encode(depositor, byRound));
    }
}
