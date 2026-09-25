// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

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
import {BlocklistToken, NoReturnToken} from "./HostileTokens.sol";

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
///
///      Five tokens: native value, a plain ERC-20, one that takes a fee on
///      transfer, one that returns nothing (USDT's shape), and one with a
///      blocklist that `setBlocked` toggles for depositors and holders. A
///      call the blocklist refuses is expected to revert with the token's
///      error, and the model does not move for it. A holder depositing to its
///      own node is expected to revert `PayingYourself`.
contract EscrowHandler is CommonBase, StdCheats, StdUtils {
    bytes32 internal constant PLATFORM = keccak256("x");

    HandleEscrow public immutable ESCROW;
    SettableNames public immutable NAMES;

    uint256 internal constant TOKENS = 5;

    address[3] public depositors;
    address[TOKENS] public tokens;
    bytes32[2] public nodes;
    address[2] public holders;

    /// How many calls the blocklist refused, and how many self-payments were
    /// refused, for reading off a run.
    uint256 public blockedRefusals;
    uint256 public selfPayRefusals;

    /// node -> token -> depositor -> the model's refundable contribution.
    mapping(bytes32 => mapping(address => mapping(address => uint256))) public modelContribution;

    constructor(HandleEscrow escrow_, SettableNames names_) {
        ESCROW = escrow_;
        NAMES = names_;
        depositors = [makeAddr("depositor 1"), makeAddr("depositor 2"), makeAddr("depositor 3")];
        tokens = [
            address(0),
            address(new TestERC20("Token", "TKN")),
            address(new FeeToken()),
            address(new NoReturnToken()),
            address(new BlocklistToken())
        ];
        nodes = [keccak256("node a"), keccak256("node b")];
        holders = [makeAddr("holder 1"), makeAddr("holder 2")];
    }

    function deposit(uint256 depositorSeed, uint256 tokenSeed, uint256 nodeSeed, uint256 amount) external {
        address depositor = depositors[depositorSeed % 3];
        address token = tokens[tokenSeed % TOKENS];
        bytes32 node = nodes[nodeSeed % 2];
        amount = bound(amount, 1, 1e24);
        address holder = NAMES.holderOf(node);

        uint256 delivered = amount;
        if (token == address(0)) {
            vm.deal(depositor, amount);
            vm.prank(depositor);
            ESCROW.depositToNode{value: amount}(PLATFORM, node, token, amount);
        } else {
            _fund(token, depositor, amount);
            if (token == tokens[2]) delivered = amount - (amount * FeeToken(token).FEE_BPS()) / 10_000;
            // The pull is from the depositor, to the holder or to the escrow.
            bool refused = _expectBlocked(token, depositor, holder == address(0) ? address(ESCROW) : holder);
            vm.prank(depositor);
            ESCROW.depositToNode(PLATFORM, node, token, amount);
            if (refused) return;
        }
        if (holder == address(0)) modelContribution[node][token][depositor] += delivered;
    }

    /// A holder depositing to its own node, in any token, is refused. A node
    /// nobody holds is given a holder first, so every call tries one.
    function payYourself(uint256 tokenSeed, uint256 nodeSeed, uint256 holderSeed, uint256 amount) external {
        address token = tokens[tokenSeed % TOKENS];
        bytes32 node = nodes[nodeSeed % 2];
        address holder = NAMES.holderOf(node);
        if (holder == address(0)) {
            holder = holders[holderSeed % 2];
            NAMES.setHolder(node, holder);
        }
        amount = bound(amount, 1, 1e24);
        uint256 value = token == address(0) ? amount : 0;
        if (token == address(0)) vm.deal(holder, amount);
        else _fund(token, holder, amount);

        vm.expectRevert(abi.encodeWithSelector(HandleEscrow.PayingYourself.selector, holder));
        vm.prank(holder);
        ESCROW.depositToNode{value: value}(PLATFORM, node, token, amount);
        ++selfPayRefusals;
    }

    /// Put an address on the blocklist token's list, or take it off.
    function setBlocked(uint256 whoSeed, bool blocked) external {
        uint256 i = whoSeed % 5;
        address who = i < 3 ? depositors[i] : holders[i - 3];
        BlocklistToken(tokens[4]).setBlocked(who, blocked);
    }

    function refund(uint256 depositorSeed, uint256 tokenSeed, uint256 nodeSeed) external {
        address depositor = depositors[depositorSeed % 3];
        address token = tokens[tokenSeed % TOKENS];
        bytes32 node = nodes[nodeSeed % 2];
        address holder = NAMES.holderOf(node);
        uint256 expected = modelContribution[node][token][depositor];
        uint256 before = _balanceOf(token, depositor);

        if (holder != address(0)) {
            vm.expectRevert(abi.encodeWithSelector(HandleEscrow.PayeeHasJoined.selector, node, holder));
        } else if (expected == 0) {
            vm.expectRevert(abi.encodeWithSelector(HandleEscrow.NothingToRefund.selector, node, token, depositor));
        } else if (_expectBlocked(token, address(ESCROW), depositor)) {
            expected = 0;
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
        address token = tokens[tokenSeed % TOKENS];
        bytes32 node = nodes[nodeSeed % 2];
        address holder = NAMES.holderOf(node);
        if (holder == address(0) || ESCROW.escrowed(node, token) == 0) return;

        bool refused = _expectBlocked(token, address(ESCROW), holder);
        vm.prank(holder);
        ESCROW.claim(node, token, holder);
        if (refused) return;
        for (uint256 i = 0; i < 3; i++) {
            modelContribution[node][token][depositors[i]] = 0;
        }
    }

    function _balanceOf(address token, address who) internal view returns (uint256) {
        return token == address(0) ? who.balance : IERC20(token).balanceOf(who);
    }

    /// Mint `amount` of `token` to `who` and approve the escrow for it. The
    /// blocklist token refuses a mint to a blocked address, so a blocked
    /// address is let off the list for its mint and put back.
    function _fund(address token, address who, uint256 amount) internal {
        if (token == tokens[3]) {
            NoReturnToken(token).mint(who, amount);
            vm.prank(who);
            NoReturnToken(token).approve(address(ESCROW), amount);
            return;
        }
        bool blocked = token == tokens[4] && BlocklistToken(token).blocked(who);
        if (blocked) BlocklistToken(token).setBlocked(who, false);
        TestERC20(token).mint(who, amount);
        if (blocked) BlocklistToken(token).setBlocked(who, true);
        vm.prank(who);
        IERC20(token).approve(address(ESCROW), amount);
    }

    /// Whether the blocklist token refuses a transfer from `from` to `to`, and
    /// if it does, expect the refusal it gives.
    function _expectBlocked(address token, address from, address to) internal returns (bool) {
        if (token != tokens[4]) return false;
        BlocklistToken blocklist = BlocklistToken(token);
        address refused = blocklist.blocked(from) ? from : blocklist.blocked(to) ? to : address(0);
        if (refused == address(0)) return false;
        vm.expectRevert(abi.encodeWithSelector(BlocklistToken.Blocked.selector, refused));
        ++blockedRefusals;
        return true;
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
        handler = new EscrowHandler(escrow, names);
        targetContract(address(handler));
        bytes4[] memory selectors = new bytes4[](7);
        selectors[0] = EscrowHandler.deposit.selector;
        selectors[1] = EscrowHandler.refund.selector;
        selectors[2] = EscrowHandler.join.selector;
        selectors[3] = EscrowHandler.retire.selector;
        selectors[4] = EscrowHandler.claim.selector;
        selectors[5] = EscrowHandler.payYourself.selector;
        selectors[6] = EscrowHandler.setBlocked.selector;
        targetSelector(FuzzSelector({addr: address(handler), selectors: selectors}));
    }

    /// A handler call that reverts unexpectedly — including its own check on
    /// what a refund paid — fails the run rather than being skipped.
    ///
    /// forge-config: default.invariant.runs = 128
    /// forge-config: default.invariant.depth = 128
    /// forge-config: default.invariant.fail-on-revert = true
    function invariant_theBooksAddUp() public view {
        for (uint256 t = 0; t < 5; t++) {
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

/// @notice Deposits, claims and refunds of arbitrary amounts, one at a time,
///         each checked against the balances it moved.
contract HandleEscrowAmountsTest is Test {
    bytes32 internal constant PLATFORM = keccak256("x");
    bytes32 internal constant NODE = keccak256("node");
    uint256 internal constant MAX = 1e36;

    HandleEscrow internal escrow;
    SettableNames internal names;
    TestERC20 internal token;
    FeeToken internal fee;

    address internal alice = makeAddr("alice");
    address internal bob = makeAddr("bob");
    address internal holder = makeAddr("holder");

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
        token = new TestERC20("Token", "TKN");
        fee = new FeeToken();
    }

    function testFuzz_aRefundReturnsExactlyTheDeposit(uint256 amount, bool native) public {
        amount = bound(amount, 1, MAX);
        address asset = _deposit(alice, amount, native);

        assertEq(escrow.escrowed(NODE, asset), amount);
        assertEq(escrow.refundable(NODE, asset, alice), amount);
        vm.prank(alice);
        escrow.refund(NODE, asset, alice);

        assertEq(_balance(asset, alice), amount, "the refund returned other than the deposit");
        assertEq(escrow.escrowed(NODE, asset), 0);
        assertEq(_balance(asset, address(escrow)), 0);
    }

    function testFuzz_aClaimTakesEveryContribution(uint256 a, uint256 b, bool native) public {
        a = bound(a, 1, MAX);
        b = bound(b, 1, MAX);
        address asset = _deposit(alice, a, native);
        _deposit(bob, b, native);
        names.setHolder(NODE, holder);

        vm.prank(holder);
        escrow.claim(NODE, asset, holder);

        assertEq(_balance(asset, holder), a + b, "the claim paid other than the sum");
        assertEq(escrow.escrowed(NODE, asset), 0);
        assertEq(_balance(asset, address(escrow)), 0);
        names.setHolder(NODE, address(0));
        assertEq(escrow.refundable(NODE, asset, alice), 0, "what the claim took is refundable");
        assertEq(escrow.refundable(NODE, asset, bob), 0, "what the claim took is refundable");
    }

    function testFuzz_aRefundLeavesTheRestForTheClaim(uint256 a, uint256 b, bool native) public {
        a = bound(a, 1, MAX);
        b = bound(b, 1, MAX);
        address asset = _deposit(alice, a, native);
        _deposit(bob, b, native);

        vm.prank(alice);
        escrow.refund(NODE, asset, alice);
        assertEq(_balance(asset, alice), a);
        assertEq(escrow.escrowed(NODE, asset), b, "the refund reached another contribution");

        names.setHolder(NODE, holder);
        vm.prank(holder);
        escrow.claim(NODE, asset, holder);
        assertEq(_balance(asset, holder), b, "the claim paid other than what was left");
        assertEq(_balance(asset, address(escrow)), 0);
    }

    function testFuzz_aFeeTokenBooksWhatArrived(uint256 amount) public {
        amount = bound(amount, 1, MAX);
        uint256 arrived = amount - (amount * fee.FEE_BPS()) / 10_000;
        fee.mint(alice, amount);
        vm.startPrank(alice);
        fee.approve(address(escrow), amount);
        escrow.depositToNode(PLATFORM, NODE, address(fee), amount);
        vm.stopPrank();

        assertEq(escrow.escrowed(NODE, address(fee)), arrived);
        assertEq(fee.balanceOf(address(escrow)), arrived, "the books and the balance disagree");
        vm.prank(alice);
        escrow.refund(NODE, address(fee), alice);
        assertEq(fee.balanceOf(alice), arrived);
    }

    function testFuzz_aPayThroughDeliversTheAmount(uint256 amount, bool native) public {
        amount = bound(amount, 1, MAX);
        names.setHolder(NODE, holder);
        address asset = _deposit(alice, amount, native);

        assertEq(_balance(asset, holder), amount);
        assertEq(escrow.escrowed(NODE, asset), 0);
        assertEq(_balance(asset, address(escrow)), 0);
    }

    function _deposit(address who, uint256 amount, bool native) internal returns (address asset) {
        if (native) {
            vm.deal(who, amount);
            vm.prank(who);
            escrow.depositToNode{value: amount}(PLATFORM, NODE, address(0), amount);
            return address(0);
        }
        token.mint(who, amount);
        vm.startPrank(who);
        token.approve(address(escrow), amount);
        escrow.depositToNode(PLATFORM, NODE, address(token), amount);
        vm.stopPrank();
        return address(token);
    }

    function _balance(address asset, address who) internal view returns (uint256) {
        return asset == address(0) ? who.balance : token.balanceOf(who);
    }
}
