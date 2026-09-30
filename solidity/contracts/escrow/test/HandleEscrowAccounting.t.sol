// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {CommonBase} from "forge-std/Base.sol";
import {StdCheats} from "forge-std/StdCheats.sol";
import {StdUtils} from "forge-std/StdUtils.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

import {HandleEscrow, NATIVE_TOKEN} from "../HandleEscrow.sol";
import {IdentityNodes} from "../../identity/IdentityNodes.sol";
import {IIdentityNames} from "../../identity/IIdentityNames.sol";
import {FeeToken, NoReturnToken, SettableRegistry, TestERC20, one} from "./EscrowMocks.sol";

// The native token as the escrow names it.
address constant NATIVE = NATIVE_TOKEN;

/// @notice Drives random deposits, refunds, joins, retirements and claims, and models each
///         `refundTo`'s refundable contribution.
contract EscrowHandler is CommonBase, StdCheats, StdUtils {
    bytes32 internal constant PLATFORM = keccak256("x");
    uint256 internal constant TOKENS = 4;

    HandleEscrow public immutable ESCROW;
    SettableRegistry public immutable REGISTRY;
    address[3] public depositors;
    address[TOKENS] public tokens;
    bytes32[2] public hashes;
    bytes32[2] public nodes;
    address[2] public wallets;

    /// node -> token -> refundTo -> refundable, as modelled.
    mapping(bytes32 => mapping(address => mapping(address => uint256))) public modelled;

    constructor(HandleEscrow escrow_, SettableRegistry registry_) {
        (ESCROW, REGISTRY) = (escrow_, registry_);
        depositors = [makeAddr("depositor 1"), makeAddr("depositor 2"), makeAddr("depositor 3")];
        tokens = [NATIVE, address(new TestERC20()), address(new FeeToken()), address(new NoReturnToken())];
        hashes = [keccak256("node a"), keccak256("node b")];
        nodes =
            [IdentityNodes.handleNodeOfHash(PLATFORM, hashes[0]), IdentityNodes.handleNodeOfHash(PLATFORM, hashes[1])];
        wallets = [makeAddr("wallet 1"), makeAddr("wallet 2")];
    }

    function deposit(uint256 fromSeed, uint256 refundToSeed, uint256 tokenSeed, uint256 nodeSeed, uint256 amount)
        external
    {
        address from = depositors[fromSeed % 3];
        address refundTo = depositors[refundToSeed % 3];
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
        ESCROW.deposit{value: token == NATIVE ? amount : 0}(PLATFORM, hashes[nodeSeed % 2], token, amount, refundTo);
        if (REGISTRY.walletOf(node) == address(0)) modelled[node][token][refundTo] += delivered;
    }

    function refund(uint256 refundToSeed, uint256 tokenSeed, uint256 nodeSeed) external {
        address refundTo = depositors[refundToSeed % 3];
        address token = tokens[tokenSeed % TOKENS];
        bytes32 node = nodes[nodeSeed % 2];
        uint256 expected = modelled[node][token][refundTo];
        uint256 before = _balanceOf(token, refundTo);

        if (expected == 0) {
            vm.expectRevert(abi.encodeWithSelector(HandleEscrow.NothingToRefund.selector, node, token, refundTo));
        }
        vm.prank(refundTo);
        ESCROW.refund(node, token, refundTo);
        require(_balanceOf(token, refundTo) - before == expected, "the refund paid other than the contribution");
        modelled[node][token][refundTo] = 0;
    }

    function join(uint256 nodeSeed, uint256 walletSeed) external {
        REGISTRY.setWallet(nodes[nodeSeed % 2], wallets[walletSeed % 2]);
    }

    function retire(uint256 nodeSeed) external {
        REGISTRY.setWallet(nodes[nodeSeed % 2], address(0));
    }

    function claim(uint256 tokenSeed, uint256 nodeSeed) external {
        address token = tokens[tokenSeed % TOKENS];
        bytes32 node = nodes[nodeSeed % 2];
        address wallet = REGISTRY.walletOf(node);
        uint256 held = ESCROW.escrowed(node, token);
        if (wallet == address(0) || held == 0) return;
        uint256 before = _balanceOf(token, wallet);

        vm.prank(wallet);
        ESCROW.claim(node, one(token), wallet);
        require(_balanceOf(token, wallet) - before == held, "the claim paid other than what was held");
        for (uint256 i = 0; i < 3; i++) {
            modelled[node][token][depositors[i]] = 0;
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
                    abi.encodeCall(HandleEscrow.initialize, (address(this), IIdentityNames(address(registry))))
                )
            )
        );
        handler = new EscrowHandler(escrow, registry);
        targetContract(address(handler));
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
                    address refundTo = handler.depositors(d);
                    uint256 model = handler.modelled(node, token, refundTo);
                    assertEq(escrow.refundable(node, token, refundTo), model, "refundable departs from the model");
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
