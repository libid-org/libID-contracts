// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {ReentrancyGuardUpgradeable} from "@openzeppelin/contracts-upgradeable/utils/ReentrancyGuardUpgradeable.sol";
import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {OwnableUpgradeable} from "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";

import {HandleNormalizer} from "../../identity/HandleNormalizer.sol";
import {HandleVectors} from "../../identity/HandleVectors.sol";
import {IdentityRegistry} from "../../identity/IdentityRegistry.sol";
import {IIdentityRegistry} from "../../identity/IIdentityRegistry.sol";
import {StubPlatformVerifier} from "../../identity/test/StubPlatformVerifier.sol";
import {TestNodes} from "../../identity/test/TestNodes.sol";
import {CeremonyProofVerifier} from "../../ceremony/CeremonyProofVerifier.sol";
import {IPlatformVerifier} from "../../ceremony/IPlatformVerifier.sol";
import {IProofVerifier} from "../../ceremony/IProofVerifier.sol";
import {HandleEscrow, NATIVE_TOKEN} from "../HandleEscrow.sol";
import {FeeToken, InertToken, RejectEther, TestERC20, one} from "./EscrowMocks.sol";

// The native token as the escrow names it.
address constant NATIVE = NATIVE_TOKEN;

/// @notice Appends one field to the namespaced root, the only change the storage rule allows.
contract HandleEscrowV2 is HandleEscrow {
    /// @custom:storage-location erc7201:libid.storage.HandleEscrow
    struct V2Storage {
        mapping(bytes32 => mapping(address => uint256)) held;
        IIdentityRegistry registry;
        mapping(bytes32 => mapping(address => uint256)) round;
        mapping(bytes32 => mapping(address => mapping(uint256 => mapping(address => uint256)))) contributions;
        uint256 appended;
    }

    function _v2() private pure returns (V2Storage storage $) {
        assembly {
            $.slot := 0xfcca8d7d2c66f78c2760f3fcd99e0bf938b0aeb0d0b471f481dd50b8aff6b400
        }
    }

    function setAppended(uint256 v) external {
        _v2().appended = v;
    }

    function read(bytes32 node, address token, uint256 round_, address refundTo)
        external
        view
        returns (uint256 held, address registry_, uint256 round, uint256 contribution, uint256 appended)
    {
        V2Storage storage $ = _v2();
        return (
            $.held[node][token],
            address($.registry),
            $.round[node][token],
            $.contributions[node][token][round_][refundTo],
            $.appended
        );
    }
}

/// @notice A router paying a handle given as text; its caller is `refundTo`.
contract TextPayer {
    HandleEscrow private immutable ESCROW;
    IdentityRegistry private immutable REGISTRY;

    constructor(HandleEscrow escrow_, IdentityRegistry registry_) {
        (ESCROW, REGISTRY) = (escrow_, registry_);
    }

    function pay(bytes32 platformId, string calldata handle) external payable {
        ESCROW.deposit{value: msg.value}(
            platformId, REGISTRY.handleNodeOf(platformId, handle), NATIVE, msg.value, msg.sender
        );
    }
}

/// @notice Makes any call for anybody, as a multicall or payment router does.
contract SharedForwarder {
    function forward(address target, bytes calldata data) external payable {
        (bool ok, bytes memory result) = target.call{value: msg.value}(data);
        if (!ok) {
            assembly {
                revert(add(result, 32), mload(result))
            }
        }
    }
}

/// @notice Takes a native payout by `call`, and from inside it reads the books and repeats the call,
///         catching the refusal, so both defences show on their own.
contract ObservingPayee {
    HandleEscrow private immutable ESCROW;
    bytes32 private immutable NODE;
    bytes private call_;
    bool private entered;
    uint256 public heldDuringPayout = type(uint256).max;
    uint256 public refundableDuringPayout = type(uint256).max;
    bytes public reentryError;

    constructor(HandleEscrow escrow_, bytes32 node_) {
        (ESCROW, NODE) = (escrow_, node_);
    }

    function fund(bytes32 platformId, bytes32 handleNode) external payable {
        ESCROW.deposit{value: msg.value}(platformId, handleNode, NATIVE, msg.value, address(this));
    }

    function take(bytes calldata data) external {
        call_ = data;
        (bool ok,) = address(ESCROW).call(data);
        require(ok, "the payout failed");
    }

    receive() external payable {
        if (entered) return;
        entered = true;
        heldDuringPayout = ESCROW.escrowed(NODE, NATIVE);
        refundableDuringPayout = ESCROW.refundable(NODE, NATIVE, address(this));
        (bool ok, bytes memory reason) = address(ESCROW).call(call_);
        require(!ok, "the reentry was let through");
        reentryError = reason;
    }
}

/// @notice Registries `initialize` must refuse or accept.
contract RegistryWithAOneWordFallback {
    fallback() external {
        assembly {
            mstore(0, 0)
            return(0, 32)
        }
    }
}

contract RegistryWithoutAcceptsBindings {
    function handleBinding(bytes32) external pure returns (address, uint64) {}
}

contract RegistryWithASilentFallback is RegistryWithoutAcceptsBindings {
    fallback() external {}
}

contract RegistryWithANonBooleanAnswer is RegistryWithoutAcceptsBindings {
    function acceptsBindings(bytes32) external pure returns (uint256) {
        return 2;
    }
}

contract RegistryWithBothCalls is RegistryWithoutAcceptsBindings {
    function acceptsBindings(bytes32) external pure returns (bool) {}
}

/// @notice The handle node escrow, against the real registry.
contract HandleEscrowTest is Test {
    IdentityRegistry internal registry;
    CeremonyProofVerifier internal proofVerifier;
    StubPlatformVerifier internal xVerifier;
    HandleEscrow internal escrow;
    TestERC20 internal token;

    bytes32 internal constant X = HandleVectors.PLATFORM_X;
    bytes32 internal constant GITHUB = HandleVectors.PLATFORM_GITHUB;
    bytes32 internal constant GOOGLE = HandleVectors.PLATFORM_GOOGLE;
    bytes32 internal constant UNWIRED = keccak256("no such platform");
    uint16 internal constant V1 = 1;

    address internal alice = makeAddr("alice");
    address internal bob = makeAddr("bob");
    address internal sender = makeAddr("sender");
    address internal owner = makeAddr("owner");

    bytes32 internal aliceNode = TestNodes.handleNode(X, "alice");
    uint256 private nonce;

    function setUp() public {
        registry = IdentityRegistry(
            address(
                new ERC1967Proxy(address(new IdentityRegistry()), abi.encodeCall(IdentityRegistry.initialize, (owner)))
            )
        );
        proofVerifier = CeremonyProofVerifier(
            address(
                new ERC1967Proxy(
                    address(new CeremonyProofVerifier()), abi.encodeCall(CeremonyProofVerifier.initialize, (owner))
                )
            )
        );
        xVerifier = new StubPlatformVerifier(X, 0);
        vm.startPrank(owner);
        registry.setProofVerifier(IProofVerifier(address(proofVerifier)));
        registry.setPlatform(X, HandleVectors.rulesFor(X), HandleVectors.handleTagFor(X));
        proofVerifier.setVerifier(X, V1, IPlatformVerifier(address(xVerifier)));
        registry.setPlatform(GITHUB, HandleVectors.rulesFor(GITHUB), HandleVectors.handleTagFor(GITHUB));
        proofVerifier.setVerifier(GITHUB, V1, IPlatformVerifier(address(new StubPlatformVerifier(GITHUB, 0))));
        vm.stopPrank();

        escrow = _deploy(address(registry));
        token = new TestERC20();
        token.mint(sender, 1_000 ether);
        vm.prank(sender);
        token.approve(address(escrow), type(uint256).max);
        vm.deal(sender, 100 ether);
        vm.warp(1_000_000);
    }

    // ─── The node ───────────────────────────────────────────────────

    /// Every row of the shared handle table lands on the node the registry binds, or is refused.
    function test_everyVectorRowLandsOnTheNodeTheRegistryBinds() public {
        vm.startPrank(owner);
        registry.setPlatform(GOOGLE, HandleVectors.rulesFor(GOOGLE), HandleVectors.handleTagFor(GOOGLE));
        proofVerifier.setVerifier(GOOGLE, V1, IPlatformVerifier(address(new StubPlatformVerifier(GOOGLE, 0))));
        vm.stopPrank();

        HandleVectors.Vector[] memory vectors = HandleVectors.all();
        for (uint256 i = 0; i < vectors.length; i++) {
            HandleVectors.Vector memory v = vectors[i];
            bytes32 platformId = keccak256(bytes(v.platform));
            if (v.accepted) {
                assertEq(registry.handleNodeOf(platformId, v.input), v.handleNode, vm.toString(i));
            } else {
                vm.expectRevert(
                    abi.encodeWithSelector(
                        IIdentityRegistry.UnusableHandle.selector, HandleNormalizer.Problem(v.errorKind + 1)
                    )
                );
                registry.handleNodeOf(platformId, v.input);
            }
        }
    }

    /// A `hashlib.sha256(b"libid.x.handlealice_1")` literal, so the registry, the test helper and the
    /// generated table cannot drift together and still pass.
    function test_theNodeDerivationIsPinned() public view {
        bytes32 pinned = 0xe09c4f5bfbbc723bc35701ea9d718a1c5edb29b1ed5bb0cb0fabb3c43d8136af;
        assertEq(registry.handleNodeOf(X, "Alice_1"), pinned);
        assertEq(TestNodes.handleNode(X, "alice_1"), pinned);
        HandleVectors.Vector memory row = HandleVectors.all()[1];
        assertEq(row.output, "alice_1");
        assertEq(row.handleNode, pinned);
    }

    /// Spellings of one handle, and a locally computed node, meet in one slot; the same handle on
    /// another platform is another node, and pays nobody on the first.
    function test_theSlotIsTheNormalizedHandleOnItsPlatform() public {
        bytes32 githubAlice = TestNodes.handleNode(GITHUB, "alice");
        _depositNative("Alice", 1 ether);
        _depositNative("ALICE", 2 ether);
        vm.startPrank(sender);
        escrow.deposit{value: 3 ether}(X, aliceNode, NATIVE, 3 ether, sender);
        escrow.deposit{value: 4 ether}(GITHUB, githubAlice, NATIVE, 4 ether, sender);
        vm.stopPrank();
        assertEq(escrow.escrowed(aliceNode, NATIVE), 6 ether);
        assertEq(escrow.escrowed(githubAlice, NATIVE), 4 ether);

        _bind(alice, "1", "alice", 100); // on X only
        _claimNative(alice, alice);
        assertEq(alice.balance, 6 ether);
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(HandleEscrow.NotTheHolder.selector, address(0), alice));
        escrow.claim(githubAlice, one(NATIVE), alice);
    }

    /// Text goes through `handleNodeOf`: refused where the rules refuse it, and otherwise landing on
    /// the node a proof binds, refundable by the router's caller.
    function test_textHashedByTheRegistryLandsOnTheProvedNode() public {
        TextPayer payer = new TextPayer(escrow, registry);
        vm.startPrank(sender);
        vm.expectRevert(
            abi.encodeWithSelector(IIdentityRegistry.UnusableHandle.selector, HandleNormalizer.Problem.BadChar)
        );
        payer.pay{value: 1 ether}(X, "ali-ce");
        vm.expectRevert(
            abi.encodeWithSelector(IIdentityRegistry.UnusableHandle.selector, HandleNormalizer.Problem.BadChar)
        );
        payer.pay{value: 1 ether}(X, "@alice");
        payer.pay{value: 1 ether}(X, "Alice");
        payer.pay{value: 2 ether}(X, "ALICE");
        escrow.refund(aliceNode, NATIVE, sender);
        payer.pay{value: 3 ether}(X, "alice");
        vm.stopPrank();
        assertEq(escrow.refundable(aliceNode, NATIVE, address(payer)), 0);

        _bind(alice, "1", "Alice", 100);
        _claimNative(alice, alice);
        assertEq(alice.balance, 3 ether);
    }

    // ─── Depositing ─────────────────────────────────────────────────

    /// Unheld: held and announced. Held: paid straight through and announced, the earlier deposit
    /// still waiting for its claim.
    function test_anUnheldHandleEscrowsAndAHeldOnePaysThrough() public {
        vm.expectEmit(address(escrow));
        emit HandleEscrow.Deposited(aliceNode, address(token), sender, sender, X, 0, 10 ether);
        vm.prank(sender);
        escrow.deposit(X, aliceNode, address(token), 10 ether, sender);
        assertEq(token.balanceOf(address(escrow)), 10 ether);

        _bind(alice, "1", "alice", 100);
        vm.expectEmit(address(escrow));
        emit HandleEscrow.Forwarded(aliceNode, NATIVE, sender, alice, X, 1 ether, 1 ether);
        vm.startPrank(sender);
        escrow.deposit{value: 1 ether}(X, aliceNode, NATIVE, 1 ether, sender);
        escrow.deposit(X, aliceNode, address(token), 5 ether, sender);
        vm.stopPrank();
        assertEq(alice.balance, 1 ether);
        assertEq(token.balanceOf(alice), 5 ether);
        assertEq(escrow.escrowed(aliceNode, address(token)), 10 ether, "the waiting balance moved");
    }

    /// A fee-on-transfer pay-through reports what was asked and what arrived.
    function test_aForwardedPaymentReportsWhatArrived() public {
        FeeToken fee = new FeeToken();
        fee.mint(sender, 100 ether);
        _bind(alice, "1", "alice", 100);
        vm.startPrank(sender);
        fee.approve(address(escrow), type(uint256).max);
        vm.expectEmit(address(escrow));
        emit HandleEscrow.Forwarded(aliceNode, address(fee), sender, alice, X, 100 ether, 99 ether);
        escrow.deposit(X, aliceNode, address(fee), 100 ether, sender);
        vm.stopPrank();
    }

    function test_badAmountsAreRefused() public {
        vm.startPrank(sender);
        vm.expectRevert(HandleEscrow.ZeroAmount.selector);
        escrow.deposit(X, aliceNode, NATIVE, 0, sender);
        vm.expectRevert(abi.encodeWithSelector(HandleEscrow.ValueMismatch.selector, 2 ether, 1 ether));
        escrow.deposit{value: 1 ether}(X, aliceNode, NATIVE, 2 ether, sender);
        vm.expectRevert(abi.encodeWithSelector(HandleEscrow.ValueMismatch.selector, 0, 1 ether));
        escrow.deposit{value: 1 ether}(X, aliceNode, address(token), 10 ether, sender);
        vm.stopPrank();
    }

    /// A token that reports success and moves nothing credits nothing, escrowed or paid through.
    function test_aTokenThatDeliversNothingIsRefused() public {
        InertToken inert = new InertToken();
        vm.prank(sender);
        vm.expectRevert(HandleEscrow.ZeroAmount.selector);
        escrow.deposit(X, aliceNode, address(inert), 10 ether, sender);
        _bind(alice, "1", "alice", 100);
        vm.prank(sender);
        vm.expectRevert(HandleEscrow.ZeroAmount.selector);
        escrow.deposit(X, aliceNode, address(inert), 10 ether, sender);
    }

    /// A holder paying its own node is refused before anything moves or is announced.
    function test_aHolderPayingItselfIsRefused() public {
        _bind(alice, "1", "alice", 100);
        vm.deal(alice, 10 ether);
        token.mint(alice, 10 ether);
        vm.startPrank(alice);
        token.approve(address(escrow), type(uint256).max);
        vm.recordLogs();
        vm.expectRevert(abi.encodeWithSelector(HandleEscrow.PayingYourself.selector, alice));
        escrow.deposit{value: 10 ether}(X, aliceNode, NATIVE, 10 ether, alice);
        vm.expectRevert(abi.encodeWithSelector(HandleEscrow.PayingYourself.selector, alice));
        escrow.deposit(X, aliceNode, address(token), 10 ether, alice);
        vm.stopPrank();
        assertEq(vm.getRecordedLogs().length, 0);
        assertEq(token.balanceOf(alice), 10 ether);
    }

    /// Escrow needs a platform a claim could bind on: unwired, not verifying yet, or retired all
    /// refuse new escrow, while a holder is still paid through and held value still refunds.
    function test_escrowNeedsAPlatformThatAcceptsClaims() public {
        bytes32 googleAlice = TestNodes.handleNode(GOOGLE, "alice@example.com");
        bytes32 carol = TestNodes.handleNode(X, "carol");
        bytes32 bobNode = TestNodes.handleNode(X, "bob");
        vm.startPrank(sender);
        vm.expectRevert(abi.encodeWithSelector(HandleEscrow.PlatformAcceptsNoBindings.selector, UNWIRED));
        escrow.deposit{value: 1 ether}(UNWIRED, aliceNode, NATIVE, 1 ether, sender);
        vm.stopPrank();
        vm.prank(owner);
        registry.setPlatform(GOOGLE, HandleVectors.rulesFor(GOOGLE), HandleVectors.handleTagFor(GOOGLE));
        vm.prank(sender);
        vm.expectRevert(abi.encodeWithSelector(HandleEscrow.PlatformAcceptsNoBindings.selector, GOOGLE));
        escrow.deposit{value: 1 ether}(GOOGLE, googleAlice, NATIVE, 1 ether, sender);

        _depositNative("bob", 1 ether);
        _bind(alice, "1", "alice", 100);
        vm.prank(owner);
        proofVerifier.setVerifier(X, V1, IPlatformVerifier(address(0)));

        _depositNative("alice", 2 ether);
        assertEq(alice.balance, 2 ether, "the holder was not paid through");
        vm.prank(sender);
        vm.expectRevert(abi.encodeWithSelector(HandleEscrow.PlatformAcceptsNoBindings.selector, X));
        escrow.deposit(X, carol, address(token), 1 ether, sender);
        vm.prank(sender);
        escrow.refund(bobNode, NATIVE, sender);
        assertEq(address(escrow).balance, 0);
    }

    // ─── Claiming ───────────────────────────────────────────────────

    /// One claim takes every listed token to the recipient the holder names, one `Claimed` each,
    /// closing each round; unlisted tokens stay.
    function test_oneClaimTakesTheListedTokens() public {
        _depositNative("alice", 1 ether);
        TestERC20 second = new TestERC20();
        second.mint(sender, 5 ether);
        vm.startPrank(sender);
        second.approve(address(escrow), type(uint256).max);
        escrow.deposit(X, aliceNode, address(token), 3 ether, sender);
        escrow.deposit(X, aliceNode, address(second), 5 ether, sender);
        vm.stopPrank();
        _bind(alice, "1", "alice", 100);

        address[] memory tokens = new address[](2);
        (tokens[0], tokens[1]) = (NATIVE, address(token));
        vm.expectEmit(address(escrow));
        emit HandleEscrow.Claimed(aliceNode, NATIVE, alice, bob, 0, 1 ether, 1 ether);
        vm.expectEmit(address(escrow));
        emit HandleEscrow.Claimed(aliceNode, address(token), alice, bob, 0, 3 ether, 3 ether);
        vm.prank(alice);
        escrow.claim(aliceNode, tokens, bob);

        assertEq(bob.balance, 1 ether);
        assertEq(token.balanceOf(bob), 3 ether);
        assertEq(escrow.escrowed(aliceNode, address(second)), 5 ether, "an unlisted token moved");
        assertEq(escrow.refundable(aliceNode, address(token), sender), 0, "the round stayed open");
    }

    /// A repeated token pays once, an empty one is skipped, and a claim that pays nothing reverts.
    function test_aClaimPaysEachHeldTokenOnceOrReverts() public {
        _depositNative("alice", 1 ether);
        _bind(alice, "1", "alice", 100);
        address[] memory tokens = new address[](3);
        (tokens[0], tokens[1], tokens[2]) = (NATIVE, address(token), NATIVE);
        vm.startPrank(alice);
        escrow.claim(aliceNode, tokens, bob);
        assertEq(bob.balance, 1 ether);
        vm.expectRevert(abi.encodeWithSelector(HandleEscrow.NothingHeld.selector, aliceNode));
        escrow.claim(aliceNode, tokens, bob);
        vm.expectRevert(abi.encodeWithSelector(HandleEscrow.NothingHeld.selector, aliceNode));
        escrow.claim(aliceNode, new address[](0), bob);
        vm.stopPrank();
    }

    /// Only the node's holder claims: not a stranger, not the depositor, not the owner, and nobody
    /// while the node is unheld.
    function test_onlyTheHolderClaims() public {
        _depositNative("alice", 1 ether);
        address[3] memory callers = [bob, sender, owner];
        for (uint256 i = 0; i < 3; i++) {
            vm.prank(callers[i]);
            vm.expectRevert(abi.encodeWithSelector(HandleEscrow.NotTheHolder.selector, address(0), callers[i]));
            escrow.claim(aliceNode, one(NATIVE), callers[i]);
        }
        _bind(alice, "1", "alice", 100);
        vm.prank(bob);
        vm.expectRevert(abi.encodeWithSelector(HandleEscrow.NotTheHolder.selector, alice, bob));
        escrow.claim(aliceNode, one(NATIVE), bob);
        assertEq(escrow.escrowed(aliceNode, NATIVE), 1 ether);
    }

    /// No payout goes to nobody or back into the escrow, and one the recipient rejects fails whole.
    function test_badRecipientsAreRefused() public {
        _depositNative("alice", 1 ether);
        _bind(alice, "1", "alice", 100);
        address rejector = address(new RejectEther());
        address[2] memory bad = [address(0), address(escrow)];
        for (uint256 i = 0; i < 2; i++) {
            vm.prank(alice);
            vm.expectRevert(abi.encodeWithSelector(HandleEscrow.BadRecipient.selector, bad[i]));
            escrow.claim(aliceNode, one(NATIVE), bad[i]);
            vm.prank(sender);
            vm.expectRevert(abi.encodeWithSelector(HandleEscrow.BadRecipient.selector, bad[i]));
            escrow.refund(aliceNode, NATIVE, bad[i]);
        }
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(HandleEscrow.NativeTransferFailed.selector, rejector, 1 ether));
        escrow.claim(aliceNode, one(NATIVE), rejector);

        _bind(rejector, "2", "bob", 100);
        bytes32 bobNode = TestNodes.handleNode(X, "bob");
        vm.prank(sender);
        vm.expectRevert(abi.encodeWithSelector(HandleEscrow.NativeTransferFailed.selector, rejector, 1 ether));
        escrow.deposit{value: 1 ether}(X, bobNode, NATIVE, 1 ether, sender);
        assertEq(escrow.escrowed(aliceNode, NATIVE), 1 ether);
    }

    /// The claim empties the slot before paying, and the guard refuses a second claim from inside.
    function test_aClaimSettlesBeforePayingAndTheGuardRefusesReentry() public {
        ObservingPayee payee = new ObservingPayee(escrow, aliceNode);
        _depositNative("alice", 1 ether);
        _depositNative("bob", 1 ether);
        _bind(address(payee), "1", "alice", 100);

        payee.take(abi.encodeCall(HandleEscrow.claim, (aliceNode, one(NATIVE), address(payee))));
        assertEq(payee.heldDuringPayout(), 0);
        assertEq(
            payee.reentryError(),
            abi.encodeWithSelector(ReentrancyGuardUpgradeable.ReentrancyGuardReentrantCall.selector)
        );
        assertEq(address(payee).balance, 1 ether);
        assertEq(address(escrow).balance, 1 ether);
    }

    // ─── Refunding ──────────────────────────────────────────────────

    /// `refundTo`, not the payer, owns the refund; each takes back exactly its own, once, to the
    /// recipient it names.
    function test_refundToOwnsTheRefund() public {
        SharedForwarder forwarder = new SharedForwarder();
        vm.prank(sender);
        forwarder.forward{value: 1 ether}(
            address(escrow), abi.encodeCall(HandleEscrow.deposit, (X, aliceNode, NATIVE, 1 ether, sender))
        );
        vm.prank(sender);
        escrow.deposit(X, aliceNode, address(token), 10 ether, bob);

        vm.prank(bob);
        vm.expectRevert(abi.encodeWithSelector(HandleEscrow.NothingToRefund.selector, aliceNode, NATIVE, bob));
        escrow.refund(aliceNode, NATIVE, bob);
        vm.prank(sender);
        vm.expectRevert(
            abi.encodeWithSelector(HandleEscrow.NothingToRefund.selector, aliceNode, address(token), sender)
        );
        escrow.refund(aliceNode, address(token), sender);

        vm.expectEmit(address(escrow));
        emit HandleEscrow.Refunded(aliceNode, address(token), bob, alice, 0, 10 ether, 10 ether);
        vm.prank(bob);
        escrow.refund(aliceNode, address(token), alice);
        vm.prank(sender);
        escrow.refund(aliceNode, NATIVE, sender);
        vm.prank(sender);
        vm.expectRevert(abi.encodeWithSelector(HandleEscrow.NothingToRefund.selector, aliceNode, NATIVE, sender));
        escrow.refund(aliceNode, NATIVE, sender);
        assertEq(token.balanceOf(alice), 10 ether);
        assertEq(address(escrow).balance, 0);
    }

    /// There is no default `refundTo`, and it cannot be the escrow, whether the node is held or not.
    function test_aDepositMustNameWhoCanRefundIt() public {
        for (uint256 i = 0; i < 2; i++) {
            if (i == 1) _bind(alice, "1", "alice", 100);
            address[2] memory bad = [address(0), address(escrow)];
            for (uint256 j = 0; j < 2; j++) {
                vm.prank(sender);
                vm.expectRevert(abi.encodeWithSelector(HandleEscrow.BadRefundTo.selector, bad[j]));
                escrow.deposit{value: 1 ether}(X, aliceNode, NATIVE, 1 ether, bad[j]);
            }
        }
        assertEq(alice.balance, 0);
    }

    /// A node of no handle funds a slot nobody claims; its `refundTo` takes it back.
    function test_aWrongNodeIsRecoverableByRefund() public {
        bytes32 garbage = keccak256("not the node of any handle");
        vm.prank(sender);
        escrow.deposit{value: 1 ether}(X, garbage, NATIVE, 1 ether, sender);
        vm.prank(sender);
        escrow.refund(garbage, NATIVE, sender);
        assertEq(address(escrow).balance, 0);
    }

    /// Refundable after the payee joins, until it claims: refund and claim race, the first wins, and
    /// what a claim took never reads as refundable.
    function test_ACCEPTED_aRefundAndAClaimRaceUntilTheClaim() public {
        _depositNative("alice", 1 ether);
        _bind(alice, "1", "alice", 100);
        uint256 staged = vm.snapshotState();

        vm.prank(sender);
        escrow.refund(aliceNode, NATIVE, sender);
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(HandleEscrow.NothingHeld.selector, aliceNode));
        escrow.claim(aliceNode, one(NATIVE), alice);

        vm.revertToState(staged);
        _claimNative(alice, alice);
        assertEq(escrow.refundable(aliceNode, NATIVE, sender), 0);
        vm.prank(sender);
        vm.expectRevert(abi.encodeWithSelector(HandleEscrow.NothingToRefund.selector, aliceNode, NATIVE, sender));
        escrow.refund(aliceNode, NATIVE, sender);
        assertEq(alice.balance, 1 ether);
    }

    /// The refund settles the contribution and the slot before paying, and the guard refuses a second.
    function test_aRefundSettlesBeforePayingAndTheGuardRefusesReentry() public {
        ObservingPayee payee = new ObservingPayee(escrow, aliceNode);
        payee.fund{value: 1 ether}(X, aliceNode);
        _depositNative("alice", 1 ether);

        payee.take(abi.encodeCall(HandleEscrow.refund, (aliceNode, NATIVE, address(payee))));
        assertEq(payee.refundableDuringPayout(), 0);
        assertEq(payee.heldDuringPayout(), 1 ether);
        assertEq(
            payee.reentryError(),
            abi.encodeWithSelector(ReentrancyGuardUpgradeable.ReentrancyGuardReentrantCall.selector)
        );
        assertEq(address(payee).balance, 1 ether);
    }

    // ─── Consequences accepted on purpose ───────────────────────────

    /// NOT a vulnerability. An unclaimed slot follows the handle, not the id: renamed away, the
    /// identity cannot claim, the depositor can still refund, and the handle's next holder claims.
    function test_ACCEPTED_aRecycledHandlePaysTheNewHolder() public {
        _depositNative("alice", 2 ether);
        _bind(alice, "1", "alice", 100);
        _bind(alice, "1", "alice2", 200);
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(HandleEscrow.NotTheHolder.selector, address(0), alice));
        escrow.claim(aliceNode, one(NATIVE), alice);
        assertEq(escrow.refundable(aliceNode, NATIVE, sender), 2 ether);

        _bind(bob, "2", "alice", 300);
        _claimNative(bob, bob);
        assertEq(bob.balance, 2 ether);
    }

    /// NOT a vulnerability. The node carries no platform the escrow can read: `platformId` decides
    /// whether an unheld node escrows and labels the event, and the value lands on the node given.
    function test_ACCEPTED_thePlatformNamedIsNotCheckedAgainstTheNode() public {
        vm.expectEmit(address(escrow));
        emit HandleEscrow.Deposited(aliceNode, NATIVE, sender, sender, GITHUB, 0, 1 ether);
        vm.prank(sender);
        escrow.deposit{value: 1 ether}(GITHUB, aliceNode, NATIVE, 1 ether, sender);

        _bind(alice, "1", "alice", 100);
        _claimNative(alice, alice);
        assertEq(alice.balance, 1 ether);
    }

    /// A claim reads the holder only, so a platform that stops accepting bindings does not stop it.
    function test_aRetiredPlatformDoesNotStopTheHolderClaiming() public {
        _depositNative("alice", 1 ether);
        _bind(alice, "1", "alice", 100);
        vm.prank(owner);
        proofVerifier.setVerifier(X, V1, IPlatformVerifier(address(0)));
        assertFalse(registry.acceptsBindings(X));

        _claimNative(alice, alice);
        assertEq(alice.balance, 1 ether);
    }

    /// Every event names its round: a claim closes the round it names, and the next deposit to the
    /// node opens the next one, which its refund names too.
    function test_theEventsNameTheRoundAClaimCloses() public {
        _depositNative("alice", 1 ether);
        _bind(alice, "1", "alice", 100);
        vm.expectEmit(address(escrow));
        emit HandleEscrow.Claimed(aliceNode, NATIVE, alice, alice, 0, 1 ether, 1 ether);
        _claimNative(alice, alice);

        _bind(alice, "1", "alice2", 200);
        vm.expectEmit(address(escrow));
        emit HandleEscrow.Deposited(aliceNode, NATIVE, sender, sender, X, 1, 2 ether);
        _depositNative("alice", 2 ether);
        vm.expectEmit(address(escrow));
        emit HandleEscrow.Refunded(aliceNode, NATIVE, sender, sender, 1, 2 ether, 2 ether);
        vm.prank(sender);
        escrow.refund(aliceNode, NATIVE, sender);
        assertEq(escrow.refundable(aliceNode, NATIVE, sender), 0);
    }

    // ─── Wiring and upgrades ────────────────────────────────────────

    /// `initialize` refuses a registry that does not answer the two calls in shape, and names the
    /// first one missing.
    function test_initializeChecksTheRegistry() public {
        assertEq(address(escrow.registry()), address(registry));
        _assertRefused(address(0), abi.encodeWithSelector(HandleEscrow.NoRegistry.selector));
        _assertLacks(makeAddr("no code"), IIdentityRegistry.handleBinding.selector);
        _assertLacks(address(new RegistryWithAOneWordFallback()), IIdentityRegistry.handleBinding.selector);
        _assertLacks(address(new RegistryWithoutAcceptsBindings()), IIdentityRegistry.acceptsBindings.selector);
        _assertLacks(address(new RegistryWithASilentFallback()), IIdentityRegistry.acceptsBindings.selector);
        _assertLacks(address(new RegistryWithANonBooleanAnswer()), IIdentityRegistry.acceptsBindings.selector);
        _deploy(address(new RegistryWithBothCalls()));

        HandleEscrow impl = new HandleEscrow();
        vm.expectRevert(Initializable.InvalidInitialization.selector);
        impl.initialize(owner, IIdentityRegistry(address(registry)));
    }

    /// `initialize` arms the guard, and a guarded call leaves it armed.
    function test_initializeArmsTheReentrancyGuard() public {
        bytes32 guardSlot = 0x9b779b17422d0df92223018b32b4d1fa46e071723d6817e2486d003becc55f00;
        assertEq(uint256(vm.load(address(escrow), guardSlot)), 1);
        _depositNative("alice", 1 ether);
        assertEq(uint256(vm.load(address(escrow), guardSlot)), 1);
    }

    function test_onlyTheOwnerUpgradesAndOwnershipStays() public {
        vm.prank(owner);
        vm.expectRevert(HandleEscrow.RenounceDisabled.selector);
        escrow.renounceOwnership();
        HandleEscrow next = new HandleEscrow();
        vm.prank(bob);
        vm.expectRevert(abi.encodeWithSelector(OwnableUpgradeable.OwnableUnauthorizedAccount.selector, bob));
        escrow.upgradeToAndCall(address(next), "");
        vm.prank(owner);
        escrow.upgradeToAndCall(address(next), "");
    }

    /// An upgrade that appends a field keeps every balance, round and contribution where it was.
    function test_balancesSurviveAnUpgrade() public {
        _depositNative("alice", 1 ether);
        _bind(alice, "1", "alice", 100);
        _claimNative(alice, alice);
        _bind(alice, "1", "alice2", 200);
        _depositNative("alice", 1 ether);

        HandleEscrowV2 next = new HandleEscrowV2();
        vm.prank(owner);
        escrow.upgradeToAndCall(address(next), "");
        HandleEscrowV2 upgraded = HandleEscrowV2(payable(address(escrow)));
        (uint256 held, address registry_, uint256 round, uint256 open, uint256 appended) =
            upgraded.read(aliceNode, NATIVE, 1, sender);
        (,,, uint256 closed,) = upgraded.read(aliceNode, NATIVE, 0, sender);
        assertEq(held, 1 ether);
        assertEq(registry_, address(registry));
        assertEq(round, 1);
        assertEq(open, 1 ether);
        assertEq(closed, 1 ether);
        assertEq(appended, 0);
        upgraded.setAppended(7);
        assertEq(escrow.refundable(aliceNode, NATIVE, sender), 1 ether);
    }

    // ─── Helpers ────────────────────────────────────────────────────

    function _deploy(address registry_) internal returns (HandleEscrow) {
        return HandleEscrow(
            address(
                new ERC1967Proxy(
                    address(new HandleEscrow()),
                    abi.encodeCall(HandleEscrow.initialize, (owner, IIdentityRegistry(registry_)))
                )
            )
        );
    }

    function _assertLacks(address registry_, bytes4 selector) internal {
        _assertRefused(registry_, abi.encodeWithSelector(HandleEscrow.RegistryLacks.selector, registry_, selector));
    }

    function _assertRefused(address registry_, bytes memory reason) internal {
        HandleEscrow impl = new HandleEscrow();
        vm.expectRevert(reason);
        new ERC1967Proxy(address(impl), abi.encodeCall(HandleEscrow.initialize, (owner, IIdentityRegistry(registry_))));
    }

    /// Prove `handle` on X for `who`.
    function _bind(address who, string memory id, string memory handle, uint64 at) internal {
        xVerifier.set(id, handle);
        xVerifier.setObservedAt(at);
        bytes memory payload = abi.encode(
            StubPlatformVerifier.StubPayload({
                ceremonyVersion: 1,
                operationDomain: keccak256(bytes("libid.claim-identity")),
                authorizationNonce: bytes32(++nonce),
                transactionData: abi.encode(who, uint256(0), address(0)),
                handle: ""
            })
        );
        vm.prank(who);
        registry.bind(X, V1, payload);
    }

    /// Deposit native value for text on X, at the node the registry names.
    function _depositNative(string memory handle, uint256 amount) internal {
        bytes32 handleNode = registry.handleNodeOf(X, handle);
        vm.prank(sender);
        escrow.deposit{value: amount}(X, handleNode, NATIVE, amount, sender);
    }

    function _claimNative(address holder, address recipient) internal {
        vm.prank(holder);
        escrow.claim(aliceNode, one(NATIVE), recipient);
    }
}
