// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {ReentrancyGuardUpgradeable} from "@openzeppelin/contracts-upgradeable/utils/ReentrancyGuardUpgradeable.sol";
import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {OwnableUpgradeable} from "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";

import {HandleNormalizer} from "../../identity/HandleNormalizer.sol";
import {HandleVectors} from "../../identity/HandleVectors.sol";
import {IdentityNames} from "../../identity/IdentityNames.sol";
import {IdentityNodes} from "../../identity/IdentityNodes.sol";
import {IIdentityNames} from "../../identity/IIdentityNames.sol";
import {StubPlatformVerifier} from "../../identity/test/StubPlatformVerifier.sol";
import {CeremonyProofVerifier} from "../../ceremony/CeremonyProofVerifier.sol";
import {IPlatformVerifier} from "../../ceremony/IPlatformVerifier.sol";
import {IProofVerifier} from "../../ceremony/IProofVerifier.sol";
import {HandleEscrow} from "../HandleEscrow.sol";
import {FeeToken, InertToken, RejectEther, TestERC20, one} from "./EscrowMocks.sol";

/// @notice Appends one field to the namespaced root, the only change the storage rule allows.
contract HandleEscrowV2 is HandleEscrow {
    /// @custom:storage-location erc7201:libid.storage.HandleEscrow
    struct V2Storage {
        mapping(bytes32 => mapping(address => uint256)) held;
        IIdentityNames names;
        mapping(bytes32 => mapping(address => uint256)) round;
        mapping(bytes32 => mapping(address => mapping(uint256 => mapping(address => uint256)))) contributions;
        mapping(bytes32 => bytes32) platformOf;
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
        returns (uint256 held, address names_, uint256 round, uint256 contribution, uint256 appended)
    {
        V2Storage storage $ = _v2();
        return (
            $.held[node][token],
            address($.names),
            $.round[node][token],
            $.contributions[node][token][round_][refundTo],
            $.appended
        );
    }
}

/// @notice A router paying a handle given as text; its caller is `refundTo`.
contract TextPayer {
    HandleEscrow private immutable ESCROW;
    IdentityNames private immutable NAMES;

    constructor(HandleEscrow escrow_, IdentityNames names_) {
        (ESCROW, NAMES) = (escrow_, names_);
    }

    function pay(bytes32 platformId, string calldata handle) external payable {
        ESCROW.deposit{value: msg.value}(
            platformId, NAMES.handleHashOf(platformId, handle), ESCROW.NATIVE(), msg.value, msg.sender, address(0)
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

    function fund(bytes32 platformId, bytes32 handleHash) external payable {
        ESCROW.deposit{value: msg.value}(platformId, handleHash, ESCROW.NATIVE(), msg.value, address(this), address(0));
    }

    function take(bytes calldata data) external {
        call_ = data;
        (bool ok,) = address(ESCROW).call(data);
        require(ok, "the payout failed");
    }

    receive() external payable {
        if (entered) return;
        entered = true;
        heldDuringPayout = ESCROW.escrowed(NODE, ESCROW.NATIVE());
        refundableDuringPayout = ESCROW.refundable(NODE, ESCROW.NATIVE(), address(this));
        (bool ok, bytes memory reason) = address(ESCROW).call(call_);
        require(!ok, "the reentry was let through");
        reentryError = reason;
    }
}

/// @notice Naming contracts `initialize` must refuse or accept.
contract NamesBeforeTheEscrow {
    function byHandle(bytes32) external pure returns (address, uint64) {}
}

contract NamesWithoutNodeOfHash is NamesBeforeTheEscrow {
    function acceptsClaims(bytes32) external pure returns (bool) {}
}

contract NamesWithAZeroFallback is NamesWithoutNodeOfHash {
    fallback() external {
        assembly {
            mstore(0, 0)
            return(0, 32)
        }
    }
}

contract NamesWithAConstantNode is NamesWithoutNodeOfHash {
    function nodeOfHash(bytes32, bytes32) external pure returns (bytes32) {
        return bytes32(uint256(1));
    }
}

contract NamesWithAnotherNodeDerivation is NamesWithoutNodeOfHash {
    function nodeOfHash(bytes32 platformId, bytes32 handleHash) external pure returns (bytes32) {
        return keccak256(abi.encode(platformId, handleHash));
    }
}

contract NamesWithASilentFallback is NamesBeforeTheEscrow {
    fallback() external {}
}

/// @notice The handle-keyed escrow, against the real naming system.
contract HandleEscrowTest is Test {
    IdentityNames internal names;
    CeremonyProofVerifier internal proofVerifier;
    StubPlatformVerifier internal xVerifier;
    HandleEscrow internal escrow;
    TestERC20 internal token;

    bytes32 internal constant X = HandleVectors.PLATFORM_X;
    bytes32 internal constant GITHUB = HandleVectors.PLATFORM_GITHUB;
    bytes32 internal constant GOOGLE = HandleVectors.PLATFORM_GOOGLE;
    bytes32 internal constant UNWIRED = keccak256("no such platform");
    address internal constant NATIVE = 0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE;
    uint16 internal constant V1 = 1;

    address internal alice = makeAddr("alice");
    address internal bob = makeAddr("bob");
    address internal sender = makeAddr("sender");
    address internal owner = makeAddr("owner");

    bytes32 internal aliceNode = IdentityNodes.handleNode(X, "alice");
    bytes32 internal aliceHash = keccak256("alice");
    uint256 private nonce;

    function setUp() public {
        names = IdentityNames(
            address(new ERC1967Proxy(address(new IdentityNames()), abi.encodeCall(IdentityNames.initialize, (owner))))
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
        names.setProofVerifier(IProofVerifier(address(proofVerifier)));
        names.setPlatform(X, HandleVectors.rulesFor(X));
        proofVerifier.setVerifier(X, V1, IPlatformVerifier(address(xVerifier)));
        names.setPlatform(GITHUB, HandleVectors.rulesFor(GITHUB));
        proofVerifier.setVerifier(GITHUB, V1, IPlatformVerifier(address(new StubPlatformVerifier(GITHUB, 0))));
        vm.stopPrank();

        escrow = _deploy(address(names));
        token = new TestERC20();
        token.mint(sender, 1_000 ether);
        vm.prank(sender);
        token.approve(address(escrow), type(uint256).max);
        vm.deal(sender, 100 ether);
        vm.warp(1_000_000);
    }

    // ─── The key ────────────────────────────────────────────────────

    /// Every row of the shared handle table keys where the naming system binds it, or is refused.
    function test_everyVectorRowKeysOnTheNamingSystemsNode() public {
        vm.startPrank(owner);
        names.setPlatform(GOOGLE, HandleVectors.rulesFor(GOOGLE));
        proofVerifier.setVerifier(GOOGLE, V1, IPlatformVerifier(address(new StubPlatformVerifier(GOOGLE, 0))));
        vm.stopPrank();

        HandleVectors.Vector[] memory vectors = HandleVectors.all();
        for (uint256 i = 0; i < vectors.length; i++) {
            HandleVectors.Vector memory v = vectors[i];
            bytes32 platformId = keccak256(bytes(v.platform));
            if (v.accepted) {
                assertEq(names.handleHashOf(platformId, v.input), keccak256(bytes(v.output)), vm.toString(i));
                assertEq(
                    names.nodeOf(platformId, v.input), IdentityNodes.handleNode(platformId, v.output), vm.toString(i)
                );
            } else {
                vm.expectRevert(
                    abi.encodeWithSelector(
                        IIdentityNames.UnusableHandle.selector, HandleNormalizer.Problem(v.errorKind + 1)
                    )
                );
                names.handleHashOf(platformId, v.input);
            }
        }
    }

    /// A `cast` literal, so the TypeScript derivation cannot drift and still pass its own tests.
    function test_theNodeDerivationIsPinned() public view {
        bytes32 pinned = 0x1c43d5d3cf3d99e9d5b6e8c74c23d14bcbb6a743712cf7fa7c15750c4fc2150d;
        assertEq(names.nodeOf(X, " Alice_1 "), pinned);
        assertEq(IdentityNodes.handleNode(X, "alice_1"), pinned);
    }

    /// Spellings of one handle, and a locally computed hash, meet in one slot; the same hash on
    /// another platform is another slot, and pays nobody on the first.
    function test_theSlotIsTheNormalizedHandleOnItsPlatform() public {
        _depositNative("@alice", 1 ether);
        _depositNative(" ALICE ", 2 ether);
        vm.startPrank(sender);
        escrow.deposit{value: 3 ether}(X, aliceHash, NATIVE, 3 ether, sender, address(0));
        escrow.deposit{value: 4 ether}(GITHUB, aliceHash, NATIVE, 4 ether, sender, address(0));
        vm.stopPrank();
        assertEq(escrow.escrowed(aliceNode, NATIVE), 6 ether);
        assertEq(escrow.escrowed(IdentityNodes.handleNode(GITHUB, "alice"), NATIVE), 4 ether);

        _bind(alice, "1", "alice", 100); // on X only
        _claimNative(alice, alice);
        assertEq(alice.balance, 6 ether);
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(HandleEscrow.NotTheHolder.selector, address(0), alice));
        escrow.claim(IdentityNodes.handleNode(GITHUB, "alice"), one(NATIVE), alice);
    }

    /// Text goes through `handleHashOf`: refused where the rules refuse it, and otherwise landing on
    /// the node a proof binds, refundable by the router's caller.
    function test_textHashedByTheNamingSystemLandsOnTheProvedNode() public {
        TextPayer payer = new TextPayer(escrow, names);
        vm.startPrank(sender);
        vm.expectRevert(
            abi.encodeWithSelector(IIdentityNames.UnusableHandle.selector, HandleNormalizer.Problem.BadChar)
        );
        payer.pay{value: 1 ether}(X, "ali-ce");
        payer.pay{value: 1 ether}(X, "  @Alice ");
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
        escrow.deposit(X, aliceHash, address(token), 10 ether, sender, address(0));
        assertEq(token.balanceOf(address(escrow)), 10 ether);

        _bind(alice, "1", "alice", 100);
        vm.expectEmit(address(escrow));
        emit HandleEscrow.Forwarded(aliceNode, NATIVE, sender, alice, X, 1 ether, 1 ether);
        vm.startPrank(sender);
        escrow.deposit{value: 1 ether}(X, aliceHash, NATIVE, 1 ether, sender, address(0));
        escrow.deposit(X, aliceHash, address(token), 5 ether, sender, address(0));
        vm.stopPrank();
        assertEq(alice.balance, 1 ether);
        assertEq(token.balanceOf(alice), 5 ether);
        assertEq(escrow.escrowed(aliceNode, address(token)), 10 ether, "the waiting balance moved");
    }

    /// `expectedHolder`: zero takes either branch, `UNHELD` only escrows, an address only pays
    /// that holder. A handle that changed hands after the sender looked is refused, not paid.
    function test_expectedHolderPinsTheOutcome() public {
        address unheld = escrow.UNHELD();
        vm.startPrank(sender);
        vm.expectRevert(abi.encodeWithSelector(HandleEscrow.UnexpectedHolder.selector, alice, address(0)));
        escrow.deposit{value: 1 ether}(X, aliceHash, NATIVE, 1 ether, sender, alice);
        escrow.deposit{value: 1 ether}(X, aliceHash, NATIVE, 1 ether, sender, unheld);
        assertEq(escrow.escrowed(aliceNode, NATIVE), 1 ether);
        vm.stopPrank();

        _bind(bob, "2", "alice", 100);
        _bind(bob, "2", "bob", 200);
        _bind(alice, "1", "alice", 300);
        vm.startPrank(sender);
        vm.expectRevert(abi.encodeWithSelector(HandleEscrow.UnexpectedHolder.selector, bob, alice));
        escrow.deposit{value: 1 ether}(X, aliceHash, NATIVE, 1 ether, sender, bob);
        vm.expectRevert(abi.encodeWithSelector(HandleEscrow.UnexpectedHolder.selector, unheld, alice));
        escrow.deposit{value: 1 ether}(X, aliceHash, NATIVE, 1 ether, sender, unheld);
        escrow.deposit{value: 1 ether}(X, aliceHash, NATIVE, 1 ether, sender, alice);
        escrow.deposit{value: 1 ether}(X, aliceHash, NATIVE, 1 ether, sender, address(0));
        vm.stopPrank();
        assertEq(alice.balance, 2 ether);
    }

    /// The zero address is not a token: native value is `NATIVE` (EIP-7528).
    function test_theZeroAddressIsNotAToken() public {
        assertEq(escrow.NATIVE(), 0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE);
        vm.prank(sender);
        vm.expectRevert(abi.encodeWithSelector(HandleEscrow.BadToken.selector, address(0)));
        escrow.deposit{value: 1 ether}(X, aliceHash, address(0), 1 ether, sender, address(0));
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
        escrow.deposit(X, aliceHash, address(fee), 100 ether, sender, address(0));
        vm.stopPrank();
    }

    function test_badAmountsAreRefused() public {
        vm.startPrank(sender);
        vm.expectRevert(HandleEscrow.ZeroAmount.selector);
        escrow.deposit(X, aliceHash, NATIVE, 0, sender, address(0));
        vm.expectRevert(abi.encodeWithSelector(HandleEscrow.ValueMismatch.selector, 2 ether, 1 ether));
        escrow.deposit{value: 1 ether}(X, aliceHash, NATIVE, 2 ether, sender, address(0));
        vm.expectRevert(abi.encodeWithSelector(HandleEscrow.ValueMismatch.selector, 0, 1 ether));
        escrow.deposit{value: 1 ether}(X, aliceHash, address(token), 10 ether, sender, address(0));
        vm.stopPrank();
    }

    /// A token that reports success and moves nothing credits nothing, escrowed or paid through.
    function test_aTokenThatDeliversNothingIsRefused() public {
        InertToken inert = new InertToken();
        vm.prank(sender);
        vm.expectRevert(HandleEscrow.ZeroAmount.selector);
        escrow.deposit(X, aliceHash, address(inert), 10 ether, sender, address(0));
        _bind(alice, "1", "alice", 100);
        vm.prank(sender);
        vm.expectRevert(HandleEscrow.ZeroAmount.selector);
        escrow.deposit(X, aliceHash, address(inert), 10 ether, sender, address(0));
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
        escrow.deposit{value: 10 ether}(X, aliceHash, NATIVE, 10 ether, alice, address(0));
        vm.expectRevert(abi.encodeWithSelector(HandleEscrow.PayingYourself.selector, alice));
        escrow.deposit(X, aliceHash, address(token), 10 ether, alice, address(0));
        vm.stopPrank();
        assertEq(vm.getRecordedLogs().length, 0);
        assertEq(token.balanceOf(alice), 10 ether);
    }

    /// Escrow needs a platform a claim could bind on: unwired, not verifying yet, or retired all
    /// refuse new escrow, while a holder is still paid through and held value still refunds.
    function test_escrowNeedsAPlatformThatAcceptsClaims() public {
        vm.startPrank(sender);
        vm.expectRevert(abi.encodeWithSelector(HandleEscrow.PlatformAcceptsNoClaims.selector, UNWIRED));
        escrow.deposit{value: 1 ether}(UNWIRED, aliceHash, NATIVE, 1 ether, sender, address(0));
        vm.stopPrank();
        vm.prank(owner);
        names.setPlatform(GOOGLE, HandleVectors.rulesFor(GOOGLE));
        vm.prank(sender);
        vm.expectRevert(abi.encodeWithSelector(HandleEscrow.PlatformAcceptsNoClaims.selector, GOOGLE));
        escrow.deposit{value: 1 ether}(GOOGLE, keccak256("alice@example.com"), NATIVE, 1 ether, sender, address(0));

        _depositNative("bob", 1 ether);
        _bind(alice, "1", "alice", 100);
        vm.prank(owner);
        proofVerifier.setVerifier(X, V1, IPlatformVerifier(address(0)));

        _depositNative("alice", 2 ether);
        assertEq(alice.balance, 2 ether, "the holder was not paid through");
        vm.prank(sender);
        vm.expectRevert(abi.encodeWithSelector(HandleEscrow.PlatformAcceptsNoClaims.selector, X));
        escrow.deposit(X, keccak256("carol"), address(token), 1 ether, sender, address(0));
        vm.prank(sender);
        escrow.refund(IdentityNodes.handleNode(X, "bob"), NATIVE, sender);
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
        escrow.deposit(X, aliceHash, address(token), 3 ether, sender, address(0));
        escrow.deposit(X, aliceHash, address(second), 5 ether, sender, address(0));
        vm.stopPrank();
        _bind(alice, "1", "alice", 100);

        address[] memory tokens = new address[](2);
        (tokens[0], tokens[1]) = (NATIVE, address(token));
        vm.expectEmit(address(escrow));
        emit HandleEscrow.Claimed(aliceNode, NATIVE, alice, bob, X, 0, 1 ether, 1 ether);
        vm.expectEmit(address(escrow));
        emit HandleEscrow.Claimed(aliceNode, address(token), alice, bob, X, 0, 3 ether, 3 ether);
        vm.prank(alice);
        escrow.claim(aliceNode, tokens, bob);

        assertEq(bob.balance, 1 ether);
        assertEq(token.balanceOf(bob), 3 ether);
        assertEq(escrow.escrowed(aliceNode, address(second)), 5 ether, "an unlisted token moved");
        assertEq(escrow.refundable(aliceNode, address(token), sender), 0, "the round stayed open");
    }

    /// Every escrow event names the platform and the round the value was booked in: a claim closes
    /// round 0, and the next deposit and its refund are round 1.
    function test_eventsCarryThePlatformAndTheRound() public {
        _depositNative("alice", 1 ether);
        _bind(alice, "1", "alice", 100);
        vm.expectEmit(address(escrow));
        emit HandleEscrow.Claimed(aliceNode, NATIVE, alice, alice, X, 0, 1 ether, 1 ether);
        _claimNative(alice, alice);
        _bind(alice, "1", "alice2", 200);

        vm.expectEmit(address(escrow));
        emit HandleEscrow.Deposited(aliceNode, NATIVE, sender, sender, X, 1, 2 ether);
        _depositNative("alice", 2 ether);
        vm.expectEmit(address(escrow));
        emit HandleEscrow.Refunded(aliceNode, NATIVE, sender, sender, X, 1, 2 ether, 2 ether);
        vm.prank(sender);
        escrow.refund(aliceNode, NATIVE, sender);
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
        vm.prank(sender);
        vm.expectRevert(abi.encodeWithSelector(HandleEscrow.NativeTransferFailed.selector, rejector, 1 ether));
        escrow.deposit{value: 1 ether}(X, keccak256("bob"), NATIVE, 1 ether, sender, address(0));
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
            address(escrow), abi.encodeCall(HandleEscrow.deposit, (X, aliceHash, NATIVE, 1 ether, sender, address(0)))
        );
        vm.prank(sender);
        escrow.deposit(X, aliceHash, address(token), 10 ether, bob, address(0));

        vm.prank(bob);
        vm.expectRevert(abi.encodeWithSelector(HandleEscrow.NothingToRefund.selector, aliceNode, NATIVE, bob));
        escrow.refund(aliceNode, NATIVE, bob);
        vm.prank(sender);
        vm.expectRevert(
            abi.encodeWithSelector(HandleEscrow.NothingToRefund.selector, aliceNode, address(token), sender)
        );
        escrow.refund(aliceNode, address(token), sender);

        vm.expectEmit(address(escrow));
        emit HandleEscrow.Refunded(aliceNode, address(token), bob, alice, X, 0, 10 ether, 10 ether);
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
                escrow.deposit{value: 1 ether}(X, aliceHash, NATIVE, 1 ether, bad[j], address(0));
            }
        }
        assertEq(alice.balance, 0);
    }

    /// A hash of no handle funds a slot nobody claims; its `refundTo` takes it back.
    function test_aWrongHashIsRecoverableByRefund() public {
        bytes32 garbageHash = keccak256("not the hash of any handle");
        bytes32 garbage = IdentityNodes.handleNodeOfHash(X, garbageHash);
        vm.prank(sender);
        escrow.deposit{value: 1 ether}(X, garbageHash, NATIVE, 1 ether, sender, address(0));
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
        payee.fund{value: 1 ether}(X, aliceHash);
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

    /// NOT a vulnerability. An unclaimed slot follows the handle, not the account: renamed away, the
    /// account cannot claim, the depositor can still refund, and the handle's next holder claims.
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

    /// A claim reads the holder only, so narrowing the platform's rules does not stop it.
    function test_aRulesChangeDoesNotStopTheHolderClaiming() public {
        _depositNative("alice_9", 1 ether);
        _bind(alice, "1", "alice_9", 100);
        HandleNormalizer.Rules memory narrowed = HandleVectors.rulesFor(X);
        narrowed.allowUnderscore = false;
        vm.prank(owner);
        names.setPlatform(X, narrowed);

        vm.expectRevert(
            abi.encodeWithSelector(IIdentityNames.UnusableHandle.selector, HandleNormalizer.Problem.BadChar)
        );
        names.handleHashOf(X, "alice_9");
        vm.prank(alice);
        escrow.claim(IdentityNodes.handleNode(X, "alice_9"), one(NATIVE), alice);
        assertEq(alice.balance, 1 ether);
    }

    // ─── Wiring and upgrades ────────────────────────────────────────

    /// `initialize` refuses a naming contract that does not answer the three calls in shape, names
    /// the first one missing, and accepts any node derivation that depends on the hash.
    function test_initializeChecksTheNamingContract() public {
        assertEq(address(escrow.names()), address(names));
        _assertRefused(address(0), abi.encodeWithSelector(HandleEscrow.NoNames.selector));
        _assertLacks(makeAddr("no code"), IIdentityNames.byHandle.selector);
        _assertLacks(address(new NamesBeforeTheEscrow()), IIdentityNames.acceptsClaims.selector);
        _assertLacks(address(new NamesWithASilentFallback()), IIdentityNames.acceptsClaims.selector);
        _assertLacks(address(new NamesWithoutNodeOfHash()), IIdentityNames.nodeOfHash.selector);
        _assertLacks(address(new NamesWithAZeroFallback()), IIdentityNames.nodeOfHash.selector);
        _assertLacks(address(new NamesWithAConstantNode()), IIdentityNames.nodeOfHash.selector);
        _deploy(address(new NamesWithAnotherNodeDerivation()));

        HandleEscrow impl = new HandleEscrow();
        vm.expectRevert(Initializable.InvalidInitialization.selector);
        impl.initialize(owner, IIdentityNames(address(names)));
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
        (uint256 held, address names_, uint256 round, uint256 open, uint256 appended) =
            upgraded.read(aliceNode, NATIVE, 1, sender);
        (,,, uint256 closed,) = upgraded.read(aliceNode, NATIVE, 0, sender);
        assertEq(held, 1 ether);
        assertEq(names_, address(names));
        assertEq(round, 1);
        assertEq(open, 1 ether);
        assertEq(closed, 1 ether);
        assertEq(appended, 0);
        upgraded.setAppended(7);
        assertEq(escrow.refundable(aliceNode, NATIVE, sender), 1 ether);
    }

    // ─── Helpers ────────────────────────────────────────────────────

    function _deploy(address names_) internal returns (HandleEscrow) {
        return HandleEscrow(
            address(
                new ERC1967Proxy(
                    address(new HandleEscrow()),
                    abi.encodeCall(HandleEscrow.initialize, (owner, IIdentityNames(names_)))
                )
            )
        );
    }

    function _assertLacks(address names_, bytes4 selector) internal {
        _assertRefused(names_, abi.encodeWithSelector(HandleEscrow.NamesLacks.selector, names_, selector));
    }

    function _assertRefused(address names_, bytes memory reason) internal {
        HandleEscrow impl = new HandleEscrow();
        vm.expectRevert(reason);
        new ERC1967Proxy(address(impl), abi.encodeCall(HandleEscrow.initialize, (owner, IIdentityNames(names_))));
    }

    /// Prove `handle` on X for `who`.
    function _bind(address who, string memory userId, string memory handle, uint64 at) internal {
        xVerifier.set(userId, handle);
        xVerifier.setObservedAt(at);
        bytes memory payload = abi.encode(
            StubPlatformVerifier.StubPayload({
                ceremonyVersion: 1,
                operationDomain: keccak256(bytes("libid.claim-identity")),
                authorizationNonce: bytes32(++nonce),
                transactionData: abi.encode(who, uint256(0), address(0))
            })
        );
        vm.prank(who);
        names.claim(X, V1, payload, false);
    }

    /// Deposit native value for text on X, hashed by the naming system.
    function _depositNative(string memory handle, uint256 amount) internal {
        bytes32 handleHash = names.handleHashOf(X, handle);
        vm.prank(sender);
        escrow.deposit{value: amount}(X, handleHash, NATIVE, amount, sender, address(0));
    }

    function _claimNative(address holder, address recipient) internal {
        vm.prank(holder);
        escrow.claim(aliceNode, one(NATIVE), recipient);
    }
}
