// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";

import {
    ReentrancyGuardTransientUpgradeable
} from "@openzeppelin/contracts-upgradeable/utils/ReentrancyGuardTransientUpgradeable.sol";

import {HandleNormalizer} from "../../identity/HandleNormalizer.sol";
import {HandleVectors} from "../../identity/HandleVectors.sol";
import {IdentityNames} from "../../identity/IdentityNames.sol";
import {IdentityNodes} from "../../identity/IdentityNodes.sol";
import {StubPlatformVerifier} from "../../identity/test/StubPlatformVerifier.sol";
import {CeremonyProofVerifier} from "../../ceremony/CeremonyProofVerifier.sol";
import {IPlatformVerifier} from "../../ceremony/IPlatformVerifier.sol";
import {IProofVerifier} from "../../ceremony/IProofVerifier.sol";
import {HandleEscrow} from "../HandleEscrow.sol";
import {IIdentityNames} from "../IIdentityNames.sol";

/// @notice A plain ERC-20 anybody can mint. Test-only: it lives beside the
///         tests so no deploy tool can reach it.
contract TestERC20 is ERC20 {
    constructor(string memory name_, string memory symbol_) ERC20(name_, symbol_) {}

    function mint(address to, uint256 amount) external {
        _mint(to, amount);
    }
}

/// @notice Takes a cut of every transfer, the way a fee-on-transfer token does.
contract FeeToken is TestERC20 {
    uint256 public constant FEE_BPS = 100; // 1%

    constructor() TestERC20("Fee", "FEE") {}

    function transferFrom(address from, address to, uint256 amount) public override returns (bool) {
        uint256 fee = (amount * FEE_BPS) / 10_000;
        _transfer(from, address(0xdead), fee);
        _transfer(from, to, amount - fee);
        _spendAllowance(from, msg.sender, amount);
        return true;
    }
}

/// @notice Reports success and moves nothing.
contract InertToken is TestERC20 {
    constructor() TestERC20("Inert", "NIL") {}

    function transferFrom(address, address, uint256) public pure override returns (bool) {
        return true;
    }
}

/// @notice A second version that APPENDS to the namespaced root, which is the
///         only change the storage rule allows.
///
/// @dev Upgrading to a byte-identical implementation proves nothing about the
///      layout. This adds a field after the existing ones and reads the old
///      ones back, so a reordered or removed field shows up as a wrong balance
///      rather than as a passing test.
contract HandleEscrowV2 is HandleEscrow {
    /// @custom:storage-location erc7201:libid.storage.HandleEscrow
    struct V2Storage {
        mapping(bytes32 => mapping(address => uint256)) held;
        IIdentityNames names;
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

    function appended() external view returns (uint256) {
        return _v2().appended;
    }

    /// Read the pre-existing fields through the V2 layout.
    function heldThroughV2(bytes32 handleNode, address token) external view returns (uint256) {
        return _v2().held[handleNode][token];
    }

    function namesThroughV2() external view returns (address) {
        return address(_v2().names);
    }
}

/// @notice Refuses every native transfer.
contract RejectEther {
    // No receive, no fallback.
}

/// @notice Deposits again from inside its own transfer, the way a token with a
///         receiver hook does, through the same entry point the outer call
///         used.
///
/// @dev This is what the guard on both deposits is for. The credit is the
///      balance the contract GAINED, measured across the transfer — so a
///      transfer that re-enters and deposits again folds the inner deposit's
///      tokens into the outer one's measurement, and the books end up
///      promising more than the contract holds.
contract ReenteringToken is TestERC20 {
    HandleEscrow public escrow;
    bytes32 public platformId;
    bool public viaNode;
    bool private entered;

    constructor() TestERC20("Hook", "HOOK") {}

    function arm(HandleEscrow escrow_, bytes32 platformId_, bool viaNode_) external {
        escrow = escrow_;
        platformId = platformId_;
        viaNode = viaNode_;
        _approve(address(this), address(escrow_), type(uint256).max);
    }

    function transferFrom(address from, address to, uint256 amount) public override returns (bool) {
        bool ok = super.transferFrom(from, to, amount);
        if (!entered && address(escrow) != address(0)) {
            entered = true;
            if (viaNode) {
                escrow.depositToNode(platformId, IdentityNodes.handleNode(platformId, "bob"), address(this), 1 ether);
            } else {
                escrow.depositToHandle(platformId, "bob", address(this), 1 ether);
            }
        }
        return ok;
    }
}

/// @notice Calls `claim` again from inside the native payout.
contract ReenteringClaimer {
    HandleEscrow private immutable ESCROW;
    bytes32 private immutable NODE;
    bool private entered;

    constructor(HandleEscrow escrow_, bytes32 node_) {
        ESCROW = escrow_;
        NODE = node_;
    }

    function take() external {
        ESCROW.claim(NODE, address(0), address(this));
    }

    receive() external payable {
        if (entered) return;
        entered = true;
        ESCROW.claim(NODE, address(0), address(this));
    }
}

/// @notice Claims, and from inside the native payout reads the slot and tries
///         to claim again — without failing the payout, so each of the two
///         defences can be seen on its own.
///
/// @dev `claimAgain` catches the inner claim's refusal and keeps it. A claim
///      that reverted here would fail the outer payout, and the outer revert
///      looks the same whichever defence stopped the second claim.
contract ObservingClaimer {
    HandleEscrow private immutable ESCROW;
    bytes32 private immutable NODE;
    bool private entered;

    /// What `escrowed` answered while this contract was being paid.
    uint256 public seenDuringPayout = type(uint256).max;
    /// Why the second claim was refused. Empty if it was not.
    bytes public reentryError;

    constructor(HandleEscrow escrow_, bytes32 node_) {
        ESCROW = escrow_;
        NODE = node_;
    }

    function take() external {
        ESCROW.claim(NODE, address(0), address(this));
    }

    receive() external payable {
        if (entered) return;
        entered = true;
        seenDuringPayout = ESCROW.escrowed(NODE, address(0));
        try ESCROW.claim(NODE, address(0), address(this)) {}
        catch (bytes memory reason) {
            reentryError = reason;
        }
    }
}

/// @notice The handle-keyed escrow, against the real naming system.
///
/// @dev Wired to a real `IdentityNames` behind its proxy, dispatching through a
///      real `CeremonyProofVerifier`, so a rename and a recycled handle are
///      stageable exactly as they happen. Only the Platform Verifier is the
///      identity suite's stub: what a real one checks has its own suite.
contract HandleEscrowTest is Test {
    IdentityNames internal names;
    CeremonyProofVerifier internal proofVerifier;
    StubPlatformVerifier internal xVerifier;
    StubPlatformVerifier internal githubVerifier;
    HandleEscrow internal escrow;
    TestERC20 internal token;

    bytes32 internal constant X = HandleVectors.PLATFORM_X;
    bytes32 internal constant GITHUB = HandleVectors.PLATFORM_GITHUB;
    bytes32 internal constant GOOGLE = HandleVectors.PLATFORM_GOOGLE;
    bytes32 internal constant UNWIRED = keccak256("no such platform");

    address internal alice = makeAddr("alice");
    address internal bob = makeAddr("bob");
    address internal sender = makeAddr("sender");
    address internal owner = makeAddr("owner");

    uint16 internal constant V1 = 1;
    address internal constant NATIVE = address(0);

    /// The node `alice` keys to on X, computed by the naming system's own
    /// library rather than read out of the escrow.
    bytes32 internal aliceNode = IdentityNodes.handleNode(X, "alice");

    function setUp() public {
        IdentityNames namesImpl = new IdentityNames();
        names = IdentityNames(
            address(new ERC1967Proxy(address(namesImpl), abi.encodeCall(IdentityNames.initialize, (owner))))
        );
        CeremonyProofVerifier pvImpl = new CeremonyProofVerifier();
        proofVerifier = CeremonyProofVerifier(
            address(new ERC1967Proxy(address(pvImpl), abi.encodeCall(CeremonyProofVerifier.initialize, (owner))))
        );
        xVerifier = new StubPlatformVerifier(X, 0);
        githubVerifier = new StubPlatformVerifier(GITHUB, 0);

        // Both platforms usable the way a deployment makes them: a keyspace,
        // and a registered verifier the Proof Verifier answers for. GitHub is
        // never claimed on below, so `verifiesPlatform` is what lets it
        // answer `rulesOf` and accept claims.
        vm.startPrank(owner);
        names.setProofVerifier(IProofVerifier(address(proofVerifier)));
        names.setPlatform(X, HandleVectors.rulesFor(X));
        proofVerifier.setVerifier(X, V1, IPlatformVerifier(address(xVerifier)));
        names.setPlatform(GITHUB, HandleVectors.rulesFor(GITHUB));
        proofVerifier.setVerifier(GITHUB, V1, IPlatformVerifier(address(githubVerifier)));
        vm.stopPrank();

        HandleEscrow escrowImpl = new HandleEscrow();
        escrow = HandleEscrow(
            address(
                new ERC1967Proxy(
                    address(escrowImpl),
                    abi.encodeCall(HandleEscrow.initialize, (owner, IIdentityNames(address(names))))
                )
            )
        );

        token = new TestERC20("Token", "TKN");
        token.mint(sender, 1_000 ether);
        vm.prank(sender);
        token.approve(address(escrow), type(uint256).max);

        vm.deal(sender, 100 ether);
        vm.warp(1_000_000);
    }

    /// A digest is spendable once, so every claim needs a nonce of its own.
    uint256 private nonce;

    /// Prove `handle` on X for `who`, the way a login does.
    ///
    /// @dev The stub is staged and the payload built BEFORE the prank: `vm.prank`
    ///      is spent on the next external call, and it has to be the claim.
    function _bind(address who, string memory userId, string memory handle, uint64 at) internal {
        xVerifier.set(userId, handle);
        xVerifier.setObservedAt(at);
        bytes memory payload = abi.encode(
            StubPlatformVerifier.StubPayload({
                ceremonyVersion: 1,
                // A literal, not `names.CLAIM_IDENTITY_DOMAIN()`: reading it
                // would be one more external call to keep the prank off.
                operationDomain: keccak256(bytes("libid.claim-identity")),
                authorizationNonce: bytes32(++nonce),
                // The free shape: a ceremony composed by hand names no fee.
                transactionData: abi.encode(who, uint256(0), address(0))
            })
        );
        vm.prank(who);
        names.claim(X, V1, payload, false);
    }

    function _depositNative(string memory handle, uint256 amount) internal {
        vm.prank(sender);
        escrow.depositToHandle{value: amount}(X, handle, NATIVE, amount);
    }

    function _nodeX(string memory normalized) internal pure returns (bytes32) {
        return IdentityNodes.handleNode(X, normalized);
    }

    // ─── The key ────────────────────────────────────────────────────

    /// The lemma the whole design rests on: the escrow keys every handle on
    /// the node the naming system binds it under. For every accepted row of
    /// the shared table, the node the escrow derives from the RAW input is
    /// `IdentityNodes.handleNode` of the table's normalized output; every
    /// refused row is refused with the table's reason. All rows run, none is
    /// skipped, and the count is checked.
    function test_everyVectorRowKeysOnTheNamingSystemsNode() public {
        // Google is wired here only: elsewhere in this suite it stands for a
        // platform that cannot verify yet.
        StubPlatformVerifier googleVerifier = new StubPlatformVerifier(GOOGLE, 0);
        vm.startPrank(owner);
        names.setPlatform(GOOGLE, HandleVectors.rulesFor(GOOGLE));
        proofVerifier.setVerifier(GOOGLE, V1, IPlatformVerifier(address(googleVerifier)));
        vm.stopPrank();

        HandleVectors.Vector[] memory vectors = HandleVectors.all();
        uint256 accepted;
        uint256 refused;
        for (uint256 i = 0; i < vectors.length; i++) {
            HandleVectors.Vector memory v = vectors[i];
            bytes32 platformId = _platformIdFor(v.platform);

            if (v.accepted) {
                assertEq(
                    escrow.nodeOf(platformId, v.input),
                    IdentityNodes.handleNode(platformId, v.output),
                    string.concat("vector ", vm.toString(i), " keys off the naming system's node")
                );
                accepted++;
            } else {
                // `Problem` is the table's error kind shifted by one: `None`
                // takes zero.
                vm.expectRevert(
                    abi.encodeWithSelector(
                        HandleEscrow.UnusableHandle.selector, HandleNormalizer.Problem(v.errorKind + 1)
                    )
                );
                escrow.nodeOf(platformId, v.input);
                refused++;
            }
        }
        assertEq(accepted + refused, vectors.length, "a row was skipped");
        assertGt(accepted, 0, "the table has no accepted rows");
        assertGt(refused, 0, "the table has no refused rows");
    }

    /// A literal, so Rust and TypeScript cannot compute a different key and
    /// still pass their own tests.
    ///
    /// Computed with `cast`, not read out of this contract:
    ///   keccak256(abi.encode(keccak256("libid.identity.handle-node.v1"),
    ///                        keccak256("x"),
    ///                        keccak256("alice_1")))
    function test_theNodeDerivationIsPinned() public view {
        bytes32 pinned = 0x1c43d5d3cf3d99e9d5b6e8c74c23d14bcbb6a743712cf7fa7c15750c4fc2150d;
        assertEq(escrow.nodeOf(X, " Alice_1 "), pinned);
        assertEq(IdentityNodes.handleNode(X, "alice_1"), pinned);
    }

    /// The node the escrow keys on is the one the naming system binds: a
    /// claim of the handle makes `byHandle` of the escrow's node answer with
    /// the claimer.
    function test_theEscrowsNodeIsTheOneTheNamingSystemBinds() public {
        _bind(alice, "1", "Alice_1", 100);

        (address holder,) = names.byHandle(escrow.nodeOf(X, "@alice_1"));
        assertEq(holder, alice);
    }

    /// X strips a leading at-sign, so both spellings are one handle there and
    /// reach one slot.
    function test_aLeadingAtSignFoldsWhereThePlatformStripsIt() public {
        assertEq(escrow.nodeOf(X, "@alice"), aliceNode);
        assertEq(escrow.nodeOf(X, "  @Alice  "), aliceNode);

        vm.startPrank(sender);
        escrow.depositToHandle{value: 1 ether}(X, "@alice", NATIVE, 1 ether);
        escrow.depositToHandle{value: 2 ether}(X, "alice", NATIVE, 2 ether);
        vm.stopPrank();
        assertEq(escrow.escrowed(aliceNode, NATIVE), 3 ether);
    }

    /// Text with nothing left after trimming and the at-sign has no node.
    function test_aBareAtSignHasNoNode() public {
        vm.expectRevert(abi.encodeWithSelector(HandleEscrow.UnusableHandle.selector, HandleNormalizer.Problem.Empty));
        escrow.nodeOf(X, " @ ");
    }

    function test_textWithNothingInItHasNoNode() public {
        vm.expectRevert(abi.encodeWithSelector(HandleEscrow.UnusableHandle.selector, HandleNormalizer.Problem.Empty));
        escrow.nodeOf(X, "   ");
    }

    function test_anUnwiredPlatformHasNoNode() public {
        vm.expectRevert(abi.encodeWithSelector(IdentityNames.UnknownPlatform.selector, UNWIRED));
        escrow.nodeOf(UNWIRED, "alice");
    }

    /// Different platforms are different keyspaces, so the same text on two of
    /// them is two slots.
    function test_theNodeIsPerPlatform() public view {
        assertTrue(escrow.nodeOf(X, "alice") != escrow.nodeOf(GITHUB, "alice"));
    }

    /// The platform id is load-bearing in the key, not decoration: the same
    /// text on two platforms is two different people, and their money must not
    /// meet. Proving it on one platform reaches only that one's slot.
    function test_theSameTextOnTwoPlatformsIsTwoEscrows() public {
        vm.startPrank(sender);
        escrow.depositToHandle{value: 1 ether}(X, "alice", NATIVE, 1 ether);
        escrow.depositToHandle{value: 2 ether}(GITHUB, "alice", NATIVE, 2 ether);
        vm.stopPrank();
        bytes32 githubNode = IdentityNodes.handleNode(GITHUB, "alice");

        _bind(alice, "1", "alice", 100); // on X only

        vm.prank(alice);
        escrow.claim(aliceNode, NATIVE, alice);
        assertEq(alice.balance, 1 ether);

        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(HandleEscrow.NotTheHolder.selector, address(0), alice));
        escrow.claim(githubNode, NATIVE, alice);

        assertEq(escrow.escrowed(githubNode, NATIVE), 2 ether, "the other platform's escrow moved");
    }

    // ─── Depositing ─────────────────────────────────────────────────

    function test_depositHoldsNativeAgainstTheHandle() public {
        _depositNative("alice", 1 ether);

        assertEq(escrow.escrowed(aliceNode, NATIVE), 1 ether);
        assertEq(address(escrow).balance, 1 ether);
    }

    function test_depositHoldsTokensAgainstTheHandle() public {
        vm.prank(sender);
        escrow.depositToHandle(X, "alice", address(token), 10 ether);

        assertEq(escrow.escrowed(aliceNode, address(token)), 10 ether);
        assertEq(token.balanceOf(address(escrow)), 10 ether);
    }

    /// Two spellings of one handle land in one slot and add up.
    function test_spellingsOfOneHandleAccumulate() public {
        _depositNative("alice", 1 ether);
        _depositNative(" ALICE ", 2 ether);

        assertEq(escrow.escrowed(aliceNode, NATIVE), 3 ether);
    }

    /// A deposit by text and a deposit by node reach one slot: the one
    /// `IdentityNodes.handleNode` names for the normalized handle.
    function test_aDepositByNodeLandsWhereTheTextDoes() public {
        _depositNative(" Alice ", 1 ether);
        vm.prank(sender);
        escrow.depositToNode{value: 2 ether}(X, aliceNode, NATIVE, 2 ether);

        assertEq(escrow.escrowed(aliceNode, NATIVE), 3 ether);
        assertEq(address(escrow).balance, 3 ether);
    }

    function test_aDepositByNodeHoldsTokens() public {
        vm.prank(sender);
        escrow.depositToNode(X, aliceNode, address(token), 10 ether);

        assertEq(escrow.escrowed(aliceNode, address(token)), 10 ether);
        assertEq(token.balanceOf(address(escrow)), 10 ether);
    }

    /// The books must never promise more than the contract holds.
    function test_aFeeOnTransferTokenCreditsWhatArrived() public {
        FeeToken fee = new FeeToken();
        fee.mint(sender, 100 ether);
        vm.startPrank(sender);
        fee.approve(address(escrow), type(uint256).max);
        escrow.depositToHandle(X, "alice", address(fee), 100 ether);
        vm.stopPrank();

        assertEq(escrow.escrowed(aliceNode, address(fee)), 99 ether, "credited more than arrived");
        assertEq(fee.balanceOf(address(escrow)), 99 ether);
    }

    /// A handle nobody holds yet is the whole point.
    function test_depositingForAnUnclaimedHandleIsFine() public {
        assertEq(names.resolveHandle(X, "nobody"), address(0));
        _depositNative("nobody", 1 ether);
        assertEq(escrow.escrowed(_nodeX("nobody"), NATIVE), 1 ether);
    }

    /// The escrow exists for the window before a handle is claimed. Once it
    /// resolves, holding the value would only add a claim transaction to reach
    /// the same wallet, so the deposit is a payment.
    function test_depositForAHeldHandleIsPaidStraightThrough() public {
        _bind(alice, "1", "alice", 100);

        uint256 before = alice.balance;
        _depositNative("alice", 1 ether);

        assertEq(alice.balance, before + 1 ether, "the holder was not paid");
        assertEq(escrow.escrowed(aliceNode, NATIVE), 0, "the value was escrowed instead");
        assertEq(address(escrow).balance, 0, "the escrow kept it");
    }

    function test_aDepositByNodeForAHeldHandleIsPaidStraightThrough() public {
        _bind(alice, "1", "alice", 100);

        vm.prank(sender);
        escrow.depositToNode(X, aliceNode, address(token), 10 ether);

        assertEq(token.balanceOf(alice), 10 ether, "the holder was not paid");
        assertEq(escrow.escrowed(aliceNode, address(token)), 0, "the value was escrowed instead");
    }

    function test_aForwardedDepositIsAnnouncedAsSuch() public {
        _bind(alice, "1", "alice", 100);

        vm.expectEmit(true, true, true, true, address(escrow));
        emit HandleEscrow.Forwarded(aliceNode, NATIVE, sender, alice, X, 1 ether);
        vm.prank(sender);
        escrow.depositToHandle{value: 1 ether}(X, "alice", NATIVE, 1 ether);
    }

    function test_tokensForAHeldHandleGoStraightToTheHolder() public {
        _bind(alice, "1", "alice", 100);

        vm.prank(sender);
        escrow.depositToHandle(X, "alice", address(token), 10 ether);

        assertEq(token.balanceOf(alice), 10 ether, "the holder was not paid");
        assertEq(token.balanceOf(address(escrow)), 0, "the escrow kept tokens");
        assertEq(escrow.escrowed(aliceNode, address(token)), 0);
    }

    /// The price of paying through: the call depends on the recipient. Failing
    /// is the honest outcome — the sender learns, instead of the value waiting
    /// in a slot only that same wallet could ever claim.
    function test_aHolderThatCannotReceiveFailsTheDeposit() public {
        address rejector = address(new RejectEther());
        _bind(rejector, "1", "alice", 100);

        vm.prank(sender);
        vm.expectRevert(abi.encodeWithSelector(HandleEscrow.NativeTransferFailed.selector, rejector, 1 ether));
        escrow.depositToHandle{value: 1 ether}(X, "alice", NATIVE, 1 ether);
    }

    /// The window the escrow is for: deposit while unclaimed, and the same
    /// handle pays through once it is claimed.
    function test_theSameHandleEscrowsThenPaysThrough() public {
        _depositNative("alice", 1 ether);
        assertEq(escrow.escrowed(aliceNode, NATIVE), 1 ether);

        _bind(alice, "1", "alice", 100);

        uint256 before = alice.balance;
        _depositNative("alice", 2 ether);
        assertEq(alice.balance, before + 2 ether, "the second deposit did not pay through");
        // The first one still waits for its claim.
        assertEq(escrow.escrowed(aliceNode, NATIVE), 1 ether, "the waiting balance moved");
    }

    function test_aDepositOfNothingIsRefused() public {
        vm.startPrank(sender);
        vm.expectRevert(HandleEscrow.ZeroAmount.selector);
        escrow.depositToHandle(X, "alice", NATIVE, 0);
        vm.expectRevert(HandleEscrow.ZeroAmount.selector);
        escrow.depositToNode(X, aliceNode, NATIVE, 0);
        vm.stopPrank();
    }

    function test_nativeValueMustEqualTheAmount() public {
        vm.startPrank(sender);
        vm.expectRevert(abi.encodeWithSelector(HandleEscrow.ValueMismatch.selector, 2 ether, 1 ether));
        escrow.depositToHandle{value: 1 ether}(X, "alice", NATIVE, 2 ether);
        vm.expectRevert(abi.encodeWithSelector(HandleEscrow.ValueMismatch.selector, 2 ether, 1 ether));
        escrow.depositToNode{value: 1 ether}(X, aliceNode, NATIVE, 2 ether);
        vm.stopPrank();
    }

    /// Ether sent alongside a token deposit has no slot to land in.
    function test_aTokenDepositCarriesNoValue() public {
        vm.startPrank(sender);
        vm.expectRevert(abi.encodeWithSelector(HandleEscrow.ValueMismatch.selector, 0, 1 ether));
        escrow.depositToHandle{value: 1 ether}(X, "alice", address(token), 10 ether);
        vm.expectRevert(abi.encodeWithSelector(HandleEscrow.ValueMismatch.selector, 0, 1 ether));
        escrow.depositToNode{value: 1 ether}(X, aliceNode, address(token), 10 ether);
        vm.stopPrank();
    }

    /// A mistyped platform id takes nobody's money. By text the naming system
    /// refuses to normalize for it; by node there is nothing to normalize, and
    /// the claim gate refuses instead.
    function test_anUnwiredPlatformIsRefused() public {
        vm.startPrank(sender);
        vm.expectRevert(abi.encodeWithSelector(IdentityNames.UnknownPlatform.selector, UNWIRED));
        escrow.depositToHandle{value: 1 ether}(UNWIRED, "alice", NATIVE, 1 ether);
        vm.expectRevert(abi.encodeWithSelector(HandleEscrow.PlatformAcceptsNoClaims.selector, UNWIRED));
        escrow.depositToNode{value: 1 ether}(UNWIRED, IdentityNodes.handleNode(UNWIRED, "alice"), NATIVE, 1 ether);
        vm.stopPrank();
    }

    /// A platform with a keyspace and no way to verify is not wired yet: no
    /// proof could claim what it would hold, so it takes nobody's money
    /// either, by text or by node.
    function test_aPlatformThatCannotVerifyYetIsRefused() public {
        vm.prank(owner);
        names.setPlatform(GOOGLE, HandleVectors.rulesFor(GOOGLE));

        vm.startPrank(sender);
        vm.expectRevert(abi.encodeWithSelector(IdentityNames.UnknownPlatform.selector, GOOGLE));
        escrow.depositToHandle{value: 1 ether}(GOOGLE, "alice@example.com", NATIVE, 1 ether);
        bytes32 node = IdentityNodes.handleNode(GOOGLE, "alice@example.com");
        vm.expectRevert(abi.encodeWithSelector(HandleEscrow.PlatformAcceptsNoClaims.selector, GOOGLE));
        escrow.depositToNode{value: 1 ether}(GOOGLE, node, NATIVE, 1 ether);
        vm.stopPrank();
    }

    /// Escrowing needs a claim that could ever take the value; paying a holder
    /// does not. A platform whose every version was retired still resolves
    /// the names bound on it, so its holders are still paid — but nothing new
    /// can bind there, and an unheld handle would hold value forever.
    function test_aPlatformThatAcceptsNoClaimsPaysHoldersButDoesNotEscrow() public {
        _depositNative("alice", 1 ether);
        _bind(alice, "1", "alice", 100);

        vm.prank(owner);
        proofVerifier.setVerifier(X, V1, IPlatformVerifier(address(0)));
        assertFalse(names.acceptsClaims(X), "the staging is wrong");

        // The holder is paid through, by text and by node.
        uint256 before = alice.balance;
        _depositNative("alice", 2 ether);
        vm.prank(sender);
        escrow.depositToNode{value: 3 ether}(X, aliceNode, NATIVE, 3 ether);
        assertEq(alice.balance, before + 5 ether, "the holder was not paid");

        // Nobody holds bob, and nothing could bind him now.
        bytes32 bobNode = _nodeX("bob");
        vm.startPrank(sender);
        vm.expectRevert(abi.encodeWithSelector(HandleEscrow.PlatformAcceptsNoClaims.selector, X));
        escrow.depositToHandle{value: 1 ether}(X, "bob", NATIVE, 1 ether);
        vm.expectRevert(abi.encodeWithSelector(HandleEscrow.PlatformAcceptsNoClaims.selector, X));
        escrow.depositToNode(X, bobNode, address(token), 1 ether);
        vm.stopPrank();
        assertEq(token.balanceOf(address(escrow)), 0, "tokens were pulled before the gate");

        // What was already held is still the holder's to take.
        vm.prank(alice);
        escrow.claim(aliceNode, NATIVE, alice);
        assertEq(escrow.escrowed(aliceNode, NATIVE), 0);
    }

    /// The reason `rulesOf` exists. Text this platform could never accept would
    /// otherwise fund a slot no proof can ever claim, and there is no refund.
    function test_aHandleThePlatformCouldNeverAcceptIsRefused() public {
        vm.startPrank(sender);

        // A space inside is not a handle on X.
        vm.expectRevert(abi.encodeWithSelector(HandleEscrow.UnusableHandle.selector, HandleNormalizer.Problem.BadChar));
        escrow.depositToHandle{value: 1 ether}(X, "ali ce", NATIVE, 1 ether);

        // A hyphen is GitHub's, not X's.
        vm.expectRevert(abi.encodeWithSelector(HandleEscrow.UnusableHandle.selector, HandleNormalizer.Problem.BadChar));
        escrow.depositToHandle{value: 1 ether}(X, "ali-ce", NATIVE, 1 ether);

        // Past X's length.
        vm.expectRevert(abi.encodeWithSelector(HandleEscrow.UnusableHandle.selector, HandleNormalizer.Problem.TooLong));
        escrow.depositToHandle{value: 1 ether}(X, "a123456789012345", NATIVE, 1 ether);

        vm.stopPrank();
    }

    /// NOT a vulnerability. A node is a hash and cannot be checked: one that
    /// is not the node of any handle escrows, and nothing can ever claim it.
    /// That is the price of an entry point that never sees the handle, and it
    /// is why the SDK derives the node rather than a user typing one.
    function test_ACCEPTED_aNodeNoHandleReachesEscrowsForNobody() public {
        bytes32 garbage = keccak256("not the node of any handle");

        vm.prank(sender);
        escrow.depositToNode{value: 1 ether}(X, garbage, NATIVE, 1 ether);
        assertEq(escrow.escrowed(garbage, NATIVE), 1 ether);

        vm.prank(sender);
        vm.expectRevert(abi.encodeWithSelector(HandleEscrow.NotTheHolder.selector, address(0), sender));
        escrow.claim(garbage, NATIVE, sender);
    }

    // ─── Claiming ───────────────────────────────────────────────────

    function test_theHolderTakesWhatIsHeld() public {
        _depositNative("alice", 1 ether);
        _bind(alice, "1", "alice", 100);

        vm.prank(alice);
        escrow.claim(aliceNode, NATIVE, alice);

        assertEq(alice.balance, 1 ether);
        assertEq(escrow.escrowed(aliceNode, NATIVE), 0);
        assertEq(address(escrow).balance, 0);
    }

    /// The claimer names where it goes, so a wallet that holds the name can pay
    /// out somewhere else.
    function test_theClaimerChoosesTheRecipient() public {
        _depositNative("alice", 1 ether);
        _bind(alice, "1", "alice", 100);

        vm.prank(alice);
        escrow.claim(aliceNode, NATIVE, bob);

        assertEq(bob.balance, 1 ether);
        assertEq(alice.balance, 0);
    }

    function test_aClaimTakesOnlyTheTokenItNames() public {
        _depositNative("alice", 1 ether);
        vm.prank(sender);
        escrow.depositToHandle(X, "alice", address(token), 10 ether);
        _bind(alice, "1", "alice", 100);

        vm.prank(alice);
        escrow.claim(aliceNode, NATIVE, alice);

        assertEq(escrow.escrowed(aliceNode, NATIVE), 0);
        assertEq(escrow.escrowed(aliceNode, address(token)), 10 ether, "the token balance moved too");
    }

    function test_somebodyElseCannotClaim() public {
        _depositNative("alice", 1 ether);
        _bind(alice, "1", "alice", 100);

        vm.prank(bob);
        vm.expectRevert(abi.encodeWithSelector(HandleEscrow.NotTheHolder.selector, alice, bob));
        escrow.claim(aliceNode, NATIVE, bob);
    }

    /// Nobody holds it yet, so nobody can take it. The value waits.
    function test_anUnclaimedHandleCannotBeDrained() public {
        _depositNative("alice", 1 ether);

        vm.prank(bob);
        vm.expectRevert(abi.encodeWithSelector(HandleEscrow.NotTheHolder.selector, address(0), bob));
        escrow.claim(aliceNode, NATIVE, bob);

        assertEq(escrow.escrowed(aliceNode, NATIVE), 1 ether);
    }

    function test_claimingAnEmptySlotIsRefused() public {
        _bind(alice, "1", "alice", 100);

        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(HandleEscrow.NothingHeld.selector, aliceNode, NATIVE));
        escrow.claim(aliceNode, NATIVE, alice);
    }

    function test_aRecipientThatRefusesNativeValueFailsTheClaim() public {
        _depositNative("alice", 1 ether);
        _bind(alice, "1", "alice", 100);
        address rejector = address(new RejectEther());

        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(HandleEscrow.NativeTransferFailed.selector, rejector, 1 ether));
        escrow.claim(aliceNode, NATIVE, rejector);
    }

    /// A token that calls back inside its own transfer would otherwise have the
    /// outer deposit credit the inner deposit's tokens as well — two slots
    /// funded by one transfer, and more promised than held.
    function test_aTokenThatReentersDepositToHandleIsRefused() public {
        _assertReentryRefused(false);
    }

    /// The same, through the node entry point: each deposit carries its own
    /// guard.
    function test_aTokenThatReentersDepositToNodeIsRefused() public {
        _assertReentryRefused(true);
    }

    function _assertReentryRefused(bool viaNode) internal {
        ReenteringToken hook = new ReenteringToken();
        hook.mint(sender, 100 ether);
        hook.mint(address(hook), 10 ether);
        hook.arm(escrow, X, viaNode);

        vm.startPrank(sender);
        hook.approve(address(escrow), type(uint256).max);
        // The guard specifically, not any revert: a mis-staged token or a
        // missing approval would also revert and would also look green.
        vm.expectRevert(
            abi.encodeWithSelector(ReentrancyGuardTransientUpgradeable.ReentrancyGuardReentrantCall.selector)
        );
        if (viaNode) {
            escrow.depositToNode(X, aliceNode, address(hook), 100 ether);
        } else {
            escrow.depositToHandle(X, "alice", address(hook), 100 ether);
        }
        vm.stopPrank();

        assertEq(escrow.escrowed(aliceNode, address(hook)), 0);
        assertEq(escrow.escrowed(_nodeX("bob"), address(hook)), 0);
        assertEq(hook.balanceOf(address(escrow)), 0, "the escrow kept tokens it never credited");
    }

    /// The payout is an external call to an address the claimer chose.
    ///
    /// Somebody else's escrow is funded alongside, and that is the point: a
    /// second drain is only observable when the contract holds more than the
    /// claimed slot. Without it, the second transfer runs out of balance and
    /// fails for a reason that has nothing to do with reentrancy.
    function test_aReenteringClaimerCannotDrainTwice() public {
        ReenteringClaimer claimer = new ReenteringClaimer(escrow, aliceNode);
        _depositNative("alice", 1 ether);
        _depositNative("bob", 1 ether); // not the claimer's
        _bind(address(claimer), "1", "alice", 100);

        vm.expectRevert(abi.encodeWithSelector(HandleEscrow.NativeTransferFailed.selector, address(claimer), 1 ether));
        claimer.take();

        assertEq(escrow.escrowed(aliceNode, NATIVE), 1 ether, "the slot was drained");
        assertEq(escrow.escrowed(_nodeX("bob"), NATIVE), 1 ether, "somebody else's escrow moved");
        assertEq(address(escrow).balance, 2 ether);
        assertEq(address(claimer).balance, 0, "the claimer took anything at all");
    }

    /// The two defences of the payout, each observable alone. The slot reads
    /// empty while the payout runs, so the books are settled before the
    /// external call; and a second claim from inside it is refused by the
    /// reentrancy guard itself, not by the empty slot behind it.
    function test_aClaimSettlesTheSlotBeforePayingAndTheGuardRefusesReentry() public {
        ObservingClaimer claimer = new ObservingClaimer(escrow, aliceNode);
        _depositNative("alice", 1 ether);
        _depositNative("bob", 1 ether); // not the claimer's
        _bind(address(claimer), "1", "alice", 100);

        claimer.take();

        assertEq(claimer.seenDuringPayout(), 0, "the slot still read full while its payout ran");
        assertEq(
            claimer.reentryError(),
            abi.encodeWithSelector(ReentrancyGuardTransientUpgradeable.ReentrancyGuardReentrantCall.selector),
            "the second claim was not refused by the guard"
        );
        assertEq(address(claimer).balance, 1 ether, "the claimer was paid other than once");
        assertEq(escrow.escrowed(_nodeX("bob"), NATIVE), 1 ether, "somebody else's escrow moved");
        assertEq(address(escrow).balance, 1 ether);
    }

    /// A payout to nobody is not a payout. The zero address ACCEPTS a native
    /// transfer, so without this the slot would be emptied, the value burned
    /// and `Claimed` would report success.
    function test_aClaimToNobodyIsRefused() public {
        _depositNative("alice", 1 ether);
        _bind(alice, "1", "alice", 100);

        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(HandleEscrow.BadRecipient.selector, address(0)));
        escrow.claim(aliceNode, NATIVE, address(0));

        assertEq(escrow.escrowed(aliceNode, NATIVE), 1 ether, "the slot was emptied");
        assertEq(address(0).balance, 0, "value was burned");
    }

    /// A payout to this contract would zero the books and leave the value here
    /// as surplus no slot points at — unreachable, with no refund and no owner
    /// lever.
    function test_aClaimBackIntoTheEscrowIsRefused() public {
        vm.prank(sender);
        escrow.depositToHandle(X, "alice", address(token), 10 ether);
        _bind(alice, "1", "alice", 100);

        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(HandleEscrow.BadRecipient.selector, address(escrow)));
        escrow.claim(aliceNode, address(token), address(escrow));

        assertEq(escrow.escrowed(aliceNode, address(token)), 10 ether);
        assertEq(token.balanceOf(address(escrow)), 10 ether);
    }

    /// The ERC-20 payout branch, which no other test reaches: every other
    /// claim in this suite takes the native token.
    function test_aTokenClaimPaysTheRecipient() public {
        vm.prank(sender);
        escrow.depositToHandle(X, "alice", address(token), 10 ether);
        _bind(alice, "1", "alice", 100);

        vm.prank(alice);
        escrow.claim(aliceNode, address(token), bob);

        assertEq(token.balanceOf(bob), 10 ether, "the recipient was not paid");
        assertEq(token.balanceOf(address(escrow)), 0, "the escrow kept tokens");
        assertEq(escrow.escrowed(aliceNode, address(token)), 0);
    }

    /// The payloads an indexer reads. None carries the handle's text: the
    /// node is what joins these to `IdentityBound.handleNode`.
    function test_depositAndClaimAnnounceTheirPayloads() public {
        vm.expectEmit(true, true, true, true, address(escrow));
        emit HandleEscrow.Deposited(aliceNode, NATIVE, sender, X, 1 ether);
        vm.prank(sender);
        escrow.depositToHandle{value: 1 ether}(X, "alice", NATIVE, 1 ether);

        vm.expectEmit(true, true, true, true, address(escrow));
        emit HandleEscrow.Deposited(aliceNode, NATIVE, sender, X, 2 ether);
        vm.prank(sender);
        escrow.depositToNode{value: 2 ether}(X, aliceNode, NATIVE, 2 ether);

        _bind(alice, "1", "alice", 100);

        vm.expectEmit(true, true, true, true, address(escrow));
        emit HandleEscrow.Claimed(aliceNode, NATIVE, alice, bob, 3 ether);
        vm.prank(alice);
        escrow.claim(aliceNode, NATIVE, bob);
    }

    /// A fee-on-transfer token delivers less than was asked for, and the event
    /// is the only record of a payment that never entered the books.
    function test_aForwardedPaymentReportsWhatArrived() public {
        FeeToken fee = new FeeToken();
        fee.mint(sender, 100 ether);
        _bind(alice, "1", "alice", 100);

        vm.startPrank(sender);
        fee.approve(address(escrow), type(uint256).max);
        vm.expectEmit(true, true, true, true, address(escrow));
        emit HandleEscrow.Forwarded(aliceNode, address(fee), sender, alice, X, 99 ether);
        escrow.depositToHandle(X, "alice", address(fee), 100 ether);
        vm.stopPrank();

        assertEq(fee.balanceOf(alice), 99 ether, "the holder received something else");
    }

    /// A holder paying itself a fee-on-transfer token ends with LESS than it
    /// started with: the fee left, and what arrived was its own. Measuring
    /// that as `after - before` underflows. Nothing was delivered, so the
    /// deposit is refused as one of nothing.
    function test_aHolderPayingItselfAFeeTokenIsRefused() public {
        _bind(alice, "1", "alice", 100);
        FeeToken fee = new FeeToken();
        fee.mint(alice, 100 ether);

        vm.startPrank(alice);
        fee.approve(address(escrow), type(uint256).max);
        vm.expectRevert(HandleEscrow.ZeroAmount.selector);
        escrow.depositToHandle(X, "alice", address(fee), 100 ether);
        vm.stopPrank();

        assertEq(fee.balanceOf(alice), 100 ether, "the refused deposit still cost the fee");
    }

    /// A plain token paid by its holder to itself moves nothing, and a
    /// `Forwarded` of zero would record a payment that never happened.
    function test_aHolderPayingItselfIsRefused() public {
        _bind(alice, "1", "alice", 100);
        token.mint(alice, 10 ether);

        vm.startPrank(alice);
        token.approve(address(escrow), type(uint256).max);
        vm.expectRevert(HandleEscrow.ZeroAmount.selector);
        escrow.depositToHandle(X, "alice", address(token), 10 ether);
        vm.stopPrank();
    }

    /// A token that reports success and moves nothing credits nothing when it
    /// escrows, and delivers nothing when it pays through. Both are refused.
    function test_aTokenThatDeliversNothingIsRefused() public {
        InertToken inert = new InertToken();

        vm.startPrank(sender);
        vm.expectRevert(HandleEscrow.ZeroAmount.selector);
        escrow.depositToHandle(X, "alice", address(inert), 10 ether);
        vm.stopPrank();
        assertEq(escrow.escrowed(aliceNode, address(inert)), 0);

        _bind(alice, "1", "alice", 100);
        vm.prank(sender);
        vm.expectRevert(HandleEscrow.ZeroAmount.selector);
        escrow.depositToNode(X, aliceNode, address(inert), 10 ether);
    }

    // ─── Consequences accepted on purpose ───────────────────────────

    /// NOT a vulnerability. The escrow is keyed by the handle and nothing else,
    /// so a platform that frees a handle and gives it to somebody new hands the
    /// new holder whatever accumulated for the old one. This is the decision,
    /// and this test exists so changing it fails here.
    function test_ACCEPTED_aRecycledHandlePaysTheNewHolder() public {
        // Escrowed while nobody held it, and never claimed.
        _depositNative("alice", 1 ether);
        _bind(alice, "1", "alice", 100);

        // The platform frees the handle: alice renames away, bob's account
        // takes it.
        _bind(alice, "1", "alice2", 200);
        _bind(bob, "2", "alice", 300);

        vm.prank(bob);
        escrow.claim(aliceNode, NATIVE, bob);

        assertEq(bob.balance, 1 ether, "the new holder did not receive it");
    }

    /// NOT a vulnerability. Between a rename and the next proof of the freed
    /// handle, the handle has no holder and the slot waits — including
    /// against the account that just renamed away from it.
    function test_ACCEPTED_aRenamedAwayHandleIsClaimableByNobody() public {
        _depositNative("alice", 1 ether);
        _bind(alice, "1", "alice", 100);
        _bind(alice, "1", "alice2", 200);

        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(HandleEscrow.NotTheHolder.selector, address(0), alice));
        escrow.claim(aliceNode, NATIVE, alice);

        // And it did not follow the account to its new name.
        assertEq(escrow.escrowed(_nodeX("alice2"), NATIVE), 0, "the balance followed the account");
        assertEq(escrow.escrowed(aliceNode, NATIVE), 1 ether);
    }

    /// NOT a vulnerability. A deposit is a gift to a name, so the sender has no
    /// way back. There is no deadline and no refund by decision.
    function test_ACCEPTED_theDepositorCannotTakeItBack() public {
        _depositNative("alice", 1 ether);

        vm.prank(sender);
        vm.expectRevert(abi.encodeWithSelector(HandleEscrow.NotTheHolder.selector, address(0), sender));
        escrow.claim(aliceNode, NATIVE, sender);

        assertEq(escrow.escrowed(aliceNode, NATIVE), 1 ether);
    }

    /// The owner is not a way in either: there is no owner function that moves
    /// a balance, and being the owner does not make it the holder.
    function test_theOwnerCannotTakeADeposit() public {
        _depositNative("alice", 1 ether);

        vm.prank(owner);
        vm.expectRevert(abi.encodeWithSelector(HandleEscrow.NotTheHolder.selector, address(0), owner));
        escrow.claim(aliceNode, NATIVE, owner);
    }

    /// A claim reads the holder of the node and nothing else, so the
    /// platform's current rules play no part in it. The owner narrowing X
    /// after a handle was bound refuses that handle's TEXT from then on — by
    /// `nodeOf`, by a text deposit and by `resolveHandle` — but the binding
    /// still sits on its node, and its holder still claims and is still paid
    /// through by node.
    function test_aRulesChangeDoesNotStopTheHolderClaiming() public {
        _depositNative("alice_9", 1 ether);
        bytes32 node = _nodeX("alice_9");
        _bind(alice, "1", "alice_9", 100);

        // The owner narrows X: no underscore any more.
        vm.prank(owner);
        names.setPlatform(
            X,
            HandleNormalizer.Rules({
                maxLength: 15, stripLeadingAt: true, isEmail: false, allowUnderscore: false, allowHyphen: false
            })
        );

        // The text is refused everywhere text is read.
        assertEq(names.resolveHandle(X, "alice_9"), address(0));
        vm.expectRevert(abi.encodeWithSelector(HandleEscrow.UnusableHandle.selector, HandleNormalizer.Problem.BadChar));
        escrow.nodeOf(X, "alice_9");
        vm.prank(sender);
        vm.expectRevert(abi.encodeWithSelector(HandleEscrow.UnusableHandle.selector, HandleNormalizer.Problem.BadChar));
        escrow.depositToHandle{value: 1 ether}(X, "alice_9", NATIVE, 1 ether);

        // The node is untouched: still held, still funded.
        (address holder,) = names.byHandle(node);
        assertEq(holder, alice, "the binding moved");
        assertEq(escrow.escrowed(node, NATIVE), 1 ether, "the value moved");

        // Paid through by node, and the holder claims what waited.
        vm.prank(sender);
        escrow.depositToNode{value: 2 ether}(X, node, NATIVE, 2 ether);
        vm.prank(alice);
        escrow.claim(node, NATIVE, alice);
        assertEq(alice.balance, 3 ether);
        assertEq(escrow.escrowed(node, NATIVE), 0);
    }

    // ─── Wiring ─────────────────────────────────────────────────────

    /// Repointing it would redirect every entitlement held, so there is no
    /// setter. Moving it is an upgrade, which leaves a record.
    function test_theNamingContractIsReadableAndHasNoSetter() public view {
        assertEq(address(escrow.names()), address(names));
    }

    function test_initializeRefusesAZeroNamingContract() public {
        HandleEscrow impl = new HandleEscrow();
        vm.expectRevert(HandleEscrow.NoNames.selector);
        new ERC1967Proxy(address(impl), abi.encodeCall(HandleEscrow.initialize, (owner, IIdentityNames(address(0)))));
    }

    function test_ownershipCannotBeRenounced() public {
        vm.prank(owner);
        vm.expectRevert("renounce disabled");
        escrow.renounceOwnership();
    }

    function test_onlyTheOwnerMayUpgrade() public {
        HandleEscrow next = new HandleEscrow();

        vm.prank(bob);
        vm.expectRevert();
        escrow.upgradeToAndCall(address(next), "");

        vm.prank(owner);
        escrow.upgradeToAndCall(address(next), "");
    }

    /// The balances have to survive it, or the upgrade is the theft the pause
    /// was refused to avoid.
    function test_balancesSurviveAnUpgrade() public {
        _depositNative("alice", 1 ether);
        // A version that APPENDS a field, not a copy of the same bytecode: a
        // byte-identical upgrade cannot detect a reordered or removed one,
        // which is the only mistake this test exists to catch.
        HandleEscrowV2 next = new HandleEscrowV2();

        vm.prank(owner);
        escrow.upgradeToAndCall(address(next), "");

        HandleEscrowV2 upgraded = HandleEscrowV2(payable(address(escrow)));
        assertEq(upgraded.heldThroughV2(aliceNode, NATIVE), 1 ether, "the balance moved under the new layout");
        assertEq(upgraded.namesThroughV2(), address(names), "the naming pointer moved");
        assertEq(upgraded.appended(), 0, "the appended field read somebody else's bytes");

        // The old surface still answers, and the new field is its own slot.
        assertEq(escrow.escrowed(aliceNode, NATIVE), 1 ether);
        upgraded.setAppended(7);
        assertEq(upgraded.appended(), 7);
        assertEq(escrow.escrowed(aliceNode, NATIVE), 1 ether, "writing the new field disturbed a balance");
    }

    // ─── Helpers ────────────────────────────────────────────────────

    function _platformIdFor(string memory platform) internal pure returns (bytes32) {
        bytes32 key = keccak256(bytes(platform));
        if (key == keccak256("x")) return HandleVectors.PLATFORM_X;
        if (key == keccak256("github")) return HandleVectors.PLATFORM_GITHUB;
        if (key == keccak256("google")) return HandleVectors.PLATFORM_GOOGLE;
        revert("unknown platform in the vector table");
    }
}
