// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";

import {ReentrancyGuardUpgradeable} from "@openzeppelin/contracts-upgradeable/utils/ReentrancyGuardUpgradeable.sol";
import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";

import {HandleNormalizer} from "../../identity/HandleNormalizer.sol";
import {HandleVectors} from "../../identity/HandleVectors.sol";
import {IdentityNames} from "../../identity/IdentityNames.sol";
import {IdentityNodes} from "../../identity/IdentityNodes.sol";
import {StubPlatformVerifier} from "../../identity/test/StubPlatformVerifier.sol";
import {CeremonyProofVerifier} from "../../ceremony/CeremonyProofVerifier.sol";
import {IPlatformVerifier} from "../../ceremony/IPlatformVerifier.sol";
import {IProofVerifier} from "../../ceremony/IProofVerifier.sol";
import {HandleEscrow} from "../HandleEscrow.sol";
import {IIdentityNames} from "../../identity/IIdentityNames.sol";

/// @notice A plain ERC-20 anybody can mint.
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

/// @notice A second version that APPENDS to the namespaced root, which is the only change the
///         storage rule allows.
contract HandleEscrowV2 is HandleEscrow {
    /// @custom:storage-location erc7201:libid.storage.HandleEscrow
    struct V2Storage {
        mapping(bytes32 => mapping(address => uint256)) held;
        IIdentityNames names;
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

    function roundThroughV2(bytes32 handleNode, address token) external view returns (uint256) {
        return _v2().round[handleNode][token];
    }

    function contributionThroughV2(bytes32 handleNode, address token, uint256 round_, address depositor)
        external
        view
        returns (uint256)
    {
        return _v2().contributions[handleNode][token][round_][depositor];
    }
}

/// @notice A router paying a handle given as text: the naming system hashes the text under the
///         platform's current rules, and the caller, who can call `refund`, is `refundTo`.
contract TextPayer {
    HandleEscrow private immutable ESCROW;
    IdentityNames private immutable NAMES;

    constructor(HandleEscrow escrow_, IdentityNames names_) {
        ESCROW = escrow_;
        NAMES = names_;
    }

    function pay(bytes32 platformId, string calldata handle) external payable {
        ESCROW.deposit{value: msg.value}(
            platformId, NAMES.handleHashOf(platformId, handle), address(0), msg.value, msg.sender
        );
    }
}

/// @notice Deposits native value for a node, then refunds it to itself and, from inside the payout,
///         refunds again.
contract ReenteringRefunder {
    HandleEscrow private immutable ESCROW;
    bytes32 private immutable NODE;
    bytes32 private immutable HASH;
    bytes32 private immutable PLATFORM;
    bool private entered;

    constructor(HandleEscrow escrow_, bytes32 platformId_, bytes32 handleHash_) {
        ESCROW = escrow_;
        PLATFORM = platformId_;
        HASH = handleHash_;
        NODE = IdentityNodes.handleNodeOfHash(platformId_, handleHash_);
    }

    function fund() external payable {
        ESCROW.deposit{value: msg.value}(PLATFORM, HASH, address(0), msg.value, address(this));
    }

    function take() external {
        ESCROW.refund(NODE, address(0), address(this));
    }

    receive() external payable {
        if (entered) return;
        entered = true;
        ESCROW.refund(NODE, address(0), address(this));
    }
}

/// @notice Refunds, and from inside the native payout reads the books and tries to refund again —
///         catching the refusal, so each of the two defences can be seen on its own, as
///         `ObservingClaimer` does for `claim`.
contract ObservingRefunder {
    HandleEscrow private immutable ESCROW;
    bytes32 private immutable NODE;
    bytes32 private immutable HASH;
    bytes32 private immutable PLATFORM;
    bool private entered;

    /// What `refundable` answered for this contract while it was being paid.
    uint256 public refundableDuringPayout = type(uint256).max;
    /// What `escrowed` answered while this contract was being paid.
    uint256 public heldDuringPayout = type(uint256).max;
    /// Why the second refund was refused. Empty if it was not.
    bytes public reentryError;

    constructor(HandleEscrow escrow_, bytes32 platformId_, bytes32 handleHash_) {
        ESCROW = escrow_;
        PLATFORM = platformId_;
        HASH = handleHash_;
        NODE = IdentityNodes.handleNodeOfHash(platformId_, handleHash_);
    }

    function fund() external payable {
        ESCROW.deposit{value: msg.value}(PLATFORM, HASH, address(0), msg.value, address(this));
    }

    function take() external {
        ESCROW.refund(NODE, address(0), address(this));
    }

    receive() external payable {
        if (entered) return;
        entered = true;
        refundableDuringPayout = ESCROW.refundable(NODE, address(0), address(this));
        heldDuringPayout = ESCROW.escrowed(NODE, address(0));
        try ESCROW.refund(NODE, address(0), address(this)) {}
        catch (bytes memory reason) {
            reentryError = reason;
        }
    }
}

/// @notice A token that deposits itself and, when the escrow pays it back, calls `refund` again
///         from inside that transfer.
contract RefundReenteringToken is TestERC20 {
    HandleEscrow private escrow;
    bytes32 private node;
    bool private entered;

    constructor() TestERC20("Back", "BACK") {}

    function fund(HandleEscrow escrow_, bytes32 platformId, bytes32 handleHash, uint256 amount) external {
        escrow = escrow_;
        node = IdentityNodes.handleNodeOfHash(platformId, handleHash);
        _mint(address(this), amount);
        _approve(address(this), address(escrow_), amount);
        escrow_.deposit(platformId, handleHash, address(this), amount, address(this));
    }

    function take() external {
        escrow.refund(node, address(this), address(this));
    }

    function transfer(address to, uint256 amount) public override returns (bool) {
        bool ok = super.transfer(to, amount);
        if (!entered && msg.sender == address(escrow)) {
            entered = true;
            escrow.refund(node, address(this), address(this));
        }
        return ok;
    }
}

/// @notice Refuses every native transfer.
contract RejectEther {
    // No receive, no fallback.
}

/// @notice A naming contract as it was before the escrow: it answers `byHandle` and nothing the
///         escrow added.
contract NamesBeforeTheEscrow {
    function byHandle(bytes32) external pure returns (address owner, uint64 observedAt) {
        return (address(0), 0);
    }
}

/// @notice One that also answers `acceptsClaims`, but not `nodeOf`.
contract NamesWithoutNodeOf is NamesBeforeTheEscrow {
    function acceptsClaims(bytes32) external pure returns (bool) {
        return false;
    }
}

/// @notice One that answers `byHandle` and `acceptsClaims` as the naming system does, and whose
///         fallback answers everything else with a zero word: `nodeOf` then "returns" the zero
///         node.
contract NamesWithAZeroFallback is NamesWithoutNodeOf {
    fallback() external {
        assembly {
            mstore(0, 0)
            return(0, 32)
        }
    }
}

/// @notice One whose `nodeOf` refuses the zero platform, but not with `UnknownPlatform`.
contract NamesWithTheWrongRevert is NamesWithoutNodeOf {
    error NoSuchPlatform(bytes32 platformId);

    function nodeOf(bytes32 platformId, string calldata) external pure returns (bytes32) {
        revert NoSuchPlatform(platformId);
    }
}

/// @notice One that answers `nodeOf` as the naming system does, but not `nodeOfHash`: an
///         `IdentityNames` from before the escrow derived nodes through it.
contract NamesWithoutNodeOfHash is NamesWithoutNodeOf {
    function nodeOf(bytes32 platformId, string calldata) external pure returns (bytes32) {
        revert IIdentityNames.UnknownPlatform(platformId);
    }
}

/// @notice One whose `nodeOfHash` keys differently from the V1 derivation the escrow expects.
contract NamesWithAnotherNodeDerivation is NamesWithoutNodeOfHash {
    function nodeOfHash(bytes32 platformId, bytes32 handleHash) external pure returns (bytes32) {
        return keccak256(abi.encode(platformId, handleHash));
    }
}

/// @notice One that answers `byHandle` and succeeds, returning nothing, on every other call: a
///         fallback that swallows what it does not know.
contract NamesWithASilentFallback is NamesBeforeTheEscrow {
    fallback() external {}
}

/// @notice Makes any call for anybody, value included, the way Multicall3's `aggregate3Value` or a
///         payment router does: the target sees this contract as `msg.sender`, whoever asked.
contract SharedForwarder {
    function forward(address target, bytes calldata data) external payable returns (bytes memory) {
        (bool ok, bytes memory result) = target.call{value: msg.value}(data);
        if (!ok) {
            assembly {
                revert(add(result, 32), mload(result))
            }
        }
        return result;
    }
}

/// @notice Deposits again from inside its own transfer, the way a token with a receiver hook does,
///         through `deposit` again.
contract ReenteringToken is TestERC20 {
    HandleEscrow public escrow;
    bytes32 public platformId;
    bool private entered;

    constructor() TestERC20("Hook", "HOOK") {}

    function arm(HandleEscrow escrow_, bytes32 platformId_) external {
        escrow = escrow_;
        platformId = platformId_;
        _approve(address(this), address(escrow_), type(uint256).max);
    }

    function transferFrom(address from, address to, uint256 amount) public override returns (bool) {
        bool ok = super.transferFrom(from, to, amount);
        if (!entered && address(escrow) != address(0)) {
            entered = true;
            escrow.deposit(platformId, keccak256("bob"), address(this), 1 ether, address(this));
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

/// @notice Claims, and from inside the native payout reads the slot and tries to claim again —
///         without failing the payout, so each of the two defences can be seen on its own.
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

    /// The node `alice` keys to on X, computed by the naming system's own library rather than read
    /// out of the escrow.
    bytes32 internal aliceNode = IdentityNodes.handleNode(X, "alice");
    /// `keccak256` of `alice`, what `deposit` takes.
    bytes32 internal aliceHash = keccak256("alice");

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

        // Both platforms usable the way a deployment makes them: a keyspace, and a registered
        // verifier the Proof Verifier answers for.
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
    function _bind(address who, string memory userId, string memory handle, uint64 at) internal {
        xVerifier.set(userId, handle);
        xVerifier.setObservedAt(at);
        bytes memory payload = abi.encode(
            StubPlatformVerifier.StubPayload({
                ceremonyVersion: 1,
                // A literal, not `names.CLAIM_IDENTITY_DOMAIN()`: reading it would be one more
                // external call to keep the prank off.
                operationDomain: keccak256(bytes("libid.claim-identity")),
                authorizationNonce: bytes32(++nonce),
                // The free shape: a ceremony composed by hand names no fee.
                transactionData: abi.encode(who, uint256(0), address(0))
            })
        );
        vm.prank(who);
        names.claim(X, V1, payload, false);
    }

    /// A deposit made from text the way a caller holding text makes one: the naming system hashes
    /// it, and the hash is what is deposited.
    function _depositNative(string memory handle, uint256 amount) internal {
        bytes32 handleHash = names.handleHashOf(X, handle);
        vm.prank(sender);
        escrow.deposit{value: amount}(X, handleHash, NATIVE, amount, sender);
    }

    function _nodeX(string memory normalized) internal pure returns (bytes32) {
        return IdentityNodes.handleNode(X, normalized);
    }

    // ─── The key ────────────────────────────────────────────────────

    /// The lemma the whole design rests on: the escrow keys every handle on the node the naming
    /// system binds it under.
    function test_everyVectorRowKeysOnTheNamingSystemsNode() public {
        // Google is wired here only: elsewhere in this suite it stands for a platform that cannot
        // verify yet.
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
                assertEq(
                    names.handleHashOf(platformId, v.input),
                    keccak256(bytes(v.output)),
                    string.concat("vector ", vm.toString(i), " hashes something other than its normalized form")
                );
                accepted++;
            } else {
                // `Problem` is the table's error kind shifted by one: `None` takes zero.
                vm.expectRevert(
                    abi.encodeWithSelector(
                        IIdentityNames.UnusableHandle.selector, HandleNormalizer.Problem(v.errorKind + 1)
                    )
                );
                escrow.nodeOf(platformId, v.input);
                vm.expectRevert(
                    abi.encodeWithSelector(
                        IIdentityNames.UnusableHandle.selector, HandleNormalizer.Problem(v.errorKind + 1)
                    )
                );
                names.handleHashOf(platformId, v.input);
                refused++;
            }
        }
        assertEq(accepted + refused, vectors.length, "a row was skipped");
        assertGt(accepted, 0, "the table has no accepted rows");
        assertGt(refused, 0, "the table has no refused rows");
    }

    /// A literal, so Rust and TypeScript cannot compute a different key and still pass their own
    /// tests.
    function test_theNodeDerivationIsPinned() public view {
        bytes32 pinned = 0x1c43d5d3cf3d99e9d5b6e8c74c23d14bcbb6a743712cf7fa7c15750c4fc2150d;
        assertEq(escrow.nodeOf(X, " Alice_1 "), pinned);
        assertEq(IdentityNodes.handleNode(X, "alice_1"), pinned);
    }

    /// The node the escrow keys on is the one the naming system binds: a claim of the handle makes
    /// `byHandle` of the escrow's node answer with the claimer.
    function test_theEscrowsNodeIsTheOneTheNamingSystemBinds() public {
        _bind(alice, "1", "Alice_1", 100);

        (address holder,) = names.byHandle(escrow.nodeOf(X, "@alice_1"));
        assertEq(holder, alice);
    }

    /// X strips a leading at-sign, so both spellings are one handle there and reach one slot.
    function test_aLeadingAtSignFoldsWhereThePlatformStripsIt() public {
        assertEq(escrow.nodeOf(X, "@alice"), aliceNode);
        assertEq(escrow.nodeOf(X, "  @Alice  "), aliceNode);

        _depositNative("@alice", 1 ether);
        _depositNative("alice", 2 ether);
        assertEq(escrow.escrowed(aliceNode, NATIVE), 3 ether);
    }

    /// Text with nothing left after trimming and the at-sign has no node.
    function test_aBareAtSignHasNoNode() public {
        vm.expectRevert(abi.encodeWithSelector(IIdentityNames.UnusableHandle.selector, HandleNormalizer.Problem.Empty));
        escrow.nodeOf(X, " @ ");
    }

    function test_textWithNothingInItHasNoNode() public {
        vm.expectRevert(abi.encodeWithSelector(IIdentityNames.UnusableHandle.selector, HandleNormalizer.Problem.Empty));
        escrow.nodeOf(X, "   ");
    }

    function test_anUnwiredPlatformHasNoNode() public {
        vm.expectRevert(abi.encodeWithSelector(IIdentityNames.UnknownPlatform.selector, UNWIRED));
        escrow.nodeOf(UNWIRED, "alice");
    }

    /// The platform a hash deposit names is part of the node it funds, so it cannot be one
    /// platform's gate with another platform's slot: the same hash on GitHub funds GitHub's node,
    /// and X's holder of that text is not paid by it.
    function test_aHashDepositFundsTheNodeOfThePlatformItNames() public {
        _bind(alice, "1", "alice", 100); // on X only

        vm.prank(sender);
        escrow.deposit{value: 1 ether}(GITHUB, aliceHash, NATIVE, 1 ether, sender);

        assertEq(alice.balance, 0, "X's holder was paid by a GitHub deposit");
        assertEq(escrow.escrowed(IdentityNodes.handleNode(GITHUB, "alice"), NATIVE), 1 ether);
        assertEq(escrow.escrowed(aliceNode, NATIVE), 0);
    }

    /// The hash path keys with the naming system's own library: the hash of the normalized handle
    /// is the inner hash of `handleNode`.
    function test_theHashPathKeysOnTheNamingSystemsNode() public pure {
        assertEq(IdentityNodes.handleNodeOfHash(X, keccak256("alice_1")), IdentityNodes.handleNode(X, "alice_1"));
    }

    /// Different platforms are different keyspaces, so the same text on two of them is two slots.
    function test_theNodeIsPerPlatform() public view {
        assertTrue(escrow.nodeOf(X, "alice") != escrow.nodeOf(GITHUB, "alice"));
    }

    /// The platform id is load-bearing in the key, not decoration: the same text on two platforms
    /// is two different people, and their money must not meet.
    function test_theSameTextOnTwoPlatformsIsTwoEscrows() public {
        vm.startPrank(sender);
        escrow.deposit{value: 1 ether}(X, aliceHash, NATIVE, 1 ether, sender);
        escrow.deposit{value: 2 ether}(GITHUB, aliceHash, NATIVE, 2 ether, sender);
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
        escrow.deposit(X, aliceHash, address(token), 10 ether, sender);

        assertEq(escrow.escrowed(aliceNode, address(token)), 10 ether);
        assertEq(token.balanceOf(address(escrow)), 10 ether);
    }

    /// Two spellings of one handle land in one slot and add up.
    function test_spellingsOfOneHandleAccumulate() public {
        _depositNative("alice", 1 ether);
        _depositNative(" ALICE ", 2 ether);

        assertEq(escrow.escrowed(aliceNode, NATIVE), 3 ether);
    }

    /// A hash the naming system computed from text and one computed locally from the normalized
    /// handle reach one slot: the one `IdentityNodes.handleNode` names for the normalized handle.
    function test_aLocalHashLandsWhereTheNamingSystemsDoes() public {
        _depositNative(" Alice ", 1 ether);
        vm.prank(sender);
        escrow.deposit{value: 2 ether}(X, aliceHash, NATIVE, 2 ether, sender);

        assertEq(escrow.escrowed(aliceNode, NATIVE), 3 ether);
        assertEq(address(escrow).balance, 3 ether);
    }

    function test_aDepositHoldsTokens() public {
        vm.prank(sender);
        escrow.deposit(X, aliceHash, address(token), 10 ether, sender);

        assertEq(escrow.escrowed(aliceNode, address(token)), 10 ether);
        assertEq(token.balanceOf(address(escrow)), 10 ether);
    }

    /// A fee-on-transfer token books what arrived, not what was asked for.
    function test_aFeeOnTransferTokenCreditsWhatArrived() public {
        FeeToken fee = new FeeToken();
        fee.mint(sender, 100 ether);
        vm.startPrank(sender);
        fee.approve(address(escrow), type(uint256).max);
        escrow.deposit(X, aliceHash, address(fee), 100 ether, sender);
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

    /// The escrow exists for the window before a handle is claimed.
    function test_depositForAHeldHandleIsPaidStraightThrough() public {
        _bind(alice, "1", "alice", 100);

        uint256 before = alice.balance;
        _depositNative("alice", 1 ether);

        assertEq(alice.balance, before + 1 ether, "the holder was not paid");
        assertEq(escrow.escrowed(aliceNode, NATIVE), 0, "the value was escrowed instead");
        assertEq(address(escrow).balance, 0, "the escrow kept it");
    }

    function test_aTokenDepositForAHeldHandleIsPaidStraightThrough() public {
        _bind(alice, "1", "alice", 100);

        vm.prank(sender);
        escrow.deposit(X, aliceHash, address(token), 10 ether, sender);

        assertEq(token.balanceOf(alice), 10 ether, "the holder was not paid");
        assertEq(escrow.escrowed(aliceNode, address(token)), 0, "the value was escrowed instead");
    }

    function test_aForwardedDepositIsAnnouncedAsSuch() public {
        _bind(alice, "1", "alice", 100);

        vm.expectEmit(true, true, true, true, address(escrow));
        emit HandleEscrow.Forwarded(aliceNode, NATIVE, sender, alice, X, 1 ether, 1 ether);
        vm.prank(sender);
        escrow.deposit{value: 1 ether}(X, aliceHash, NATIVE, 1 ether, sender);
    }

    function test_tokensForAHeldHandleGoStraightToTheHolder() public {
        _bind(alice, "1", "alice", 100);

        vm.prank(sender);
        escrow.deposit(X, aliceHash, address(token), 10 ether, sender);

        assertEq(token.balanceOf(alice), 10 ether, "the holder was not paid");
        assertEq(token.balanceOf(address(escrow)), 0, "the escrow kept tokens");
        assertEq(escrow.escrowed(aliceNode, address(token)), 0);
    }

    /// The price of paying through: the call depends on the recipient.
    function test_aHolderThatCannotReceiveFailsTheDeposit() public {
        address rejector = address(new RejectEther());
        _bind(rejector, "1", "alice", 100);

        vm.prank(sender);
        vm.expectRevert(abi.encodeWithSelector(HandleEscrow.NativeTransferFailed.selector, rejector, 1 ether));
        escrow.deposit{value: 1 ether}(X, aliceHash, NATIVE, 1 ether, sender);
    }

    /// The window the escrow is for: deposit while unclaimed, and the same handle pays through once
    /// it is claimed.
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
        escrow.deposit(X, aliceHash, NATIVE, 0, sender);
        vm.expectRevert(HandleEscrow.ZeroAmount.selector);
        escrow.deposit(X, aliceHash, NATIVE, 0, sender);
        vm.stopPrank();
    }

    function test_nativeValueMustEqualTheAmount() public {
        vm.startPrank(sender);
        vm.expectRevert(abi.encodeWithSelector(HandleEscrow.ValueMismatch.selector, 2 ether, 1 ether));
        escrow.deposit{value: 1 ether}(X, aliceHash, NATIVE, 2 ether, sender);
        vm.expectRevert(abi.encodeWithSelector(HandleEscrow.ValueMismatch.selector, 2 ether, 1 ether));
        escrow.deposit{value: 1 ether}(X, aliceHash, NATIVE, 2 ether, sender);
        vm.stopPrank();
    }

    /// Ether sent alongside a token deposit has no slot to land in.
    function test_aTokenDepositCarriesNoValue() public {
        vm.startPrank(sender);
        vm.expectRevert(abi.encodeWithSelector(HandleEscrow.ValueMismatch.selector, 0, 1 ether));
        escrow.deposit{value: 1 ether}(X, aliceHash, address(token), 10 ether, sender);
        vm.expectRevert(abi.encodeWithSelector(HandleEscrow.ValueMismatch.selector, 0, 1 ether));
        escrow.deposit{value: 1 ether}(X, aliceHash, address(token), 10 ether, sender);
        vm.stopPrank();
    }

    /// A mistyped platform id takes nobody's money.
    function test_anUnwiredPlatformIsRefused() public {
        vm.expectRevert(abi.encodeWithSelector(IIdentityNames.UnknownPlatform.selector, UNWIRED));
        names.handleHashOf(UNWIRED, "alice");
        vm.prank(sender);
        vm.expectRevert(abi.encodeWithSelector(HandleEscrow.PlatformAcceptsNoClaims.selector, UNWIRED));
        escrow.deposit{value: 1 ether}(UNWIRED, keccak256("alice"), NATIVE, 1 ether, sender);
    }

    /// A platform with a keyspace and no way to verify is not wired yet: no proof could claim what
    /// it would hold, so it takes nobody's money either.
    function test_aPlatformThatCannotVerifyYetIsRefused() public {
        vm.prank(owner);
        names.setPlatform(GOOGLE, HandleVectors.rulesFor(GOOGLE));

        assertEq(escrow.nodeOf(GOOGLE, "alice@example.com"), IdentityNodes.handleNode(GOOGLE, "alice@example.com"));
        bytes32 handleHash = names.handleHashOf(GOOGLE, "Alice@Example.com");
        assertEq(handleHash, keccak256("alice@example.com"));
        vm.prank(sender);
        vm.expectRevert(abi.encodeWithSelector(HandleEscrow.PlatformAcceptsNoClaims.selector, GOOGLE));
        escrow.deposit{value: 1 ether}(GOOGLE, handleHash, NATIVE, 1 ether, sender);
    }

    /// Escrowing needs a claim that could ever take the value; paying a holder does not.
    function test_aPlatformThatAcceptsNoClaimsPaysHoldersButDoesNotEscrow() public {
        _depositNative("alice", 1 ether);
        _bind(alice, "1", "alice", 100);

        vm.prank(owner);
        proofVerifier.setVerifier(X, V1, IPlatformVerifier(address(0)));
        assertFalse(names.acceptsClaims(X), "the staging is wrong");

        // The holder is paid through, from text and from a hash.
        uint256 before = alice.balance;
        _depositNative("alice", 2 ether);
        vm.prank(sender);
        escrow.deposit{value: 3 ether}(X, aliceHash, NATIVE, 3 ether, sender);
        assertEq(alice.balance, before + 5 ether, "the holder was not paid");

        // Nobody holds bob, and nothing could bind him now.
        vm.startPrank(sender);
        vm.expectRevert(abi.encodeWithSelector(HandleEscrow.PlatformAcceptsNoClaims.selector, X));
        escrow.deposit{value: 1 ether}(X, keccak256("bob"), NATIVE, 1 ether, sender);
        vm.expectRevert(abi.encodeWithSelector(HandleEscrow.PlatformAcceptsNoClaims.selector, X));
        escrow.deposit(X, keccak256("bob"), address(token), 1 ether, sender);
        vm.stopPrank();
        assertEq(token.balanceOf(address(escrow)), 0, "tokens were pulled before the gate");

        // What was already held is still the holder's to take.
        vm.prank(alice);
        escrow.claim(aliceNode, NATIVE, alice);
        assertEq(escrow.escrowed(aliceNode, NATIVE), 0);
    }

    /// Why text goes through the naming system's `handleHashOf`, which refuses what `resolveHandle`
    /// would answer with nobody.
    function test_aHandleThePlatformCouldNeverAcceptIsRefused() public {
        TextPayer payer = new TextPayer(escrow, names);

        // A space inside is not a handle on X.
        vm.prank(sender);
        vm.expectRevert(
            abi.encodeWithSelector(IIdentityNames.UnusableHandle.selector, HandleNormalizer.Problem.BadChar)
        );
        payer.pay{value: 1 ether}(X, "ali ce");

        // A hyphen is GitHub's, not X's.
        vm.prank(sender);
        vm.expectRevert(
            abi.encodeWithSelector(IIdentityNames.UnusableHandle.selector, HandleNormalizer.Problem.BadChar)
        );
        payer.pay{value: 1 ether}(X, "ali-ce");

        // Past X's length.
        vm.prank(sender);
        vm.expectRevert(
            abi.encodeWithSelector(IIdentityNames.UnusableHandle.selector, HandleNormalizer.Problem.TooLong)
        );
        payer.pay{value: 1 ether}(X, "a123456789012345");

        assertEq(address(escrow).balance, 0);
    }

    /// Text a caller hashes through the naming system and then deposits lands on the node a proof
    /// of that text is bound under, whatever the platform's normalization folds on the way, and the
    /// router's caller can refund it.
    function test_textHashedByTheNamingSystemLandsOnTheProvedNode() public {
        TextPayer payer = new TextPayer(escrow, names);

        vm.startPrank(sender);
        payer.pay{value: 1 ether}(X, "  @Alice ");
        payer.pay{value: 2 ether}(X, "ALICE");
        vm.stopPrank();
        assertEq(escrow.escrowed(aliceNode, NATIVE), 3 ether);
        assertEq(escrow.refundable(aliceNode, NATIVE, sender), 3 ether);
        assertEq(escrow.refundable(aliceNode, NATIVE, address(payer)), 0);

        _bind(alice, "1", "Alice", 100);
        vm.prank(alice);
        escrow.claim(aliceNode, NATIVE, alice);
        assertEq(alice.balance, 3 ether);
    }

    /// What a router books under its caller, the caller takes back.
    function test_aRoutersCallerCanRefund() public {
        TextPayer payer = new TextPayer(escrow, names);
        vm.prank(sender);
        payer.pay{value: 1 ether}(X, "Alice");

        uint256 before = sender.balance;
        vm.prank(sender);
        escrow.refund(aliceNode, NATIVE, sender);
        assertEq(sender.balance, before + 1 ether);
    }

    /// NOT a vulnerability.
    function test_ACCEPTED_aHashNoHandleReachesEscrowsForNobody() public {
        bytes32 garbageHash = keccak256("not the hash of any handle");
        bytes32 garbage = IdentityNodes.handleNodeOfHash(X, garbageHash);

        vm.prank(sender);
        escrow.deposit{value: 1 ether}(X, garbageHash, NATIVE, 1 ether, sender);
        assertEq(escrow.escrowed(garbage, NATIVE), 1 ether);

        vm.prank(sender);
        vm.expectRevert(abi.encodeWithSelector(HandleEscrow.NotTheHolder.selector, address(0), sender));
        escrow.claim(garbage, NATIVE, sender);

        uint256 before = sender.balance;
        vm.prank(sender);
        escrow.refund(garbage, NATIVE, sender);
        assertEq(sender.balance, before + 1 ether, "the depositor did not get it back");
        assertEq(escrow.escrowed(garbage, NATIVE), 0);
        assertEq(address(escrow).balance, 0);
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

    /// The claimer names where it goes, so a wallet that holds the name can pay out somewhere else.
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
        escrow.deposit(X, aliceHash, address(token), 10 ether, sender);
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

    /// A token whose transfer re-enters `deposit` is refused: were it not, the outer deposit would
    /// credit the inner deposit's tokens as well — two slots funded by one transfer, and more
    /// promised than held.
    function test_aTokenThatReentersDepositIsRefused() public {
        ReenteringToken hook = new ReenteringToken();
        hook.mint(sender, 100 ether);
        hook.mint(address(hook), 10 ether);
        hook.arm(escrow, X);

        vm.startPrank(sender);
        hook.approve(address(escrow), type(uint256).max);
        // The guard specifically, not any revert: a mis-staged token or a missing approval would
        // also revert and would also look green.
        vm.expectRevert(abi.encodeWithSelector(ReentrancyGuardUpgradeable.ReentrancyGuardReentrantCall.selector));
        escrow.deposit(X, aliceHash, address(hook), 100 ether, sender);
        vm.stopPrank();

        assertEq(escrow.escrowed(aliceNode, address(hook)), 0);
        assertEq(escrow.escrowed(_nodeX("bob"), address(hook)), 0);
        assertEq(hook.balanceOf(address(escrow)), 0, "the escrow kept tokens it never credited");
    }

    /// The payout is an external call to an address the claimer chose.
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

    /// The two defences of the payout, each observable alone.
    function test_aClaimSettlesTheSlotBeforePayingAndTheGuardRefusesReentry() public {
        ObservingClaimer claimer = new ObservingClaimer(escrow, aliceNode);
        _depositNative("alice", 1 ether);
        _depositNative("bob", 1 ether); // not the claimer's
        _bind(address(claimer), "1", "alice", 100);

        claimer.take();

        assertEq(claimer.seenDuringPayout(), 0, "the slot still read full while its payout ran");
        assertEq(
            claimer.reentryError(),
            abi.encodeWithSelector(ReentrancyGuardUpgradeable.ReentrancyGuardReentrantCall.selector),
            "the second claim was not refused by the guard"
        );
        assertEq(address(claimer).balance, 1 ether, "the claimer was paid other than once");
        assertEq(escrow.escrowed(_nodeX("bob"), NATIVE), 1 ether, "somebody else's escrow moved");
        assertEq(address(escrow).balance, 1 ether);
    }

    /// A payout to nobody is not a payout.
    function test_aClaimToNobodyIsRefused() public {
        _depositNative("alice", 1 ether);
        _bind(alice, "1", "alice", 100);

        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(HandleEscrow.BadRecipient.selector, address(0)));
        escrow.claim(aliceNode, NATIVE, address(0));

        assertEq(escrow.escrowed(aliceNode, NATIVE), 1 ether, "the slot was emptied");
        assertEq(address(0).balance, 0, "value was burned");
    }

    /// A payout to this contract would zero the books and leave the value here as surplus no slot
    /// points at, and no function here recovers it.
    function test_aClaimBackIntoTheEscrowIsRefused() public {
        vm.prank(sender);
        escrow.deposit(X, aliceHash, address(token), 10 ether, sender);
        _bind(alice, "1", "alice", 100);

        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(HandleEscrow.BadRecipient.selector, address(escrow)));
        escrow.claim(aliceNode, address(token), address(escrow));

        assertEq(escrow.escrowed(aliceNode, address(token)), 10 ether);
        assertEq(token.balanceOf(address(escrow)), 10 ether);
    }

    /// The ERC-20 payout branch, which no other test reaches: every other claim in this suite takes
    /// the native token.
    function test_aTokenClaimPaysTheRecipient() public {
        vm.prank(sender);
        escrow.deposit(X, aliceHash, address(token), 10 ether, sender);
        _bind(alice, "1", "alice", 100);

        vm.prank(alice);
        escrow.claim(aliceNode, address(token), bob);

        assertEq(token.balanceOf(bob), 10 ether, "the recipient was not paid");
        assertEq(token.balanceOf(address(escrow)), 0, "the escrow kept tokens");
        assertEq(escrow.escrowed(aliceNode, address(token)), 0);
    }

    /// The payloads an indexer reads.
    function test_depositAndClaimAnnounceTheirPayloads() public {
        vm.expectEmit(true, true, true, true, address(escrow));
        emit HandleEscrow.Deposited(aliceNode, NATIVE, sender, sender, X, 1 ether);
        vm.prank(sender);
        escrow.deposit{value: 1 ether}(X, aliceHash, NATIVE, 1 ether, sender);

        vm.expectEmit(true, true, true, true, address(escrow));
        emit HandleEscrow.Deposited(aliceNode, NATIVE, sender, sender, X, 2 ether);
        vm.prank(sender);
        escrow.deposit{value: 2 ether}(X, aliceHash, NATIVE, 2 ether, sender);

        _bind(alice, "1", "alice", 100);

        vm.expectEmit(true, true, true, true, address(escrow));
        emit HandleEscrow.Claimed(aliceNode, NATIVE, alice, bob, 3 ether, 3 ether);
        vm.prank(alice);
        escrow.claim(aliceNode, NATIVE, bob);
    }

    /// A fee-on-transfer token delivers less than was asked for, and the event is the only record
    /// of a payment that never entered the books: it carries both.
    function test_aForwardedPaymentReportsWhatArrived() public {
        FeeToken fee = new FeeToken();
        fee.mint(sender, 100 ether);
        _bind(alice, "1", "alice", 100);

        vm.startPrank(sender);
        fee.approve(address(escrow), type(uint256).max);
        vm.expectEmit(true, true, true, true, address(escrow));
        emit HandleEscrow.Forwarded(aliceNode, address(fee), sender, alice, X, 100 ether, 99 ether);
        escrow.deposit(X, aliceHash, address(fee), 100 ether, sender);
        vm.stopPrank();

        assertEq(fee.balanceOf(alice), 99 ether, "the holder received something else");
    }

    /// A holder depositing to its own node would pay itself.
    function test_aHolderPayingItselfNativeIsRefused() public {
        _assertPayingYourselfRefused(NATIVE);
    }

    function test_aHolderPayingItselfTokensIsRefused() public {
        _assertPayingYourselfRefused(address(token));
    }

    /// A fee-on-transfer token paid by its holder to itself would leave it with LESS than it
    /// started with.
    function test_aHolderPayingItselfAFeeTokenIsRefused() public {
        _bind(alice, "1", "alice", 100);
        FeeToken fee = new FeeToken();
        fee.mint(alice, 100 ether);

        vm.startPrank(alice);
        fee.approve(address(escrow), type(uint256).max);
        vm.expectRevert(abi.encodeWithSelector(HandleEscrow.PayingYourself.selector, alice));
        escrow.deposit(X, aliceHash, address(fee), 100 ether, alice);
        vm.stopPrank();

        assertEq(fee.balanceOf(alice), 100 ether, "the refused deposit still cost the fee");
    }

    function _assertPayingYourselfRefused(address asset) internal {
        _bind(alice, "1", "alice", 100);
        vm.deal(alice, 10 ether);
        token.mint(alice, 10 ether);
        vm.prank(alice);
        token.approve(address(escrow), type(uint256).max);
        uint256 value = asset == NATIVE ? 10 ether : 0;

        vm.recordLogs();
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(HandleEscrow.PayingYourself.selector, alice));
        escrow.deposit{value: value}(X, aliceHash, asset, 10 ether, alice);

        assertEq(vm.getRecordedLogs().length, 0, "a refused deposit announced something");
        assertEq(alice.balance, 10 ether, "native value moved");
        assertEq(token.balanceOf(alice), 10 ether, "tokens moved");
        assertEq(escrow.escrowed(aliceNode, asset), 0, "the refused deposit was booked");
    }

    /// A token that reports success and moves nothing credits nothing when it escrows, and delivers
    /// nothing when it pays through.
    function test_aTokenThatDeliversNothingIsRefused() public {
        InertToken inert = new InertToken();

        vm.startPrank(sender);
        vm.expectRevert(HandleEscrow.ZeroAmount.selector);
        escrow.deposit(X, aliceHash, address(inert), 10 ether, sender);
        vm.stopPrank();
        assertEq(escrow.escrowed(aliceNode, address(inert)), 0);

        _bind(alice, "1", "alice", 100);
        vm.prank(sender);
        vm.expectRevert(HandleEscrow.ZeroAmount.selector);
        escrow.deposit(X, aliceHash, address(inert), 10 ether, sender);
    }

    // ─── Refunding ──────────────────────────────────────────────────

    function test_aDepositorRefundsItsOwnDepositWhileNobodyHoldsTheHandle() public {
        _depositNative("alice", 1 ether);
        assertEq(escrow.refundable(aliceNode, NATIVE, sender), 1 ether);

        uint256 before = sender.balance;
        vm.prank(sender);
        escrow.refund(aliceNode, NATIVE, sender);

        assertEq(sender.balance, before + 1 ether, "the depositor was not paid back");
        assertEq(escrow.escrowed(aliceNode, NATIVE), 0, "the books still hold the refunded value");
        assertEq(escrow.refundable(aliceNode, NATIVE, sender), 0);
        assertEq(address(escrow).balance, 0);
    }

    /// The ERC-20 payout branch of a refund, to a recipient the depositor names.
    function test_aTokenRefundPaysTheRecipientTheDepositorNames() public {
        vm.prank(sender);
        escrow.deposit(X, aliceHash, address(token), 10 ether, sender);

        vm.prank(sender);
        escrow.refund(aliceNode, address(token), bob);

        assertEq(token.balanceOf(bob), 10 ether, "the recipient was not paid");
        assertEq(token.balanceOf(address(escrow)), 0, "the escrow kept tokens");
        assertEq(escrow.escrowed(aliceNode, address(token)), 0);
    }

    /// A refund reaches the caller's own contribution and nothing else.
    function test_nobodyRefundsSomebodyElsesDeposit() public {
        _depositNative("alice", 1 ether);

        vm.prank(bob);
        vm.expectRevert(abi.encodeWithSelector(HandleEscrow.NothingToRefund.selector, aliceNode, NATIVE, bob));
        escrow.refund(aliceNode, NATIVE, bob);

        assertEq(escrow.refundable(aliceNode, NATIVE, bob), 0);
        assertEq(escrow.escrowed(aliceNode, NATIVE), 1 ether, "somebody else's deposit moved");
    }

    /// A deposit made through a contract that calls for anybody is booked to the `refundTo` it
    /// names, not to the contract.
    function test_aDepositThroughASharedForwarderIsRefundableOnlyByItsRefundTo() public {
        SharedForwarder forwarder = new SharedForwarder();
        vm.expectEmit(true, true, true, true, address(escrow));
        emit HandleEscrow.Deposited(aliceNode, NATIVE, sender, address(forwarder), X, 1 ether);
        vm.prank(sender);
        forwarder.forward{value: 1 ether}(
            address(escrow), abi.encodeCall(HandleEscrow.deposit, (X, aliceHash, NATIVE, 1 ether, sender))
        );
        assertEq(escrow.refundable(aliceNode, NATIVE, address(forwarder)), 0, "booked to the forwarder");
        assertEq(escrow.refundable(aliceNode, NATIVE, sender), 1 ether, "not booked to refundTo");

        // Through the forwarder the escrow sees the forwarder, which has nothing booked; directly,
        // the stranger has nothing booked either.
        vm.prank(bob);
        vm.expectRevert(
            abi.encodeWithSelector(HandleEscrow.NothingToRefund.selector, aliceNode, NATIVE, address(forwarder))
        );
        forwarder.forward(address(escrow), abi.encodeCall(HandleEscrow.refund, (aliceNode, NATIVE, bob)));
        vm.prank(bob);
        vm.expectRevert(abi.encodeWithSelector(HandleEscrow.NothingToRefund.selector, aliceNode, NATIVE, bob));
        escrow.refund(aliceNode, NATIVE, bob);
        assertEq(bob.balance, 0, "the stranger was paid");

        uint256 before = sender.balance;
        vm.prank(sender);
        escrow.refund(aliceNode, NATIVE, sender);
        assertEq(sender.balance, before + 1 ether, "refundTo did not get it back");
        assertEq(escrow.escrowed(aliceNode, NATIVE), 0);
    }

    /// Whoever pays, the deposit is the named address's to take back, and not the payer's.
    function test_aDepositMadeForSomebodyElseIsTheirsToRefund() public {
        vm.prank(sender);
        escrow.deposit(X, aliceHash, address(token), 10 ether, bob);

        assertEq(escrow.refundable(aliceNode, address(token), bob), 10 ether);
        assertEq(escrow.refundable(aliceNode, address(token), sender), 0);
        vm.prank(sender);
        vm.expectRevert(
            abi.encodeWithSelector(HandleEscrow.NothingToRefund.selector, aliceNode, address(token), sender)
        );
        escrow.refund(aliceNode, address(token), sender);

        vm.expectEmit(true, true, true, true, address(escrow));
        emit HandleEscrow.Refunded(aliceNode, address(token), bob, bob, 10 ether, 10 ether);
        vm.prank(bob);
        escrow.refund(aliceNode, address(token), bob);
        assertEq(token.balanceOf(bob), 10 ether);
    }

    /// There is no default refundTo: a router passing a zero through must not book the deposit to
    /// itself.
    function test_aDepositMustNameWhoMayRefundIt() public {
        vm.startPrank(sender);
        vm.expectRevert(abi.encodeWithSelector(HandleEscrow.BadRefundTo.selector, address(0)));
        escrow.deposit{value: 1 ether}(X, aliceHash, NATIVE, 1 ether, address(0));
        vm.expectRevert(abi.encodeWithSelector(HandleEscrow.BadRefundTo.selector, address(0)));
        escrow.deposit(X, aliceHash, address(token), 1 ether, address(0));
        vm.stopPrank();

        // A held node pays through and books nothing, and is refused the same, so one calldata does
        // not succeed or fail by the race.
        _bind(alice, "1", "alice", 100);
        vm.startPrank(sender);
        vm.expectRevert(abi.encodeWithSelector(HandleEscrow.BadRefundTo.selector, address(0)));
        escrow.deposit{value: 1 ether}(X, aliceHash, NATIVE, 1 ether, address(0));
        vm.expectRevert(abi.encodeWithSelector(HandleEscrow.BadRefundTo.selector, address(0)));
        escrow.deposit(X, aliceHash, address(token), 1 ether, address(0));
        vm.stopPrank();

        assertEq(alice.balance, 0, "the holder was paid");
        assertEq(token.balanceOf(address(escrow)), 0);
        assertEq(address(escrow).balance, 0);
    }

    /// The escrow never calls `refund`, so naming it as `refundTo` would lock what a wrong hash
    /// funds.
    function test_theEscrowCannotBeWhoMayRefund() public {
        bytes memory refused = abi.encodeWithSelector(HandleEscrow.BadRefundTo.selector, address(escrow));
        vm.startPrank(sender);
        vm.expectRevert(refused);
        escrow.deposit{value: 1 ether}(X, keccak256("Alice"), NATIVE, 1 ether, address(escrow));
        vm.expectRevert(refused);
        escrow.deposit(X, aliceHash, address(token), 1 ether, address(escrow));
        vm.stopPrank();
    }

    /// Two depositors share a slot and each takes back exactly its own, once.
    function test_twoDepositorsEachRefundTheirOwn() public {
        vm.deal(bob, 10 ether);
        _depositNative("alice", 1 ether);
        vm.prank(bob);
        escrow.deposit{value: 2 ether}(X, aliceHash, NATIVE, 2 ether, bob);
        _depositNative(" Alice ", 3 ether); // the same depositor again

        assertEq(escrow.escrowed(aliceNode, NATIVE), 6 ether);
        assertEq(escrow.refundable(aliceNode, NATIVE, sender), 4 ether);
        assertEq(escrow.refundable(aliceNode, NATIVE, bob), 2 ether);

        uint256 senderBefore = sender.balance;
        vm.prank(sender);
        escrow.refund(aliceNode, NATIVE, sender);
        assertEq(sender.balance, senderBefore + 4 ether);
        assertEq(escrow.escrowed(aliceNode, NATIVE), 2 ether, "the other depositor's share moved");
        assertEq(escrow.refundable(aliceNode, NATIVE, bob), 2 ether);

        vm.prank(sender);
        vm.expectRevert(abi.encodeWithSelector(HandleEscrow.NothingToRefund.selector, aliceNode, NATIVE, sender));
        escrow.refund(aliceNode, NATIVE, sender);

        uint256 bobBefore = bob.balance;
        vm.prank(bob);
        escrow.refund(aliceNode, NATIVE, bob);
        assertEq(bob.balance, bobBefore + 2 ether);
        assertEq(escrow.escrowed(aliceNode, NATIVE), 0);
        assertEq(address(escrow).balance, 0);
    }

    /// Refundable until collected: the payee having joined does not close the refund, only its
    /// claim does.
    function test_aRefundWorksAfterThePayeeJoinsUntilItClaims() public {
        _depositNative("alice", 1 ether);
        vm.deal(bob, 2 ether);
        vm.prank(bob);
        escrow.deposit{value: 2 ether}(X, aliceHash, NATIVE, 2 ether, bob);
        _bind(alice, "1", "alice", 100);

        assertEq(escrow.refundable(aliceNode, NATIVE, sender), 1 ether, "a held node reads as not refundable");
        uint256 before = sender.balance;
        vm.prank(sender);
        escrow.refund(aliceNode, NATIVE, sender);
        assertEq(sender.balance, before + 1 ether, "the depositor was not paid back");

        vm.prank(alice);
        escrow.claim(aliceNode, NATIVE, alice);
        assertEq(alice.balance, 2 ether, "the holder did not get what the refund left");
        assertEq(escrow.refundable(aliceNode, NATIVE, bob), 0, "what the claim took reads as refundable");
    }

    /// A refund and the payee's claim racing: whichever lands first wins.
    function test_ACCEPTED_aRefundAndAClaimRaceAndTheFirstWins() public {
        _depositNative("alice", 1 ether);
        _bind(alice, "1", "alice", 100);
        uint256 staged = vm.snapshotState();

        vm.prank(sender);
        escrow.refund(aliceNode, NATIVE, sender);
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(HandleEscrow.NothingHeld.selector, aliceNode, NATIVE));
        escrow.claim(aliceNode, NATIVE, alice);

        vm.revertToState(staged);
        vm.prank(alice);
        escrow.claim(aliceNode, NATIVE, alice);
        vm.prank(sender);
        vm.expectRevert(abi.encodeWithSelector(HandleEscrow.NothingToRefund.selector, aliceNode, NATIVE, sender));
        escrow.refund(aliceNode, NATIVE, sender);
        assertEq(alice.balance, 1 ether);
    }

    /// A claim closes the round.
    function test_whatAClaimTookIsNeverRefundable() public {
        _depositNative("alice", 1 ether);
        _bind(alice, "1", "alice", 100);
        vm.prank(alice);
        escrow.claim(aliceNode, NATIVE, alice);

        _bind(alice, "1", "alice2", 200); // alice renames away: no holder again
        assertEq(escrow.refundable(aliceNode, NATIVE, sender), 0, "a claimed contribution reads as refundable");
        vm.prank(sender);
        vm.expectRevert(abi.encodeWithSelector(HandleEscrow.NothingToRefund.selector, aliceNode, NATIVE, sender));
        escrow.refund(aliceNode, NATIVE, sender);

        _depositNative("alice", 2 ether);
        assertEq(escrow.refundable(aliceNode, NATIVE, sender), 2 ether, "only the new deposit is refundable");
        vm.prank(sender);
        escrow.refund(aliceNode, NATIVE, sender);
        assertEq(escrow.escrowed(aliceNode, NATIVE), 0);
        assertEq(address(escrow).balance, 0);
    }

    /// A holder who never claimed and renamed away leaves a node with no holder, and every
    /// contribution it left is still refundable.
    function test_aRetiredHandlesUnclaimedContributionsStayRefundable() public {
        _depositNative("alice", 1 ether);
        _bind(alice, "1", "alice", 100);
        _bind(alice, "1", "alice2", 200);

        assertEq(escrow.refundable(aliceNode, NATIVE, sender), 1 ether);
        uint256 before = sender.balance;
        vm.prank(sender);
        escrow.refund(aliceNode, NATIVE, sender);
        assertEq(sender.balance, before + 1 ether);

        // Nothing is left for whoever proves the handle next.
        _bind(bob, "2", "alice", 300);
        vm.prank(bob);
        vm.expectRevert(abi.encodeWithSelector(HandleEscrow.NothingHeld.selector, aliceNode, NATIVE));
        escrow.claim(aliceNode, NATIVE, bob);
    }

    /// A contribution is what the escrow received, so the contributions in a slot add up to what it
    /// holds, and a refund returns what arrived.
    function test_aFeeOnTransferContributionIsWhatArrived() public {
        FeeToken fee = new FeeToken();
        fee.mint(sender, 100 ether);
        fee.mint(bob, 50 ether);
        vm.prank(sender);
        fee.approve(address(escrow), type(uint256).max);
        vm.prank(bob);
        fee.approve(address(escrow), type(uint256).max);

        vm.prank(sender);
        escrow.deposit(X, aliceHash, address(fee), 100 ether, sender);
        vm.prank(bob);
        escrow.deposit(X, aliceHash, address(fee), 50 ether, bob);

        assertEq(escrow.refundable(aliceNode, address(fee), sender), 99 ether, "booked what was asked for");
        assertEq(escrow.refundable(aliceNode, address(fee), bob), 49.5 ether, "booked what was asked for");
        assertEq(
            escrow.refundable(aliceNode, address(fee), sender) + escrow.refundable(aliceNode, address(fee), bob),
            escrow.escrowed(aliceNode, address(fee)),
            "the contributions do not add up to what is held"
        );
        assertEq(fee.balanceOf(address(escrow)), 148.5 ether);

        vm.prank(sender);
        escrow.refund(aliceNode, address(fee), sender);
        assertEq(fee.balanceOf(sender), 99 ether);
        vm.prank(bob);
        escrow.refund(aliceNode, address(fee), bob);
        assertEq(fee.balanceOf(bob), 49.5 ether);
        assertEq(fee.balanceOf(address(escrow)), 0, "a refund left value behind");
    }

    /// The same deposit through the hash path, the one no rules check: a refund is what makes a
    /// mistaken hash recoverable.
    function test_aHashDepositIsRefundable() public {
        bytes32 bobNode = _nodeX("bob");
        vm.prank(sender);
        escrow.deposit(X, keccak256("bob"), address(token), 10 ether, sender);

        vm.prank(sender);
        escrow.refund(bobNode, address(token), sender);
        assertEq(token.balanceOf(sender), 1_000 ether, "the tokens did not come back");
        assertEq(escrow.escrowed(bobNode, address(token)), 0);
    }

    /// A platform that stops accepting claims stops taking new escrow, and nothing could ever claim
    /// what it holds for an unheld node, so that value must still come back.
    function test_aPlatformThatAcceptsNoClaimsStillRefunds() public {
        _depositNative("alice", 1 ether);
        vm.prank(owner);
        proofVerifier.setVerifier(X, V1, IPlatformVerifier(address(0)));
        assertFalse(names.acceptsClaims(X), "the staging is wrong");

        vm.prank(sender);
        escrow.refund(aliceNode, NATIVE, sender);
        assertEq(escrow.escrowed(aliceNode, NATIVE), 0);
    }

    function test_aRefundToNobodyIsRefused() public {
        _depositNative("alice", 1 ether);

        vm.prank(sender);
        vm.expectRevert(abi.encodeWithSelector(HandleEscrow.BadRecipient.selector, address(0)));
        escrow.refund(aliceNode, NATIVE, address(0));

        assertEq(escrow.escrowed(aliceNode, NATIVE), 1 ether, "the slot was emptied");
        assertEq(escrow.refundable(aliceNode, NATIVE, sender), 1 ether);
        assertEq(address(0).balance, 0, "value was burned");
    }

    function test_aRefundBackIntoTheEscrowIsRefused() public {
        vm.prank(sender);
        escrow.deposit(X, aliceHash, address(token), 10 ether, sender);

        vm.prank(sender);
        vm.expectRevert(abi.encodeWithSelector(HandleEscrow.BadRecipient.selector, address(escrow)));
        escrow.refund(aliceNode, address(token), address(escrow));

        assertEq(escrow.escrowed(aliceNode, address(token)), 10 ether);
        assertEq(escrow.refundable(aliceNode, address(token), sender), 10 ether);
        assertEq(token.balanceOf(address(escrow)), 10 ether);
    }

    /// The payout goes to an address the depositor chose.
    function test_aReenteringRefunderCannotTakeTwice() public {
        ReenteringRefunder refunder = new ReenteringRefunder(escrow, X, aliceHash);
        refunder.fund{value: 1 ether}();
        _depositNative("alice", 1 ether); // not the refunder's

        vm.expectRevert(abi.encodeWithSelector(HandleEscrow.NativeTransferFailed.selector, address(refunder), 1 ether));
        refunder.take();

        assertEq(escrow.escrowed(aliceNode, NATIVE), 2 ether, "the slot moved");
        assertEq(escrow.refundable(aliceNode, NATIVE, address(refunder)), 1 ether);
        assertEq(escrow.refundable(aliceNode, NATIVE, sender), 1 ether, "somebody else's contribution moved");
        assertEq(address(escrow).balance, 2 ether);
        assertEq(address(refunder).balance, 0, "the refunder took anything at all");
    }

    /// The two defences of the refund payout, each observable alone: the contribution and the slot
    /// read settled while the payout runs, and a second refund from inside it is refused by the
    /// guard itself.
    function test_aRefundSettlesTheBooksBeforePayingAndTheGuardRefusesReentry() public {
        ObservingRefunder refunder = new ObservingRefunder(escrow, X, aliceHash);
        refunder.fund{value: 1 ether}();
        _depositNative("alice", 1 ether); // not the refunder's

        refunder.take();

        assertEq(refunder.refundableDuringPayout(), 0, "the contribution still read full while its payout ran");
        assertEq(refunder.heldDuringPayout(), 1 ether, "the slot still counted the refund while its payout ran");
        assertEq(
            refunder.reentryError(),
            abi.encodeWithSelector(ReentrancyGuardUpgradeable.ReentrancyGuardReentrantCall.selector),
            "the second refund was not refused by the guard"
        );
        assertEq(address(refunder).balance, 1 ether, "the refunder was paid other than once");
        assertEq(escrow.refundable(aliceNode, NATIVE, sender), 1 ether, "somebody else's contribution moved");
        assertEq(address(escrow).balance, 1 ether);
    }

    /// A token that calls `refund` again from inside the escrow's transfer is refused by the guard.
    function test_aTokenThatReentersRefundIsRefused() public {
        RefundReenteringToken hook = new RefundReenteringToken();
        hook.fund(escrow, X, aliceHash, 10 ether);
        hook.mint(sender, 10 ether);
        vm.startPrank(sender);
        hook.approve(address(escrow), type(uint256).max);
        escrow.deposit(X, aliceHash, address(hook), 10 ether, sender); // not the token's
        vm.stopPrank();

        vm.expectRevert(abi.encodeWithSelector(ReentrancyGuardUpgradeable.ReentrancyGuardReentrantCall.selector));
        hook.take();

        assertEq(escrow.escrowed(aliceNode, address(hook)), 20 ether);
        assertEq(escrow.refundable(aliceNode, address(hook), address(hook)), 10 ether);
        assertEq(hook.balanceOf(address(escrow)), 20 ether);
    }

    function test_aRefundIsAnnouncedWithItsPayload() public {
        _depositNative("alice", 1 ether);

        vm.expectEmit(true, true, true, true, address(escrow));
        emit HandleEscrow.Refunded(aliceNode, NATIVE, sender, bob, 1 ether, 1 ether);
        vm.prank(sender);
        escrow.refund(aliceNode, NATIVE, bob);
    }

    // ─── Consequences accepted on purpose ───────────────────────────

    /// NOT a vulnerability.
    function test_ACCEPTED_aRecycledHandlePaysTheNewHolder() public {
        // Escrowed while nobody held it, and never claimed.
        _depositNative("alice", 1 ether);
        _bind(alice, "1", "alice", 100);

        // The platform frees the handle: alice renames away, bob's account takes it.
        _bind(alice, "1", "alice2", 200);
        _bind(bob, "2", "alice", 300);

        vm.prank(bob);
        escrow.claim(aliceNode, NATIVE, bob);

        assertEq(bob.balance, 1 ether, "the new holder did not receive it");
    }

    /// NOT a vulnerability.
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

    /// A depositor is not the holder, so `claim` is not its way back; `refund` is.
    function test_theDepositorTakesItBackByRefundNotByClaim() public {
        _depositNative("alice", 1 ether);

        vm.prank(sender);
        vm.expectRevert(abi.encodeWithSelector(HandleEscrow.NotTheHolder.selector, address(0), sender));
        escrow.claim(aliceNode, NATIVE, sender);
        assertEq(escrow.escrowed(aliceNode, NATIVE), 1 ether);

        vm.prank(sender);
        escrow.refund(aliceNode, NATIVE, sender);
        assertEq(escrow.escrowed(aliceNode, NATIVE), 0);
    }

    /// Being the escrow's owner does not make it the holder, and no owner function moves a balance.
    function test_theOwnerHasNoFunctionThatMovesADeposit() public {
        _depositNative("alice", 1 ether);

        vm.prank(owner);
        vm.expectRevert(abi.encodeWithSelector(HandleEscrow.NotTheHolder.selector, address(0), owner));
        escrow.claim(aliceNode, NATIVE, owner);

        vm.prank(owner);
        vm.expectRevert(abi.encodeWithSelector(HandleEscrow.NothingToRefund.selector, aliceNode, NATIVE, owner));
        escrow.refund(aliceNode, NATIVE, owner);
    }

    /// A claim reads the holder of the node and nothing else, so the platform's current rules play
    /// no part in it.
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
        vm.expectRevert(
            abi.encodeWithSelector(IIdentityNames.UnusableHandle.selector, HandleNormalizer.Problem.BadChar)
        );
        escrow.nodeOf(X, "alice_9");
        vm.expectRevert(
            abi.encodeWithSelector(IIdentityNames.UnusableHandle.selector, HandleNormalizer.Problem.BadChar)
        );
        names.handleHashOf(X, "alice_9");

        // The node is untouched: still held, still funded.
        (address holder,) = names.byHandle(node);
        assertEq(holder, alice, "the binding moved");
        assertEq(escrow.escrowed(node, NATIVE), 1 ether, "the value moved");

        // Paid through by hash, and the holder claims what waited.
        vm.prank(sender);
        escrow.deposit{value: 2 ether}(X, keccak256("alice_9"), NATIVE, 2 ether, sender);
        vm.prank(alice);
        escrow.claim(node, NATIVE, alice);
        assertEq(alice.balance, 3 ether);
        assertEq(escrow.escrowed(node, NATIVE), 0);
    }

    // ─── Wiring ─────────────────────────────────────────────────────

    /// Repointing it would redirect every entitlement held, so there is no setter.
    function test_theNamingContractIsReadableAndHasNoSetter() public view {
        assertEq(address(escrow.names()), address(names));
    }

    function test_initializeRefusesAZeroNamingContract() public {
        HandleEscrow impl = new HandleEscrow();
        vm.expectRevert(HandleEscrow.NoNames.selector);
        new ERC1967Proxy(address(impl), abi.encodeCall(HandleEscrow.initialize, (owner, IIdentityNames(address(0)))));
    }

    /// An escrow wired to a naming contract that lacks what it calls is refused at `initialize`,
    /// naming the first function missing, rather than deploying and failing on its first deposit.
    function test_initializeRefusesANamingContractThatLacksWhatTheEscrowCalls() public {
        address old = address(new NamesBeforeTheEscrow());
        address halfway = address(new NamesWithoutNodeOf());
        address silent = address(new NamesWithASilentFallback());
        address noCode = makeAddr("no code");

        _assertInitializeRefused(old, IIdentityNames.acceptsClaims.selector);
        _assertInitializeRefused(halfway, IIdentityNames.nodeOf.selector);
        // A call that succeeds is not an answer: it must be one bool wide.
        _assertInitializeRefused(silent, IIdentityNames.acceptsClaims.selector);
        _assertInitializeRefused(noCode, IIdentityNames.byHandle.selector);
        // A zero word from a fallback is not a node, and a refusal other than `UnknownPlatform` is
        // not the naming system's.
        _assertInitializeRefused(address(new NamesWithAZeroFallback()), IIdentityNames.nodeOf.selector);
        _assertInitializeRefused(address(new NamesWithTheWrongRevert()), IIdentityNames.nodeOf.selector);
        // Deposits key through `nodeOfHash`, so it must exist and derive the node claims bind.
        _assertInitializeRefused(address(new NamesWithoutNodeOfHash()), IIdentityNames.nodeOfHash.selector);
        _assertInitializeRefused(address(new NamesWithAnotherNodeDerivation()), IIdentityNames.nodeOfHash.selector);
    }

    /// The implementation behind the proxy is never initialized: whoever could would own a contract
    /// that holds nothing, but could still call what an owner may.
    function test_theImplementationRefusesInitialize() public {
        HandleEscrow impl = new HandleEscrow();
        vm.expectRevert(Initializable.InvalidInitialization.selector);
        impl.initialize(owner, IIdentityNames(address(names)));
    }

    function _assertInitializeRefused(address names_, bytes4 missing) internal {
        HandleEscrow impl = new HandleEscrow();
        vm.expectRevert(abi.encodeWithSelector(HandleEscrow.NamesLacks.selector, names_, missing));
        new ERC1967Proxy(address(impl), abi.encodeCall(HandleEscrow.initialize, (owner, IIdentityNames(names_))));
    }

    function test_ownershipCannotBeRenounced() public {
        vm.prank(owner);
        vm.expectRevert(HandleEscrow.RenounceDisabled.selector);
        escrow.renounceOwnership();
        assertEq(escrow.owner(), owner, "ownership moved");
    }

    function test_onlyTheOwnerMayUpgrade() public {
        HandleEscrow next = new HandleEscrow();

        vm.prank(bob);
        vm.expectRevert();
        escrow.upgradeToAndCall(address(next), "");

        vm.prank(owner);
        escrow.upgradeToAndCall(address(next), "");
    }

    /// The balances have to survive it, or the upgrade is the theft the pause was refused to avoid.
    function test_balancesSurviveAnUpgrade() public {
        _depositNative("alice", 1 ether);
        // A second round, so the round counter and a closed round's contribution are both non-zero
        // to read back.
        _bind(alice, "1", "alice", 100);
        vm.prank(alice);
        escrow.claim(aliceNode, NATIVE, alice);
        _bind(alice, "1", "alice2", 200);
        _depositNative("alice", 1 ether);
        // A version that APPENDS a field, not a copy of the same bytecode: a byte-identical upgrade
        // cannot detect a reordered or removed one, which is the only mistake this test exists to
        // catch.
        HandleEscrowV2 next = new HandleEscrowV2();

        vm.prank(owner);
        escrow.upgradeToAndCall(address(next), "");

        HandleEscrowV2 upgraded = HandleEscrowV2(payable(address(escrow)));
        assertEq(upgraded.heldThroughV2(aliceNode, NATIVE), 1 ether, "the balance moved under the new layout");
        assertEq(upgraded.namesThroughV2(), address(names), "the naming pointer moved");
        assertEq(upgraded.roundThroughV2(aliceNode, NATIVE), 1, "the round moved under the new layout");
        assertEq(upgraded.contributionThroughV2(aliceNode, NATIVE, 0, sender), 1 ether, "a closed round moved");
        assertEq(upgraded.contributionThroughV2(aliceNode, NATIVE, 1, sender), 1 ether, "the open round moved");
        assertEq(upgraded.appended(), 0, "the appended field read somebody else's bytes");

        // The old surface still answers, and the new field is its own slot.
        assertEq(escrow.escrowed(aliceNode, NATIVE), 1 ether);
        upgraded.setAppended(7);
        assertEq(upgraded.appended(), 7);
        assertEq(escrow.escrowed(aliceNode, NATIVE), 1 ether, "writing the new field disturbed a balance");
        assertEq(escrow.refundable(aliceNode, NATIVE, sender), 1 ether, "writing the new field disturbed a refund");
    }

    /// OpenZeppelin's ERC-7201 root for the storage-based reentrancy guard,
    /// `openzeppelin.storage.ReentrancyGuard`.
    bytes32 internal constant GUARD_SLOT = 0x9b779b17422d0df92223018b32b4d1fa46e071723d6817e2486d003becc55f00;
    bytes32 internal constant ESCROW_ROOT = 0xfcca8d7d2c66f78c2760f3fcd99e0bf938b0aeb0d0b471f481dd50b8aff6b400;

    /// `initialize` arms the guard: its word reads NOT_ENTERED (1), and reads it again after a
    /// guarded call has run and returned.
    function test_initializeArmsTheReentrancyGuard() public {
        assertTrue(GUARD_SLOT != ESCROW_ROOT);
        assertEq(uint256(vm.load(address(escrow), GUARD_SLOT)), 1, "initialize did not arm the guard");
        _depositNative("alice", 1 ether);
        assertEq(uint256(vm.load(address(escrow), GUARD_SLOT)), 1, "a guarded call left the guard entered");
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
