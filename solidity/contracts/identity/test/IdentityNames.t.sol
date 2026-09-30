// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, Vm} from "forge-std/Test.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

import {HandleNormalizer} from "../HandleNormalizer.sol";
import {HandleVectors} from "../HandleVectors.sol";
import {IIdentityNames} from "../IIdentityNames.sol";
import {IdentityNames} from "../IdentityNames.sol";
import {IdentityNodes} from "../IdentityNodes.sol";
import {CeremonyProofVerifier} from "../../ceremony/CeremonyProofVerifier.sol";
import {IPlatformVerifier} from "../../ceremony/IPlatformVerifier.sol";
import {IProofVerifier} from "../../ceremony/IProofVerifier.sol";
import {StubPlatformVerifier} from "./StubPlatformVerifier.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";

/// @notice The identity contract, against a stubbed Platform Verifier.
///
/// @dev Every rule here belongs to the Consumer rather than to a platform, so
///      one stub proves them for both platforms at once. What a real Platform
///      Verifier checks — the attestations, the proof, the freshness window —
///      has its own suite.
contract IdentityNamesTest is Test {
    IdentityNames internal names;
    CeremonyProofVerifier internal proofVerifier;
    StubPlatformVerifier internal xVerifier;
    StubPlatformVerifier internal githubVerifier;

    bytes32 internal constant X = HandleVectors.PLATFORM_X;
    bytes32 internal constant GITHUB = HandleVectors.PLATFORM_GITHUB;

    address internal alice = makeAddr("alice");
    address internal bob = makeAddr("bob");
    address internal owner = makeAddr("owner");
    address internal mallory = makeAddr("mallory");

    function setUp() public {
        IdentityNames impl = new IdentityNames();
        names =
            IdentityNames(address(new ERC1967Proxy(address(impl), abi.encodeCall(IdentityNames.initialize, (owner)))));
        CeremonyProofVerifier pvImpl = new CeremonyProofVerifier();
        proofVerifier = CeremonyProofVerifier(
            address(new ERC1967Proxy(address(pvImpl), abi.encodeCall(CeremonyProofVerifier.initialize, (owner))))
        );
        xVerifier = new StubPlatformVerifier(X, 0);
        githubVerifier = new StubPlatformVerifier(GITHUB, 0);

        vm.startPrank(owner);
        names.setProofVerifier(IProofVerifier(address(proofVerifier)));
        _wire(X, address(xVerifier));
        _wire(GITHUB, address(githubVerifier));
        vm.stopPrank();

        // Observations are provider timestamps, so the chain has to be past
        // them for a proof to read as already-made rather than future-dated.
        vm.warp(1_000_000);
    }

    /// The version every platform's first verifier lands on.
    uint16 internal constant V1 = 1;

    /// Configure a platform's keyspace and its first verifier, the way a
    /// deployment does. Caller supplies the prank.
    function _wire(bytes32 platformId, address verifierAddr) internal {
        names.setPlatform(platformId, HandleVectors.rulesFor(platformId));
        proofVerifier.setVerifier(platformId, V1, IPlatformVerifier(verifierAddr));
    }

    /// Who the next submission's Authorized Transaction Data names.
    address private stagedTarget;

    /// A digest is spendable once, so every claim needs a nonce of its own.
    uint256 private nonce;

    /// Stage what the Platform Verifier reports, and who the submission names.
    ///
    /// @dev The stubs are written HERE rather than in `_claim`, because a test
    ///      pranks between the two and `vm.prank` is spent on the next external
    ///      call. Writing them later would spend it on the stub and send the
    ///      claim from the test contract.
    function _stage(string memory id, string memory handle, address target, uint64 at) internal {
        stagedTarget = target;
        xVerifier.set(id, handle);
        xVerifier.setObservedAt(at);
        githubVerifier.set(id, handle);
        githubVerifier.setObservedAt(at);
    }

    /// The stub's payload for the staged target, under the ceremony version
    /// the stub will echo back.
    function _payload(uint16 ceremonyVersion) internal returns (bytes memory) {
        return abi.encode(
            StubPlatformVerifier.StubPayload({
                ceremonyVersion: ceremonyVersion,
                // A literal, not `names.OPERATION_DOMAIN()`: reading it
                // is an external call, and it would spend the caller's prank.
                operationDomain: keccak256(bytes("libid.claim-identity")),
                authorizationNonce: bytes32(++nonce),
                // The free shape: these tests are about the binding rules, and
                // a ceremony composed by hand pays no application.
                transactionData: abi.encode(stagedTarget, uint256(0), address(0))
            })
        );
    }

    /// Submit the staged claim. The caller supplies the prank, the way a
    /// wallet supplies `msg.sender`.
    function _claim(bytes32 platformId, bool publish) internal {
        bytes memory payload = _payload(V1);
        names.bind(platformId, V1, payload, publish);
    }

    /// Stage a claim and bind it as `who`.
    function _bind(address who, string memory id, string memory handle, uint64 at) internal {
        _stage(id, handle, who, at);
        vm.prank(who);
        _claim(X, false);
    }

    // ─── Binding ────────────────────────────────────────────────────

    function test_bindWritesBothMappings() public {
        _bind(alice, "123", "alice", 100);

        assertEq(names.resolveId(X, "123"), alice, "the id does not resolve");
        assertEq(names.resolveHandle(X, "alice"), alice, "the handle does not resolve");
    }

    /// The write entry point is `bind`. The old `claim` selector reaches no
    /// function, since there is no fallback, so a caller built against the old
    /// ABI reverts; the payload it sent stays unspent and binds through `bind`.
    function test_theClaimSelectorIsGone() public {
        _stage("123", "alice", alice, 100);
        bytes memory payload = _payload(V1);

        vm.prank(alice);
        (bool ok,) =
            address(names).call(abi.encodeWithSignature("claim(bytes32,uint16,bytes,bool)", X, V1, payload, false));
        assertFalse(ok, "the claim selector still answers");
        assertEq(names.resolveHandle(X, "alice"), address(0));

        vm.prank(alice);
        names.bind(X, V1, payload, false);
        assertEq(names.resolveHandle(X, "alice"), alice, "the unspent payload does not bind");
    }

    /// The one authorization rule. A proof read from the mempool is useless to
    /// its reader, because spending it means being the address it names.
    function test_onlyTheProofsTargetMayBind() public {
        _stage("123", "alice", alice, 100);

        vm.prank(bob);
        vm.expectRevert(abi.encodeWithSelector(IdentityNames.NotProofTarget.selector, alice, bob));
        _claim(X, false);
    }

    /// Authorized Transaction Data naming nobody is data anybody could redirect
    /// at themselves. It is refused the same way any other address that is not
    /// the caller is.
    function test_aClaimWithNoTargetIsRefused() public {
        _stage("123", "alice", address(0), 100);

        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(IdentityNames.NotProofTarget.selector, address(0), alice));
        _claim(X, false);
    }

    function test_anUnconfiguredPlatformIsRefused() public {
        bytes32 unknown = keccak256("nowhere");
        _stage("123", "alice", alice, 100);

        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(IIdentityNames.UnknownPlatform.selector, unknown));
        _claim(unknown, false);
    }

    /// The handle is normalized on the way in, so the node comes from the same
    /// transform every reader uses.
    function test_theHandleIsNormalizedOnTheWayIn() public {
        _bind(alice, "123", " @Alice_1 ", 100);

        assertEq(names.resolveHandle(X, "alice_1"), alice);
        assertEq(names.resolveHandle(X, "@ALICE_1"), alice, "a reader's spelling should not matter");
    }

    // ─── The watermark ──────────────────────────────────────────────

    /// A proof held back must not undo a newer one. This is the case the
    /// watermark exists for.
    function test_anOlderProofCannotTakeAHandleBack() public {
        _bind(alice, "123", "shared", 100);

        // Bob proves the same handle later, which is a legitimate takeover.
        _bind(bob, "456", "shared", 200);
        assertEq(names.resolveHandle(X, "shared"), bob);

        // Alice submits a proof she was holding from before bob's.
        _stage("123", "shared", alice, 150);
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(IdentityNames.StaleProof.selector, uint64(150), uint64(200)));
        _claim(X, false);

        assertEq(names.resolveHandle(X, "shared"), bob, "the handle moved back");
    }

    /// Replaying the exact proof is refused by the same rule, because equal is
    /// not newer. That is why the contract needs no nullifier.
    function test_replayingAProofIsRefused() public {
        _bind(alice, "123", "alice", 100);

        _stage("123", "alice", alice, 100);
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(IdentityNames.StaleProof.selector, uint64(100), uint64(100)));
        _claim(X, false);
    }

    /// A rename keeps the id and takes a new handle. A rename is invisible to
    /// the chain until somebody proves the new state, and this second bind is
    /// that proof — so the handle the identity left has to stop resolving, or a
    /// payment meant for whoever has it now goes to the wallet that renamed
    /// away from it.
    function test_aRenameRetiresTheHandleTheIdentityLeft() public {
        _bind(alice, "123", "alice", 100);
        _bind(alice, "123", "alice2", 200);

        assertEq(names.resolveId(X, "123"), alice, "the id follows the identity");
        assertEq(names.resolveHandle(X, "alice2"), alice);
        assertEq(names.resolveHandle(X, "alice"), address(0), "the handle it left no longer resolves");
    }

    /// Only the entry this identity itself wrote. One wallet may have two
    /// identities on a platform, and the second may have taken the handle the
    /// first released — retiring that would delete a binding nobody renamed.
    function test_aRetirementSkipsAHandleAnotherIdentityHasSinceTaken() public {
        _bind(alice, "123", "shared", 100);
        // A second identity, same wallet, takes the handle the first had.
        _bind(alice, "456", "shared", 200);
        // Now the first identity renames. Its own record still names "shared".
        _bind(alice, "123", "renamed", 300);

        assertEq(names.resolveHandle(X, "shared"), alice, "the second identity keeps it");
        assertEq(names.resolveHandle(X, "renamed"), alice);
    }

    /// Retiring clears the wallet and keeps the watermark. Deleting the whole
    /// record would return the node to `observedAt == 0` and let a proof older
    /// than the retired one take it.
    function test_aRetiredHandleStillOutranksAnOlderProof() public {
        _bind(alice, "123", "alice", 200);
        _bind(alice, "123", "alice2", 300);

        _stage("456", "alice", bob, 100);
        vm.prank(bob);
        vm.expectRevert(abi.encodeWithSelector(IdentityNames.StaleProof.selector, uint64(100), uint64(200)));
        _claim(X, false);
    }

    /// And a newer proof takes it as usual, so retiring frees the handle rather
    /// than burning it.
    function test_aRetiredHandleIsFreeForANewerProof() public {
        _bind(alice, "123", "alice", 100);
        _bind(alice, "123", "alice2", 200);
        _bind(bob, "456", "alice", 300);

        assertEq(names.resolveHandle(X, "alice"), bob);
    }

    /// A proof with no observation time cannot be ordered against any other, so
    /// it is refused rather than treated as the oldest.
    function test_aProofWithNoObservationTimeIsRefused() public {
        _stage("123", "alice", alice, 0);
        vm.prank(alice);
        vm.expectRevert(IdentityNames.NoObservationTime.selector);
        _claim(X, false);
    }

    /// Every shipped verifier refuses an empty id already. This is what keeps
    /// that true for a verifier written later: without it, every identity such a
    /// verifier reported would land on the single node `idNode(platformId, "")`
    /// and each would take it from the one before.
    function test_aClaimWithNoIdIsRefused() public {
        _stage("", "alice", alice, 100);
        vm.prank(alice);
        vm.expectRevert(IdentityNames.NoId.selector);
        _claim(X, false);
    }

    // ─── Platform configuration ─────────────────────────────────────

    // ─── The freshness signal ───────────────────────────────────────

    /// All three resolvers answer an unwired platform the same way. A zero
    /// address would tell a caller "nobody proved this" when the truth is
    /// that the platform is not configured, and a zero cannot say which.
    function test_everyResolverRefusesAnUnknownPlatform() public {
        bytes32 unwired = keccak256("nowhere");

        vm.expectRevert(abi.encodeWithSelector(IIdentityNames.UnknownPlatform.selector, unwired));
        names.resolveId(unwired, "123");

        vm.expectRevert(abi.encodeWithSelector(IIdentityNames.UnknownPlatform.selector, unwired));
        names.resolveHandle(unwired, "alice");

        vm.expectRevert(abi.encodeWithSelector(IIdentityNames.UnknownPlatform.selector, unwired));
        names.resolveHandleAndId(unwired, "alice", "123");

        vm.expectRevert(abi.encodeWithSelector(IIdentityNames.UnknownPlatform.selector, unwired));
        names.rulesOf(unwired);
        vm.expectRevert(abi.encodeWithSelector(IIdentityNames.UnknownPlatform.selector, unwired));
        names.handleHashOf(unwired, "alice");
        vm.expectRevert(abi.encodeWithSelector(IIdentityNames.UnknownPlatform.selector, unwired));
        names.handleNodeOf(unwired, "alice");
    }

    /// `rulesOf` reports the rules as set now, `handleHashOf` is `keccak256` of the handle
    /// normalized under them, and `handleNodeOf`/`handleNodeOfHash` name the node a proof of it
    /// binds.
    function test_theKeyspaceViewsAgreeWithWhatAClaimBinds() public {
        assertEq(names.rulesOf(X).maxLength, HandleVectors.rulesFor(X).maxLength);
        bytes32 handleHash = names.handleHashOf(X, "  @Alice ");
        assertEq(handleHash, keccak256("alice"));
        assertEq(names.handleNodeOf(X, "  @Alice "), names.handleNodeOfHash(X, handleHash));
        assertEq(names.handleNodeOfHash(X, handleHash), IdentityNodes.handleNode(X, "alice"));

        _bind(alice, "123", "alice", 100);
        (address wallet,) = names.handleBinding(names.handleNodeOfHash(X, handleHash));
        assertEq(wallet, alice);
    }

    /// Text the rules of the moment refuse reverts with the normalizer's reason, where
    /// `resolveHandle` answers nobody.
    function test_theKeyspaceViewsRefuseWhatTheCurrentRulesRefuse() public {
        bytes memory badChar =
            abi.encodeWithSelector(IIdentityNames.UnusableHandle.selector, HandleNormalizer.Problem.BadChar);
        vm.expectRevert(badChar);
        names.handleHashOf(X, "ali-ce");
        vm.expectRevert(badChar);
        names.handleNodeOf(X, "ali-ce");
        assertEq(names.resolveHandle(X, "ali-ce"), address(0));

        vm.prank(owner);
        names.setPlatform(X, HandleVectors.rulesFor(GITHUB));
        assertTrue(names.rulesOf(X).allowHyphen);
        assertEq(names.handleHashOf(X, "ali-ce"), keccak256("ali-ce"));
        vm.expectRevert(badChar);
        names.handleNodeOf(X, "alice_1");
    }

    function test_resolveHandleAndIdAgreesWhileOneIdentityHasBoth() public {
        _bind(alice, "123", "alice", 100);

        (address wallet, bool agrees) = names.resolveHandleAndId(X, "alice", "123");
        assertEq(wallet, alice);
        assertTrue(agrees, "one identity has both, so they must agree");
    }

    /// The case the two mappings exist for: a consumer has a pair from two
    /// different moments, and the chain can say so.
    function test_resolveHandleAndIdReportsAHandleThatChangedHands() public {
        _bind(alice, "123", "shared", 100);
        _bind(bob, "456", "shared", 200);

        (address wallet, bool agrees) = names.resolveHandleAndId(X, "shared", "123");
        assertEq(wallet, bob, "the handle routes to whoever proved it last");
        assertFalse(agrees, "the caller's id belongs to a different wallet now");
    }

    /// An id the chain has never seen leaves a caller exactly as uninformed as
    /// a stale one, so it does not agree either.
    function test_resolveHandleAndIdDoesNotAgreeOnAnUnknownId() public {
        _bind(alice, "123", "alice", 100);

        (address wallet, bool agrees) = names.resolveHandleAndId(X, "alice", "999");
        assertEq(wallet, alice);
        assertFalse(agrees);
    }

    // ─── Reverse resolution ─────────────────────────────────────────

    function test_publishingIsOptional() public {
        _bind(alice, "123", "alice", 100);
        assertEq(bytes(names.publishedHandleOf(alice, X)).length, 0, "nothing should be published by default");

        _stage("123", "alice", alice, 200);
        vm.prank(alice);
        _claim(X, true);
        assertEq(names.publishedHandleOf(alice, X), "alice");
    }

    /// Publishing is the one thing here a wallet can undo, and it must not
    /// depend on being able to log in again: for Google the published handle is
    /// an email address, and withdrawing it should not require a fresh proof.
    function test_aPublishedHandleCanBeWithdrawn() public {
        _stage("123", "alice", alice, 100);
        vm.prank(alice);
        _claim(X, true);
        assertEq(names.publishedHandleOf(alice, X), "alice");

        vm.prank(alice);
        names.unpublish(X);
        assertEq(bytes(names.publishedHandleOf(alice, X)).length, 0);
    }

    /// The binding survives. This withdraws a displayed string, not the proof
    /// of which wallet the identity is bound to.
    function test_withdrawingAPublishedHandleKeepsTheBinding() public {
        _stage("123", "alice", alice, 100);
        vm.prank(alice);
        _claim(X, true);

        vm.prank(alice);
        names.unpublish(X);

        assertEq(names.resolveId(X, "123"), alice);
        assertEq(names.resolveHandle(X, "alice"), alice);
    }

    /// Binding again with `publish: false` must NOT withdraw an earlier
    /// publish — a caller re-proving after a rename should not silently drop a
    /// handle because a flag defaulted, and withdrawing has its own door. It
    /// must not leave the OLD handle on display either: the wallet just proved
    /// it has a different one.
    function test_bindingAgainRefreshesAPublishedHandleRatherThanWithdrawingIt() public {
        _stage("123", "alice", alice, 100);
        vm.prank(alice);
        _claim(X, true);

        _stage("123", "alice2", alice, 200);
        vm.prank(alice);
        _claim(X, false);

        assertEq(names.publishedHandleOf(alice, X), "alice2", "the display follows the handle it has");
    }

    /// The complement: a wallet that never published does not start now.
    function test_bindingWithoutPublishingStillPublishesNothing() public {
        _bind(alice, "123", "alice", 100);
        _bind(alice, "123", "alice2", 200);

        assertEq(names.publishedHandleOf(alice, X), "", "nothing was ever on display");
    }

    /// An indexer mirrors the published handles from the log alone, so the log
    /// has to say whether the handle is on display. Only `unpublish` is
    /// observable otherwise, and a publish would have to be guessed.
    function test_theLogSaysWhetherTheHandleIsPublished() public {
        _stage("123", "alice", alice, 100);
        vm.recordLogs();
        vm.prank(alice);
        _claim(X, true);
        assertTrue(_lastBindPublished(), "published");

        _stage("456", "bob", bob, 100);
        vm.recordLogs();
        vm.prank(bob);
        _claim(X, false);
        assertFalse(_lastBindPublished(), "not published");
    }

    /// The refresh is observable too, or an indexer would still show the
    /// handle the wallet renamed away from.
    function test_theLogSaysPublishedWhenARefreshKeepsTheHandleOnDisplay() public {
        _stage("123", "alice", alice, 100);
        vm.prank(alice);
        _claim(X, true);

        _stage("123", "alice2", alice, 200);
        vm.recordLogs();
        vm.prank(alice);
        _claim(X, false);

        assertTrue(_lastBindPublished(), "the flag was false, the handle is still on display");
    }

    /// The `published` flag and the ceremony version out of the last
    /// `IdentityBound` in the recorded logs.
    function _lastBind() internal view returns (bool published, uint16 ceremonyVersion) {
        Vm.Log[] memory logs = vm.getRecordedLogs();
        bytes32 topic = keccak256("IdentityBound(address,bytes32,bytes32,bytes32,string,string,uint64,bool,uint16)");
        for (uint256 i = logs.length; i > 0; i--) {
            if (logs[i - 1].topics[0] != topic) continue;
            (,,,, published, ceremonyVersion) =
                abi.decode(logs[i - 1].data, (bytes32, string, string, uint64, bool, uint16));
            return (published, ceremonyVersion);
        }
        revert("no IdentityBound in the logs");
    }

    function _lastBindPublished() internal view returns (bool published) {
        (published,) = _lastBind();
    }

    /// One wallet's withdrawal is its own. There is no path to another's.
    function test_withdrawingTouchesOnlyTheCallersRecord() public {
        _stage("123", "alice", alice, 100);
        vm.prank(alice);
        _claim(X, true);

        vm.prank(mallory);
        names.unpublish(X);

        assertEq(names.publishedHandleOf(alice, X), "alice");
    }

    /// The forward check ENS requires of its integrators, done here so an
    /// integrator cannot skip it.
    function test_publishedHandleOfGoesEmptyOnceTheHandleMovesOn() public {
        _stage("123", "shared", alice, 100);
        vm.prank(alice);
        _claim(X, true);
        assertEq(names.publishedHandleOf(alice, X), "shared", "it resolves back, so it stands");

        // Bob proves the same handle. Alice's published handle is now bound to
        // somebody else, though nothing rewrote her record.
        _bind(bob, "456", "shared", 200);
        assertEq(names.publishedHandleOf(alice, X), "", "it no longer resolves back");

        // Proving it back without publishing finds the record still set.
        _stage("123", "shared", alice, 300);
        vm.prank(alice);
        _claim(X, false);
        assertEq(names.publishedHandleOf(alice, X), "shared", "the record was untouched");
    }

    // ─── A wallet's identities ──────────────────────────────────────

    /// Every identity bound to a wallet, in one read.
    function _identities(address wallet) internal view returns (IdentityNames.Identity[] memory) {
        return names.identitiesOf(wallet, 0, names.identityCount(wallet));
    }

    function _is(IdentityNames.Identity memory a, bytes32 platformId, string memory id) internal pure returns (bool) {
        return a.platformId == platformId && keccak256(bytes(a.id)) == keccak256(bytes(id));
    }

    /// Whether a page carries this identity.
    function _carries(IdentityNames.Identity[] memory page, bytes32 platformId, string memory id)
        internal
        pure
        returns (bool)
    {
        for (uint256 i = 0; i < page.length; i++) {
            if (_is(page[i], platformId, id)) return true;
        }
        return false;
    }

    /// The listed identity. Order is arbitrary, so a test that wants one
    /// identity finds it by what identifies it.
    function _identity(address wallet, bytes32 platformId, string memory id)
        internal
        view
        returns (IdentityNames.Identity memory)
    {
        IdentityNames.Identity[] memory all = _identities(wallet);
        for (uint256 i = 0; i < all.length; i++) {
            if (_is(all[i], platformId, id)) return all[i];
        }
        revert("not listed");
    }

    function test_aClaimListsTheIdentityWithItsPlatformIdAndHandle() public {
        _bind(alice, "123", "alice", 100);

        assertEq(names.identityCount(alice), 1);
        IdentityNames.Identity memory a = _identity(alice, X, "123");
        assertEq(a.handle, "alice");
        assertTrue(a.handleCurrent);
        assertEq(names.identityCount(bob), 0, "each wallet keeps its own list");
    }

    function test_identitiesOnEveryPlatformShareOneList() public {
        _bind(alice, "123", "alice", 100);
        _stage("123", "alice", alice, 200);
        vm.prank(alice);
        _claim(GITHUB, false);

        assertEq(names.identityCount(alice), 2);
        assertTrue(_identity(alice, X, "123").handleCurrent);
        assertTrue(_identity(alice, GITHUB, "123").handleCurrent);
    }

    function test_theListedHandleIsTheNormalizedOne() public {
        _bind(alice, "123", "@Alice", 100);
        assertEq(_identity(alice, X, "123").handle, "alice");
    }

    function test_aWalletMayHaveSeveralIdentitiesOnOnePlatform() public {
        _bind(alice, "123", "alice", 100);
        _bind(alice, "456", "alicia", 200);

        assertEq(names.identityCount(alice), 2);
        assertEq(_identity(alice, X, "123").handle, "alice");
        assertEq(_identity(alice, X, "456").handle, "alicia");
    }

    function test_aRenameMovesTheHandleAndKeepsOneEntry() public {
        _bind(alice, "123", "alice", 100);
        _bind(alice, "123", "alicia", 200);

        assertEq(names.identityCount(alice), 1);
        IdentityNames.Identity memory a = _identity(alice, X, "123");
        assertEq(a.handle, "alicia");
        assertTrue(a.handleCurrent);
    }

    function test_provingTheSameHandleAgainListsNothingTwice() public {
        _bind(alice, "123", "alice", 100);
        _bind(alice, "123", "alice", 200);
        assertEq(names.identityCount(alice), 1);
    }

    /// The list is alice's: bob taking her handle changes what it resolves
    /// to, and the entry says so, but the entry is still there with the
    /// handle her identity was last known by.
    function test_aHandleTakenElsewhereStaysListedAsStale() public {
        _bind(alice, "123", "shared", 100);
        _bind(bob, "456", "shared", 200);

        assertEq(names.identityCount(alice), 1);
        IdentityNames.Identity memory a = _identity(alice, X, "123");
        assertEq(a.handle, "shared");
        assertFalse(a.handleCurrent, "the handle resolves to bob now");
        assertTrue(_identity(bob, X, "456").handleCurrent);
    }

    /// The handle node is still bound to the wallet, through the other
    /// identity. A wallet check alone would call both identities current.
    function test_aSecondIdentityOfTheSameWalletTakingTheHandleIsToldApart() public {
        _bind(alice, "123", "first", 100);
        _bind(alice, "456", "second", 200);
        _bind(alice, "456", "first", 300);

        assertEq(names.identityCount(alice), 2);
        assertFalse(_identity(alice, X, "123").handleCurrent);
        IdentityNames.Identity memory second = _identity(alice, X, "456");
        assertEq(second.handle, "first");
        assertTrue(second.handleCurrent);
    }

    function test_anIdentityProvedFromANewWalletMovesBetweenLists() public {
        _bind(alice, "123", "alice", 100);
        _bind(bob, "123", "alice", 200);

        assertEq(names.identityCount(alice), 0);
        assertEq(names.identityCount(bob), 1);
        assertTrue(_identity(bob, X, "123").handleCurrent);
    }

    function test_leavingFromTheMiddleKeepsTheOthersListed() public {
        _bind(alice, "1", "one", 100);
        _bind(alice, "2", "two", 200);
        _bind(alice, "3", "three", 300);
        _bind(bob, "2", "two", 400);

        assertEq(names.identityCount(alice), 2);
        assertEq(_identity(alice, X, "1").handle, "one");
        assertEq(_identity(alice, X, "3").handle, "three");
        assertEq(_identity(bob, X, "2").handle, "two");

        // And back: an identity returns to a list it left.
        _bind(alice, "2", "two", 500);
        assertEq(names.identityCount(alice), 3);
        assertEq(names.identityCount(bob), 0);
        assertEq(_identity(alice, X, "2").handle, "two");
    }

    function test_pagesClipToTheList() public {
        _bind(alice, "1", "one", 100);
        _bind(alice, "2", "two", 200);
        _bind(alice, "3", "three", 300);

        assertEq(names.identitiesOf(alice, 0, 2).length, 2);
        assertEq(names.identitiesOf(alice, 2, 5).length, 1, "clipped at the end");
        assertEq(names.identitiesOf(alice, 3, 1).length, 0, "past the end is empty, not a revert");
        assertEq(names.identitiesOf(alice, 0, 0).length, 0);
        assertEq(names.identitiesOf(alice, 1, type(uint256).max).length, 2, "a limit past the end is clipped too");

        // Two pages cover the list once each.
        IdentityNames.Identity[] memory first = names.identitiesOf(alice, 0, 2);
        IdentityNames.Identity[] memory second = names.identitiesOf(alice, 2, 2);
        assertEq(second.length, 1);
        assertTrue(_carries(first, X, "1") != _carries(second, X, "1"));
        assertTrue(_carries(first, X, "2") != _carries(second, X, "2"));
        assertTrue(_carries(first, X, "3") != _carries(second, X, "3"));
    }

    /// The flag reads the nodes. Narrowing a platform's rules moves its
    /// handles to other nodes, which `resolveHandle` sees at once and the list
    /// does not.
    function test_handleCurrentReadsTheNodesNotTheRules() public {
        _bind(alice, "123", "with_score", 100);
        HandleNormalizer.Rules memory rules = HandleVectors.rulesFor(X);
        rules.allowUnderscore = false;
        vm.prank(owner);
        names.setPlatform(X, rules);

        assertEq(names.resolveHandle(X, "with_score"), address(0));
        assertTrue(_identity(alice, X, "123").handleCurrent);
    }

    /// After any sequence of claims: an identity nobody proved is in no
    /// list, an identity somebody proved is in exactly one, the list of the
    /// wallet whose proof of it is newest, and a handle reported current
    /// resolves to that wallet and is current for no second identity.
    function testFuzz_everyProvedIdentitySitsInExactlyOneList(bytes memory script) public {
        address[3] memory wallets = [alice, bob, mallory];
        bytes32[2] memory platforms = [X, GITHUB];
        string[4] memory ids = ["1", "2", "3", "4"];
        string[4] memory handles = ["one", "two", "three", "four"];

        uint64 at = 100;
        for (uint256 i = 0; i + 1 < script.length && i < 64; i += 2) {
            uint256 a = uint8(script[i]);
            uint256 b = uint8(script[i + 1]);
            address who = wallets[a % 3];
            _stage(ids[b % 4], handles[(b / 4) % 4], who, ++at);
            vm.prank(who);
            _claim(platforms[(a / 3) % 2], false);
        }

        uint256 listed;
        IdentityNames.Identity[] memory current = new IdentityNames.Identity[](wallets.length * ids.length * 2);
        uint256 currents;
        for (uint256 w = 0; w < wallets.length; w++) {
            IdentityNames.Identity[] memory page = _identities(wallets[w]);
            listed += page.length;
            for (uint256 i = 0; i < page.length; i++) {
                assertEq(names.resolveId(page[i].platformId, page[i].id), wallets[w], "listed under its prover");
                for (uint256 j = 0; j < i; j++) {
                    assertFalse(_is(page[j], page[i].platformId, page[i].id), "listed once");
                }
                if (page[i].handleCurrent) {
                    assertEq(
                        names.resolveHandle(page[i].platformId, page[i].handle), wallets[w], "current, so it resolves"
                    );
                    current[currents++] = page[i];
                }
            }
        }
        for (uint256 i = 0; i < currents; i++) {
            for (uint256 j = 0; j < i; j++) {
                bool sameHandle = current[i].platformId == current[j].platformId
                    && keccak256(bytes(current[i].handle)) == keccak256(bytes(current[j].handle));
                assertFalse(sameHandle, "a handle is current for one identity");
            }
        }

        uint256 proved;
        for (uint256 p = 0; p < platforms.length; p++) {
            for (uint256 i = 0; i < ids.length; i++) {
                if (names.resolveId(platforms[p], ids[i]) != address(0)) proved++;
            }
        }
        assertEq(listed, proved, "every proved identity is listed, and nothing else");
    }

    // ─── Reading is total in the handle ─────────────────────────────

    /// A contract resolving whatever was typed must not have its whole
    /// transaction reverted by a stray space, with a library error it cannot
    /// tell apart from `UnknownPlatform`. Text the rules refuse answers the
    /// zero address, which is the same answer as a handle nobody proved.
    function test_resolvingTextTheRulesRefuseAnswersNobody() public view {
        assertEq(names.resolveHandle(X, "ali ce"), address(0), "a stray space");
        assertEq(names.resolveHandle(X, unicode"aliçe"), address(0), "a byte above 0x7f");
        assertEq(names.resolveHandle(X, ""), address(0), "nothing at all");
        assertEq(names.resolveHandle(X, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"), address(0), "too long");
        assertEq(names.resolveHandle(GITHUB, "-octocat"), address(0), "an arrangement the platform refuses");
    }

    /// `resolveHandleAndId` matters more: its documented job is to let a
    /// caller decide what to tell whoever is paying, not to refuse.
    function test_resolveHandleAndIdAnswersRatherThanRevertingOnAMalformedHandle() public view {
        (address wallet, bool idAgrees) = names.resolveHandleAndId(X, "ali ce", "123");
        assertEq(wallet, address(0));
        assertFalse(idAgrees);
    }

    /// An unwired platform still reverts. Zero would answer "nobody proved
    /// this" to a question that was never asked, and the caller cannot tell the
    /// two apart from an address.
    function test_anUnwiredPlatformStillReverts() public {
        bytes32 unknown = keccak256("nowhere");
        vm.expectRevert(abi.encodeWithSelector(IIdentityNames.UnknownPlatform.selector, unknown));
        names.resolveHandle(unknown, "alice");
    }

    /// `bind` keeps reverting. A handle that arrives inside a proof and does
    /// not normalize is a broken proof, and failing loudly is right.
    function test_claimStillRefusesAHandleThatDoesNotNormalize() public {
        _stage("123", "ali ce", alice, 100);
        vm.prank(alice);
        vm.expectRevert(HandleNormalizer.BadCharacter.selector);
        _claim(X, false);
    }

    /// After the owner narrows a platform's rules, an already-written handle
    /// sits on a node the forward resolver can no longer name.
    /// `publishedHandleOf` must go with it: handing out a handle
    /// `resolveHandle` refuses would contradict both its own promise and the
    /// statement that entries moved by a rules change no longer answer the
    /// public resolvers.
    function test_publishedHandleOfGoesEmptyWhenTheRulesNoLongerAllowTheHandle() public {
        _stage("123", "octo-cat", alice, 100);
        vm.prank(alice);
        _claim(GITHUB, true);
        assertEq(names.publishedHandleOf(alice, GITHUB), "octo-cat");

        HandleNormalizer.Rules memory narrowed = HandleVectors.rulesFor(GITHUB);
        narrowed.allowHyphen = false;
        vm.prank(owner);
        names.setPlatform(GITHUB, narrowed);

        assertEq(names.resolveHandle(GITHUB, "octo-cat"), address(0), "the forward resolver cannot name it");
        assertEq(names.publishedHandleOf(alice, GITHUB), "", "so neither does the reverse one");

        vm.prank(owner);
        names.setPlatform(GITHUB, HandleVectors.rulesFor(GITHUB));
        assertEq(names.publishedHandleOf(alice, GITHUB), "octo-cat", "the record was untouched");
    }

    // ─── Node separation ────────────────────────────────────────────

    /// A numeric handle and an id of the same digits must not collide.
    /// Numeric handles are legal on X and old ids are short, so this is
    /// reachable rather than theoretical.
    function test_aNumericHandleDoesNotCollideWithAnId() public {
        assertTrue(
            IdentityNodes.idNode(X, "12345") != IdentityNodes.handleNode(X, "12345"),
            "an id node and a handle node collided"
        );

        _bind(alice, "12345", "bob", 100);
        _bind(bob, "999", "12345", 100);

        assertEq(names.resolveId(X, "12345"), alice, "the id belongs to alice");
        assertEq(names.resolveHandle(X, "12345"), bob, "the handle belongs to bob");
    }

    /// The same text on two platforms is two identities.
    function test_platformsDoNotShareAKeyspace() public {
        _bind(alice, "123", "alice", 100);

        _stage("123", "alice", bob, 100);
        vm.prank(bob);
        _claim(GITHUB, false);

        assertEq(names.resolveHandle(X, "alice"), alice);
        assertEq(names.resolveHandle(GITHUB, "alice"), bob);
    }

    // ─── Proof versions ─────────────────────────────────────────────
    //
    // A platform's proof can change shape without the identity behind it
    // changing — X gaining OIDC, say. Both formats have to be accepted during
    // a migration, so the Proof Verifier keys its verifiers by version and
    // the keyspace is not keyed at all.

    /// A binding belongs to the identity that proved it, not to the format the
    /// proof was written in. Removing a version from the Supported Version Set
    /// must not unbind anybody.
    function test_retiringAVersionLeavesItsBindingsResolving() public {
        _bind(alice, "123", "alice", 100);

        vm.prank(owner);
        proofVerifier.setVerifier(X, V1, IPlatformVerifier(address(0)));

        assertEq(names.resolveHandle(X, "alice"), alice, "the binding went with the format");
        assertEq(names.resolveId(X, "123"), alice);
    }

    /// Which ceremony version proved a binding is logged and never stored.
    /// By the time anybody asks, the proof has happened and the effect has
    /// been applied; the question is an operator's, and the log answers it.
    /// The binding itself is a wallet and a watermark, nothing more.
    function test_theLogRecordsWhichCeremonyVersionProvedIt() public {
        StubPlatformVerifier v2 = new StubPlatformVerifier(X, 0);
        vm.prank(owner);
        proofVerifier.setVerifier(X, 2, IPlatformVerifier(address(v2)));

        _stage("456", "bob", bob, 100);
        v2.set("456", "bob");
        v2.setObservedAt(100);
        vm.recordLogs();

        bytes memory payload = _payload(2);
        vm.prank(bob);
        names.bind(X, 2, payload, false);

        (address idWallet, uint64 idAt) = names.idBinding(IdentityNodes.idNode(X, "456"));
        (address handleWallet, uint64 handleAt) = names.handleBinding(IdentityNodes.handleNode(X, "bob"));
        assertEq(idWallet, bob, "the id node");
        assertEq(handleWallet, bob, "the handle node");
        assertEq(idAt, 100);
        assertEq(handleAt, 100);

        (, uint16 logged) = _lastBind();
        assertEq(logged, 2, "the log an indexer reads");
    }

    // ─── A platform is not usable until it can verify ───────────────

    /// Between `setPlatform` and `setVerifier` a platform has a keyspace and
    /// can verify nothing. Answering `address(0)` there would tell a caller
    /// "nobody proved this" about a platform that is not wired yet.
    function test_aPlatformWithoutAVerifierDoesNotResolve() public {
        bytes32 fresh = keccak256("fresh");
        vm.prank(owner);
        names.setPlatform(fresh, HandleVectors.rulesFor(X));

        vm.expectRevert(abi.encodeWithSelector(IIdentityNames.UnknownPlatform.selector, fresh));
        names.resolveId(fresh, "123");

        vm.expectRevert(abi.encodeWithSelector(IIdentityNames.UnknownPlatform.selector, fresh));
        names.resolveHandle(fresh, "alice");

        vm.expectRevert(abi.encodeWithSelector(IIdentityNames.UnknownPlatform.selector, fresh));
        names.resolveHandleAndId(fresh, "alice", "123");

        // The keyspace questions answer, and agree with each other: a client
        // normalizing under `rulesOf` reaches the node `handleNodeOf` names.
        assertEq(names.rulesOf(fresh).maxLength, HandleVectors.rulesFor(X).maxLength);
        assertEq(names.handleHashOf(fresh, "Alice"), keccak256("alice"));
        assertEq(names.handleNodeOf(fresh, "Alice"), names.handleNodeOfHash(fresh, keccak256("alice")));
    }

    /// And claiming says the same thing, rather than naming a version the
    /// caller never chose. The keyspace exists here, so the Consumer lets the
    /// claim through and the Proof Verifier is the one with nothing to
    /// dispatch to.
    function test_claimingAPlatformWithoutAVerifierIsRefused() public {
        bytes32 fresh = keccak256("fresh");
        vm.prank(owner);
        names.setPlatform(fresh, HandleVectors.rulesFor(X));

        _stage("123", "alice", alice, 100);
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(CeremonyProofVerifier.UnknownVersion.selector, fresh, V1));
        _claim(fresh, false);
    }

    /// A new claim can bind only with a keyspace and a verifier the Proof Verifier answers for;
    /// retiring the last version stops new claims while bound identities keep resolving.
    function test_acceptsBindingsNeedsAKeyspaceAndAVerifier() public {
        assertTrue(names.acceptsBindings(X));
        (bytes32 noKeyspace, bytes32 noVerifier) = (keccak256("no keyspace"), keccak256("no verifier"));
        StubPlatformVerifier verifier = new StubPlatformVerifier(noKeyspace, 0);
        vm.startPrank(owner);
        proofVerifier.setVerifier(noKeyspace, V1, IPlatformVerifier(address(verifier)));
        names.setPlatform(noVerifier, HandleVectors.rulesFor(X));
        vm.stopPrank();
        assertFalse(names.acceptsBindings(noKeyspace));
        assertFalse(names.acceptsBindings(noVerifier));

        IdentityNames bare = IdentityNames(
            address(new ERC1967Proxy(address(new IdentityNames()), abi.encodeCall(IdentityNames.initialize, (owner))))
        );
        vm.prank(owner);
        bare.setPlatform(X, HandleVectors.rulesFor(X));
        assertEq(address(bare.proofVerifier()), address(0));
        assertFalse(bare.acceptsBindings(X), "no Proof Verifier");

        _bind(alice, "123", "alice", 100);
        vm.prank(owner);
        proofVerifier.setVerifier(X, V1, IPlatformVerifier(address(0)));
        assertFalse(names.acceptsBindings(X));
        assertEq(names.resolveHandle(X, "alice"), alice);
    }

    /// `setPlatform` writes field-wise now, so a rules change must leave the
    /// platform exactly as wired as it was. Reintroducing the whole-struct
    /// assignment would unconfigure every platform it touched.
    function test_changingTheRulesLeavesThePlatformWired() public {
        HandleNormalizer.Rules memory narrowed = HandleVectors.rulesFor(X);
        narrowed.maxLength = 12;
        vm.prank(owner);
        names.setPlatform(X, narrowed);

        _stage("123", "alice", alice, 100);
        vm.prank(alice);
        _claim(X, false);
        assertEq(names.resolveHandle(X, "alice"), alice);
    }

    /// A retired handle has no wallet and keeps its watermark, so a proof
    /// older than the one that retired it cannot take the node back.
    function test_aRetiredHandleHasNoWalletAndKeepsItsWatermark() public {
        _bind(alice, "123", "alice", 100);
        _bind(alice, "123", "alice2", 200);

        (address wallet, uint64 at) = names.handleBinding(IdentityNodes.handleNode(X, "alice"));
        assertEq(wallet, address(0), "the handle was retired");
        assertEq(at, 100, "the watermark stays");
    }

    // ─── Ownership ──────────────────────────────────────────────────

    /// The owner has no privileged path to a binding. It obeys the same target
    /// rule as anybody else, so holding the owner key does not let it spend a
    /// proof that names a different address.
    function test_theOwnerHasNoPrivilegedPathToABinding() public {
        _bind(alice, "123", "alice", 100);

        _stage("123", "alice", alice, 200);
        vm.prank(owner);
        vm.expectRevert(abi.encodeWithSelector(IdentityNames.NotProofTarget.selector, alice, owner));
        _claim(X, false);

        assertEq(names.resolveId(X, "123"), alice, "the binding moved");
    }

    /// Configuring a platform is the whole of the owner's power here, and it
    /// reaches no existing binding. Replacing the verifier a version dispatches
    /// to must not disturb a binding that the previous one's proof established.
    function test_reconfiguringAPlatformLeavesBindingsAlone() public {
        _bind(alice, "123", "alice", 100);

        StubPlatformVerifier replacement = new StubPlatformVerifier(X, 0);
        vm.prank(owner);
        proofVerifier.setVerifier(X, V1, IPlatformVerifier(address(replacement)));

        assertEq(names.resolveId(X, "123"), alice);
        assertEq(names.resolveHandle(X, "alice"), alice);
        assertEq(address(proofVerifier.verifierOf(X, V1)), address(replacement));
    }

    function test_onlyTheOwnerConfiguresAPlatform() public {
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, alice));
        names.setPlatform(X, HandleVectors.rulesFor(X));
    }
}
