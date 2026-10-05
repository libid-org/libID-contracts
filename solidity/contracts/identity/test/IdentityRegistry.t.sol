// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, Vm} from "forge-std/Test.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

import {HandleNormalizer} from "../HandleNormalizer.sol";
import {HandleVectors} from "../HandleVectors.sol";
import {IIdentityRegistry} from "../IIdentityRegistry.sol";
import {IdentityRegistry} from "../IdentityRegistry.sol";
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
contract IdentityRegistryTest is Test {
    IdentityRegistry internal registry;
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
        IdentityRegistry impl = new IdentityRegistry();
        registry = IdentityRegistry(
            address(new ERC1967Proxy(address(impl), abi.encodeCall(IdentityRegistry.initialize, (owner))))
        );
        CeremonyProofVerifier pvImpl = new CeremonyProofVerifier();
        proofVerifier = CeremonyProofVerifier(
            address(new ERC1967Proxy(address(pvImpl), abi.encodeCall(CeremonyProofVerifier.initialize, (owner))))
        );
        xVerifier = new StubPlatformVerifier(X, 0);
        githubVerifier = new StubPlatformVerifier(GITHUB, 0);

        vm.startPrank(owner);
        registry.setProofVerifier(IProofVerifier(address(proofVerifier)));
        _wire(X, address(xVerifier));
        _wire(GITHUB, address(githubVerifier));
        vm.stopPrank();

        // Observations are provider timestamps, so the chain has to be past
        // them for a proof to read as already-made rather than future-dated.
        vm.warp(1_000_000);
    }

    /// The version every platform's first verifier lands on.
    uint16 internal constant V1 = 1;

    /// Configure a platform's rules and its first verifier, the way a
    /// deployment does. Caller supplies the prank.
    function _wire(bytes32 platformId, address verifierAddr) internal {
        registry.setPlatform(platformId, HandleVectors.rulesFor(platformId));
        proofVerifier.setVerifier(platformId, V1, IPlatformVerifier(verifierAddr));
    }

    /// Who the next submission's Authorized Transaction Data names.
    address private stagedTarget;

    /// A digest is spendable once, so every bind needs a nonce of its own.
    uint256 private nonce;

    /// Stage what the Platform Verifier reports, and who the submission names.
    ///
    /// @dev The stubs are written HERE rather than in `_submit`, because a test
    ///      pranks between the two and `vm.prank` is spent on the next external
    ///      call. Writing them later would spend it on the stub and send the
    ///      bind from the test contract.
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
                // A literal, not `registry.OPERATION_DOMAIN()`: reading it
                // is an external call, and it would spend the caller's prank.
                operationDomain: keccak256(bytes("libid.claim-identity")),
                authorizationNonce: bytes32(++nonce),
                // The free shape: these tests are about the binding rules, and
                // a ceremony composed by hand pays no application.
                transactionData: abi.encode(stagedTarget, uint256(0), address(0))
            })
        );
    }

    /// Submit the staged bind. The caller supplies the prank, the way a
    /// wallet supplies `msg.sender`.
    function _submit(bytes32 platformId, bool publish) internal {
        bytes memory payload = _payload(V1);
        registry.bind(platformId, V1, payload, publish);
    }

    /// Stage and bind as `who`.
    function _bind(address who, string memory id, string memory handle, uint64 at) internal {
        _stage(id, handle, who, at);
        vm.prank(who);
        _submit(X, false);
    }

    // ─── Binding ────────────────────────────────────────────────────

    function test_bindWritesBothMappings() public {
        _bind(alice, "123", "alice", 100);

        assertEq(registry.resolveId(X, "123"), alice, "the id does not resolve");
        assertEq(registry.resolveHandle(X, "alice"), alice, "the handle does not resolve");
    }

    /// The write entry point is `bind`. The old `claim` selector reaches no
    /// function, since there is no fallback, so a caller built against the old
    /// ABI reverts; the payload it sent stays unspent and binds through `bind`.
    function test_theClaimSelectorIsGone() public {
        _stage("123", "alice", alice, 100);
        bytes memory payload = _payload(V1);

        vm.prank(alice);
        (bool ok,) =
            address(registry).call(abi.encodeWithSignature("claim(bytes32,uint16,bytes,bool)", X, V1, payload, false));
        assertFalse(ok, "the claim selector still answers");
        assertEq(registry.resolveHandle(X, "alice"), address(0));

        vm.prank(alice);
        registry.bind(X, V1, payload, false);
        assertEq(registry.resolveHandle(X, "alice"), alice, "the unspent payload does not bind");
    }

    /// The one authorization rule. A proof read from the mempool is useless to
    /// its reader, because spending it means being the address it names.
    function test_onlyTheProofsTargetMayBind() public {
        _stage("123", "alice", alice, 100);

        vm.prank(bob);
        vm.expectRevert(abi.encodeWithSelector(IdentityRegistry.NotProofTarget.selector, alice, bob));
        _submit(X, false);
    }

    /// Authorized Transaction Data naming nobody is data anybody could redirect
    /// at themselves. It is refused the same way any other address that is not
    /// the caller is.
    function test_aBindWithNoTargetIsRefused() public {
        _stage("123", "alice", address(0), 100);

        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(IdentityRegistry.NotProofTarget.selector, address(0), alice));
        _submit(X, false);
    }

    function test_anUnconfiguredPlatformIsRefused() public {
        bytes32 unknown = keccak256("nowhere");
        _stage("123", "alice", alice, 100);

        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(IIdentityRegistry.UnknownPlatform.selector, unknown));
        _submit(unknown, false);
    }

    /// The handle is normalized on the way in, so the node comes from the same
    /// transform every reader uses.
    function test_theHandleIsNormalizedOnTheWayIn() public {
        _bind(alice, "123", " @Alice_1 ", 100);

        assertEq(registry.resolveHandle(X, "alice_1"), alice);
        assertEq(registry.resolveHandle(X, "@ALICE_1"), alice, "a reader's spelling should not matter");
    }

    // ─── The watermark ──────────────────────────────────────────────

    /// A proof held back must not undo a newer one. This is the case the
    /// watermark exists for.
    function test_anOlderProofCannotTakeAHandleBack() public {
        _bind(alice, "123", "shared", 100);

        // Bob proves the same handle later, which is a legitimate takeover.
        _bind(bob, "456", "shared", 200);
        assertEq(registry.resolveHandle(X, "shared"), bob);

        // Alice submits a proof she was holding from before bob's.
        _stage("123", "shared", alice, 150);
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(IdentityRegistry.StaleProof.selector, uint64(150), uint64(200)));
        _submit(X, false);

        assertEq(registry.resolveHandle(X, "shared"), bob, "the handle moved back");
    }

    /// A second proof of the same observation, under a fresh digest, is
    /// refused by the same rule, because equal is not newer. The exact proof
    /// stops earlier, at its spent digest (`test_aDigestIsSpendableOnce` in
    /// `CeremonyBind.t.sol`).
    function test_replayingAProofIsRefused() public {
        _bind(alice, "123", "alice", 100);

        _stage("123", "alice", alice, 100);
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(IdentityRegistry.StaleProof.selector, uint64(100), uint64(100)));
        _submit(X, false);
    }

    /// A rename keeps the id and takes a new handle. A rename is invisible to
    /// the chain until somebody proves the new state, and this second bind is
    /// that proof — so the handle the identity left has to stop resolving, or a
    /// payment meant for whoever has it now goes to the holder that renamed
    /// away from it.
    function test_aRenameRetiresTheHandleTheIdentityLeft() public {
        _bind(alice, "123", "alice", 100);
        _bind(alice, "123", "alice2", 200);

        assertEq(registry.resolveId(X, "123"), alice, "the id follows the identity");
        assertEq(registry.resolveHandle(X, "alice2"), alice);
        assertEq(registry.resolveHandle(X, "alice"), address(0), "the handle it left no longer resolves");
    }

    /// Only the entry this identity itself wrote. One holder may have two
    /// identities on a platform, and the second may have taken the handle the
    /// first released — retiring that would delete a binding nobody renamed.
    function test_aRetirementSkipsAHandleAnotherIdentityHasSinceTaken() public {
        _bind(alice, "123", "shared", 100);
        // A second identity, same holder, takes the handle the first had.
        _bind(alice, "456", "shared", 200);
        // Now the first identity renames. Its own record still names "shared".
        _bind(alice, "123", "renamed", 300);

        assertEq(registry.resolveHandle(X, "shared"), alice, "the second identity keeps it");
        assertEq(registry.resolveHandle(X, "renamed"), alice);
    }

    /// Retiring clears the holder and keeps the watermark. Deleting the whole
    /// record would return the node to `observedAt == 0` and let a proof older
    /// than the retired one take it.
    function test_aRetiredHandleStillOutranksAnOlderProof() public {
        _bind(alice, "123", "alice", 200);
        _bind(alice, "123", "alice2", 300);

        _stage("456", "alice", bob, 100);
        vm.prank(bob);
        vm.expectRevert(abi.encodeWithSelector(IdentityRegistry.StaleProof.selector, uint64(100), uint64(200)));
        _submit(X, false);
    }

    /// And a newer proof takes it as usual, so retiring frees the handle rather
    /// than burning it.
    function test_aRetiredHandleIsFreeForANewerProof() public {
        _bind(alice, "123", "alice", 100);
        _bind(alice, "123", "alice2", 200);
        _bind(bob, "456", "alice", 300);

        assertEq(registry.resolveHandle(X, "alice"), bob);
    }

    /// A proof with no observation time cannot be ordered against any other, so
    /// it is refused rather than treated as the oldest.
    function test_aProofWithNoObservationTimeIsRefused() public {
        _stage("123", "alice", alice, 0);
        vm.prank(alice);
        vm.expectRevert(IdentityRegistry.NoObservationTime.selector);
        _submit(X, false);
    }

    /// Every shipped verifier refuses an empty id already. This is what keeps
    /// that true for a verifier written later: without it, every identity such a
    /// verifier reported would land on the single node `idNode(platformId, "")`
    /// and each would take it from the one before.
    function test_aBindWithNoIdIsRefused() public {
        _stage("", "alice", alice, 100);
        vm.prank(alice);
        vm.expectRevert(IdentityRegistry.NoId.selector);
        _submit(X, false);
    }

    // ─── Platform configuration ─────────────────────────────────────

    // ─── The freshness signal ───────────────────────────────────────

    /// All three resolvers answer an unwired platform the same way. A zero
    /// address would tell a caller "nobody proved this" when the truth is
    /// that the platform is not configured, and a zero cannot say which.
    function test_everyResolverRefusesAnUnknownPlatform() public {
        bytes32 unwired = keccak256("nowhere");

        vm.expectRevert(abi.encodeWithSelector(IIdentityRegistry.UnknownPlatform.selector, unwired));
        registry.resolveId(unwired, "123");

        vm.expectRevert(abi.encodeWithSelector(IIdentityRegistry.UnknownPlatform.selector, unwired));
        registry.resolveHandle(unwired, "alice");

        vm.expectRevert(abi.encodeWithSelector(IIdentityRegistry.UnknownPlatform.selector, unwired));
        registry.resolveHandleAndId(unwired, "alice", "123");

        vm.expectRevert(abi.encodeWithSelector(IIdentityRegistry.UnknownPlatform.selector, unwired));
        registry.rulesOf(unwired);
        vm.expectRevert(abi.encodeWithSelector(IIdentityRegistry.UnknownPlatform.selector, unwired));
        registry.handleHashOf(unwired, "alice");
        vm.expectRevert(abi.encodeWithSelector(IIdentityRegistry.UnknownPlatform.selector, unwired));
        registry.handleNodeOf(unwired, "alice");
    }

    /// `rulesOf` reports the rules as set now, `handleHashOf` is `keccak256` of the handle
    /// normalized under them, and `handleNodeOf`/`handleNodeOfHash` name the node a proof of it
    /// binds.
    function test_theHashingViewsAgreeWithWhatABindWrites() public {
        assertEq(registry.rulesOf(X).maxLength, HandleVectors.rulesFor(X).maxLength);
        bytes32 handleHash = registry.handleHashOf(X, "  @Alice ");
        assertEq(handleHash, keccak256("alice"));
        assertEq(registry.handleNodeOf(X, "  @Alice "), registry.handleNodeOfHash(X, handleHash));
        assertEq(registry.handleNodeOfHash(X, handleHash), IdentityNodes.handleNode(X, "alice"));

        _bind(alice, "123", "alice", 100);
        (address holder,) = registry.handleBinding(registry.handleNodeOfHash(X, handleHash));
        assertEq(holder, alice);
    }

    /// Text the rules of the moment refuse reverts with the normalizer's reason, where
    /// `resolveHandle` answers nobody.
    function test_theHashingViewsRefuseWhatTheCurrentRulesRefuse() public {
        bytes memory badChar = _unusable(HandleNormalizer.Problem.BadChar);
        vm.expectRevert(badChar);
        registry.handleHashOf(X, "ali-ce");
        vm.expectRevert(badChar);
        registry.handleNodeOf(X, "ali-ce");
        assertEq(registry.resolveHandle(X, "ali-ce"), address(0));

        vm.prank(owner);
        registry.setPlatform(X, HandleVectors.rulesFor(GITHUB));
        assertTrue(registry.rulesOf(X).allowHyphen);
        assertEq(registry.handleHashOf(X, "ali-ce"), keccak256("ali-ce"));
        vm.expectRevert(badChar);
        registry.handleNodeOf(X, "alice_1");
    }

    function test_resolveHandleAndIdAgreesWhileOneIdentityHasBoth() public {
        _bind(alice, "123", "alice", 100);

        (address holder, bool agrees) = registry.resolveHandleAndId(X, "alice", "123");
        assertEq(holder, alice);
        assertTrue(agrees, "one identity has both, so they must agree");
    }

    /// The case the two mappings exist for: a consumer has a pair from two
    /// different moments, and the chain can say so.
    function test_resolveHandleAndIdReportsAHandleThatChangedHands() public {
        _bind(alice, "123", "shared", 100);
        _bind(bob, "456", "shared", 200);

        (address holder, bool agrees) = registry.resolveHandleAndId(X, "shared", "123");
        assertEq(holder, bob, "the handle routes to whoever proved it last");
        assertFalse(agrees, "the caller's id belongs to a different holder now");
    }

    /// An id the chain has never seen leaves a caller exactly as uninformed as
    /// a stale one, so it does not agree either.
    function test_resolveHandleAndIdDoesNotAgreeOnAnUnknownId() public {
        _bind(alice, "123", "alice", 100);

        (address holder, bool agrees) = registry.resolveHandleAndId(X, "alice", "999");
        assertEq(holder, alice);
        assertFalse(agrees);
    }

    // ─── Reverse resolution ─────────────────────────────────────────

    function test_publishingIsOptional() public {
        _bind(alice, "123", "alice", 100);
        assertEq(bytes(registry.publishedHandleOf(alice, X)).length, 0, "nothing should be published by default");

        _stage("123", "alice", alice, 200);
        vm.prank(alice);
        _submit(X, true);
        assertEq(registry.publishedHandleOf(alice, X), "alice");
    }

    /// Publishing is the one thing here a holder can undo, and it must not
    /// depend on being able to log in again: for Google the published handle is
    /// an email address, and withdrawing it should not require a fresh proof.
    function test_aPublishedHandleCanBeWithdrawn() public {
        _stage("123", "alice", alice, 100);
        vm.prank(alice);
        _submit(X, true);
        assertEq(registry.publishedHandleOf(alice, X), "alice");

        vm.prank(alice);
        registry.unpublish(X);
        assertEq(bytes(registry.publishedHandleOf(alice, X)).length, 0);
    }

    /// The binding survives. This withdraws a displayed string, not the proof
    /// that binds the identity to its holder.
    function test_withdrawingAPublishedHandleKeepsTheBinding() public {
        _stage("123", "alice", alice, 100);
        vm.prank(alice);
        _submit(X, true);

        vm.prank(alice);
        registry.unpublish(X);

        assertEq(registry.resolveId(X, "123"), alice);
        assertEq(registry.resolveHandle(X, "alice"), alice);
    }

    /// Binding again with `publish: false` must NOT withdraw an earlier
    /// publish — a caller re-proving after a rename should not silently drop a
    /// handle because a flag defaulted, and withdrawing has its own door. It
    /// must not leave the OLD handle on display either: the holder just proved
    /// it has a different one.
    function test_bindingAgainRefreshesAPublishedHandleRatherThanWithdrawingIt() public {
        _stage("123", "alice", alice, 100);
        vm.prank(alice);
        _submit(X, true);

        _stage("123", "alice2", alice, 200);
        vm.prank(alice);
        _submit(X, false);

        assertEq(registry.publishedHandleOf(alice, X), "alice2", "the display follows the handle it has");
    }

    /// The complement: a holder that never published does not start now.
    function test_bindingWithoutPublishingStillPublishesNothing() public {
        _bind(alice, "123", "alice", 100);
        _bind(alice, "123", "alice2", 200);

        assertEq(registry.publishedHandleOf(alice, X), "", "nothing was ever on display");
    }

    /// An indexer mirrors the published handles from the log alone, so the log
    /// has to say whether the handle is on display. Only `unpublish` is
    /// observable otherwise, and a publish would have to be guessed.
    function test_theLogSaysWhetherTheHandleIsPublished() public {
        _stage("123", "alice", alice, 100);
        vm.recordLogs();
        vm.prank(alice);
        _submit(X, true);
        assertTrue(_lastBindPublished(), "published");

        _stage("456", "bob", bob, 100);
        vm.recordLogs();
        vm.prank(bob);
        _submit(X, false);
        assertFalse(_lastBindPublished(), "not published");
    }

    /// The refresh is observable too, or an indexer would still show the
    /// handle the holder renamed away from.
    function test_theLogSaysPublishedWhenARefreshKeepsTheHandleOnDisplay() public {
        _stage("123", "alice", alice, 100);
        vm.prank(alice);
        _submit(X, true);

        _stage("123", "alice2", alice, 200);
        vm.recordLogs();
        vm.prank(alice);
        _submit(X, false);

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

    /// One holder's withdrawal is its own. There is no path to another's.
    function test_withdrawingTouchesOnlyTheCallersRecord() public {
        _stage("123", "alice", alice, 100);
        vm.prank(alice);
        _submit(X, true);

        vm.prank(mallory);
        registry.unpublish(X);

        assertEq(registry.publishedHandleOf(alice, X), "alice");
    }

    /// The forward check ENS requires of its integrators, done here so an
    /// integrator cannot skip it.
    function test_publishedHandleOfGoesEmptyOnceTheHandleMovesOn() public {
        _stage("123", "shared", alice, 100);
        vm.prank(alice);
        _submit(X, true);
        assertEq(registry.publishedHandleOf(alice, X), "shared", "it resolves back, so it stands");

        // Bob proves the same handle. Alice's published handle now has another
        // holder, though nothing rewrote her record.
        _bind(bob, "456", "shared", 200);
        assertEq(registry.publishedHandleOf(alice, X), "", "it no longer resolves back");

        // Proving it back without publishing finds the record still set.
        _stage("123", "shared", alice, 300);
        vm.prank(alice);
        _submit(X, false);
        assertEq(registry.publishedHandleOf(alice, X), "shared", "the record was untouched");
    }

    // ─── A holder's identities ──────────────────────────────────────

    /// Every identity of a holder, in one read.
    function _identities(address holder) internal view returns (IdentityRegistry.Identity[] memory) {
        return registry.identitiesOf(holder, 0, registry.identityCount(holder));
    }

    function _is(IdentityRegistry.Identity memory a, bytes32 platformId, string memory id)
        internal
        pure
        returns (bool)
    {
        return a.platformId == platformId && keccak256(bytes(a.id)) == keccak256(bytes(id));
    }

    /// Whether a page carries this identity.
    function _carries(IdentityRegistry.Identity[] memory page, bytes32 platformId, string memory id)
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
    function _identity(address holder, bytes32 platformId, string memory id)
        internal
        view
        returns (IdentityRegistry.Identity memory)
    {
        IdentityRegistry.Identity[] memory all = _identities(holder);
        for (uint256 i = 0; i < all.length; i++) {
            if (_is(all[i], platformId, id)) return all[i];
        }
        revert("not listed");
    }

    function test_aBindListsTheIdentityWithItsPlatformIdAndHandle() public {
        _bind(alice, "123", "alice", 100);

        assertEq(registry.identityCount(alice), 1);
        IdentityRegistry.Identity memory a = _identity(alice, X, "123");
        assertEq(a.handle, "alice");
        assertTrue(a.handleCurrent);
        assertEq(registry.identityCount(bob), 0, "each holder keeps its own list");
    }

    function test_identitiesOnEveryPlatformShareOneList() public {
        _bind(alice, "123", "alice", 100);
        _stage("123", "alice", alice, 200);
        vm.prank(alice);
        _submit(GITHUB, false);

        assertEq(registry.identityCount(alice), 2);
        assertTrue(_identity(alice, X, "123").handleCurrent);
        assertTrue(_identity(alice, GITHUB, "123").handleCurrent);
    }

    function test_theListedHandleIsTheNormalizedOne() public {
        _bind(alice, "123", "@Alice", 100);
        assertEq(_identity(alice, X, "123").handle, "alice");
    }

    function test_aHolderMayHaveSeveralIdentitiesOnOnePlatform() public {
        _bind(alice, "123", "alice", 100);
        _bind(alice, "456", "alicia", 200);

        assertEq(registry.identityCount(alice), 2);
        assertEq(_identity(alice, X, "123").handle, "alice");
        assertEq(_identity(alice, X, "456").handle, "alicia");
    }

    function test_aRenameMovesTheHandleAndKeepsOneEntry() public {
        _bind(alice, "123", "alice", 100);
        _bind(alice, "123", "alicia", 200);

        assertEq(registry.identityCount(alice), 1);
        IdentityRegistry.Identity memory a = _identity(alice, X, "123");
        assertEq(a.handle, "alicia");
        assertTrue(a.handleCurrent);
    }

    function test_provingTheSameHandleAgainListsNothingTwice() public {
        _bind(alice, "123", "alice", 100);
        _bind(alice, "123", "alice", 200);
        assertEq(registry.identityCount(alice), 1);
    }

    /// The list is alice's: bob taking her handle changes what it resolves
    /// to, and the entry says so, but the entry is still there with the
    /// handle her identity was last known by.
    function test_aHandleTakenElsewhereStaysListedAsStale() public {
        _bind(alice, "123", "shared", 100);
        _bind(bob, "456", "shared", 200);

        assertEq(registry.identityCount(alice), 1);
        IdentityRegistry.Identity memory a = _identity(alice, X, "123");
        assertEq(a.handle, "shared");
        assertFalse(a.handleCurrent, "the handle resolves to bob now");
        assertTrue(_identity(bob, X, "456").handleCurrent);
    }

    /// The holder still holds the handle node, through the other identity. A
    /// holder check alone would call both identities current.
    function test_aSecondIdentityOfTheSameHolderTakingTheHandleIsToldApart() public {
        _bind(alice, "123", "first", 100);
        _bind(alice, "456", "second", 200);
        _bind(alice, "456", "first", 300);

        assertEq(registry.identityCount(alice), 2);
        assertFalse(_identity(alice, X, "123").handleCurrent);
        IdentityRegistry.Identity memory second = _identity(alice, X, "456");
        assertEq(second.handle, "first");
        assertTrue(second.handleCurrent);
    }

    function test_anIdentityProvedByANewHolderMovesBetweenLists() public {
        _bind(alice, "123", "alice", 100);
        _bind(bob, "123", "alice", 200);

        assertEq(registry.identityCount(alice), 0);
        assertEq(registry.identityCount(bob), 1);
        assertTrue(_identity(bob, X, "123").handleCurrent);
    }

    function test_leavingFromTheMiddleKeepsTheOthersListed() public {
        _bind(alice, "1", "one", 100);
        _bind(alice, "2", "two", 200);
        _bind(alice, "3", "three", 300);
        _bind(bob, "2", "two", 400);

        assertEq(registry.identityCount(alice), 2);
        assertEq(_identity(alice, X, "1").handle, "one");
        assertEq(_identity(alice, X, "3").handle, "three");
        assertEq(_identity(bob, X, "2").handle, "two");

        // And back: an identity returns to a list it left.
        _bind(alice, "2", "two", 500);
        assertEq(registry.identityCount(alice), 3);
        assertEq(registry.identityCount(bob), 0);
        assertEq(_identity(alice, X, "2").handle, "two");
    }

    function test_pagesClipToTheList() public {
        _bind(alice, "1", "one", 100);
        _bind(alice, "2", "two", 200);
        _bind(alice, "3", "three", 300);

        assertEq(registry.identitiesOf(alice, 0, 2).length, 2);
        assertEq(registry.identitiesOf(alice, 2, 5).length, 1, "clipped at the end");
        assertEq(registry.identitiesOf(alice, 3, 1).length, 0, "past the end is empty, not a revert");
        assertEq(registry.identitiesOf(alice, 0, 0).length, 0);
        assertEq(registry.identitiesOf(alice, 1, type(uint256).max).length, 2, "a limit past the end is clipped too");

        // Two pages cover the list once each.
        IdentityRegistry.Identity[] memory first = registry.identitiesOf(alice, 0, 2);
        IdentityRegistry.Identity[] memory second = registry.identitiesOf(alice, 2, 2);
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
        _forbidUnderscoresOnX();

        assertEq(registry.resolveHandle(X, "with_score"), address(0));
        assertTrue(_identity(alice, X, "123").handleCurrent);
    }

    /// The owner narrows X's rules so a handle with an underscore no longer
    /// normalizes.
    function _forbidUnderscoresOnX() internal {
        HandleNormalizer.Rules memory rules = HandleVectors.rulesFor(X);
        rules.allowUnderscore = false;
        vm.prank(owner);
        registry.setPlatform(X, rules);
    }

    /// After any sequence of binds: an identity nobody proved is in no
    /// list, an identity somebody proved is in exactly one, the list of the
    /// holder whose proof of it is newest, and a handle reported current
    /// resolves to that holder and is current for no second identity.
    function testFuzz_everyProvedIdentitySitsInExactlyOneList(bytes memory script) public {
        address[3] memory holders = [alice, bob, mallory];
        bytes32[2] memory platforms = [X, GITHUB];
        string[4] memory ids = ["1", "2", "3", "4"];
        string[4] memory handles = ["one", "two", "three", "four"];

        uint64 at = 100;
        for (uint256 i = 0; i + 1 < script.length && i < 64; i += 2) {
            uint256 a = uint8(script[i]);
            uint256 b = uint8(script[i + 1]);
            address who = holders[a % 3];
            _stage(ids[b % 4], handles[(b / 4) % 4], who, ++at);
            vm.prank(who);
            _submit(platforms[(a / 3) % 2], false);
        }

        uint256 listed;
        IdentityRegistry.Identity[] memory current = new IdentityRegistry.Identity[](holders.length * ids.length * 2);
        uint256 currents;
        for (uint256 w = 0; w < holders.length; w++) {
            IdentityRegistry.Identity[] memory page = _identities(holders[w]);
            listed += page.length;
            for (uint256 i = 0; i < page.length; i++) {
                assertEq(registry.resolveId(page[i].platformId, page[i].id), holders[w], "listed under its prover");
                for (uint256 j = 0; j < i; j++) {
                    assertFalse(_is(page[j], page[i].platformId, page[i].id), "listed once");
                }
                if (page[i].handleCurrent) {
                    assertEq(
                        registry.resolveHandle(page[i].platformId, page[i].handle),
                        holders[w],
                        "current, so it resolves"
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
                if (registry.resolveId(platforms[p], ids[i]) != address(0)) proved++;
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
        assertEq(registry.resolveHandle(X, "ali ce"), address(0), "a stray space");
        assertEq(registry.resolveHandle(X, unicode"aliçe"), address(0), "a byte above 0x7f");
        assertEq(registry.resolveHandle(X, ""), address(0), "nothing at all");
        assertEq(registry.resolveHandle(X, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"), address(0), "too long");
        assertEq(registry.resolveHandle(GITHUB, "-octocat"), address(0), "an arrangement the platform refuses");
    }

    /// `resolveHandleAndId` matters more: its documented job is to let a
    /// caller decide what to tell whoever is paying, not to refuse.
    function test_resolveHandleAndIdAnswersRatherThanRevertingOnAMalformedHandle() public view {
        (address holder, bool idAgrees) = registry.resolveHandleAndId(X, "ali ce", "123");
        assertEq(holder, address(0));
        assertFalse(idAgrees);
    }

    /// An unwired platform still reverts. Zero would answer "nobody proved
    /// this" to a question that was never asked, and the caller cannot tell the
    /// two apart from an address.
    function test_anUnwiredPlatformStillReverts() public {
        bytes32 unknown = keccak256("nowhere");
        vm.expectRevert(abi.encodeWithSelector(IIdentityRegistry.UnknownPlatform.selector, unknown));
        registry.resolveHandle(unknown, "alice");
    }

    /// `bind` keeps reverting. A handle that arrives inside a proof and does
    /// not normalize is a broken proof, and failing loudly is right.
    function test_bindStillRefusesAHandleThatDoesNotNormalize() public {
        _stage("123", "ali ce", alice, 100);
        vm.prank(alice);
        vm.expectRevert(HandleNormalizer.BadCharacter.selector);
        _submit(X, false);
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
        _submit(GITHUB, true);
        assertEq(registry.publishedHandleOf(alice, GITHUB), "octo-cat");

        HandleNormalizer.Rules memory narrowed = HandleVectors.rulesFor(GITHUB);
        narrowed.allowHyphen = false;
        vm.prank(owner);
        registry.setPlatform(GITHUB, narrowed);

        assertEq(registry.resolveHandle(GITHUB, "octo-cat"), address(0), "the forward resolver cannot name it");
        assertEq(registry.publishedHandleOf(alice, GITHUB), "", "so neither does the reverse one");

        vm.prank(owner);
        registry.setPlatform(GITHUB, HandleVectors.rulesFor(GITHUB));
        assertEq(registry.publishedHandleOf(alice, GITHUB), "octo-cat", "the record was untouched");
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

        assertEq(registry.resolveId(X, "12345"), alice, "the id belongs to alice");
        assertEq(registry.resolveHandle(X, "12345"), bob, "the handle belongs to bob");
    }

    /// The same text on two platforms is two identities.
    function test_platformsDoNotShareNodes() public {
        _bind(alice, "123", "alice", 100);

        _stage("123", "alice", bob, 100);
        vm.prank(bob);
        _submit(GITHUB, false);

        assertEq(registry.resolveHandle(X, "alice"), alice);
        assertEq(registry.resolveHandle(GITHUB, "alice"), bob);
    }

    // ─── Proof versions ─────────────────────────────────────────────
    //
    // A platform's proof can change shape without the identity behind it
    // changing — X gaining OIDC, say. Both formats have to be accepted during
    // a migration, so the Proof Verifier keys its verifiers by version and
    // the rules are not keyed at all.

    /// A binding belongs to the identity that proved it, not to the format the
    /// proof was written in. Removing a version from the Supported Version Set
    /// must not unbind anybody.
    function test_retiringAVersionLeavesItsBindingsResolving() public {
        _bind(alice, "123", "alice", 100);

        vm.prank(owner);
        proofVerifier.setVerifier(X, V1, IPlatformVerifier(address(0)));

        assertEq(registry.resolveHandle(X, "alice"), alice, "the binding went with the format");
        assertEq(registry.resolveId(X, "123"), alice);
    }

    /// Which ceremony version proved a binding is logged and never stored.
    /// By the time anybody asks, the proof has happened and the effect has
    /// been applied; the question is an operator's, and the log answers it.
    /// The binding itself is a holder and a watermark, nothing more.
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
        registry.bind(X, 2, payload, false);

        (address idHolder, uint64 idAt) = registry.idBinding(IdentityNodes.idNode(X, "456"));
        (address handleHolder, uint64 handleAt) = registry.handleBinding(IdentityNodes.handleNode(X, "bob"));
        assertEq(idHolder, bob, "the id node");
        assertEq(handleHolder, bob, "the handle node");
        assertEq(idAt, 100);
        assertEq(handleAt, 100);

        (, uint16 logged) = _lastBind();
        assertEq(logged, 2, "the log an indexer reads");
    }

    // ─── A platform is not usable until it can verify ───────────────

    /// Between `setPlatform` and `setVerifier` a platform has rules and
    /// can verify nothing. Answering `address(0)` there would tell a caller
    /// "nobody proved this" about a platform that is not wired yet.
    function test_aPlatformWithoutAVerifierDoesNotResolve() public {
        bytes32 fresh = keccak256("fresh");
        vm.prank(owner);
        registry.setPlatform(fresh, HandleVectors.rulesFor(X));

        vm.expectRevert(abi.encodeWithSelector(IIdentityRegistry.UnknownPlatform.selector, fresh));
        registry.resolveId(fresh, "123");

        vm.expectRevert(abi.encodeWithSelector(IIdentityRegistry.UnknownPlatform.selector, fresh));
        registry.resolveHandle(fresh, "alice");

        vm.expectRevert(abi.encodeWithSelector(IIdentityRegistry.UnknownPlatform.selector, fresh));
        registry.resolveHandleAndId(fresh, "alice", "123");

        // The hashing views answer, and agree with each other: a client
        // normalizing under `rulesOf` reaches the node `handleNodeOf` names.
        assertEq(registry.rulesOf(fresh).maxLength, HandleVectors.rulesFor(X).maxLength);
        assertEq(registry.handleHashOf(fresh, "Alice"), keccak256("alice"));
        assertEq(registry.handleNodeOf(fresh, "Alice"), registry.handleNodeOfHash(fresh, keccak256("alice")));
    }

    /// And binding says the same thing, rather than naming a version the
    /// caller never chose. The platform is configured here, so the Consumer
    /// lets the bind through and the Proof Verifier is the one with nothing
    /// to dispatch to.
    function test_bindingOnAPlatformWithoutAVerifierIsRefused() public {
        bytes32 fresh = keccak256("fresh");
        vm.prank(owner);
        registry.setPlatform(fresh, HandleVectors.rulesFor(X));

        _stage("123", "alice", alice, 100);
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(CeremonyProofVerifier.UnknownVersion.selector, fresh, V1));
        _submit(fresh, false);
    }

    /// A new bind needs rules and a verifier the Proof Verifier answers for; retiring the
    /// last version stops new binds while bound identities keep resolving.
    function test_acceptsBindingsNeedsRulesAndAVerifier() public {
        assertTrue(registry.acceptsBindings(X));
        (bytes32 noRules, bytes32 noVerifier) = (keccak256("no rules"), keccak256("no verifier"));
        StubPlatformVerifier verifier = new StubPlatformVerifier(noRules, 0);
        vm.startPrank(owner);
        proofVerifier.setVerifier(noRules, V1, IPlatformVerifier(address(verifier)));
        registry.setPlatform(noVerifier, HandleVectors.rulesFor(X));
        vm.stopPrank();
        assertFalse(registry.acceptsBindings(noRules));
        assertFalse(registry.acceptsBindings(noVerifier));

        IdentityRegistry bare = IdentityRegistry(
            address(
                new ERC1967Proxy(address(new IdentityRegistry()), abi.encodeCall(IdentityRegistry.initialize, (owner)))
            )
        );
        vm.prank(owner);
        bare.setPlatform(X, HandleVectors.rulesFor(X));
        assertEq(address(bare.proofVerifier()), address(0));
        assertFalse(bare.acceptsBindings(X), "no Proof Verifier");

        _bind(alice, "123", "alice", 100);
        vm.prank(owner);
        proofVerifier.setVerifier(X, V1, IPlatformVerifier(address(0)));
        assertFalse(registry.acceptsBindings(X));
        assertEq(registry.resolveHandle(X, "alice"), alice);
    }

    /// `setPlatform` writes field-wise now, so a rules change must leave the
    /// platform exactly as wired as it was. Reintroducing the whole-struct
    /// assignment would unconfigure every platform it touched.
    function test_changingTheRulesLeavesThePlatformWired() public {
        HandleNormalizer.Rules memory narrowed = HandleVectors.rulesFor(X);
        narrowed.maxLength = 12;
        vm.prank(owner);
        registry.setPlatform(X, narrowed);

        _stage("123", "alice", alice, 100);
        vm.prank(alice);
        _submit(X, false);
        assertEq(registry.resolveHandle(X, "alice"), alice);
    }

    /// A retired handle has no holder and keeps its watermark, so a proof
    /// older than the one that retired it cannot take the node back.
    function test_aRetiredHandleHasNoHolderAndKeepsItsWatermark() public {
        _bind(alice, "123", "alice", 100);
        _bind(alice, "123", "alice2", 200);

        (address holder, uint64 at) = registry.handleBinding(IdentityNodes.handleNode(X, "alice"));
        assertEq(holder, address(0), "the handle was retired");
        assertEq(at, 100, "the watermark stays");
    }

    // ─── One-call reads ─────────────────────────────────────────────

    /// The holder and the proof's age in one call, read the way
    /// `resolveHandle` reads: normalized on chain, so a reader's spelling does
    /// not matter.
    function test_handleBindingOfReadsTheHolderAndWhenItWasProved() public {
        _bind(alice, "123", " @Alice_1 ", 100);

        _assertHandleBinding(X, "alice_1", alice, 100);
        _assertHandleBinding(X, "@ALICE_1", alice, 100);
        _assertHandleBinding(X, " @Alice_1 ", alice, 100);
        _assertHandleBinding(X, "nobody", address(0), 0);
    }

    /// One handle text on two platforms is two bindings: `alice` is valid on
    /// both, and each platform answers only its own.
    function test_handleBindingOfKeepsPlatformsApart() public {
        _bind(alice, "123", "alice", 100);
        _assertHandleBinding(GITHUB, "alice", address(0), 0);

        _stage("123", "alice", bob, 200);
        vm.prank(bob);
        _submit(GITHUB, false);

        _assertHandleBinding(X, "alice", alice, 100);
        _assertHandleBinding(GITHUB, "alice", bob, 200);
        assertEq(registry.idOfHandle(X, "alice"), "123");
        assertEq(registry.idOfHandle(GITHUB, "alice"), "123");
    }

    /// Text the rules refuse answers `(0, 0)`, as `resolveHandle` answers
    /// zero, rather than reverting.
    function test_handleBindingOfAnswersNobodyForTextTheRulesRefuse() public {
        _bind(alice, "123", "alice", 100);

        _assertHandleBinding(X, "ali ce", address(0), 0);
        _assertHandleBinding(X, "ali-ce", address(0), 0);
        _assertHandleBinding(X, "", address(0), 0);
        _assertHandleBinding(GITHUB, "-octocat", address(0), 0);
    }

    /// A retired handle has no holder and keeps the watermark a newer proof
    /// has to beat; `handleBinding` on its node says the same.
    function test_handleBindingOfShowsARetiredHandlesWatermark() public {
        _bind(alice, "123", "alice", 100);
        _bind(alice, "123", "alice2", 200);

        _assertHandleBinding(X, "alice", address(0), 100);
        _assertHandleBinding(X, "alice2", alice, 200);

        _bind(bob, "456", "alice", 300);
        _assertHandleBinding(X, "@Alice", bob, 300);
    }

    function test_idBindingOfReadsTheHolderAndWhenItWasProved() public {
        _bind(alice, "123", "alice", 100);
        _bind(alice, "123", "alice2", 200);

        _assertIdBinding(X, "123", alice, 200);
        _assertIdBinding(X, "456", address(0), 0);
        _assertIdBinding(GITHUB, "123", address(0), 0);

        _bind(bob, "123", "bob", 300);
        _assertIdBinding(X, "123", bob, 300);
    }

    /// The id is read verbatim, as `resolveId` reads it: no normalization.
    function test_idBindingOfDoesNotNormalizeTheId() public {
        _bind(alice, "AbC", "alice", 100);

        _assertIdBinding(X, "AbC", alice, 100);
        _assertIdBinding(X, "abc", address(0), 0);
        _assertIdBinding(X, " AbC", address(0), 0);
    }

    /// An identity's latest handle, current while the handle node points back
    /// at it. A rename moves it; another identity proving the handle turns
    /// `current` false and leaves the string.
    function test_handleOfIdFollowsARenameAndATakeover() public {
        _assertHandle(X, "123", "", false);

        _bind(alice, "123", "@Alice", 100);
        _assertHandle(X, "123", "alice", true);

        _bind(alice, "123", "Alice2", 200);
        _assertHandle(X, "123", "alice2", true);

        _bind(bob, "456", "alice2", 300);
        _assertHandle(X, "123", "alice2", false);
        _assertHandle(X, "456", "alice2", true);
    }

    /// `current` is the identity's, not the holder's: a second identity of
    /// the same holder taking the handle turns it false for the first.
    function test_handleOfIdTellsTwoIdentitiesOfOneHolderApart() public {
        _bind(alice, "123", "shared", 100);
        _bind(alice, "456", "shared", 200);

        _assertHandle(X, "123", "shared", false);
        _assertHandle(X, "456", "shared", true);
        assertEq(registry.idOfHandle(X, "shared"), "456");
    }

    /// The same answer the identity's entry in `identitiesOf` gives.
    function test_handleOfIdAgreesWithTheList() public {
        _bind(alice, "123", "alice", 100);
        _bind(bob, "456", "alice", 200);

        IdentityRegistry.Identity memory listed = _identity(alice, X, "123");
        (string memory handle, bool current) = registry.handleOfId(X, "123");
        assertEq(handle, listed.handle);
        assertEq(current, listed.handleCurrent);
    }

    /// The id of the identity a handle belongs to, through every spelling the
    /// rules fold together, and following the handle to its next owner.
    function test_idOfHandleFollowsTheHandle() public {
        assertEq(registry.idOfHandle(X, "alice"), "", "nobody proved it");

        _bind(alice, "123", "alice", 100);
        assertEq(registry.idOfHandle(X, "alice"), "123");
        assertEq(registry.idOfHandle(X, "@ALICE"), "123");
        assertEq(registry.idOfHandle(X, " @Alice "), "123");
        assertEq(registry.idOfHandle(GITHUB, "alice"), "", "another platform");

        _bind(bob, "456", "alice", 200);
        assertEq(registry.idOfHandle(X, "alice"), "456", "the new owner");
    }

    /// A handle the identity renamed away from belongs to nobody, as
    /// `resolveHandle` answers zero for it, until another identity proves it.
    function test_idOfHandleIsEmptyForARetiredHandle() public {
        _bind(alice, "123", "alice", 100);
        _bind(alice, "123", "alice2", 200);

        assertEq(registry.resolveHandle(X, "alice"), address(0));
        assertEq(registry.idOfHandle(X, "alice"), "");
        assertEq(registry.idOfHandle(X, "alice2"), "123");

        _bind(bob, "456", "alice", 300);
        assertEq(registry.idOfHandle(X, "alice"), "456");
    }

    /// After the owner narrows the rules so a bound handle no longer
    /// normalizes, `idOfHandle` answers nobody with `resolveHandle`, while
    /// `handleOfId` still reports the handle as current.
    function test_idOfHandleFollowsTheRulesWhenTheyNarrow() public {
        _bind(alice, "123", "with_score", 100);
        assertEq(registry.idOfHandle(X, "with_score"), "123");

        _forbidUnderscoresOnX();

        assertEq(registry.resolveHandle(X, "with_score"), address(0));
        assertEq(registry.idOfHandle(X, "with_score"), "");
        _assertHandleBinding(X, "with_score", address(0), 0);
        _assertHandle(X, "123", "with_score", true);
    }

    function test_idOfHandleIsEmptyForTextTheRulesRefuse() public {
        _bind(alice, "123", "alice", 100);

        assertEq(registry.idOfHandle(X, "ali ce"), "");
        assertEq(registry.idOfHandle(X, "ali-ce"), "");
        assertEq(registry.idOfHandle(X, ""), "");
    }

    /// The id comes back byte for byte as the platform issued it.
    function test_idOfHandleAnswersTheIdVerbatim() public {
        _bind(alice, "MDQ6VXNlcjIwMjEzMTc0", "octocat", 100);
        assertEq(registry.idOfHandle(X, "OctoCat"), "MDQ6VXNlcjIwMjEzMTc0");
    }

    /// The string `handleHashOf` hashes and a proof of the handle binds.
    function test_normalizeHandleAnswersWhatABindStores() public {
        assertEq(registry.normalizeHandle(X, " @Alice_1 "), "alice_1");
        assertEq(registry.normalizeHandle(X, "@ALICE"), "alice");
        assertEq(registry.normalizeHandle(X, "alice"), "alice");
        assertEq(registry.normalizeHandle(GITHUB, "Octo-Cat"), "octo-cat");
        assertEq(keccak256(bytes(registry.normalizeHandle(X, "@ALICE"))), registry.handleHashOf(X, "@ALICE"));

        _bind(alice, "123", " @Alice_1 ", 100);
        _assertHandle(X, "123", registry.normalizeHandle(X, "@ALICE_1"), true);
    }

    /// Text the rules refuse reverts with the normalizer's reason, as the
    /// other rules views do.
    function test_normalizeHandleRefusesWhatTheRulesRefuse() public {
        vm.expectRevert(_unusable(HandleNormalizer.Problem.BadChar));
        registry.normalizeHandle(X, "ali-ce");
        vm.expectRevert(_unusable(HandleNormalizer.Problem.Empty));
        registry.normalizeHandle(X, "@");
        vm.expectRevert(_unusable(HandleNormalizer.Problem.TooLong));
        registry.normalizeHandle(X, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        vm.expectRevert(_unusable(HandleNormalizer.Problem.Shape));
        registry.normalizeHandle(GITHUB, "-octocat");
    }

    /// Every one-call read refuses a platform that is not configured.
    function test_theOneCallReadsRefuseAnUnknownPlatform() public {
        bytes32 unwired = keccak256("nowhere");

        _expectTheResolversRefuse(unwired);
        vm.expectRevert(abi.encodeWithSelector(IIdentityRegistry.UnknownPlatform.selector, unwired));
        registry.handleBindingOf(unwired, "ali ce");
        vm.expectRevert(abi.encodeWithSelector(IIdentityRegistry.UnknownPlatform.selector, unwired));
        registry.normalizeHandle(unwired, "alice");
    }

    /// The four resolvers refuse a platform with rules and no verifier, like
    /// `resolveHandle`; `normalizeHandle` answers from the rules, like
    /// `handleHashOf`.
    function test_theOneCallReadsOnAPlatformWithoutAVerifier() public {
        bytes32 fresh = keccak256("fresh");
        vm.prank(owner);
        registry.setPlatform(fresh, HandleVectors.rulesFor(X));

        _expectTheResolversRefuse(fresh);

        assertEq(registry.normalizeHandle(fresh, "@Alice"), "alice");
    }

    /// A platform whose every version was retired keeps answering what it
    /// holds, as the other resolvers do.
    function test_theOneCallReadsOutliveTheLastVersion() public {
        _bind(alice, "123", "alice", 100);
        vm.prank(owner);
        proofVerifier.setVerifier(X, V1, IPlatformVerifier(address(0)));

        _assertHandleBinding(X, "alice", alice, 100);
        _assertIdBinding(X, "123", alice, 100);
        _assertHandle(X, "123", "alice", true);
        assertEq(registry.idOfHandle(X, "alice"), "123");
    }

    function _unusable(HandleNormalizer.Problem problem) internal pure returns (bytes memory) {
        return abi.encodeWithSelector(IIdentityRegistry.UnusableHandle.selector, problem);
    }

    /// The four one-call resolvers each revert `UnknownPlatform`.
    function _expectTheResolversRefuse(bytes32 platformId) internal {
        bytes memory unknown = abi.encodeWithSelector(IIdentityRegistry.UnknownPlatform.selector, platformId);
        vm.expectRevert(unknown);
        registry.handleBindingOf(platformId, "alice");
        vm.expectRevert(unknown);
        registry.idBindingOf(platformId, "123");
        vm.expectRevert(unknown);
        registry.handleOfId(platformId, "123");
        vm.expectRevert(unknown);
        registry.idOfHandle(platformId, "alice");
    }

    function _assertHandleBinding(bytes32 platformId, string memory handle, address wantHolder, uint64 wantAt)
        internal
        view
    {
        (address holder, uint64 observedAt) = registry.handleBindingOf(platformId, handle);
        assertEq(holder, wantHolder, "holder");
        assertEq(observedAt, wantAt, "observedAt");
    }

    function _assertIdBinding(bytes32 platformId, string memory id, address wantHolder, uint64 wantAt) internal view {
        (address holder, uint64 observedAt) = registry.idBindingOf(platformId, id);
        assertEq(holder, wantHolder, "holder");
        assertEq(observedAt, wantAt, "observedAt");
    }

    function _assertHandle(bytes32 platformId, string memory id, string memory wantHandle, bool wantCurrent)
        internal
        view
    {
        (string memory handle, bool current) = registry.handleOfId(platformId, id);
        assertEq(handle, wantHandle, "handle");
        assertEq(current, wantCurrent, "current");
    }

    // ─── Ownership ──────────────────────────────────────────────────

    /// The owner has no privileged path to a binding. It obeys the same target
    /// rule as anybody else, so holding the owner key does not let it spend a
    /// proof that names a different address.
    function test_theOwnerHasNoPrivilegedPathToABinding() public {
        _bind(alice, "123", "alice", 100);

        _stage("123", "alice", alice, 200);
        vm.prank(owner);
        vm.expectRevert(abi.encodeWithSelector(IdentityRegistry.NotProofTarget.selector, alice, owner));
        _submit(X, false);

        assertEq(registry.resolveId(X, "123"), alice, "the binding moved");
    }

    /// Configuring a platform is the whole of the owner's power here, and it
    /// reaches no existing binding. Replacing the verifier a version dispatches
    /// to must not disturb a binding that the previous one's proof established.
    function test_reconfiguringAPlatformLeavesBindingsAlone() public {
        _bind(alice, "123", "alice", 100);

        StubPlatformVerifier replacement = new StubPlatformVerifier(X, 0);
        vm.prank(owner);
        proofVerifier.setVerifier(X, V1, IPlatformVerifier(address(replacement)));

        assertEq(registry.resolveId(X, "123"), alice);
        assertEq(registry.resolveHandle(X, "alice"), alice);
        assertEq(address(proofVerifier.verifierOf(X, V1)), address(replacement));
    }

    function test_onlyTheOwnerConfiguresAPlatform() public {
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, alice));
        registry.setPlatform(X, HandleVectors.rulesFor(X));
    }
}
