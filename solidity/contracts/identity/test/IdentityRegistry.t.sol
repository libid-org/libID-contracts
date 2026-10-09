// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Vm} from "forge-std/Test.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

import {HandleNormalizer} from "../../handles/HandleNormalizer.sol";
import {HandlePlatforms} from "../../handles/HandlePlatforms.sol";
import {IdentityRegistry} from "../IdentityRegistry.sol";
import {CeremonyProofVerifier} from "../../ceremony/CeremonyProofVerifier.sol";
import {IPlatformVerifier} from "../../ceremony/IPlatformVerifier.sol";
import {IProofVerifier} from "../../ceremony/IProofVerifier.sol";
import {AttestationBuilder} from "../../ceremony/test/AttestationBuilder.sol";
import {PrivacyScan} from "./PrivacyScan.sol";
import {StubPlatformVerifier} from "./StubPlatformVerifier.sol";
import {TestNodes} from "./TestNodes.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";

/// @notice The identity contract, against a stubbed Platform Verifier.
///
/// @dev Every rule here belongs to the Consumer rather than to a platform, so
///      one stub proves them for both platforms at once. What a real Platform
///      Verifier checks — the attestations, the proof, the freshness window —
///      has its own suite. The stub reports the nodes a circuit would: the id
///      hashed as given, the handle folded and hashed, under the platform's
///      tags.
contract IdentityRegistryTest is PrivacyScan {
    IdentityRegistry internal registry;
    CeremonyProofVerifier internal proofVerifier;
    StubPlatformVerifier internal xVerifier;
    StubPlatformVerifier internal githubVerifier;

    bytes32 internal constant X = HandlePlatforms.PLATFORM_X;
    bytes32 internal constant GITHUB = HandlePlatforms.PLATFORM_GITHUB;

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

    /// Enable a platform: register its first verifier. Caller supplies the
    /// prank.
    function _wire(bytes32 platformId, address verifierAddr) internal {
        proofVerifier.setVerifier(platformId, V1, IPlatformVerifier(verifierAddr));
    }

    /// The id node a circuit outputs for this id.
    function _id(bytes32 platformId, string memory id) internal pure returns (bytes32) {
        return TestNodes.idNode(platformId, id);
    }

    /// The handle node a circuit outputs for this handle, already folded.
    ///
    /// @dev Both helpers call the SHA-256 precompile, which is a call: one
    ///      written between `vm.prank` or `vm.expectRevert` and the call it is
    ///      meant for spends the cheatcode. Compute nodes before either.
    function _hn(bytes32 platformId, string memory folded) internal pure returns (bytes32) {
        return TestNodes.handleNode(platformId, folded);
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
        return _payload(ceremonyVersion, "");
    }

    /// The same, disclosing `handle` (empty for a private submission).
    function _payload(uint16 ceremonyVersion, string memory handle) internal returns (bytes memory) {
        return abi.encode(
            StubPlatformVerifier.StubPayload({
                ceremonyVersion: ceremonyVersion,
                // A literal, not `registry.OPERATION_DOMAIN()`: reading it
                // is an external call, and it would spend the caller's prank.
                operationDomain: keccak256(bytes("libid.claim-identity")),
                authorizationNonce: bytes32(++nonce),
                // The free shape: these tests are about the binding rules, and
                // a ceremony composed by hand pays no application.
                transactionData: abi.encode(stagedTarget, uint256(0), address(0)),
                handle: handle
            })
        );
    }

    /// Submit the staged bind, disclosing `disclosed` (empty for a private
    /// bind). The caller supplies the prank, the way a wallet supplies
    /// `msg.sender`.
    function _submit(bytes32 platformId, string memory disclosed) internal {
        bytes memory payload = _payload(V1, disclosed);
        registry.bind(platformId, V1, payload);
    }

    /// Stage and bind privately as `who`.
    function _bind(address who, string memory id, string memory handle, uint64 at) internal {
        _stage(id, handle, who, at);
        vm.prank(who);
        _submit(X, "");
    }

    /// Stage and bind as `who`, disclosing the handle as staged.
    function _bindDisclosing(address who, string memory id, string memory handle, uint64 at) internal {
        _stage(id, handle, who, at);
        vm.prank(who);
        _submit(X, handle);
    }

    // ─── Binding ────────────────────────────────────────────────────

    function test_bindWritesBothMappings() public {
        _bind(alice, "123", "alice", 100);

        assertEq(registry.resolveId(_id(X, "123")), alice, "the id does not resolve");
        assertEq(registry.resolveHandle(X, "alice"), alice, "the handle does not resolve");
    }

    /// The write entry point is `bind` with a disclosed handle. The old `claim`
    /// selector and the `bind` that took a publish flag reach no function,
    /// since there is no fallback, so a caller built against an old ABI
    /// reverts; the payload it sent stays unspent and binds through `bind`.
    function test_theOldSelectorsAreGone() public {
        _stage("123", "alice", alice, 100);
        bytes memory payload = _payload(V1);

        vm.prank(alice);
        (bool ok,) =
            address(registry).call(abi.encodeWithSignature("claim(bytes32,uint16,bytes,bool)", X, V1, payload, false));
        assertFalse(ok, "the claim selector still answers");
        vm.prank(alice);
        (ok,) = address(registry).call(abi.encodeWithSignature("bind(bytes32,uint16,bytes,bool)", X, V1, payload, true));
        assertFalse(ok, "the publish-flag bind still answers");
        assertEq(registry.resolveHandle(X, "alice"), address(0));

        vm.prank(alice);
        registry.bind(X, V1, payload);
        assertEq(registry.resolveHandle(X, "alice"), alice, "the unspent payload does not bind");
    }

    /// The one authorization rule. A proof read from the mempool is useless to
    /// its reader, because spending it means being the address it names.
    function test_onlyTheProofsTargetMayBind() public {
        _stage("123", "alice", alice, 100);

        vm.prank(bob);
        vm.expectRevert(abi.encodeWithSelector(IdentityRegistry.NotProofTarget.selector, alice, bob));
        _submit(X, "");
    }

    /// Authorized Transaction Data naming nobody is data anybody could redirect
    /// at themselves. It is refused the same way any other address that is not
    /// the caller is.
    function test_aBindWithNoTargetIsRefused() public {
        _stage("123", "alice", address(0), 100);

        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(IdentityRegistry.NotProofTarget.selector, address(0), alice));
        _submit(X, "");
    }

    function test_anUnknownPlatformIsRefused() public {
        bytes32 unknown = keccak256("nowhere");
        _stage("123", "alice", alice, 100);

        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(IdentityRegistry.UnknownPlatform.selector, unknown));
        _submit(unknown, "");
    }

    /// The circuit folds the handle and outputs the node; the registry keys
    /// the binding by that node. A reader's spelling reaches it through the
    /// same fold, and only through the fold: an at sign is refused, not stripped.
    function test_theRegistryKeysTheNodeTheCircuitFolded() public {
        _bind(alice, "123", "Alice_1", 100);

        (address holder,) = registry.handleBinding(_hn(X, "alice_1"));
        assertEq(holder, alice, "the folded node");
        assertEq(registry.resolveHandle(X, "ALICE_1"), alice, "a reader's case should not matter");
        assertEq(registry.resolveHandle(X, "@alice_1"), address(0), "an @ is not part of a handle");
    }

    /// The registry never folds or hashes what it binds. A node no circuit
    /// would output -- the hash of an unfolded handle -- binds as given, and
    /// no text a reader can type reaches it: every reader folds first.
    function test_theRegistryNeverRefoldsANodeItIsGiven() public {
        bytes32 unfolded = TestNodes.handleNode(X, "Alice");
        _stage("123", "Alice", alice, 100);
        xVerifier.setNodes(_id(X, "123"), unfolded);
        vm.prank(alice);
        _submit(X, "");

        (address holder,) = registry.handleBinding(unfolded);
        assertEq(holder, alice, "the node as given");
        assertEq(registry.resolveHandle(X, "Alice"), address(0), "the reader folds to another node");

        vm.expectRevert(abi.encodeWithSelector(IdentityRegistry.NotYourHandle.selector, _hn(X, "alice")));
        vm.prank(alice);
        registry.publish(X, "Alice");
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
        _submit(X, "");

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
        _submit(X, "");
    }

    /// A rename keeps the id and takes a new handle. A rename is invisible to
    /// the chain until somebody proves the new state, and this second bind is
    /// that proof — so the handle the identity left has to stop resolving, or a
    /// payment meant for whoever has it now goes to the holder that renamed
    /// away from it.
    function test_aRenameRetiresTheHandleTheIdentityLeft() public {
        _bind(alice, "123", "alice", 100);
        _bind(alice, "123", "alice2", 200);

        assertEq(registry.resolveId(_id(X, "123")), alice, "the id follows the identity");
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
        _submit(X, "");
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
        _submit(X, "");
    }

    /// Every shipped circuit outputs a SHA-256 node, never zero. This is what
    /// keeps that true for a verifier written later: without it, every identity
    /// such a verifier reported would land on the zero node and each would take
    /// it from the one before.
    function test_aBindWithNoIdNodeIsRefused() public {
        _stage("123", "alice", alice, 100);
        xVerifier.setNodes(bytes32(0), _hn(X, "alice"));
        vm.prank(alice);
        vm.expectRevert(IdentityRegistry.NoId.selector);
        _submit(X, "");
    }

    // ─── Platforms ──────────────────────────────────────────────────

    /// Which platforms exist, and their rules and tags, are the generated
    /// constants the circuits carry: the registry answers them for every
    /// platform `handles.json` names, verifier or not, and has nothing an owner
    /// could set.
    function test_aPlatformsRulesAndTagAreTheCircuitsOwn() public view {
        bytes32[3] memory platforms = [X, GITHUB, HandlePlatforms.PLATFORM_GOOGLE];
        for (uint256 i = 0; i < platforms.length; i++) {
            bytes32 platformId = platforms[i];
            assertEq(registry.handleTagOf(platformId), HandlePlatforms.handleTagFor(platformId));
            assertEq(
                keccak256(abi.encode(registry.rulesOf(platformId))),
                keccak256(abi.encode(HandlePlatforms.rulesFor(platformId)))
            );
        }
        assertEq(registry.handleTagOf(X), bytes("libid.x.handle"));
    }

    // ─── The freshness signal ───────────────────────────────────────

    /// Every entry point that names a platform answers an unknown one the
    /// same way. A zero address would tell a caller "nobody proved this" when
    /// the truth is that no such platform exists, and a zero cannot say which.
    /// `resolveId` takes a node, which names no platform, so it has nothing to
    /// refuse and answers nobody; `acceptsBindings` is the question itself,
    /// and answers false.
    function test_everyEntryPointRefusesAnUnknownPlatform() public {
        bytes32 unwired = keccak256("nowhere");
        bytes32 idNode = _id(X, "123");

        _stage("123", "alice", alice, 100);
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(IdentityRegistry.UnknownPlatform.selector, unwired));
        _submit(unwired, "");
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(IdentityRegistry.UnknownPlatform.selector, unwired));
        registry.publish(unwired, "alice");
        assertFalse(registry.acceptsBindings(unwired));
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(IdentityRegistry.UnknownPlatform.selector, unwired));
        registry.unpublish(unwired);
        vm.expectRevert(abi.encodeWithSelector(IdentityRegistry.UnknownPlatform.selector, unwired));
        registry.publishedHandleOf(alice, unwired);

        vm.expectRevert(abi.encodeWithSelector(IdentityRegistry.UnknownPlatform.selector, unwired));
        registry.resolveHandle(unwired, "alice");

        vm.expectRevert(abi.encodeWithSelector(IdentityRegistry.UnknownPlatform.selector, unwired));
        registry.resolveHandleAndId(unwired, "alice", idNode);

        vm.expectRevert(abi.encodeWithSelector(IdentityRegistry.UnknownPlatform.selector, unwired));
        registry.rulesOf(unwired);
        vm.expectRevert(abi.encodeWithSelector(IdentityRegistry.UnknownPlatform.selector, unwired));
        registry.handleTagOf(unwired);
        vm.expectRevert(abi.encodeWithSelector(IdentityRegistry.UnknownPlatform.selector, unwired));
        registry.handleNodeOf(unwired, "alice");

        assertEq(registry.resolveId(keccak256("no such node")), address(0));
    }

    /// `rulesOf` and `handleTagOf` report what the platform was wired with, and
    /// `handleNodeOf` names the node a proof of the handle binds: the shared
    /// table's node for it, whatever case it was typed in.
    function test_theHashingViewsAgreeWithWhatABindWrites() public {
        assertEq(registry.rulesOf(X).maxLength, HandlePlatforms.rulesFor(X).maxLength);
        assertEq(registry.handleTagOf(X), bytes("libid.x.handle"));
        // `handles.json`: x, "alice".
        bytes32 tableNode = 0x0bed64615b5776d2567a82467d7be0e266e02803910d694a72703ee2a4cc911a;
        assertEq(registry.handleNodeOf(X, "Alice"), tableNode);
        assertEq(registry.handleNodeOf(X, "alice"), _hn(X, "alice"));

        _bind(alice, "123", "alice", 100);
        (address holder,) = registry.handleBinding(registry.handleNodeOf(X, "ALICE"));
        assertEq(holder, alice);
    }

    /// Text the rules refuse reverts with the normalizer's reason, where
    /// `resolveHandle` answers nobody. A space or an at sign is refused, not
    /// trimmed.
    function test_theHashingViewRefusesWhatTheRulesRefuse() public {
        bytes memory badChar =
            abi.encodeWithSelector(HandleNormalizer.UnusableHandle.selector, HandleNormalizer.Problem.BadChar);
        vm.expectRevert(badChar);
        registry.handleNodeOf(X, "ali-ce");
        vm.expectRevert(badChar);
        registry.handleNodeOf(X, " alice");
        vm.expectRevert(badChar);
        registry.handleNodeOf(X, "@alice");
        assertEq(registry.resolveHandle(X, "ali-ce"), address(0));

        // The same text is a handle where the rules allow it.
        assertEq(registry.handleNodeOf(GITHUB, "ali-ce"), _hn(GITHUB, "ali-ce"));
    }

    function test_resolveHandleAndIdAgreesWhileOneIdentityHasBoth() public {
        _bind(alice, "123", "alice", 100);

        (address holder, bool agrees) = registry.resolveHandleAndId(X, "alice", _id(X, "123"));
        assertEq(holder, alice);
        assertTrue(agrees, "one identity has both, so they must agree");
    }

    /// An id node agrees with a handle only on the handle's platform: one
    /// wallet holding an X handle and a GitHub id is two identities.
    function test_resolveHandleAndIdDoesNotAgreeAcrossPlatforms() public {
        _bind(alice, "123", "alice", 100);
        _stage("123", "alice", alice, 100);
        vm.prank(alice);
        _submit(GITHUB, "");

        (address holder, bool agrees) = registry.resolveHandleAndId(X, "alice", _id(GITHUB, "123"));
        assertEq(holder, alice);
        assertFalse(agrees, "a GitHub id node agreed with an X handle");
        (, agrees) = registry.resolveHandleAndId(X, "alice", _id(X, "123"));
        assertTrue(agrees);
    }

    /// The case the two mappings exist for: a consumer has a pair from two
    /// different moments, and the chain can say so.
    function test_resolveHandleAndIdReportsAHandleThatChangedHands() public {
        _bind(alice, "123", "shared", 100);
        _bind(bob, "456", "shared", 200);

        (address holder, bool agrees) = registry.resolveHandleAndId(X, "shared", _id(X, "123"));
        assertEq(holder, bob, "the handle routes to whoever proved it last");
        assertFalse(agrees, "the caller's id belongs to a different holder now");
    }

    /// An id the chain has never seen leaves a caller exactly as uninformed as
    /// a stale one, so it does not agree either.
    function test_resolveHandleAndIdDoesNotAgreeOnAnUnknownId() public {
        _bind(alice, "123", "alice", 100);

        (address holder, bool agrees) = registry.resolveHandleAndId(X, "alice", _id(X, "999"));
        assertEq(holder, alice);
        assertFalse(agrees);
    }

    // ─── Disclosure ─────────────────────────────────────────────────

    function test_aPrivateBindPublishesNothing() public {
        vm.recordLogs();
        _bind(alice, "123", "alice", 100);

        assertEq(registry.publishedHandleOf(alice, X), "", "nothing should be published by default");
        assertEq(_count(vm.getRecordedLogs(), IdentityRegistry.HandlePublished.selector), 0);
    }

    /// A disclosure at bind normalizes the text with the platform's rules,
    /// checks it hashes to the node the proof just bound, and stores and logs
    /// the folded name.
    function test_disclosingAtBindStoresTheNormalizedName() public {
        _stage("123", "Alice", alice, 100);
        bytes32 node = _hn(X, "alice");
        vm.expectEmit(true, true, true, true, address(registry));
        emit IdentityRegistry.HandlePublished(alice, X, node, "alice");
        vm.prank(alice);
        _submit(X, "ALICE");

        assertEq(registry.publishedHandleOf(alice, X), "alice");
    }

    /// A binding discloses the handle its own proof bound, and no other the
    /// caller happens to hold: the Platform Verifier checks the disclosure
    /// against this proof's node. `publish` is the call for another one.
    function test_aBindDisclosesOnlyTheHandleItsProofBound() public {
        _bind(alice, "456", "alicia", 100);
        _stage("123", "alice", alice, 200);
        bytes32 alicia = _hn(X, "alicia");
        bytes32 proved = _hn(X, "alice");
        vm.expectRevert(abi.encodeWithSelector(StubPlatformVerifier.HandleNotProved.selector, alicia, proved));
        vm.prank(alice);
        _submit(X, "alicia");

        // The same wallet may still publish it.
        vm.prank(alice);
        registry.publish(X, "alicia");
        assertEq(registry.publishedHandleOf(alice, X), "alicia");
    }

    /// Disclosing later needs no new proof: the holder already holds the node.
    /// Any case the platform shows reaches it.
    function test_publishDisclosesAHandleTheCallerHolds() public {
        _bind(alice, "123", "alice", 100);

        bytes32 node = _hn(X, "alice");
        vm.expectEmit(true, true, true, true, address(registry));
        emit IdentityRegistry.HandlePublished(alice, X, node, "alice");
        vm.prank(alice);
        registry.publish(X, "ALICE");

        assertEq(registry.publishedHandleOf(alice, X), "alice");
    }

    /// The node is the proof: a handle another account proved, or one nobody
    /// proved, hashes to a node the caller does not hold.
    function test_publishingAHandleTheCallerDoesNotHoldIsRefused() public {
        _bind(alice, "123", "alice", 100);
        _bind(bob, "456", "bob", 100);

        vm.expectRevert(abi.encodeWithSelector(IdentityRegistry.NotYourHandle.selector, _hn(X, "alice")));
        vm.prank(bob);
        registry.publish(X, "alice");

        vm.expectRevert(abi.encodeWithSelector(IdentityRegistry.NotYourHandle.selector, _hn(X, "nobody")));
        vm.prank(mallory);
        registry.publish(X, "nobody");

        assertEq(registry.publishedHandleOf(bob, X), "");
        assertEq(registry.publishedHandleOf(mallory, X), "");
    }

    /// Text the rules refuse names no node, and the normalizer says why. A
    /// space or an at sign is refused rather than stripped, so the name stored is
    /// never a repair of what the caller sent.
    function test_publishingTextTheRulesRefuseRevertsWithTheNormalizersReason() public {
        _bind(alice, "123", "alice", 100);

        vm.startPrank(alice);
        vm.expectRevert(
            abi.encodeWithSelector(HandleNormalizer.UnusableHandle.selector, HandleNormalizer.Problem.BadChar)
        );
        registry.publish(X, " alice");
        vm.expectRevert(
            abi.encodeWithSelector(HandleNormalizer.UnusableHandle.selector, HandleNormalizer.Problem.BadChar)
        );
        registry.publish(X, "@alice");
        vm.expectRevert(
            abi.encodeWithSelector(HandleNormalizer.UnusableHandle.selector, HandleNormalizer.Problem.Empty)
        );
        registry.publish(X, "");
        vm.expectRevert(abi.encodeWithSelector(IdentityRegistry.UnknownPlatform.selector, keccak256("nowhere")));
        registry.publish(keccak256("nowhere"), "alice");
        vm.stopPrank();
    }

    /// A disclosure the proof does not back undoes the whole bind: the
    /// Platform Verifier refuses it, nothing is bound or named, and the digest
    /// stays unspent, so the same submission binds once the disclosure is
    /// dropped.
    function test_aBindDisclosingAHandleItDidNotProveWritesNothing() public {
        _bind(bob, "456", "bob", 100);
        _stage("123", "alice", alice, 200);
        uint256 reuse = nonce + 1;
        bytes32 proved = _hn(X, "alice");
        bytes32 bobNode = _hn(X, "bob");
        bytes32 aliciaNode = _hn(X, "alicia");

        bytes memory payload = _payloadAt(reuse, "bob");
        vm.expectRevert(abi.encodeWithSelector(StubPlatformVerifier.HandleNotProved.selector, bobNode, proved));
        vm.prank(alice);
        registry.bind(X, V1, payload);

        payload = _payloadAt(reuse, "alicia");
        vm.expectRevert(abi.encodeWithSelector(StubPlatformVerifier.HandleNotProved.selector, aliciaNode, proved));
        vm.prank(alice);
        registry.bind(X, V1, payload);

        payload = _payloadAt(reuse, "@alice");
        vm.prank(alice);
        vm.expectRevert(
            abi.encodeWithSelector(HandleNormalizer.UnusableHandle.selector, HandleNormalizer.Problem.BadChar)
        );
        registry.bind(X, V1, payload);

        assertEq(registry.resolveId(_id(X, "123")), address(0), "the id was bound");
        assertEq(registry.resolveHandle(X, "alice"), address(0), "the handle was bound");
        assertEq(registry.identityCount(alice), 0, "the identity was listed");
        assertEq(registry.publishedHandleOf(alice, X), "");
        assertEq(registry.publishedHandleOf(bob, X), "");

        payload = _payloadAt(reuse, "");
        vm.prank(alice);
        registry.bind(X, V1, payload);
        assertEq(registry.resolveHandle(X, "alice"), alice, "the digest was spent");
    }

    /// The registry owns the name slot, so it does not take a verifier's word
    /// that a returned handle names the returned node: it hashes the handle
    /// under the platform's tag and refuses a mismatch, writing nothing.
    function test_aDisclosureThatDoesNotNameTheBoundNodeIsRefused() public {
        bytes32 idNode = _id(X, "123");
        bytes32 bound = _hn(X, "alice");
        bytes32 disclosed = _hn(X, "bob");
        _stage("123", "alice", alice, 100);
        xVerifier.setNodes(idNode, bound);

        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(IdentityRegistry.DisclosureMismatch.selector, disclosed, bound));
        _submit(X, "bob");

        assertEq(registry.resolveId(idNode), address(0), "the id was bound");
        assertEq(registry.publishedHandleOf(alice, X), "", "the name was written");

        // The same verifier's matching disclosure is stored.
        vm.prank(alice);
        _submit(X, "alice");
        assertEq(registry.publishedHandleOf(alice, X), "alice");
    }

    /// One submission's payload under a chosen nonce, so a test can submit
    /// the same ceremony with different disclosures.
    function _payloadAt(uint256 authorizationNonce, string memory handle) internal view returns (bytes memory) {
        return abi.encode(
            StubPlatformVerifier.StubPayload({
                ceremonyVersion: V1,
                operationDomain: keccak256(bytes("libid.claim-identity")),
                authorizationNonce: bytes32(authorizationNonce),
                transactionData: abi.encode(stagedTarget, uint256(0), address(0)),
                handle: handle
            })
        );
    }

    /// Publishing is the one thing here a holder can undo, and it must not
    /// depend on being able to log in again: for Google the published handle is
    /// an email address, and withdrawing it should not require a fresh proof.
    function test_aPublishedHandleCanBeWithdrawn() public {
        _bindDisclosing(alice, "123", "alice", 100);
        assertEq(registry.publishedHandleOf(alice, X), "alice");

        vm.expectEmit(true, true, false, false, address(registry));
        emit IdentityRegistry.HandleUnpublished(alice, X);
        vm.prank(alice);
        registry.unpublish(X);
        assertEq(registry.publishedHandleOf(alice, X), "");
    }

    /// The binding survives. This withdraws a displayed string, not the proof
    /// that binds the identity to its holder.
    function test_withdrawingAPublishedHandleKeepsTheBinding() public {
        _bindDisclosing(alice, "123", "alice", 100);

        vm.prank(alice);
        registry.unpublish(X);

        assertEq(registry.resolveId(_id(X, "123")), alice);
        assertEq(registry.resolveHandle(X, "alice"), alice);
    }

    /// The name slot is written only by a disclosure. A later private bind --
    /// the same handle again, a rename, a rename back -- neither withdraws nor
    /// rewrites it, and logs nothing about it; `publishedHandleOf` follows
    /// whether the holder still holds the name it disclosed.
    function test_aBindWithoutDisclosureLeavesTheNameAlone() public {
        _bindDisclosing(alice, "123", "alice", 100);

        vm.recordLogs();
        _bind(alice, "123", "alice", 200);
        Vm.Log[] memory logs = vm.getRecordedLogs();
        assertEq(_count(logs, IdentityRegistry.HandlePublished.selector), 0, "a private bind published");
        assertEq(_count(logs, IdentityRegistry.HandleUnpublished.selector), 0, "a private bind withdrew");
        assertEq(registry.publishedHandleOf(alice, X), "alice", "a re-proof dropped the name");

        _bind(alice, "123", "alice2", 300);
        assertEq(registry.publishedHandleOf(alice, X), "", "a name the holder renamed away from");

        _bind(alice, "123", "alice", 400);
        assertEq(registry.publishedHandleOf(alice, X), "alice", "the slot was rewritten");
    }

    /// One name per wallet per platform: a second disclosure replaces the
    /// first, here for a holder with two identities.
    function test_aSecondDisclosureReplacesTheFirst() public {
        _bind(alice, "123", "alice", 100);
        _bind(alice, "456", "alicia", 200);

        vm.startPrank(alice);
        registry.publish(X, "alice");
        registry.publish(X, "Alicia");
        vm.stopPrank();

        assertEq(registry.publishedHandleOf(alice, X), "alicia");
    }

    /// One holder's withdrawal is its own. There is no path to another's.
    function test_withdrawingTouchesOnlyTheCallersRecord() public {
        _bindDisclosing(alice, "123", "alice", 100);

        vm.prank(mallory);
        registry.unpublish(X);

        assertEq(registry.publishedHandleOf(alice, X), "alice");
    }

    /// The forward check ENS requires of its integrators, done here so an
    /// integrator cannot skip it.
    function test_publishedHandleOfGoesEmptyOnceTheHandleMovesOn() public {
        _bindDisclosing(alice, "123", "shared", 100);
        assertEq(registry.publishedHandleOf(alice, X), "shared", "it resolves back, so it stands");

        // Bob proves the same handle. Alice's published handle now has another
        // holder, though nothing rewrote her record.
        _bind(bob, "456", "shared", 200);
        assertEq(registry.publishedHandleOf(alice, X), "", "it no longer resolves back");

        // Proving it back without disclosing finds the record still set.
        _bind(alice, "123", "shared", 300);
        assertEq(registry.publishedHandleOf(alice, X), "shared", "the record was untouched");
    }

    /// How many logs carry this event.
    function _count(Vm.Log[] memory logs, bytes32 topic) internal pure returns (uint256 n) {
        for (uint256 i = 0; i < logs.length; i++) {
            if (logs[i].topics.length > 0 && logs[i].topics[0] == topic) n++;
        }
    }

    // ─── Privacy ────────────────────────────────────────────────────

    /// Ten digits and thirteen mixed-case characters, long enough that a match
    /// inside a SHA-256 node or an address would not be chance.
    string internal constant SECRET_ID = "2244994945";
    string internal constant SECRET_HANDLE = "Alice_Wonder1";
    string internal constant SECRET_FOLDED = "alice_wonder1";

    function _secrets() internal pure override returns (string[3] memory) {
        return [SECRET_ID, SECRET_HANDLE, SECRET_FOLDED];
    }

    /// Every log a private bind emits -- the registry's, the Proof Verifier's,
    /// any -- carries no byte run of the id or the handle, raw or folded, in
    /// its topics or its data.
    function test_aPrivateBindLogsNoByteOfTheIdOrTheHandle() public {
        _stage(SECRET_ID, SECRET_HANDLE, alice, 100);
        vm.recordLogs();
        vm.prank(alice);
        _submit(X, "");
        _assertLogsHideTheSecrets(vm.getRecordedLogs());
        assertEq(registry.resolveHandle(X, SECRET_HANDLE), alice, "the bind did not happen");
    }

    /// The scan finds a disclosed handle where it is: in `HandlePublished`. A
    /// scan that could not would pass the test above for nothing.
    function test_theScanFindsADisclosedHandle() public {
        _stage(SECRET_ID, SECRET_HANDLE, alice, 100);
        vm.recordLogs();
        vm.prank(alice);
        _submit(X, SECRET_HANDLE);
        Vm.Log[] memory logs = vm.getRecordedLogs();

        bool found;
        for (uint256 i = 0; i < logs.length; i++) {
            if (AttestationBuilder.contains(logs[i].data, bytes(SECRET_FOLDED))) {
                assertEq(logs[i].topics[0], IdentityRegistry.HandlePublished.selector, "found it outside the event");
                found = true;
            }
        }
        assertTrue(found, "the disclosed handle is not in the logs");
    }

    /// Nothing a private bind writes holds the id or the handle, so no getter,
    /// present or added by an upgrade, can return them. Every storage word the
    /// bind touched on the registry and the Proof Verifier is read back and
    /// scanned; the getters that return a holder's identity return nodes only.
    function test_aPrivateBindStoresNoByteOfTheIdOrTheHandle() public {
        _stage(SECRET_ID, SECRET_HANDLE, alice, 100);
        vm.record();
        vm.prank(alice);
        _submit(X, "");

        assertGt(_assertStorageHidesTheSecrets(address(registry)), 0, "the bind wrote nothing to check");
        _assertStorageHidesTheSecrets(address(proofVerifier));

        assertEq(registry.publishedHandleOf(alice, X), "");
        IdentityRegistry.Identity memory a = registry.identitiesOf(alice, 0, 1)[0];
        assertEq(a.idNode, _id(X, SECRET_ID));
        assertEq(a.handleNode, _hn(X, SECRET_FOLDED));
    }

    /// The storage scan finds a disclosed name in the word that holds it. A
    /// scan that could not would pass the test above for nothing.
    function test_theStorageScanFindsADisclosedName() public {
        _stage(SECRET_ID, SECRET_HANDLE, alice, 100);
        vm.record();
        vm.prank(alice);
        _submit(X, SECRET_HANDLE);

        (, bytes32[] memory writes) = vm.accesses(address(registry));
        bool found;
        for (uint256 i = 0; i < writes.length; i++) {
            bytes memory word = abi.encodePacked(vm.load(address(registry), writes[i]));
            if (AttestationBuilder.contains(word, bytes(SECRET_FOLDED))) found = true;
            assertFalse(AttestationBuilder.contains(word, bytes(SECRET_ID)), "the id is stored beside the name");
        }
        assertTrue(found, "the disclosed name is not in storage");
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
        return a.platformId == platformId && a.idNode == _id(platformId, id);
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

    function test_aBindListsTheIdentityWithItsPlatformAndNodes() public {
        _bind(alice, "123", "alice", 100);

        assertEq(registry.identityCount(alice), 1);
        IdentityRegistry.Identity memory a = registry.identitiesOf(alice, 0, 1)[0];
        assertEq(a.platformId, X);
        assertEq(a.idNode, _id(X, "123"));
        assertEq(a.handleNode, _hn(X, "alice"));
        assertTrue(a.handleCurrent);
        assertEq(registry.identityCount(bob), 0, "each holder keeps its own list");
    }

    function test_identitiesOnEveryPlatformShareOneList() public {
        _bind(alice, "123", "alice", 100);
        _stage("123", "alice", alice, 200);
        vm.prank(alice);
        _submit(GITHUB, "");

        assertEq(registry.identityCount(alice), 2);
        assertTrue(_identity(alice, X, "123").handleCurrent);
        assertTrue(_identity(alice, GITHUB, "123").handleCurrent);
        assertEq(_identity(alice, GITHUB, "123").handleNode, _hn(GITHUB, "alice"));
    }

    function test_theListedHandleNodeIsTheFoldedOne() public {
        _bind(alice, "123", "Alice", 100);
        assertEq(_identity(alice, X, "123").handleNode, _hn(X, "alice"));
    }

    function test_aHolderMayHaveSeveralIdentitiesOnOnePlatform() public {
        _bind(alice, "123", "alice", 100);
        _bind(alice, "456", "alicia", 200);

        assertEq(registry.identityCount(alice), 2);
        assertEq(_identity(alice, X, "123").handleNode, _hn(X, "alice"));
        assertEq(_identity(alice, X, "456").handleNode, _hn(X, "alicia"));
    }

    function test_aRenameMovesTheHandleAndKeepsOneEntry() public {
        _bind(alice, "123", "alice", 100);
        _bind(alice, "123", "alicia", 200);

        assertEq(registry.identityCount(alice), 1);
        IdentityRegistry.Identity memory a = _identity(alice, X, "123");
        assertEq(a.handleNode, _hn(X, "alicia"));
        assertTrue(a.handleCurrent);
    }

    function test_provingTheSameHandleAgainListsNothingTwice() public {
        _bind(alice, "123", "alice", 100);
        _bind(alice, "123", "alice", 200);
        assertEq(registry.identityCount(alice), 1);
    }

    /// The list is alice's: bob taking her handle changes what it resolves
    /// to, and the entry says so, but the entry is still there with the
    /// handle node her identity was last known by.
    function test_aHandleTakenElsewhereStaysListedAsStale() public {
        _bind(alice, "123", "shared", 100);
        _bind(bob, "456", "shared", 200);

        assertEq(registry.identityCount(alice), 1);
        IdentityRegistry.Identity memory a = _identity(alice, X, "123");
        assertEq(a.handleNode, _hn(X, "shared"));
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
        assertEq(second.handleNode, _hn(X, "first"));
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
        assertEq(_identity(alice, X, "1").handleNode, _hn(X, "one"));
        assertEq(_identity(alice, X, "3").handleNode, _hn(X, "three"));
        assertEq(_identity(bob, X, "2").handleNode, _hn(X, "two"));

        // And back: an identity returns to a list it left.
        _bind(alice, "2", "two", 500);
        assertEq(registry.identityCount(alice), 3);
        assertEq(registry.identityCount(bob), 0);
        assertEq(_identity(alice, X, "2").handleNode, _hn(X, "two"));
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

    /// After any sequence of binds: an identity nobody proved is in no
    /// list, an identity somebody proved is in exactly one, the list of the
    /// holder whose proof of it is newest, and a handle node reported current
    /// is held by that holder and is current for no second identity.
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
            _submit(platforms[(a / 3) % 2], "");
        }

        uint256 listed;
        IdentityRegistry.Identity[] memory current = new IdentityRegistry.Identity[](holders.length * ids.length * 2);
        uint256 currents;
        for (uint256 w = 0; w < holders.length; w++) {
            IdentityRegistry.Identity[] memory page = _identities(holders[w]);
            listed += page.length;
            for (uint256 i = 0; i < page.length; i++) {
                assertEq(registry.resolveId(page[i].idNode), holders[w], "listed under its prover");
                for (uint256 j = 0; j < i; j++) {
                    assertFalse(page[j].idNode == page[i].idNode, "listed once");
                }
                if (page[i].handleCurrent) {
                    (address holder,) = registry.handleBinding(page[i].handleNode);
                    assertEq(holder, holders[w], "current, so it resolves");
                    current[currents++] = page[i];
                }
            }
        }
        for (uint256 i = 0; i < currents; i++) {
            for (uint256 j = 0; j < i; j++) {
                assertFalse(current[i].handleNode == current[j].handleNode, "a handle is current for one identity");
            }
        }

        uint256 proved;
        for (uint256 p = 0; p < platforms.length; p++) {
            for (uint256 i = 0; i < ids.length; i++) {
                if (registry.resolveId(_id(platforms[p], ids[i])) != address(0)) proved++;
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
        assertEq(registry.resolveHandle(X, " alice"), address(0), "a leading space");
        assertEq(registry.resolveHandle(X, "@alice"), address(0), "a leading @");
        assertEq(registry.resolveHandle(X, unicode"aliçe"), address(0), "a byte above 0x7f");
        assertEq(registry.resolveHandle(X, ""), address(0), "nothing at all");
        assertEq(registry.resolveHandle(X, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"), address(0), "too long");
        assertEq(registry.resolveHandle(GITHUB, "-octocat"), address(0), "an arrangement the platform refuses");
    }

    /// `resolveHandleAndId` matters more: its documented job is to let a
    /// caller decide what to tell whoever is paying, not to refuse.
    function test_resolveHandleAndIdAnswersRatherThanRevertingOnAMalformedHandle() public view {
        (address holder, bool idAgrees) = registry.resolveHandleAndId(X, "ali ce", _id(X, "123"));
        assertEq(holder, address(0));
        assertFalse(idAgrees);
    }

    // ─── Node separation ────────────────────────────────────────────

    /// A numeric handle and an id of the same digits must not collide.
    /// Numeric handles are legal on X and old ids are short, so this is
    /// reachable rather than theoretical. The two tags keep them apart.
    function test_aNumericHandleDoesNotCollideWithAnId() public {
        assertTrue(_id(X, "12345") != _hn(X, "12345"), "an id node and a handle node collided");

        _bind(alice, "12345", "bob", 100);
        _bind(bob, "999", "12345", 100);

        assertEq(registry.resolveId(_id(X, "12345")), alice, "the id belongs to alice");
        assertEq(registry.resolveHandle(X, "12345"), bob, "the handle belongs to bob");
    }

    /// The same text on two platforms is two identities.
    function test_platformsDoNotShareNodes() public {
        _bind(alice, "123", "alice", 100);

        _stage("123", "alice", bob, 100);
        vm.prank(bob);
        _submit(GITHUB, "");

        assertEq(registry.resolveHandle(X, "alice"), alice);
        assertEq(registry.resolveHandle(GITHUB, "alice"), bob);
        assertEq(registry.resolveId(_id(X, "123")), alice);
        assertEq(registry.resolveId(_id(GITHUB, "123")), bob);
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
        assertEq(registry.resolveId(_id(X, "123")), alice);
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
        registry.bind(X, 2, payload);

        (address idHolder, uint64 idAt) = registry.idBinding(_id(X, "456"));
        (address handleHolder, uint64 handleAt) = registry.handleBinding(_hn(X, "bob"));
        assertEq(idHolder, bob, "the id node");
        assertEq(handleHolder, bob, "the handle node");
        assertEq(idAt, 100);
        assertEq(handleAt, 100);

        assertEq(_lastBindVersion(), 2, "the log an indexer reads");
    }

    /// The ceremony version out of the last `IdentityBound` in the recorded
    /// logs, which carries the two nodes as topics and nothing they hash.
    function _lastBindVersion() internal view returns (uint16 ceremonyVersion) {
        Vm.Log[] memory logs = vm.getRecordedLogs();
        bytes32 topic = keccak256("IdentityBound(address,bytes32,bytes32,bytes32,uint64,uint16)");
        for (uint256 i = logs.length; i > 0; i--) {
            if (logs[i - 1].topics[0] != topic) continue;
            (,, ceremonyVersion) = abi.decode(logs[i - 1].data, (bytes32, uint64, uint16));
            return ceremonyVersion;
        }
        revert("no IdentityBound in the logs");
    }

    // ─── A platform is not usable until it can verify ───────────────

    /// A platform `handles.json` names but no verifier serves has rules and
    /// can verify nothing. Answering `address(0)` there would tell a caller
    /// "nobody proved this" about a platform that cannot bind yet.
    function test_aPlatformWithoutAVerifierDoesNotResolve() public {
        bytes32 google = HandlePlatforms.PLATFORM_GOOGLE;
        bytes32 idNode = _id(google, "123");
        bytes32 handleNode = _hn(google, "alice@gmail.com");

        vm.expectRevert(abi.encodeWithSelector(IdentityRegistry.UnknownPlatform.selector, google));
        registry.resolveHandle(google, "alice@gmail.com");

        vm.expectRevert(abi.encodeWithSelector(IdentityRegistry.UnknownPlatform.selector, google));
        registry.resolveHandleAndId(google, "alice@gmail.com", idNode);

        // The hashing views answer: a client folding under `rulesOf` and
        // hashing under `handleTagOf` reaches the node `handleNodeOf` names.
        assertEq(registry.rulesOf(google).maxLength, HandlePlatforms.rulesFor(google).maxLength);
        assertEq(registry.handleTagOf(google), HandlePlatforms.handleTagFor(google));
        assertEq(registry.handleNodeOf(google, "Alice@Gmail.com"), handleNode);
    }

    /// And binding says the same thing, rather than naming a version the
    /// caller never chose. The platform is known, so the Consumer lets the
    /// bind through and the Proof Verifier is the one with nothing to
    /// dispatch to.
    function test_bindingOnAPlatformWithoutAVerifierIsRefused() public {
        bytes32 google = HandlePlatforms.PLATFORM_GOOGLE;
        _stage("123", "alice", alice, 100);
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(CeremonyProofVerifier.UnknownVersion.selector, google, V1));
        _submit(google, "");
    }

    /// A new bind needs a known platform and a verifier the Proof Verifier
    /// answers for: registering one enables the platform, retiring the last
    /// version withdraws it, and bound identities keep resolving.
    function test_acceptsBindingsNeedsAKnownPlatformAndAVerifier() public {
        bytes32 google = HandlePlatforms.PLATFORM_GOOGLE;
        assertTrue(registry.acceptsBindings(X));
        assertFalse(registry.acceptsBindings(google), "no verifier");

        StubPlatformVerifier unknownVerifier = new StubPlatformVerifier(keccak256("nowhere"), 0);
        StubPlatformVerifier googleVerifier = new StubPlatformVerifier(google, 0);
        vm.startPrank(owner);
        proofVerifier.setVerifier(keccak256("nowhere"), V1, IPlatformVerifier(address(unknownVerifier)));
        proofVerifier.setVerifier(google, V1, IPlatformVerifier(address(googleVerifier)));
        vm.stopPrank();
        assertFalse(registry.acceptsBindings(keccak256("nowhere")), "not in handles.json");
        assertTrue(registry.acceptsBindings(google));

        IdentityRegistry bare = IdentityRegistry(
            address(
                new ERC1967Proxy(address(new IdentityRegistry()), abi.encodeCall(IdentityRegistry.initialize, (owner)))
            )
        );
        assertEq(address(bare.proofVerifier()), address(0));
        assertFalse(bare.acceptsBindings(X), "no Proof Verifier");

        _bind(alice, "123", "alice", 100);
        vm.prank(owner);
        proofVerifier.setVerifier(X, V1, IPlatformVerifier(address(0)));
        assertFalse(registry.acceptsBindings(X));
        assertEq(registry.resolveHandle(X, "alice"), alice);
    }

    /// A retired handle has no holder and keeps its watermark, so a proof
    /// older than the one that retired it cannot take the node back.
    function test_aRetiredHandleHasNoHolderAndKeepsItsWatermark() public {
        _bind(alice, "123", "alice", 100);
        _bind(alice, "123", "alice2", 200);

        (address holder, uint64 at) = registry.handleBinding(_hn(X, "alice"));
        assertEq(holder, address(0), "the handle was retired");
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
        vm.expectRevert(abi.encodeWithSelector(IdentityRegistry.NotProofTarget.selector, alice, owner));
        _submit(X, "");

        assertEq(registry.resolveId(_id(X, "123")), alice, "the binding moved");
    }

    /// Choosing a platform's verifiers is the whole of the owner's power here,
    /// and it reaches no existing binding. Replacing the verifier a version
    /// dispatches to must not disturb a binding that the previous one's proof
    /// established.
    function test_replacingAVerifierLeavesBindingsAlone() public {
        _bind(alice, "123", "alice", 100);

        StubPlatformVerifier replacement = new StubPlatformVerifier(X, 0);
        vm.prank(owner);
        proofVerifier.setVerifier(X, V1, IPlatformVerifier(address(replacement)));

        assertEq(registry.resolveId(_id(X, "123")), alice);
        assertEq(registry.resolveHandle(X, "alice"), alice);
        assertEq(address(proofVerifier.verifierOf(X, V1)), address(replacement));
    }

    function test_onlyTheOwnerSetsTheProofVerifier() public {
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, alice));
        registry.setProofVerifier(IProofVerifier(address(0xBEEF)));
    }
}
