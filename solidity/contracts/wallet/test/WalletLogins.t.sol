// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Vm} from "forge-std/Test.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {Execution} from "@openzeppelin/contracts/interfaces/draft-IERC7579.sol";

import {IOperationLists} from "../../ceremony/IOperationLists.sol";
import {IProofVerifier} from "../../ceremony/IProofVerifier.sol";
import {operationList} from "../../ceremony/test/OperationListVector.sol";
import {IdentityRegistry} from "../../identity/IdentityRegistry.sol";
import {IWalletRegistry} from "../IWalletRegistry.sol";
import {AUTHORIZED_MODE, IWebWallet} from "../IWebWallet.sol";
import {OtherClientVerifier, WalletSuite} from "./WalletSuite.sol";

/// Submits a removal login: anyone may, so a batch can reach the wallet's entry through it below quorum.
contract Remover {
    function run(address w, bytes32 platformId, uint16 version, bytes calldata payload) external {
        IWebWallet.Policy memory none;
        IWebWallet(w).removeSessionsByLogin(platformId, version, payload, "", none);
    }
}

/// @notice Logins that add and remove sessions, the threshold they lower, app lists and Operation List entries:
///         0e2721f's WalletLogins, WalletLoginsAbuse and OperationListWallet suites.
contract WalletLoginsTest is WalletSuite {
    /// X at this version verifies through `OtherClientVerifier`, client "another-app".
    uint16 internal constant OTHER_APP = 2;
    bytes32 internal constant DAVE = keccak256("dave's GitHub id node");

    function setUp() public override {
        super.setUp();
        OtherClientVerifier other = new OtherClientVerifier(xStub);
        vm.prank(owner);
        proofVerifier.setVerifier(X, OTHER_APP, other);
    }

    /// Alice's genesis X admin, then Bob's GitHub and Carol's Google admins up to `platforms`, at threshold `t`.
    function _wallet(uint8 platforms, uint8 t) internal returns (address w) {
        w = _claim();
        if (platforms > 1) _link(w, GITHUB, BOB, _key(BOB_PK), _admin());
        if (platforms > 2) _link(w, GOOGLE, CAROL, _key(CAROL_PK), _admin());
        if (t > 1) _threshold(w, t);
        vm.warp(_now() + 1);
    }

    function _none() internal pure returns (IWebWallet.Policy memory none) {}

    function _removePayload(address w, bytes32 platformId, bytes32 idNode) internal returns (bytes memory) {
        return _payload(platformId, idNode, REMOVE, _txData(w, "", 0));
    }

    /// A stranger submits a removal login of `(platformId, idNode)` for `w`.
    function _loginRemove(address w, bytes32 platformId, bytes32 idNode) internal {
        bytes memory payload = _removePayload(w, platformId, idNode);
        vm.prank(mallory);
        IWebWallet(w).removeSessionsByLogin(platformId, V1, payload, "", _none());
    }

    function _loginAdd(address w, bytes32 platformId, bytes32 idNode, uint256 pk, IWebWallet.Policy memory p) internal {
        _addByLogin(relayer, platformId, idNode, w, _key(pk), p);
    }

    function _delay(uint32 d) internal pure returns (bytes memory) {
        return abi.encodeCall(IWebWallet.setRootDelay, (d));
    }

    function _apps(bytes memory a) internal pure returns (bytes[] memory l) {
        l = new bytes[](1);
        l[0] = a;
    }

    function _setApps(address w, bytes[] memory apps) internal {
        vm.prank(w);
        IWebWallet(w).setAppList(X, apps);
    }

    /// The position + 1 of the first log of `w` with `topic0`, else 0.
    function _logged(Vm.Log[] memory logs, address w, bytes32 topic0) internal pure returns (uint256) {
        for (uint256 i; i < logs.length; ++i) {
            if (logs[i].emitter == w && logs[i].topics[0] == topic0) return i + 1;
        }
        return 0;
    }

    // ─── Removal by login ───────────────────────────────────────────

    /// With no key: kills the identity's sessions, unlinks it, voids every queued root operation and lowers the
    /// threshold to the platforms left.
    function test_aRemovalKillsUnlinksVoidsAndLowersTheThreshold() public {
        address w = _wallet(3, 3);
        bytes32 bob = _identity(GITHUB, BOB);
        _addSession(w, bob, _key(NEW_PK), _admin());
        bytes32 id = _queueW(w, _delay(1 days));
        uint32 gen = IWebWallet(w).generationOf(bob);
        vm.warp(_now() + 1);

        vm.recordLogs();
        _loginRemove(w, GITHUB, BOB);
        assertGt(_logged(vm.getRecordedLogs(), w, IWebWallet.SessionsRemovedByLogin.selector), 0, "no event");
        assertFalse(IWebWallet(w).isLinked(bob), "a non-genesis identity stays linked");
        assertGt(IWebWallet(w).generationOf(bob), gen, "the generation did not move");
        assertEq(IWebWallet(w).linkedPlatforms(), 2, "platforms");
        assertEq(IWebWallet(w).threshold(), 2, "not min(3, 2)");
        assertEq(IWebWallet(w).rootReadyAt(id), 0, "the queued operation survived");
        vm.warp(_now() + 1 days);
        vm.expectRevert(abi.encodeWithSelector(IWebWallet.RootOperationVoid.selector, id));
        IWebWallet(w).executeRoot(id);

        bytes memory hit = _one(_hitX());
        _refusesBy(w, hit, _pks(ALICE_PK, BOB_PK), NOT_SIGNED);
        _refusesBy(w, hit, _pks(ALICE_PK, NEW_PK), NOT_SIGNED);
        _runsBy(w, hit, _pks(ALICE_PK, CAROL_PK));
    }

    /// Two identities on one platform: removing one leaves the platform, and the threshold.
    function test_aRemovalCountsPlatformsNotIdentities() public {
        address w = _wallet(2, 2);
        _link(w, GITHUB, DAVE, "", _admin());
        _loginRemove(w, GITHUB, DAVE);
        assertEq(IWebWallet(w).linkedPlatforms(), 2, "platforms");
        assertEq(IWebWallet(w).threshold(), 2, "the threshold dropped");
    }

    function test_aGenesisRemovalKeepsTheLink() public {
        address w = _wallet(2, 2);
        bytes32 alice = _identity(X, ALICE);
        _addSession(w, alice, _key(ALICE2_PK), _admin());
        bytes32 id = _queueW(w, _delay(1 days));
        vm.warp(_now() + 1);

        _loginRemove(w, X, ALICE);
        assertTrue(IWebWallet(w).isLinked(alice), "the genesis was unlinked");
        assertEq(IWebWallet(w).threshold(), 2, "threshold");
        assertEq(IWebWallet(w).rootReadyAt(id), 0, "the queued operation survived");
        bytes memory hit = _one(_hitX());
        _refusesBy(w, hit, _pks(ALICE_PK, BOB_PK), NOT_SIGNED);
        _refusesBy(w, hit, _pks(ALICE2_PK, BOB_PK), NOT_SIGNED);

        // The user signs in again.
        _loginAdd(w, X, ALICE, NEW_PK, _admin());
        vm.warp(_now() + 1);
        _runsBy(w, hit, _pks(NEW_PK, BOB_PK));
    }

    /// The last admin goes too, with no refusal; signing in again gives the wallet back.
    function test_aRemovalNeverRevertsOnTheLastAdminOrTheThreshold() public {
        address w = _wallet(2, 2);
        _loginRemove(w, GITHUB, BOB);
        assertEq(IWebWallet(w).threshold(), 1, "not min(2, 1)");
        _loginRemove(w, X, ALICE);
        assertEq(IWebWallet(w).threshold(), 1, "threshold");
        bytes memory hit = _one(_hitX());
        _refusesBy(w, hit, _pks(ALICE_PK), NOT_SIGNED);

        _loginAdd(w, X, ALICE, NEW_PK, _admin());
        assertTrue(IWebWallet(w).sessionOf(_key(NEW_PK)).byProof, "not by login");
        vm.warp(_now() + 1);
        _runsBy(w, hit, _pks(NEW_PK));
    }

    /// The drop is to the platforms left, not to those holding an admin.
    function test_aRemovalDropsToPlatformsNotAdminPlatforms() public {
        address w = _wallet(3, 3);
        _loginRemove(w, X, ALICE);
        _loginRemove(w, GITHUB, BOB);
        assertEq(IWebWallet(w).threshold(), 2, "not min(3, 2)");
        _refusesBy(w, _one(_hitX()), _pks(CAROL_PK), NOT_SIGNED);
    }

    function test_theWalletsOwnUnlinkLowersTheThreshold() public {
        address w = _wallet(2, 2);
        bytes32 bob = _identity(GITHUB, BOB);
        _rootW(w, abi.encodeCall(IWebWallet.unlink, (bob)));
        assertFalse(IWebWallet(w).isLinked(bob), "linked");
        assertEq(IWebWallet(w).threshold(), 1, "not min(2, 1)");
        _runsBy(w, _one(_hitX()), _pks(ALICE_PK));
    }

    /// An unlink may leave the wallet no admin session.
    function test_theWalletsOwnUnlinkMayLeaveNoAdmin() public {
        address w = _wallet(2, 1);
        _revoke(w, _key(ALICE_PK));
        _rootW(w, abi.encodeCall(IWebWallet.unlink, (_identity(GITHUB, BOB))));
        assertEq(IWebWallet(w).threshold(), 1, "threshold");
        _refusesBy(w, _one(_hitX()), _pks(BOB_PK), NOT_SIGNED);

        _loginAdd(w, X, ALICE, NEW_PK, _admin());
        vm.warp(_now() + 1);
        _runsBy(w, _one(_hitX()), _pks(NEW_PK));
    }

    function test_aRemovalMayBeAnOperationListEntry() public {
        address w = _wallet(2, 1);
        bytes memory data = _txData(w, "", 0);
        bytes memory payload = _payload(GITHUB, BOB, OPERATIONS, operationList(REMOVE, data, BIND, abi.encode(w)));
        vm.prank(mallory);
        IWebWallet(w).removeSessionsByLogin(GITHUB, V1, payload, data, _none());
        assertFalse(IWebWallet(w).isLinked(_identity(GITHUB, BOB)), "not removed");
        assertTrue(registry.spentDigests(_digestOf(payload)), "not spent");
    }

    function test_aRemovalWithAKeyReplacesTheSessions() public {
        _replaceBob(false);
    }

    /// Beside another Consumer's entry.
    function test_aRemovalWithAKeyMayBeAListEntry() public {
        _replaceBob(true);
    }

    /// With a key: Bob's login on a 2-of-2 wallet kills his sessions, keeps his link, voids the queued root
    /// operations, and adds NEW_PK as a login session.
    function _replaceBob(bool list) internal {
        address w = _wallet(2, 2);
        bytes32 bob = _identity(GITHUB, BOB);
        bytes32 id = _queueW(w, _delay(1 days));
        vm.warp(_now() + 1);

        bytes memory data = _txData(w, _key(NEW_PK), _ph(_admin()));
        bytes memory payload = list
            ? _payload(GITHUB, BOB, OPERATIONS, operationList(REMOVE, data, BIND, abi.encode(w)))
            : _payload(GITHUB, BOB, REMOVE, data);
        vm.recordLogs();
        vm.prank(mallory);
        IWebWallet(w).removeSessionsByLogin(GITHUB, V1, payload, list ? data : bytes(""), _admin());

        Vm.Log[] memory logs = vm.getRecordedLogs();
        uint256 removed = _logged(logs, w, IWebWallet.SessionsRemovedByLogin.selector);
        uint256 added = _logged(logs, w, IWebWallet.SessionAdded.selector);
        assertTrue(removed != 0 && removed < added, "not removed, then added");
        assertTrue(IWebWallet(w).isLinked(bob), "unlinked");
        assertEq(IWebWallet(w).threshold(), 2, "threshold");
        assertEq(IWebWallet(w).rootReadyAt(id), 0, "the queued operation survived");
        IWebWallet.Session memory s = IWebWallet(w).sessionOf(_key(NEW_PK));
        assertTrue(s.byProof && s.identity == bob, "not Bob's session by login");

        vm.warp(_now() + 1);
        bytes memory hit = _one(_hitX());
        _refusesBy(w, hit, _pks(ALICE_PK, BOB_PK), NOT_SIGNED);
        _runsBy(w, hit, _pks(ALICE_PK, NEW_PK));
    }

    // ─── Login sessions and the threshold ───────────────────────────

    function test_aLimitedLoginSessionActsAloneOnlyAtThresholdOne() public {
        address w = _wallet(2, 2);
        _loginAdd(w, X, ALICE, APP_PK, _hitOnly());
        IWebWallet.Session memory s = IWebWallet(w).sessionOf(_key(APP_PK));
        assertTrue(s.byProof, "not byProof");
        assertEq(s.activeAt, _now(), "not from the next second");
        _addSession(w, _identity(X, ALICE), _key(NEW_PK), _hitOnly());
        vm.warp(_now() + 1);

        bytes memory hit = _one(_hitX());
        _refuses(w, hit, _direct(w, _pks(APP_PK), hit, true), NOT_SIGNED);
        // The wallet's own limited session acts alone at 2: the refusal is byProof's.
        _runs(w, hit, _direct(w, _pks(NEW_PK), hit, true));
        _threshold(w, 1);
        _runs(w, hit, _direct(w, _pks(APP_PK), hit, true));
    }

    /// ERC-1271 too: a login session signs for an app alone only at threshold 1.
    function test_aLoginSessionSignsForAnAppAloneOnlyAtThresholdOne() public {
        address w = _wallet(2, 2);
        bytes32 app = keccak256("an app's domain separator");
        IWebWallet.Policy memory p = _hitOnly();
        p.rules.domainsRoot = _domainLeaf(app);
        _loginAdd(w, X, ALICE, APP_PK, p);
        _addSession(w, _identity(X, ALICE), _key(NEW_PK), p);
        vm.warp(_now() + 1);
        bytes32[] memory none = new bytes32[](0);

        (bytes32 h, bytes memory sig) = _typedSigBy(w, _pks(APP_PK), app, none);
        assertEq(IWebWallet(w).isValidSignature(h, sig), bytes4(0xffffffff), "a login session alone at 2");
        (h, sig) = _typedSigBy(w, _pks(NEW_PK), app, none);
        assertEq(IWebWallet(w).isValidSignature(h, sig), MAGIC, "control: the wallet's own session");
        _threshold(w, 1);
        (h, sig) = _typedSigBy(w, _pks(APP_PK), app, none);
        assertEq(IWebWallet(w).isValidSignature(h, sig), MAGIC, "a login session alone at 1");
    }

    // ─── No login helps its own batch's check ───────────────────────

    function test_aLoginAddInTheBatchCannotSignIt() public {
        address w = _wallet(2, 2);
        bytes memory payload = _loginPayload(w, GITHUB, BOB, _key(NEW_PK), _admin());
        bytes memory add = abi.encodeCall(IWebWallet.addSessionByLogin, (GITHUB, V1, payload, "", _admin()));
        _refusesBy(w, _then(_x(w, 0, add)), _pks(ALICE_PK, NEW_PK), NOT_SIGNED);
        assertEq(IWebWallet(w).sessionOf(_key(NEW_PK)).identity, bytes32(0), "the add stayed");

        vm.prank(relayer);
        IWebWallet(w).addSessionByLogin(GITHUB, V1, payload, "", _admin());
        _refusesBy(w, _one(_hitX()), _pks(ALICE_PK, NEW_PK), NOT_SIGNED);
        vm.warp(_now() + 1);
        _runsBy(w, _one(_hitX()), _pks(ALICE_PK, NEW_PK));
    }

    function test_aLoginRemovalInTheBatchDoesNotLowerItsCheck() public {
        address w = _wallet(2, 2);
        bytes memory payload = _removePayload(w, GITHUB, BOB);
        bytes memory rm = abi.encodeCall(IWebWallet.removeSessionsByLogin, (GITHUB, V1, payload, "", _none()));
        _refusesBy(w, _then(_x(w, 0, rm)), _pks(ALICE_PK), NOT_SIGNED);
        assertTrue(IWebWallet(w).isLinked(_identity(GITHUB, BOB)), "the removal stayed");

        vm.prank(mallory);
        IWebWallet(w).removeSessionsByLogin(GITHUB, V1, payload, "", _none());
        vm.warp(_now() + 1);
        _runsBy(w, _one(_hitX()), _pks(ALICE_PK));
    }

    /// A batch read at threshold 2 that drops to 1 by its own removal keeps the byProof refusal.
    function test_aBatchDroppingToThresholdOneKeepsTheByProofRefusal() public {
        address w = _wallet(2, 2);
        Remover remover = new Remover();
        bytes32[] memory leaves = new bytes32[](2);
        leaves[0] = _leaf(address(remover), Remover.run.selector, 0);
        leaves[1] = _hitScope();
        IWebWallet.CallProof[] memory proofs = new IWebWallet.CallProof[](2);
        bytes32 root;
        (root, proofs[0].proof) = _tree(leaves, 0);
        (, proofs[1].proof) = _tree(leaves, 1);
        IWebWallet.Policy memory p = _hitOnly();
        p.rules.scopeRoot = root;
        _loginAdd(w, X, ALICE, APP_PK, p);
        _addSession(w, _identity(X, ALICE), _key(NEW_PK), p);
        vm.warp(_now() + 1);

        bytes memory payload = _removePayload(w, GITHUB, BOB);
        bytes memory calls = _then(_x(address(remover), 0, abi.encodeCall(Remover.run, (w, GITHUB, V1, payload))));
        uint256 n = _nonce(w);
        uint48 at = uint48(_now());
        _refuses(w, calls, _directAt(w, _pks(APP_PK), calls, n, at, true, proofs), NOT_SIGNED);
        assertTrue(IWebWallet(w).isLinked(_identity(GITHUB, BOB)), "the removal stayed");

        // Control: the wallet's own session with the same rules runs the same batch.
        uint256 state = vm.snapshotState();
        _runs(w, calls, _directAt(w, _pks(NEW_PK), calls, n, at, true, proofs));
        assertEq(IWebWallet(w).threshold(), 1, "control: threshold");
        vm.revertToState(state);

        vm.prank(relayer);
        remover.run(w, GITHUB, V1, payload);
        vm.warp(_now() + 1);
        bytes memory hit = _one(_hitX());
        IWebWallet.CallProof[] memory one = new IWebWallet.CallProof[](1);
        one[0] = proofs[1];
        _runs(w, hit, _directAt(w, _pks(APP_PK), hit, _nonce(w), uint48(_now()), true, one));
    }

    /// A phished platform revokes the owner's admins and removes a platform by login, in one batch below quorum.
    function test_revokesThenALoginRemovalBelowQuorumFail() public {
        address w = _wallet(2, 2);
        bytes32 bob = _identity(GITHUB, BOB);
        _link(w, GOOGLE, CAROL, _key(CAROL_PK), _admin());
        vm.warp(_now() + 1);
        bytes memory payload = _removePayload(w, GITHUB, BOB);
        Execution[] memory x = new Execution[](3);
        x[0] = _x(w, 0, abi.encodeCall(IWebWallet.revokeSession, (_key(BOB_PK))));
        x[1] = _x(w, 0, abi.encodeCall(IWebWallet.removeSessionsByLogin, (GITHUB, V1, payload, "", _none())));
        x[2] = _hitX();
        bytes memory calls = abi.encode(x);
        uint256 n = _nonce(w);
        uint256 state = vm.snapshotState();
        _runsBy(w, calls, _pks(ALICE_PK, CAROL_PK));
        assertFalse(IWebWallet(w).isLinked(bob), "control: Bob stays");
        vm.revertToState(state);
        for (uint256 below; below < 2; ++below) {
            bytes memory auth = _direct(w, _pks(CAROL_PK), calls, below == 1);
            vm.prank(relayer);
            vm.expectRevert();
            IWebWallet(w).execute(AUTHORIZED_MODE, _data(calls, auth));
        }
        assertEq(_nonce(w), n, "nonce");
        assertTrue(IWebWallet(w).isLinked(bob), "Bob removed");
        assertEq(IWebWallet(w).sessionOf(_key(BOB_PK)).identity, bob, "Bob's admin revoked");
        _runsBy(w, _one(_hitX()), _pks(ALICE_PK, CAROL_PK));
    }

    // ─── Refused logins ─────────────────────────────────────────────

    struct Row {
        string name;
        bytes32 platformId;
        bytes32 idNode;
        bytes32 domain;
        bytes txData;
        /// The call's `data`: the Operation List entry's bytes, or empty.
        bytes data;
        bytes err;
    }

    /// Each row, submitted by a stranger, reverts with its error and leaves the wallet and the digest as they were.
    function _rows(address w, Row[] memory rows, bool add) internal {
        for (uint256 i; i < rows.length; ++i) {
            Row memory r = rows[i];
            uint256 state = vm.snapshotState();
            bytes memory payload = _payload(r.platformId, r.idNode, r.domain, r.txData);
            vm.expectRevert(r.err);
            vm.prank(mallory);
            if (add) IWebWallet(w).addSessionByLogin(r.platformId, V1, payload, r.data, _admin());
            else IWebWallet(w).removeSessionsByLogin(r.platformId, V1, payload, r.data, _none());
            assertTrue(IWebWallet(w).isLinked(_identity(GITHUB, BOB)), r.name);
            assertEq(IWebWallet(w).threshold(), 2, r.name);
            assertFalse(registry.spentDigests(_digestOf(payload)), r.name);
            vm.revertToState(state);
        }
    }

    function test_refusedRemovals() public {
        address w = _wallet(2, 2);
        bytes memory good = _txData(w, "", 0);
        bytes4 bad = IWalletRegistry.BadTransactionData.selector;
        bytes4 notLinked = IWebWallet.NotLinked.selector;
        bytes4 domain = IWalletRegistry.WrongOperationDomain.selector;
        bytes memory addData = _txData(w, _key(NEW_PK), _ph(_admin()));
        Row[] memory rows = new Row[](8);
        rows[0] = Row(
            "another chain",
            GITHUB,
            BOB,
            REMOVE,
            abi.encode(block.chainid + 1, w, bytes(""), bytes32(0)),
            "",
            abi.encodeWithSelector(IWalletRegistry.WrongChain.selector, block.chainid + 1)
        );
        rows[1] = Row(
            "trailing byte", GITHUB, BOB, REMOVE, bytes.concat(good, hex"00"), "", abi.encodeWithSelector(bad, 161)
        );
        rows[2] = Row(
            "no key, with a policy hash",
            GITHUB,
            BOB,
            REMOVE,
            _txData(w, "", _ph(_admin())),
            "",
            abi.encodeWithSelector(bad, 160)
        );
        rows[3] = Row(
            "an identity not linked here",
            GITHUB,
            DAVE,
            REMOVE,
            good,
            "",
            abi.encodeWithSelector(notLinked, _identity(GITHUB, DAVE))
        );
        rows[4] = Row(
            "Bob's id on another platform",
            X,
            BOB,
            REMOVE,
            good,
            "",
            abi.encodeWithSelector(notLinked, _identity(X, BOB))
        );
        rows[5] = Row("a link proof", GITHUB, BOB, LINK, addData, "", abi.encodeWithSelector(domain, REMOVE, LINK));
        rows[6] = Row(
            "data without a list",
            GITHUB,
            BOB,
            REMOVE,
            good,
            good,
            abi.encodeWithSelector(IWalletRegistry.DataWithoutList.selector)
        );
        rows[7] = Row(
            "a list's add-session entry",
            GITHUB,
            BOB,
            OPERATIONS,
            operationList(ADD, addData, BIND, abi.encode(w)),
            addData,
            abi.encodeWithSelector(domain, REMOVE, ADD)
        );
        _rows(w, rows, false);
    }

    function test_refusedAdds() public {
        address w = _wallet(2, 2);
        vm.prank(relayer);
        address fresh = factory.createWallet(X, CAROL, 0);
        Row[] memory rows = new Row[](2);
        rows[0] = Row(
            "an identity not linked here",
            GITHUB,
            DAVE,
            ADD,
            _txData(w, _key(NEW_PK), _ph(_admin())),
            "",
            abi.encodeWithSelector(IWebWallet.NotLinked.selector, _identity(GITHUB, DAVE))
        );
        rows[1] = Row(
            "a removal proof",
            GITHUB,
            BOB,
            REMOVE,
            _txData(w, "", 0),
            "",
            abi.encodeWithSelector(IWalletRegistry.WrongOperationDomain.selector, ADD, REMOVE)
        );
        _rows(w, rows, true);
        // A wallet that never had a session takes its first one from its own bootstrap only.
        bytes memory payload = _loginPayload(fresh, X, CAROL, _key(NEW_PK), _admin());
        vm.expectRevert(IWebWallet.FirstSessionRefused.selector);
        IWebWallet(fresh).addSessionByLogin(X, V1, payload, "", _admin());
    }

    /// A spent removal does not run twice, even while its identity, the genesis, stays linked.
    function test_aRemovalIsSpentOnce() public {
        address w = _wallet(2, 2);
        bytes memory payload = _removePayload(w, X, ALICE);
        IWebWallet(w).removeSessionsByLogin(X, V1, payload, "", _none());
        _addSession(w, _identity(X, ALICE), _key(NEW_PK), _admin());
        vm.expectRevert(abi.encodeWithSelector(IWalletRegistry.DigestSpent.selector, _digestOf(payload)));
        IWebWallet(w).removeSessionsByLogin(X, V1, payload, "", _none());
        assertEq(IWebWallet(w).sessionOf(_key(NEW_PK)).identity, _identity(X, ALICE), "the replay removed");
    }

    // ─── App lists ──────────────────────────────────────────────────

    /// A listed app adds; an unlisted one reverts `AppNotListed` and spends nothing; the list governs only a
    /// keyed removal's add, and survives a removal.
    function test_aListRefusesOtherAppsAddsAndSurvivesARemoval() public {
        address w = _wallet(1, 1);
        bytes32 alice = _identity(X, ALICE);
        bytes[] memory apps = _apps("client");
        vm.expectEmit(true, false, false, true, w);
        emit IWebWallet.AppListSet(X, apps);
        _setApps(w, apps);
        assertEq(abi.encode(IWebWallet(w).appList(X)), abi.encode(apps), "list");

        IWebWallet.Policy memory p = _admin();
        bytes memory add = _loginPayload(w, X, ALICE, _key(NEW_PK), p);
        bytes memory notListed = abi.encodeWithSelector(IWebWallet.AppNotListed.selector, bytes("another-app"));
        vm.expectRevert(notListed);
        IWebWallet(w).addSessionByLogin(X, OTHER_APP, add, "", p);
        assertFalse(registry.spentDigests(_digestOf(add)), "a refused login spent the digest");
        IWebWallet(w).addSessionByLogin(X, V1, add, "", p);
        assertEq(IWebWallet(w).sessionOf(_key(NEW_PK)).identity, alice, "the listed app was refused");

        // A keyed removal adds, so the list refuses it and nothing changes.
        bytes memory keyed = _payload(X, ALICE, REMOVE, _txData(w, _key(APP_PK), _ph(p)));
        vm.expectRevert(notListed);
        IWebWallet(w).removeSessionsByLogin(X, OTHER_APP, keyed, "", p);
        assertEq(IWebWallet(w).sessionOf(_key(NEW_PK)).identity, alice, "removed");
        assertEq(IWebWallet(w).sessionOf(_key(APP_PK)).identity, bytes32(0), "added");
        assertFalse(registry.spentDigests(_digestOf(keyed)), "a refused removal spent the digest");

        // A removal with no key from any app is accepted, and leaves the list.
        IWebWallet(w).removeSessionsByLogin(X, OTHER_APP, _removePayload(w, X, ALICE), "", _none());
        assertEq(IWebWallet(w).sessionOf(_key(NEW_PK)).identity, bytes32(0), "not removed");
        assertEq(abi.encode(IWebWallet(w).appList(X)), abi.encode(apps), "the removal cleared the list");
    }

    /// Every entry of a list admits its app, not only the first; an entry of an Operation List is held to it too.
    function test_aListOfTwoAdmitsItsSecondAndRefusesTheRest() public {
        address w = _wallet(1, 1);
        bytes[] memory apps = new bytes[](2);
        (apps[0], apps[1]) = (bytes("a third app"), bytes("client"));
        _setApps(w, apps);
        IWebWallet.Policy memory p = _admin();
        bytes memory payload = _loginPayload(w, X, ALICE, _key(NEW_PK), p);
        vm.expectPartialRevert(IWebWallet.AppNotListed.selector);
        IWebWallet(w).addSessionByLogin(X, OTHER_APP, payload, "", p);
        IWebWallet(w).addSessionByLogin(X, V1, payload, "", p);
        assertTrue(IWebWallet(w).sessionOf(_key(NEW_PK)).byProof, "the second entry was refused");

        bytes memory add = _txData(w, _key(APP_PK), _ph(p));
        payload = _payload(X, ALICE, OPERATIONS, operationList(ADD, add, BIND, abi.encode(w)));
        vm.expectPartialRevert(IWebWallet.AppNotListed.selector);
        IWebWallet(w).addSessionByLogin(X, OTHER_APP, payload, add, p);
        IWebWallet(w).addSessionByLogin(X, V1, payload, add, p);
        assertTrue(IWebWallet(w).sessionOf(_key(APP_PK)).byProof, "control: the listed app's entry");
    }

    /// Only the wallet writes its list; an empty list admits any app.
    function test_onlyTheWalletWritesItsList() public {
        address w = _wallet(1, 1);
        assertEq(IWebWallet(w).appList(X).length, 0, "a list by default");
        vm.prank(mallory);
        vm.expectRevert(IWebWallet.OnlySelf.selector);
        IWebWallet(w).setAppList(X, _apps("mallory's app"));
        assertEq(IWebWallet(w).appList(X).length, 0, "a stranger wrote the wallet's list");
        bytes memory payload = _loginPayload(w, X, ALICE, _key(NEW_PK), _admin());
        IWebWallet(w).addSessionByLogin(X, OTHER_APP, payload, "", _admin());
        assertTrue(IWebWallet(w).sessionOf(_key(NEW_PK)).byProof, "an empty list refused another app");
    }

    function test_belowQuorumABatchCannotSetTheList() public {
        address w = _wallet(2, 2);
        bytes memory calls = _then(_x(w, 0, abi.encodeCall(IWebWallet.setAppList, (X, _apps("client")))));
        _refuses(w, calls, _direct(w, _pks(ALICE_PK), calls, true), NOT_ALLOWED);
        assertEq(IWebWallet(w).appList(X).length, 0, "set below quorum");
        _runsBy(w, calls, _pks(ALICE_PK, BOB_PK));
        assertEq(IWebWallet(w).appList(X).length, 1, "control: not set at quorum");
    }

    // ─── Operation Lists ────────────────────────────────────────────

    function _linkData(address w) internal view returns (bytes memory) {
        return _txData(w, _key(ALICE_PK), _ph(_admin()));
    }

    /// The fresh wallet's own link of `payload` with `data`.
    function _ownLink(address w, bytes memory payload, bytes memory data) internal {
        vm.prank(w);
        IWebWallet(w).linkIdentity(X, V1, payload, data, _admin());
    }

    function _fresh() internal returns (address w) {
        vm.prank(relayer);
        w = factory.createWallet(X, ALICE, 0);
    }

    /// One proof: the wallet's first session and its binding at IdentityRegistry, each spent once.
    function test_bothConsumersAcceptOneListOnce() public {
        IdentityRegistry identities = IdentityRegistry(
            address(
                new ERC1967Proxy(address(new IdentityRegistry()), abi.encodeCall(IdentityRegistry.initialize, (owner)))
            )
        );
        vm.prank(owner);
        identities.setProofVerifier(IProofVerifier(address(proofVerifier)));
        address w = _fresh();
        bytes memory link = _linkData(w);
        bytes memory payload = _payload(X, ALICE, OPERATIONS, operationList(BIND, abi.encode(w), LINK, link));
        _ownLink(w, payload, link);
        vm.prank(w);
        identities.bindPrivately(X, V1, payload, 0, address(0));
        bytes32 digest = _digestOf(payload);
        assertLe(IWebWallet(w).sessionOf(_key(ALICE_PK)).activeAt, _now(), "no active first session");
        assertEq(identities.resolveId(ALICE), w, "not bound");
        assertTrue(registry.spentDigests(digest) && identities.digestSpent(digest), "not spent at both");
        vm.expectRevert(abi.encodeWithSelector(IWalletRegistry.DigestSpent.selector, digest));
        _ownLink(w, payload, link);
        vm.prank(w);
        vm.expectRevert(abi.encodeWithSelector(IdentityRegistry.DigestAlreadySpent.selector, digest));
        identities.bindPrivately(X, V1, payload, 0, address(0));
    }

    /// The entry the data selects decides the function: an add-session entry is no link. A list with a link and
    /// an add-session for one chain, which REQ-COMMON-01L forbids the Application to compose, is spent once.
    function test_theEntryMustBeTheCalledFunction() public {
        uint256 unclaimed = vm.snapshotState();
        address w = _claim();
        bytes memory add = _txData(w, _key(ALICE2_PK), _ph(_app()));
        bytes memory payload = _payload(X, ALICE, OPERATIONS, operationList(ADD, add, BIND, hex"ff"));
        vm.expectRevert(abi.encodeWithSelector(IWalletRegistry.WrongOperationDomain.selector, LINK, ADD));
        vm.prank(w);
        IWebWallet(w).linkIdentity(X, V1, payload, add, _app());
        IWebWallet(w).addSessionByLogin(X, V1, payload, add, _app());
        assertEq(IWebWallet(w).sessionOf(_key(ALICE2_PK)).identity, _identity(X, ALICE), "no session");

        vm.revertToState(unclaimed);
        w = _fresh();
        bytes memory link = _linkData(w);
        add = _txData(w, _key(ALICE2_PK), _ph(_admin()));
        payload = _payload(X, ALICE, OPERATIONS, operationList(LINK, link, ADD, add));
        _ownLink(w, payload, link);
        vm.expectRevert(abi.encodeWithSelector(IWalletRegistry.DigestSpent.selector, _digestOf(payload)));
        IWebWallet(w).addSessionByLogin(X, V1, payload, add, _admin());
    }

    /// No own entry, a nested list, bytes that are no list, data beside one operation, another chain's entry.
    function test_badListsAreRefused() public {
        address w = _fresh();
        bytes memory link = _linkData(w);
        bytes[6] memory txData = [
            operationList(BIND, abi.encode(w), BIND, hex"ff"),
            operationList(LINK, link, OPERATIONS, hex"ff"),
            link,
            bytes.concat(operationList(LINK, link, BIND, hex"ff"), hex"00"),
            link,
            operationList(LINK, abi.encode(block.chainid + 1, w, _key(ALICE_PK), _ph(_admin())), BIND, hex"ff")
        ];
        bytes32[6] memory domains = [OPERATIONS, OPERATIONS, OPERATIONS, OPERATIONS, LINK, OPERATIONS];
        bytes[6] memory errs = [
            abi.encodeWithSelector(IOperationLists.NoOwnOperation.selector),
            abi.encodeWithSelector(IOperationLists.NestedOperationList.selector),
            abi.encodeWithSelector(IOperationLists.NoncanonicalOperationList.selector),
            abi.encodeWithSelector(IOperationLists.NoncanonicalOperationList.selector),
            abi.encodeWithSelector(IWalletRegistry.DataWithoutList.selector),
            abi.encodeWithSelector(IWalletRegistry.WrongChain.selector, block.chainid + 1)
        ];
        for (uint256 i; i < errs.length; ++i) {
            bytes memory data = i == 5 ? abi.encode(block.chainid + 1, w, _key(ALICE_PK), _ph(_admin())) : link;
            bytes memory payload = _payload(X, ALICE, domains[i], txData[i]);
            vm.expectRevert(errs[i]);
            _ownLink(w, payload, data);
        }
    }

    /// TEST-COMMON-02D: link entries naming chains A and B, accepted once on each.
    function test_entriesForTwoChainsAreAcceptedOnEach() public {
        address w = _fresh();
        (uint256 a, uint256 b) = (vm.getChainId(), vm.getChainId() + 1);
        bytes memory dataA = abi.encode(a, w, _key(ALICE_PK), _ph(_admin()));
        bytes memory dataB = abi.encode(b, w, _key(ALICE_PK), _ph(_admin()));
        bytes memory payload = _payload(X, ALICE, OPERATIONS, operationList(LINK, dataA, LINK, dataB));
        uint256 fresh = vm.snapshotState();
        vm.expectRevert(abi.encodeWithSelector(IWalletRegistry.WrongChain.selector, b));
        _ownLink(w, payload, dataB);
        _ownLink(w, payload, dataA);
        vm.revertToState(fresh);
        vm.chainId(b);
        _ownLink(w, payload, dataB);
        assertEq(IWebWallet(w).sessionOf(_key(ALICE_PK)).identity, _identity(X, ALICE), "not linked on B");
    }
}
