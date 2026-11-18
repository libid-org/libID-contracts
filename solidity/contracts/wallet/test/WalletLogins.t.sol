// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Vm} from "forge-std/Vm.sol";
import {Execution} from "@openzeppelin/contracts/interfaces/draft-IERC7579.sol";

import {operationList} from "../../ceremony/test/OperationListVector.sol";
import {IIdentityValidator} from "../IIdentityValidator.sol";
import {IWalletRegistry} from "../IWalletRegistry.sol";
import {IWebWallet} from "../IWebWallet.sol";
import {ExecuteBase, OtherClientVerifier} from "./DirectExecute.t.sol";

/// Submits a removal login: anyone may, so a batch can reach the registry through it below quorum.
contract Remover {
    function run(IWalletRegistry r, bytes32 platformId, uint16 version, bytes calldata payload) external {
        IIdentityValidator.Policy memory none;
        r.removeSessionsByLogin(platformId, version, payload, "", none);
    }
}

/// @notice Logins that add and remove sessions, and the wallets they act on.
abstract contract LoginBase is ExecuteBase {
    // cast keccak "libid.webwallet.remove-sessions"
    bytes32 internal constant REMOVE = 0x7cabdd831000d819c7b2ae4f79b4d6b566aa21992764e735f944b1459cb43c1b;
    // cast keccak "client": the stub's clientIdentifier.
    bytes32 internal constant CLIENT = 0x971ee2c8925badb60ae2abac1a4faf0aa9b739dd57ac1b3b7a1e150be855cde3;
    /// X at this version verifies through `OtherClientVerifier`, client "another-app".
    uint16 internal constant OTHER_APP = 2;
    bytes32 internal constant DAVE = keccak256("dave's GitHub id node");

    function setUp() public virtual override {
        super.setUp();
        OtherClientVerifier other = new OtherClientVerifier(xStub);
        vm.prank(owner);
        proofVerifier.setVerifier(X, OTHER_APP, other);
    }

    /// Alice's genesis X admin, then Bob's GitHub and Carol's Google admins up to `platforms`, at threshold `t`.
    function _wallet(uint8 platforms, uint8 t) internal returns (address w) {
        w = _fresh();
        if (platforms > 1) _link(w, GITHUB, BOB, w, _key(BOB_PK), _admin());
        if (platforms > 2) _link(w, GOOGLE, CAROL, w, _key(CAROL_PK), _admin());
        if (t > 1) _root(w, address(validator), abi.encodeCall(IIdentityValidator.setThreshold, (t)));
        vm.warp(_now() + 1);
    }

    function _removeData(address w) internal view returns (bytes memory) {
        return _txData(w, "", bytes32(0));
    }

    /// The policy of a removal with no key, which the registry ignores.
    function _none() internal pure returns (IIdentityValidator.Policy memory none) {}

    function _removePayload(address w, bytes32 platformId, bytes32 idNode) internal returns (bytes memory) {
        return _payload(platformId, idNode, REMOVE, _removeData(w));
    }

    function _addPayload(address w, bytes32 platformId, bytes32 idNode, uint256 pk, IIdentityValidator.Policy memory p)
        internal
        returns (bytes memory)
    {
        return _payload(platformId, idNode, ADD, _txData(w, _key(pk), _ph(p)));
    }

    /// A stranger submits a removal login of `(platformId, idNode)` for `w`.
    function _loginRemove(address w, bytes32 platformId, bytes32 idNode) internal {
        bytes memory payload = _removePayload(w, platformId, idNode);
        vm.prank(mallory);
        registry.removeSessionsByLogin(platformId, V1, payload, "", _none());
    }

    /// A relayer submits an add-session login of `(platformId, idNode)` for `w`'s key `pk`.
    function _loginAdd(address w, bytes32 platformId, bytes32 idNode, uint256 pk, IIdentityValidator.Policy memory p)
        internal
    {
        bytes memory payload = _addPayload(w, platformId, idNode, pk, p);
        vm.prank(relayer);
        registry.addSessionByLogin(platformId, V1, payload, "", p);
    }

    function _delay(uint48 d) internal pure returns (bytes memory) {
        return abi.encodeCall(IIdentityValidator.setRootDelay, (d));
    }

    function _list(bytes32 a) internal pure returns (bytes32[] memory l) {
        l = new bytes32[](1);
        l[0] = a;
    }

    /// A log with `topic0` whose first indexed argument is `account`, from any emitter.
    function _logged(bytes32 topic0, address account) internal view returns (bool) {
        Vm.Log[] memory logs = vm.getRecordedLogs();
        for (uint256 i; i < logs.length; ++i) {
            if (
                logs[i].topics.length > 1 && logs[i].topics[0] == topic0
                    && logs[i].topics[1] == bytes32(uint256(uint160(account)))
            ) return true;
        }
        return false;
    }
}

/// @notice Login removal, the threshold it lowers, login sessions at threshold 1, and app lists.
contract WalletLoginsTest is LoginBase {
    // ─── Login removal ──────────────────────────────────────────────

    function test_aRemovalKillsUnlinksVoidsAndLowersTheThreshold() public {
        address w = _wallet(3, 3);
        bytes32 bob = _identity(GITHUB, BOB);
        vm.prank(w);
        validator.addSession(bob, _key(NEW_PK), _admin());
        vm.prank(w);
        bytes32 opId = validator.queueRoot(address(validator), _delay(1 days));
        uint32 gen = validator.generationOf(w, bob);
        vm.warp(_now() + 1);

        vm.recordLogs();
        _loginRemove(w, GITHUB, BOB);
        assertTrue(_logged(IIdentityValidator.SessionsRemovedByLogin.selector, w), "no SessionsRemovedByLogin");
        assertFalse(validator.isLinked(w, bob), "a non-genesis identity stays linked");
        assertGt(validator.generationOf(w, bob), gen, "the generation did not move");
        assertEq(validator.linkedPlatforms(w), 2, "platforms");
        assertEq(validator.threshold(w), 2, "not min(3, 2)");
        assertEq(validator.rootReadyAt(w, opId), 0, "the queued operation survived");
        vm.expectRevert(abi.encodeWithSelector(IIdentityValidator.RootSuperseded.selector, opId));
        validator.executeRoot(w, address(validator), _delay(1 days));

        bytes memory hit = _one(_hitX());
        _refusesBy(w, hit, _pks(ALICE_PK, BOB_PK), NOT_SIGNED);
        _refusesBy(w, hit, _pks(ALICE_PK, NEW_PK), NOT_SIGNED);
        _runsBy(w, hit, _pks(ALICE_PK, CAROL_PK));
    }

    /// Two identities on one platform: removing one leaves the platform, and the threshold.
    function test_aRemovalCountsPlatformsNotIdentities() public {
        address w = _wallet(2, 2);
        _link(w, GITHUB, DAVE, w, "", _admin());
        _loginRemove(w, GITHUB, DAVE);
        assertEq(validator.linkedPlatforms(w), 2, "platforms");
        assertEq(validator.threshold(w), 2, "the threshold dropped");
    }

    function test_aGenesisRemovalKeepsTheLink() public {
        address w = _wallet(2, 2);
        bytes32 alice = _identity(X, ALICE);
        vm.prank(w);
        validator.addSession(alice, _key(ALICE2_PK), _admin());
        vm.prank(w);
        bytes32 opId = validator.queueRoot(address(validator), _delay(1 days));
        vm.warp(_now() + 1);

        _loginRemove(w, X, ALICE);
        assertTrue(validator.isLinked(w, alice), "the genesis was unlinked");
        assertEq(validator.threshold(w), 2, "threshold");
        assertEq(validator.rootReadyAt(w, opId), 0, "the queued operation survived");
        bytes memory hit = _one(_hitX());
        _refusesBy(w, hit, _pks(ALICE_PK, BOB_PK), NOT_SIGNED);
        _refusesBy(w, hit, _pks(ALICE2_PK, BOB_PK), NOT_SIGNED);

        // The user signs in again.
        _loginAdd(w, X, ALICE, NEW_PK, _admin());
        vm.warp(_now() + 1);
        _runsBy(w, hit, _pks(NEW_PK, BOB_PK));
    }

    /// The last admin goes too; signing in again gives the wallet back.
    function test_aRemovalNeverRevertsOnTheLastAdminOrTheThreshold() public {
        address w = _wallet(2, 2);
        _loginRemove(w, GITHUB, BOB);
        assertEq(validator.threshold(w), 1, "not min(2, 1)");
        _loginRemove(w, X, ALICE);
        assertEq(validator.threshold(w), 1, "threshold");
        bytes memory hit = _one(_hitX());
        _refusesBy(w, hit, _pks(ALICE_PK), NOT_SIGNED);

        _loginAdd(w, X, ALICE, NEW_PK, _admin());
        assertTrue(validator.sessionOf(w, _key(NEW_PK)).byProof, "not by login");
        vm.warp(_now() + 1);
        _runsBy(w, hit, _pks(NEW_PK));
    }

    /// The drop is to the platforms left, not to those holding an admin.
    function test_aRemovalDropsToPlatformsNotAdminPlatforms() public {
        address w = _wallet(3, 3);
        _loginRemove(w, X, ALICE);
        _loginRemove(w, GITHUB, BOB);
        assertEq(validator.threshold(w), 2, "not min(3, 2)");
        _refusesBy(w, _one(_hitX()), _pks(CAROL_PK), NOT_SIGNED);
    }

    function test_theWalletsOwnUnlinkLowersTheThreshold() public {
        address w = _wallet(2, 2);
        bytes32 bob = _identity(GITHUB, BOB);
        _root(w, address(validator), abi.encodeCall(IIdentityValidator.unlink, (bob)));
        assertFalse(validator.isLinked(w, bob), "linked");
        assertEq(validator.threshold(w), 1, "not min(2, 1)");
        _runsBy(w, _one(_hitX()), _pks(ALICE_PK));
    }

    /// An unlink may leave the wallet no admin session.
    function test_theWalletsOwnUnlinkMayLeaveNoAdmin() public {
        address w = _wallet(2, 1);
        vm.prank(w);
        validator.revokeSession(_key(ALICE_PK));
        _root(w, address(validator), abi.encodeCall(IIdentityValidator.unlink, (_identity(GITHUB, BOB))));
        assertEq(validator.threshold(w), 1, "threshold");
        _refusesBy(w, _one(_hitX()), _pks(BOB_PK), NOT_SIGNED);

        _loginAdd(w, X, ALICE, NEW_PK, _admin());
        vm.warp(_now() + 1);
        _runsBy(w, _one(_hitX()), _pks(NEW_PK));
    }

    function test_aRemovalMayBeAnOperationListEntry() public {
        address w = _wallet(2, 1);
        assertEq(registry.REMOVE_SESSIONS_DOMAIN(), REMOVE, "domain");
        bytes memory data = _removeData(w);
        bytes memory payload = _payload(GITHUB, BOB, OPERATIONS, operationList(REMOVE, data, BIND, abi.encode(w)));
        vm.prank(mallory);
        registry.removeSessionsByLogin(GITHUB, V1, payload, data, _none());
        assertFalse(validator.isLinked(w, _identity(GITHUB, BOB)), "not removed");
        assertTrue(registry.digestSpent(githubStub.lastDigest()), "not spent");
    }

    function test_aRemovalWithAKeyReplacesTheSessions() public {
        _replaceBob(false);
    }

    /// Beside another Consumer's entry.
    function test_aRemovalWithAKeyMayBeAListEntry() public {
        _replaceBob(true);
    }

    /// Bob's GitHub login on a 2-of-2 wallet removes his sessions and adds NEW_PK, one operation or a list entry.
    function _replaceBob(bool list) internal {
        address w = _wallet(2, 2);
        bytes32 bob = _identity(GITHUB, BOB);
        vm.prank(w);
        bytes32 opId = validator.queueRoot(address(validator), _delay(1 days));
        vm.warp(_now() + 1);

        IIdentityValidator.Policy memory p = _admin();
        bytes memory data = _txData(w, _key(NEW_PK), _ph(p));
        bytes memory payload = list
            ? _payload(GITHUB, BOB, OPERATIONS, operationList(REMOVE, data, BIND, abi.encode(w)))
            : _payload(GITHUB, BOB, REMOVE, data);
        vm.recordLogs();
        vm.prank(mallory);
        registry.removeSessionsByLogin(GITHUB, V1, payload, list ? data : bytes(""), p);

        Vm.Log[] memory logs = vm.getRecordedLogs();
        (uint256 removed, uint256 added) = (0, 0);
        for (uint256 i; i < logs.length; ++i) {
            if (logs[i].topics[0] == IIdentityValidator.SessionsRemovedByLogin.selector) removed = i + 1;
            if (logs[i].topics[0] == IIdentityValidator.SessionAddedByLogin.selector) added = i + 1;
        }
        assertTrue(removed != 0 && removed < added, "not removed, then added");
        assertTrue(validator.isLinked(w, bob), "unlinked");
        assertEq(validator.threshold(w), 2, "threshold");
        assertEq(validator.rootReadyAt(w, opId), 0, "the queued operation survived");
        IIdentityValidator.Session memory s = validator.sessionOf(w, _key(NEW_PK));
        assertTrue(s.byProof && s.identity == bob, "not Bob's session by login");

        vm.warp(_now() + 1);
        bytes memory hit = _one(_hitX());
        _refusesBy(w, hit, _pks(ALICE_PK, BOB_PK), NOT_SIGNED);
        _runsBy(w, hit, _pks(ALICE_PK, NEW_PK));
    }

    // ─── Login sessions and the threshold ───────────────────────────

    function test_aLimitedLoginSessionActsAloneOnlyAtThresholdOne() public {
        address w = _wallet(2, 2);
        vm.recordLogs();
        _loginAdd(w, X, ALICE, APP_PK, _hitOnly());
        assertTrue(_logged(IIdentityValidator.SessionAddedByLogin.selector, w), "no SessionAddedByLogin");
        IIdentityValidator.Session memory s = validator.sessionOf(w, _key(APP_PK));
        assertTrue(s.byProof, "not byProof");
        assertEq(s.activeAt, _now(), "not from the next second");
        vm.prank(w);
        validator.addSession(_identity(X, ALICE), _key(NEW_PK), _hitOnly());
        vm.warp(_now() + 1);

        bytes memory hit = _one(_hitX());
        _refuses(w, hit, _direct(w, address(validator), _pks(APP_PK), hit, true), NOT_SIGNED);
        // The wallet's own limited session acts alone at 2: the refusal is byProof's.
        _runs(w, hit, _direct(w, address(validator), _pks(NEW_PK), hit, true));

        _root(w, address(validator), abi.encodeCall(IIdentityValidator.setThreshold, (1)));
        _runs(w, hit, _direct(w, address(validator), _pks(APP_PK), hit, true));
    }

    /// ERC-1271 too: a login session signs for an app alone only at threshold 1.
    function test_aLoginSessionSignsForAnAppAloneOnlyAtThresholdOne() public {
        address w = _wallet(2, 2);
        bytes32 app = keccak256("an app's domain separator");
        IIdentityValidator.Policy memory p = _hitOnly();
        p.rules.domainsRoot = _domainLeaf(app);
        _loginAdd(w, X, ALICE, APP_PK, p);
        vm.prank(w);
        validator.addSession(_identity(X, ALICE), _key(NEW_PK), p);
        vm.warp(_now() + 1);
        bytes32[] memory none = new bytes32[](0);

        (bytes32 h, bytes memory sig) = _typedSigBy(w, _pks(APP_PK), app, none);
        assertEq(IWebWallet(w).isValidSignature(h, sig), bytes4(0xffffffff), "a login session alone at 2");
        (h, sig) = _typedSigBy(w, _pks(NEW_PK), app, none);
        assertEq(IWebWallet(w).isValidSignature(h, sig), bytes4(0x1626ba7e), "control: the wallet's own session");
        _root(w, address(validator), abi.encodeCall(IIdentityValidator.setThreshold, (1)));
        (h, sig) = _typedSigBy(w, _pks(APP_PK), app, none);
        assertEq(IWebWallet(w).isValidSignature(h, sig), bytes4(0x1626ba7e), "a login session alone at 1");
    }

    // ─── The end check: rows for logins (other writers: DirectExecuteTest) ──

    function test_aLoginAddInTheBatchCannotSignIt() public {
        address w = _wallet(2, 2);
        bytes memory payload = _addPayload(w, GITHUB, BOB, NEW_PK, _admin());
        bytes memory add = abi.encodeCall(IWalletRegistry.addSessionByLogin, (GITHUB, V1, payload, "", _admin()));
        _refusesBy(w, _then(_x(address(registry), 0, add)), _pks(ALICE_PK, NEW_PK), OUTSIDE_WINDOW);
        assertEq(validator.sessionOf(w, _key(NEW_PK)).identity, bytes32(0), "the add stayed");

        vm.prank(relayer);
        registry.addSessionByLogin(GITHUB, V1, payload, "", _admin());
        _refusesBy(w, _one(_hitX()), _pks(ALICE_PK, NEW_PK), OUTSIDE_WINDOW);
        vm.warp(_now() + 1);
        _runsBy(w, _one(_hitX()), _pks(ALICE_PK, NEW_PK));
    }

    function test_aLoginRemovalInTheBatchDoesNotLowerItsCheck() public {
        address w = _wallet(2, 2);
        bytes memory payload = _removePayload(w, GITHUB, BOB);
        bytes memory rm = abi.encodeCall(IWalletRegistry.removeSessionsByLogin, (GITHUB, V1, payload, "", _none()));
        _refusesBy(w, _then(_x(address(registry), 0, rm)), _pks(ALICE_PK), NOT_SIGNED);
        assertTrue(validator.isLinked(w, _identity(GITHUB, BOB)), "the removal stayed");

        vm.prank(mallory);
        registry.removeSessionsByLogin(GITHUB, V1, payload, "", _none());
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
        IIdentityValidator.CallProof[] memory proofs = new IIdentityValidator.CallProof[](2);
        bytes32 root;
        (root, proofs[0].proof) = _tree(leaves, 0);
        (, proofs[1].proof) = _tree(leaves, 1);
        IIdentityValidator.Policy memory p = _hitOnly();
        p.rules.scopeRoot = root;
        _loginAdd(w, X, ALICE, APP_PK, p);
        vm.prank(w);
        validator.addSession(_identity(X, ALICE), _key(NEW_PK), p);
        vm.warp(_now() + 1);

        bytes memory payload = _removePayload(w, GITHUB, BOB);
        Execution[] memory x = new Execution[](2);
        x[0] = _x(address(remover), 0, abi.encodeCall(Remover.run, (registry, GITHUB, V1, payload)));
        x[1] = _hitX();
        bytes memory calls = abi.encode(x);
        uint256 n = _nonce(w, address(validator));
        uint48 at = uint48(_now());
        _refuses(w, calls, _directAt(w, _pks(APP_PK), calls, n, at, true, proofs), NOT_SIGNED);
        assertTrue(validator.isLinked(w, _identity(GITHUB, BOB)), "the removal stayed");

        // Control: the wallet's own session with the same rules runs the same batch.
        uint256 state = vm.snapshotState();
        _runs(w, calls, _directAt(w, _pks(NEW_PK), calls, n, at, true, proofs));
        assertEq(validator.threshold(w), 1, "control: threshold");
        vm.revertToState(state);

        vm.prank(relayer);
        remover.run(registry, GITHUB, V1, payload);
        vm.warp(_now() + 1);
        bytes memory hit = _one(_hitX());
        IIdentityValidator.CallProof[] memory one = new IIdentityValidator.CallProof[](1);
        one[0] = proofs[1];
        _runs(w, hit, _directAt(w, _pks(APP_PK), hit, _nonce(w, address(validator)), uint48(_now()), true, one));
    }

    // ─── App lists ──────────────────────────────────────────────────

    function test_aListRefusesOtherAppsAndSurvivesARemoval() public {
        address w = _wallet(1, 1);
        bytes32 alice = _identity(X, ALICE);
        bytes32[] memory apps = _list(CLIENT);
        vm.expectEmit(true, true, false, true, address(registry));
        emit IWalletRegistry.AppListSet(w, alice, apps);
        vm.prank(w);
        registry.setAppList(alice, apps);
        assertEq(abi.encode(registry.appList(w, alice)), abi.encode(apps), "list");

        IIdentityValidator.Policy memory p = _admin();
        bytes memory off = _addPayload(w, X, ALICE, NEW_PK, p);
        vm.expectPartialRevert(IWalletRegistry.AppNotListed.selector);
        registry.addSessionByLogin(X, OTHER_APP, off, "", p);
        registry.addSessionByLogin(X, V1, off, "", p);
        assertEq(validator.sessionOf(w, _key(NEW_PK)).identity, alice, "the listed app was refused");

        // Any app removes; the list stays, so the removing app still cannot add.
        bytes memory rm = _removePayload(w, X, ALICE);
        registry.removeSessionsByLogin(X, OTHER_APP, rm, "", _none());
        assertEq(abi.encode(registry.appList(w, alice)), abi.encode(apps), "the removal cleared the list");
        bytes memory again = _addPayload(w, X, ALICE, APP_PK, p);
        vm.expectPartialRevert(IWalletRegistry.AppNotListed.selector);
        registry.addSessionByLogin(X, OTHER_APP, again, "", p);
    }

    /// Every entry of a list admits its app, not only the first.
    function test_aListOfTwoAdmitsItsSecondAndRefusesTheRest() public {
        address w = _wallet(1, 1);
        bytes32[] memory apps = new bytes32[](2);
        (apps[0], apps[1]) = (keccak256("a third app"), CLIENT);
        vm.prank(w);
        registry.setAppList(_identity(X, ALICE), apps);
        IIdentityValidator.Policy memory p = _admin();
        bytes memory payload = _addPayload(w, X, ALICE, NEW_PK, p);
        vm.expectPartialRevert(IWalletRegistry.AppNotListed.selector);
        registry.addSessionByLogin(X, OTHER_APP, payload, "", p);
        registry.addSessionByLogin(X, V1, payload, "", p);
        assertTrue(validator.sessionOf(w, _key(NEW_PK)).byProof, "the second entry was refused");
    }

    function test_aStrangerWritesOnlyItsOwnList() public {
        address w = _wallet(1, 1);
        bytes32 alice = _identity(X, ALICE);
        assertEq(registry.appList(w, alice).length, 0, "a list by default");
        vm.prank(mallory);
        try registry.setAppList(alice, _list(keccak256("mallory's app"))) {} catch {}
        assertEq(registry.appList(w, alice).length, 0, "a stranger wrote the wallet's list");
        bytes memory payload = _addPayload(w, X, ALICE, NEW_PK, _admin());
        registry.addSessionByLogin(X, OTHER_APP, payload, "", _admin());
        assertTrue(validator.sessionOf(w, _key(NEW_PK)).byProof, "an empty list refused another app");
    }

    function test_belowQuorumABatchCannotSetTheList() public {
        address w = _wallet(2, 2);
        bytes32 alice = _identity(X, ALICE);
        bytes memory set = abi.encodeCall(IWalletRegistry.setAppList, (alice, _list(CLIENT)));
        bytes memory calls = _then(_x(address(registry), 0, set));
        _refuses(w, calls, _direct(w, address(validator), _pks(ALICE_PK), calls, true), NOT_ALLOWED);
        assertEq(registry.appList(w, alice).length, 0, "set below quorum");
        _runsBy(w, calls, _pks(ALICE_PK, BOB_PK));
        assertEq(registry.appList(w, alice).length, 1, "control: not set at quorum");
    }

    function test_aListEntryFromAnOffListAppIsRefused() public {
        address w = _wallet(1, 1);
        vm.prank(w);
        registry.setAppList(_identity(X, ALICE), _list(CLIENT));
        bytes memory add = _txData(w, _key(NEW_PK), _ph(_admin()));
        bytes memory payload = _payload(X, ALICE, OPERATIONS, operationList(ADD, add, BIND, abi.encode(w)));
        vm.expectPartialRevert(IWalletRegistry.AppNotListed.selector);
        registry.addSessionByLogin(X, OTHER_APP, payload, add, _admin());
        registry.addSessionByLogin(X, V1, payload, add, _admin());
        assertTrue(validator.sessionOf(w, _key(NEW_PK)).byProof, "control: the listed app's entry");
    }
}

