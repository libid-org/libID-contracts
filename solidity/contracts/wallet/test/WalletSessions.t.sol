// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Vm} from "forge-std/Test.sol";
import {PackedUserOperation} from "@openzeppelin/contracts/interfaces/IERC4337.sol";
import {Base64} from "@openzeppelin/contracts/utils/Base64.sol";
import {P256} from "@openzeppelin/contracts/utils/cryptography/P256.sol";
import {WebAuthn} from "@openzeppelin/contracts/utils/cryptography/WebAuthn.sol";
import {
    ERC7913WebAuthnVerifier
} from "@openzeppelin/contracts/utils/cryptography/verifiers/ERC7913WebAuthnVerifier.sol";

import {IIdentityAdmin, IWalletCore, IWebWallet} from "../IWebWallet.sol";
import {IUserOpHash} from "./WalletBase.sol";
import {WalletSuite} from "./WalletSuite.sol";

/// An ERC-1271 signer that accepts every signature.
contract Accepting1271 {
    function isValidSignature(bytes32, bytes calldata) external pure returns (bytes4) {
        return 0x1626ba7e;
    }
}

/// @notice Sessions, links, the threshold, root operations and ERC-1271, from 0e2721f's IdentityValidator,
///         RootEpoch, Genesis*, LinkedPlatforms, QuorumByProof, SessionSigners and Passkey suites.
contract WalletSessionsTest is WalletSuite {
    bytes32 internal constant APP = keccak256("app A");

    function _alice() internal pure returns (bytes32) {
        return _identity(X, ALICE);
    }

    function _bob() internal pure returns (bytes32) {
        return _identity(GITHUB, BOB);
    }

    function _hitBy(address w, uint256[] memory pks) internal view returns (PackedUserOperation memory) {
        return _signedWith(_op(w, _hitCall()), pks, _hitProofs(1));
    }

    function _tooHigh(uint8 t, uint32 left) internal pure returns (bytes memory) {
        return abi.encodeWithSelector(IWebWallet.ThresholdTooHigh.selector, t, left);
    }

    // ─── Genesis and links ──────────────────────────────────────────

    /// Creation links the genesis with no session; its link proof adds the first one; platforms count once.
    function test_theGenesisLinksAndPlatformsCount() public {
        vm.prank(relayer);
        address fresh = factory.createWallet(GITHUB, BOB, 0);
        assertTrue(IWebWallet(fresh).isLinked(_bob()), "genesis not linked");
        assertFalse(IWebWallet(fresh).hadSession(), "a session without a proof");

        address w = _claim();
        assertLe(IWebWallet(w).sessionOf(_key(ALICE_PK)).activeAt, _now(), "the first session waits");
        assertEq(IWebWallet(w).linkedPlatforms(), 1, "genesis");
        _link(w, X, MALLORY, "", _admin());
        assertEq(IWebWallet(w).linkedPlatforms(), 1, "two X identities are one platform");
        _link(w, GOOGLE, CAROL, "", _admin());
        assertEq(IWebWallet(w).linkedPlatforms(), 2, "X and Google");
        _rootW(w, abi.encodeCall(IIdentityAdmin.unlink, (_identity(GOOGLE, CAROL))));
        assertEq(IWebWallet(w).linkedPlatforms(), 1, "Google unlinked");
    }

    function test_theGenesisIdentityCannotBeUnlinked() public {
        address w = _claim();
        _link(w, GITHUB, BOB, _key(BOB_PK), _admin());
        _rootReverts(
            w,
            abi.encodeCall(IIdentityAdmin.unlink, (_alice())),
            abi.encodeWithSelector(IWebWallet.GenesisIdentity.selector, _alice())
        );
        assertTrue(IWebWallet(w).isLinked(_alice()), "genesis unlinked");
        _rootW(w, abi.encodeCall(IIdentityAdmin.unlink, (_bob())));
        assertFalse(IWebWallet(w).isLinked(_bob()), "another identity stays unlinkable");
        _rootReverts(
            w,
            abi.encodeCall(IIdentityAdmin.unlink, (_bob())),
            abi.encodeWithSelector(IWebWallet.NotLinked.selector, _bob())
        );
    }

    function test_theWalletsEntriesRefuseBadInput() public {
        address w = _claim();
        bytes memory short = hex"0102";
        bytes memory key19 = hex"00112233445566778899aabbccddeeff001122";
        vm.startPrank(w);
        vm.expectRevert(abi.encodeWithSelector(IWebWallet.RootOperationNotAllowed.selector, bytes4(0)));
        IWebWallet(w).queueRoot("");
        bytes4 cancel = IIdentityAdmin.cancelRoot.selector;
        vm.expectRevert(abi.encodeWithSelector(IWebWallet.RootOperationNotAllowed.selector, cancel));
        IWebWallet(w).queueRoot(abi.encodeCall(IIdentityAdmin.cancelRoot, (bytes32(0))));
        vm.expectRevert(abi.encodeWithSelector(IWebWallet.RootOperationUnknown.selector, keccak256("never queued")));
        IWebWallet(w).cancelRoot(keccak256("never queued"));
        vm.expectRevert(abi.encodeWithSelector(IWebWallet.InvalidKey.selector, short));
        IWebWallet(w).addSession(_alice(), short, _app());
        vm.expectRevert(abi.encodeWithSelector(IWebWallet.InvalidKey.selector, key19));
        IWebWallet(w).addSession(_alice(), key19, _app());
        vm.expectRevert(abi.encodeWithSelector(IWebWallet.SessionExists.selector, _key(ALICE_PK)));
        IWebWallet(w).addSession(_alice(), _key(ALICE_PK), _app());
        vm.expectRevert(abi.encodeWithSelector(IWebWallet.NoSession.selector, _key(APP_PK)));
        IWebWallet(w).revokeSession(_key(APP_PK));
        vm.stopPrank();
    }

    // ─── Validation data ────────────────────────────────────────────

    function _addHitOnly(address w, uint256 pk, uint48 validAfter, uint48 validUntil) internal {
        IIdentityAdmin.Policy memory p = _hitGas();
        (p.validAfter, p.validUntil) = (validAfter, validUntil);
        _addSession(w, _alice(), _key(pk), p);
    }

    /// The window comes back packed; `activeAt` folds into `validAfter`. No clock is read.
    function test_validationReturnsThePackedWindowAndReadsNoClock() public {
        uint48 start = uint48(_now() + 10);
        uint48 end = uint48(_now() + 1000);
        address w = _claim();
        _addHitOnly(w, APP_PK, start, end);
        assertEq(_answer(_hitBy(w, _pks(APP_PK))), _window(start, end), "policy window");
        _addHitOnly(w, BOB_PK, 0, end);
        uint256 early = _answer(_hitBy(w, _pks(BOB_PK)));
        assertEq(early, _window(uint48(_now()), end), "window");
        _addByLogin(relayer, X, ALICE, w, _key(ALICE2_PK), _admin());
        assertEq(_validate(w, _hitCall(), _pks(ALICE2_PK)), _window(uint48(_now()), 0), "session by proof window");
        vm.warp(_now() + 3650 days);
        assertEq(_answer(_hitBy(w, _pks(BOB_PK))), early, "an expired session answered differently");
    }

    /// Co-signers' windows intersect, whatever their order.
    function test_windowIsTheIntersectionOfAllSigners() public {
        address w = _claim();
        uint48 t = uint48(_now());
        _addSession(w, _alice(), _key(ALICE2_PK), IIdentityAdmin.Policy(t + 10, 0, true, 0, _noRules()));
        _addSession(w, _alice(), _key(BOB_PK), IIdentityAdmin.Policy(t + 20, 0, true, 0, _noRules()));
        assertEq(_validate(w, _hitCall(), _pks(ALICE2_PK, BOB_PK)), _window(t + 20, 0), "early first");
        assertEq(_validate(w, _hitCall(), _pks(BOB_PK, ALICE2_PK)), _window(t + 20, 0), "late first");
        assertEq(_validate(w, _hitCall(), _pks(BOB_PK, ALICE_PK)), _window(t + 20, 0), "unbounded last");
    }

    /// A 20-byte key is recovered, never asked through ERC-1271; an empty list, unknown and revoked keys fail.
    function test_signersThatAreNoSessionFail() public {
        address w = _claim();
        bytes[2] memory keys = [abi.encodePacked(address(new Accepting1271())), abi.encodePacked(address(0))];
        IWalletCore.SessionSignature[] memory s = new IWalletCore.SessionSignature[](1);
        PackedUserOperation memory op = _opN(w, 0, _hitCall());
        for (uint256 i; i < keys.length; ++i) {
            _addSession(w, _alice(), keys[i], _app());
            s[0] = IWalletCore.SessionSignature({key: keys[i], signature: hex"1234"});
            op.signature = _wrap(s);
            vm.prank(EP);
            assertEq(IWebWallet(w).validateUserOp(op, keccak256("op"), 0), 1, "a 20-byte key took a bad signature");
        }
        op.signature = _wrap(new IWalletCore.SessionSignature[](0));
        vm.prank(EP);
        assertEq(IWebWallet(w).validateUserOp(op, keccak256("h"), 0), 1, "no signatures");
        assertEq(_validate(w, _hitCall(), _pks(MALLORY_PK)), 1, "unknown key");
        _addSession(w, _alice(), _key(ALICE2_PK), _admin());
        _revoke(w, _key(ALICE2_PK));
        assertEq(_validate(w, _hitCall(), _pks(ALICE2_PK)), 1, "revoked key");
    }

    /// A UserOperation calls only `execute` with mode selector 0, even an admin's: the rest is refused in validation.
    function test_outerCallScope() public {
        address w = _claim();
        bytes[3] memory calls = [
            abi.encodeCall(IIdentityAdmin.addSession, (_alice(), _key(MALLORY_PK), _admin())),
            abi.encodeCall(IWalletCore.execute, (MODE_BATCH | bytes32(uint256(0xdeadbeef) << 176), _one(_hitX()))),
            abi.encodePacked(IWalletCore.execute.selector, bytes31(MODE_BATCH))
        ];
        for (uint256 i; i < calls.length; ++i) {
            assertEq(_validate(w, calls[i], _pks(ALICE_PK)), 1, vm.toString(i));
        }
    }

    /// `UserOperationRevertReason` of EntryPoint v0.9.
    event UserOperationRevertReason(
        bytes32 indexed userOpHash, address indexed sender, uint256 nonce, bytes revertReason
    );

    /// At quorum, validation reads no more of the call: `execute` refuses a call type it does not run and a
    /// non-canonical batch, and the account pays for the operation.
    function test_atQuorumExecuteRefusesWhatValidationLetsThrough() public {
        address w = _claim();
        vm.warp(_now() + 1);
        bytes[2] memory calls = [
            abi.encodeCall(IWalletCore.execute, (bytes32(uint256(0xff) << 248), _one(_hitX()))),
            abi.encodeCall(IWalletCore.execute, (MODE_BATCH, bytes.concat(_one(_hitX()), hex"00")))
        ];
        bytes4[2] memory errs = [IWebWallet.UnsupportedMode.selector, IWebWallet.NoncanonicalBatch.selector];
        for (uint256 i; i < calls.length; ++i) {
            assertEq(_validate(w, calls[i], _pks(ALICE_PK)), 0, vm.toString(i));
            uint256 n = _nonce(w);
            vm.recordLogs();
            _handle(_signed(_op(w, calls[i]), _pks(ALICE_PK)));
            assertEq(_nonce(w), n + 1, "not included");
            Vm.Log[] memory logs = vm.getRecordedLogs();
            bytes memory reason;
            for (uint256 j; j < logs.length; ++j) {
                if (logs[j].topics[0] == UserOperationRevertReason.selector) {
                    (, reason) = abi.decode(logs[j].data, (uint256, bytes));
                }
            }
            assertEq(bytes4(reason), errs[i], vm.toString(i));
        }
        assertEq(target.calls(), 0, "a refused call ran");
    }

    /// Validation at quorum reads two slots per signer: its session's first and its link's. An EIP-8141 frame
    /// caps validation gas, so a signer costs two cold reads.
    function test_validationReadsTwoSlotsPerSigner() public {
        bytes32[3] memory platforms = [X, GITHUB, GOOGLE];
        bytes32[3] memory nodes = [ALICE, BOB, CAROL];
        uint256[3] memory keys = [ALICE_PK, BOB_PK, CAROL_PK];
        uint256[3] memory reads;
        for (uint256 n = 1; n <= 3; ++n) {
            uint256 snap = vm.snapshotState();
            address w = _claim();
            uint256[] memory pks = new uint256[](n);
            pks[0] = ALICE_PK;
            for (uint256 i = 1; i < n; ++i) {
                _link(w, platforms[i], nodes[i], _key(keys[i]), _admin());
                pks[i] = keys[i];
            }
            // forge-lint: disable-next-line(unsafe-typecast)
            if (n > 1) _threshold(w, uint8(n));
            vm.warp(_now() + 1);
            PackedUserOperation memory op = _signed(_op(w, _hitCall()), pks);
            bytes32 h = IUserOpHash(EP).getUserOpHash(op);
            vm.record();
            vm.prank(EP);
            assertNotEq(IWebWallet(w).validateUserOp(op, h, 0), 1, "refused");
            (bytes32[] memory slots,) = vm.accesses(w);
            reads[n - 1] = _distinct(slots);
            vm.revertToStateAndDelete(snap);
        }
        assertEq(reads[1], reads[0] + 2, "a second signer");
        assertEq(reads[2], reads[1] + 2, "a third signer");
    }

    function _distinct(bytes32[] memory slots) internal pure returns (uint256 n) {
        for (uint256 i; i < slots.length; ++i) {
            bool seen;
            for (uint256 j; j < i && !seen; ++j) {
                seen = slots[j] == slots[i];
            }
            if (!seen) ++n;
        }
    }

    // ─── Threshold ──────────────────────────────────────────────────

    function test_thresholdCountsDistinctAdminPlatforms() public {
        address w = _claim();
        _link(w, GITHUB, BOB, _key(BOB_PK), _admin());
        _addSession(w, _alice(), _key(ALICE2_PK), _admin());
        _addSession(w, _bob(), _key(APP_PK), _app());
        uint256 added = _window(uint48(_now()), 0);
        _threshold(w, 2);
        assertEq(IWebWallet(w).threshold(), 2, "threshold");
        bytes memory adminOp = _exec(w, abi.encodeCall(IIdentityAdmin.queueRoot, (_raise())));
        assertEq(_validate(w, adminOp, _pks(ALICE_PK)), 1, "one identity");
        assertEq(_validate(w, adminOp, _pks(ALICE_PK, ALICE_PK)), 1, "one key twice");
        assertEq(_validate(w, adminOp, _pks(ALICE_PK, ALICE2_PK)), 1, "two keys of one identity");
        assertEq(_validate(w, adminOp, _pks(ALICE_PK, APP_PK)), 1, "a non-admin session counted");
        assertEq(_validate(w, adminOp, _pks(ALICE_PK, BOB_PK)), added, "two admin platforms");
        assertEq(_validate(w, _hitCall(), _pks(ALICE_PK)), 1, "below quorum, an admin with no scope");
    }

    /// Admin sessions of two identities on one platform count once.
    function test_identitiesOfOnePlatformCountOnce() public {
        address w = _claim();
        _link(w, X, MALLORY, _key(MALLORY_PK), _admin());
        _link(w, GOOGLE, CAROL, _key(CAROL_PK), _admin());
        uint256 linked = _window(uint48(_now()), 0);
        _threshold(w, 2);
        bytes memory adminOp = _exec(w, abi.encodeCall(IIdentityAdmin.queueRoot, (_raise())));
        assertEq(_validate(w, adminOp, _pks(ALICE_PK, MALLORY_PK)), 1, "two X identities met the threshold");
        assertEq(_validate(w, adminOp, _pks(MALLORY_PK, CAROL_PK)), linked, "X and Google missed the threshold");
        assertEq(_validate(w, _hitCall(), _pks(ALICE_PK, MALLORY_PK)), 1, "two X identities skipped the rules");
        assertEq(_validate(w, _hitCall(), _pks(MALLORY_PK, CAROL_PK)), linked, "X and Google were held to the rules");
    }

    /// The threshold may not exceed the platforms holding an admin session.
    function test_thresholdIsBoundedByAdminPlatforms() public {
        address w = _claim();
        bytes memory two = abi.encodeCall(IIdentityAdmin.setThreshold, (2));
        _link(w, X, MALLORY, _key(MALLORY_PK), _admin());
        _link(w, GOOGLE, CAROL, _key(CAROL_PK), _app());
        _rootReverts(w, two, _tooHigh(2, 1));
        _addSession(w, _identity(GOOGLE, CAROL), _key(APP_PK), _admin());
        _rootW(w, two);
        assertEq(IWebWallet(w).threshold(), 2, "threshold");
    }

    /// A revoke may not leave admin sessions on fewer platforms than the threshold, root or not.
    function test_revokeKeepsTheAdminPlatformsTheThresholdNeeds() public {
        address w = _claim();
        _link(w, GITHUB, BOB, _key(BOB_PK), _admin());
        _addSession(w, _bob(), _key(APP_PK), _admin());
        _threshold(w, 2);
        _revoke(w, _key(APP_PK));
        vm.prank(w);
        vm.expectRevert(_tooHigh(2, 1));
        IWebWallet(w).revokeSession(_key(BOB_PK));
        _rootReverts(w, abi.encodeCall(IIdentityAdmin.revokeSession, (_key(BOB_PK))), _tooHigh(2, 1));
        assertEq(IWebWallet(w).sessionOf(_key(BOB_PK)).identity, _bob(), "revoked anyway");
    }

    /// An unlink lowers the threshold to the platforms still linked, not the admin ones; a re-link counts again.
    function test_unlinkLowersTheThresholdToThePlatformsLeft() public {
        address w = _claim();
        _link(w, GITHUB, BOB, _key(BOB_PK), _admin());
        _link(w, GITHUB, CAROL, "", _admin());
        _threshold(w, 2);
        _rootW(w, abi.encodeCall(IIdentityAdmin.unlink, (_bob())));
        assertEq(IWebWallet(w).threshold(), 2, "an unlink within a platform lowered the threshold");
        _rootW(w, abi.encodeCall(IIdentityAdmin.unlink, (_identity(GITHUB, CAROL))));
        assertEq(IWebWallet(w).threshold(), 1, "not min(2, 1)");
        bytes memory two = abi.encodeCall(IIdentityAdmin.setThreshold, (2));
        _rootReverts(w, two, _tooHigh(2, 1));
        _link(w, GITHUB, CAROL, _key(CAROL_PK), _admin());
        _rootW(w, two);
        assertEq(IWebWallet(w).threshold(), 2, "a re-link did not count its platform again");
    }

    /// Both entries refuse an expiring admin session, which time would take off the quorum, and a bound setting
    /// bit 47, which EntryPoint v0.9 reads as a block-number flag.
    function test_badPoliciesAreRefused() public {
        address w = _claim();
        uint48 flag = uint48(1 << 47);
        IIdentityAdmin.Policy memory expiring = _admin();
        expiring.validUntil = uint48(_now() + 7 days);
        IIdentityAdmin.Policy[3] memory ps = [
            expiring,
            IIdentityAdmin.Policy(flag, 0, false, 0, _noRules()),
            IIdentityAdmin.Policy(0, flag, false, 0, _noRules())
        ];
        for (uint256 i; i < ps.length; ++i) {
            bytes memory err = i == 0
                ? abi.encodeWithSelector(IWebWallet.AdminSessionExpires.selector, ps[i].validUntil)
                : abi.encodeWithSelector(IWebWallet.PolicyOutOfRange.selector, ps[i].validAfter, ps[i].validUntil);
            vm.prank(w);
            vm.expectRevert(err);
            IWebWallet(w).addSession(_alice(), _key(APP_PK), ps[i]);
            bytes memory payload = _loginPayload(w, address(this), X, ALICE, _key(APP_PK), ps[i]);
            vm.expectRevert(err);
            IWebWallet(w).addSessionByLogin(X, V1, payload, ps[i]);
        }
        vm.warp(flag);
        bytes memory late = _loginPayload(w, address(this), X, ALICE, _key(APP_PK), _app());
        vm.expectRevert(abi.encodeWithSelector(IWebWallet.PolicyOutOfRange.selector, 0, 0));
        IWebWallet(w).addSessionByLogin(X, V1, late, _app());
    }

    // ─── Root operations ────────────────────────────────────────────

    function test_rootOperationWaitsThenRunsOnce() public {
        address w = _claim();
        _rootW(w, abi.encodeCall(IIdentityAdmin.setRootDelay, (48 hours)));
        bytes32 id = keccak256(_raise());
        assertEq(_queueW(w, _raise()), id, "op id");
        uint48 ready = uint48(_now() + 48 hours);
        assertEq(IWebWallet(w).rootReadyAt(id), ready, "ready time");
        vm.warp(ready - 1);
        vm.expectRevert(abi.encodeWithSelector(IWebWallet.RootOperationNotReady.selector, id));
        IWebWallet(w).executeRoot(id);
        vm.warp(ready);
        vm.prank(mallory);
        IWebWallet(w).executeRoot(id);
        assertEq(IWebWallet(w).rootDelay(), 72 hours, "not run");
        assertEq(IWebWallet(w).rootReadyAt(id), 0, "op kept");
        vm.expectRevert(abi.encodeWithSelector(IWebWallet.RootOperationUnknown.selector, id));
        IWebWallet(w).executeRoot(id);
    }

    /// Each delay change waits out the current delay, a zero delay the next second; the delay is at most 365 days.
    function test_theRootDelayChangesAfterTheCurrentDelay() public {
        address w = _claim();
        uint32[3] memory delays = [uint32(1 days), 2 days, 0];
        uint256 wait = 1;
        for (uint256 i; i < delays.length; ++i) {
            bytes32 id = _queueW(w, abi.encodeCall(IIdentityAdmin.setRootDelay, (delays[i])));
            assertEq(IWebWallet(w).rootReadyAt(id), _now() + wait, "not after the current delay");
            vm.warp(_now() + wait - 1);
            vm.expectRevert(abi.encodeWithSelector(IWebWallet.RootOperationNotReady.selector, id));
            IWebWallet(w).executeRoot(id);
            vm.warp(_now() + 1);
            IWebWallet(w).executeRoot(id);
            assertEq(IWebWallet(w).rootDelay(), delays[i], "not changed");
            wait = delays[i] == 0 ? 1 : delays[i];
        }
        uint32 over = 365 days + 1;
        bytes memory tooLong = abi.encodeWithSelector(IWebWallet.RootDelayTooLong.selector, over);
        _rootReverts(w, abi.encodeCall(IIdentityAdmin.setRootDelay, (over)), tooLong);
        _rootW(w, abi.encodeCall(IIdentityAdmin.setRootDelay, (365 days)));
        assertEq(IWebWallet(w).rootDelay(), 365 days, "max");
    }

    function test_onlyTheWalletCancelsItsRootOperation() public {
        address w = _claim();
        bytes32 id = _queueW(w, abi.encodeCall(IIdentityAdmin.setThreshold, (1)));
        vm.prank(mallory);
        try IWebWallet(w).cancelRoot(id) {} catch {}
        assertGt(IWebWallet(w).rootReadyAt(id), 0, "a stranger cancelled");
        vm.prank(w);
        IWebWallet(w).cancelRoot(id);
        assertEq(IWebWallet(w).rootReadyAt(id), 0, "not cancelled");
        vm.warp(_now() + 48 hours);
        vm.expectRevert(abi.encodeWithSelector(IWebWallet.RootOperationUnknown.selector, id));
        IWebWallet(w).executeRoot(id);
    }

    /// Outside `executeRoot` the wallet's own call reaches no root change, and revoking the last admin needs one.
    function test_rootChangesRefusedOutsideTheTimelock() public {
        address w = _claim();
        _addSession(w, _alice(), _key(ALICE2_PK), _admin());
        _revoke(w, _key(ALICE2_PK));
        bytes[3] memory calls = [
            abi.encodeCall(IIdentityAdmin.setThreshold, (1)),
            abi.encodeCall(IIdentityAdmin.revokeSession, (_key(ALICE_PK))),
            abi.encodeCall(IIdentityAdmin.unlink, (_alice()))
        ];
        for (uint256 i; i < calls.length; ++i) {
            vm.prank(w);
            (bool ok, bytes memory err) = w.call(calls[i]);
            assertFalse(ok, "a root change ran without the timelock");
            assertEq(err, abi.encodeWithSelector(IWebWallet.RootOperationRequired.selector), vm.toString(i));
        }
        _rootW(w, calls[1]);
        assertEq(IWebWallet(w).sessionOf(_key(ALICE_PK)).identity, bytes32(0), "not revoked");
        _addByLogin(relayer, X, ALICE, w, _key(ALICE2_PK), _admin());
        assertEq(IWebWallet(w).sessionOf(_key(ALICE2_PK)).activeAt, _now(), "no login after the last admin");
    }

    /// Alice's wallet with a second admin key, which queues a root operation through the EntryPoint.
    function _leaked() internal returns (address w, bytes32 id) {
        w = _claim();
        _addSession(w, _alice(), _key(ALICE2_PK), _admin());
        vm.warp(_now() + 1);
        _handle(_signed(_op(w, _exec(w, abi.encodeCall(IIdentityAdmin.queueRoot, (_raise())))), _pks(ALICE2_PK)));
        id = keccak256(_raise());
        assertGt(IWebWallet(w).rootReadyAt(id), 0, "not queued");
    }

    function _assertVoid(address w, bytes32 id) internal {
        vm.warp(_now() + 48 hours);
        assertEq(IWebWallet(w).rootReadyAt(id), 0, "a void operation reads as ready");
        vm.expectRevert(abi.encodeWithSelector(IWebWallet.RootOperationVoid.selector, id));
        IWebWallet(w).executeRoot(id);
    }

    /// A queued root operation does not outlive the admin sessions that could have queued it.
    function test_revokingAnAdminVoidsEarlierRootOperations() public {
        (address w, bytes32 id) = _leaked();
        uint256 state = vm.snapshotState();
        _revoke(w, _key(ALICE2_PK));
        _assertVoid(w, id);
        vm.revertToState(state);
        _rootW(w, abi.encodeCall(IIdentityAdmin.revokeSession, (_key(ALICE2_PK))));
        _assertVoid(w, id);
    }

    /// The salt `eip712Domain()` reports is `keccak256(abi.encode(epoch(), rootEpoch()))`, before and after a
    /// revoked admin moves the root epoch.
    function test_theSaltIsTheEpochAndRootEpoch() public {
        address w = _claim();
        _addSession(w, _identity(X, ALICE), _key(ALICE2_PK), _admin());
        vm.warp(_now() + 1);
        assertEq(IWebWallet(w).rootEpoch(), 0, "a new wallet's root epoch");
        _assertSalt(w);
        _revoke(w, _key(ALICE2_PK));
        assertEq(IWebWallet(w).rootEpoch(), 1, "the revoke did not move it");
        _assertSalt(w);
    }

    function _assertSalt(address w) internal view {
        (,,,,, bytes32 salt,) = IWebWallet(w).eip712Domain();
        assertEq(salt, keccak256(abi.encode(IWebWallet(w).epoch(), IWebWallet(w).rootEpoch())), "salt");
    }

    /// Revoking an app session, or an admin session added this second, keeps queued operations.
    function test_otherRevokesKeepQueuedRootOperations() public {
        (address w, bytes32 id) = _leaked();
        _addSession(w, _alice(), _key(APP_PK), _app());
        _revoke(w, _key(APP_PK));
        _addByLogin(relayer, X, ALICE, w, _key(BOB_PK), _admin());
        _revoke(w, _key(BOB_PK));
        vm.warp(_now() + 48 hours);
        IWebWallet(w).executeRoot(id);
        assertEq(IWebWallet(w).rootReadyAt(id), 0, "not executed");
    }

    /// The settings emit their values, an unlink's lowering of the threshold included; 0 reads as 1.
    function test_settingsEmitTheirValues() public {
        address w = _claim();
        _link(w, GITHUB, BOB, _key(BOB_PK), _admin());
        bytes[4] memory ops = [
            abi.encodeCall(IIdentityAdmin.setRootDelay, (48 hours)),
            abi.encodeCall(IIdentityAdmin.setThreshold, (2)),
            abi.encodeCall(IIdentityAdmin.unlink, (_bob())),
            abi.encodeCall(IIdentityAdmin.setThreshold, (0))
        ];
        for (uint256 i; i < ops.length; ++i) {
            bytes32 id = _queueW(w, ops[i]);
            vm.warp(_now() + 48 hours);
            vm.expectEmit(w);
            if (i == 0) emit IWebWallet.RootDelaySet(48 hours);
            else emit IWebWallet.ThresholdSet(i == 1 ? 2 : 1);
            IWebWallet(w).executeRoot(id);
        }
    }

    /// A root operation queued at threshold 1 is void once the threshold is 2.
    function test_aThresholdChangeVoidsEarlierRootOperations() public {
        address w = _claim();
        _link(w, GITHUB, BOB, _key(BOB_PK), _admin());
        bytes32 id = _queueW(w, abi.encodeCall(IIdentityAdmin.setRootDelay, (72 hours)));
        _threshold(w, 2);
        assertEq(IWebWallet(w).rootReadyAt(id), 0, "a void operation reads as ready");
        vm.expectRevert(abi.encodeWithSelector(IWebWallet.RootOperationVoid.selector, id));
        IWebWallet(w).executeRoot(id);
    }

    function test_anUnlinkVoidsEarlierRootOperations() public {
        address w = _claim();
        _link(w, GITHUB, BOB, "", _admin());
        bytes32 id = _queueW(w, abi.encodeCall(IIdentityAdmin.setThreshold, (2)));
        _rootW(w, abi.encodeCall(IIdentityAdmin.unlink, (_bob())));
        _assertVoid(w, id);
    }

    // ─── Unlinks and generations ────────────────────────────────────

    /// After the timelock every session of the identity stops, and no login adds one.
    function test_unlinkStopsTheIdentitysSessions() public {
        address w = _claim();
        _rootW(w, abi.encodeCall(IIdentityAdmin.setRootDelay, (48 hours)));
        _link(w, GITHUB, BOB, _key(BOB_PK), _admin());
        _addByLogin(relayer, GITHUB, BOB, w, _key(APP_PK), _admin());
        bytes32 id = _queueW(w, abi.encodeCall(IIdentityAdmin.unlink, (_bob())));
        vm.warp(_now() + 48 hours - 1);
        vm.expectRevert(abi.encodeWithSelector(IWebWallet.RootOperationNotReady.selector, id));
        IWebWallet(w).executeRoot(id);
        vm.warp(_now() + 1);
        bytes32 h = keccak256("a message");
        assertEq(_validate(w, _hitCall(), _pks(APP_PK)), _window(uint48(_now() - 48 hours), 0), "by-proof control");
        assertTrue(_isValid1271(w, h, BOB_PK, _wrapped(w, h)), "active control");
        vm.expectEmit(true, false, false, false, w);
        emit IWebWallet.IdentityUnlinked(_bob());
        IWebWallet(w).executeRoot(id);
        assertFalse(IWebWallet(w).isLinked(_bob()), "still linked");
        assertEq(_validate(w, _hitCall(), _pks(BOB_PK)), 1, "active session validates");
        assertEq(_validate(w, _hitCall(), _pks(APP_PK)), 1, "session by proof validates");
        assertFalse(_isValid1271(w, h, BOB_PK, _wrapped(w, h)), "ERC-1271 accepts an unlinked identity");
        assertTrue(_isValid1271(w, h, ALICE_PK, _wrapped(w, h)), "the other identity stopped");
        bytes memory payload = _loginPayload(w, address(this), GITHUB, BOB, _key(MALLORY_PK), _admin());
        vm.expectRevert(abi.encodeWithSelector(IWebWallet.NotLinked.selector, _bob()));
        IWebWallet(w).addSessionByLogin(GITHUB, V1, payload, _admin());
    }

    /// A re-link starts a new generation: sessions of the earlier link stay dead, and their keys can be re-added.
    function test_relinkDoesNotReviveSessions() public {
        address w = _claim();
        bytes32 h = keccak256("a message");
        _link(w, GITHUB, BOB, _key(BOB_PK), _admin());
        _addByLogin(mallory, GITHUB, BOB, w, _key(MALLORY_PK), _admin());
        assertEq(IWebWallet(w).generationOf(_bob()), 0, "generation");
        _rootW(w, abi.encodeCall(IIdentityAdmin.unlink, (_bob())));
        assertEq(IWebWallet(w).generationOf(_bob()), 1, "the generation did not move");
        assertEq(IWebWallet(w).sessionOf(_key(BOB_PK)).identity, bytes32(0), "a dead session reads as live");
        _link(w, GITHUB, BOB, "", _admin());
        uint256[2] memory old = [BOB_PK, MALLORY_PK];
        for (uint256 i; i < old.length; ++i) {
            assertEq(_validate(w, _hitCall(), _pks(old[i])), 1, "an old session revived");
            assertFalse(_isValid1271(w, h, old[i], _wrapped(w, h)), "an old session signs ERC-1271");
        }
        _addSession(w, _bob(), _key(APP_PK), _admin());
        assertEq(_validate(w, _hitCall(), _pks(APP_PK)), _window(uint48(_now()), 0), "a fresh session fails");
        // A dead session's key is free for another identity, once.
        _addSession(w, _alice(), _key(BOB_PK), _hitGas());
        vm.prank(w);
        vm.expectRevert(abi.encodeWithSelector(IWebWallet.SessionExists.selector, _key(BOB_PK)));
        IWebWallet(w).addSession(_alice(), _key(BOB_PK), _hitGas());
        assertEq(_answer(_hitBy(w, _pks(BOB_PK))), _window(uint48(_now()), 0), "the re-added session fails");
        vm.warp(_now() + 1);
        assertTrue(_isValid1271(w, h, APP_PK, _wrapped(w, h)), "a fresh session fails ERC-1271");
    }

    /// An unlinked identity's admin sessions stop counting; counts follow revokes, links and unlinks.
    function test_countsFollowRevokesLinksAndUnlinks() public {
        address w = _claim();
        bytes memory unlinkBob = abi.encodeCall(IIdentityAdmin.unlink, (_bob()));
        _link(w, GITHUB, BOB, _key(BOB_PK), _admin());
        _rootW(w, unlinkBob);
        _link(w, GITHUB, BOB, "", _admin());
        _revoke(w, _key(BOB_PK));
        vm.prank(w);
        vm.expectRevert(IWebWallet.RootOperationRequired.selector);
        IWebWallet(w).revokeSession(_key(ALICE_PK));

        _link(w, GITHUB, BOB, _key(BOB_PK), _admin());
        _revoke(w, _key(BOB_PK));
        _rootW(w, unlinkBob);
        _link(w, GITHUB, BOB, _key(APP_PK), _admin());
        _rootW(w, unlinkBob);
        _link(w, GITHUB, BOB, "", _admin());
        _rootW(w, unlinkBob);
        _link(w, X, ALICE, "", _admin());
        _rootReverts(w, abi.encodeCall(IIdentityAdmin.setThreshold, (2)), _tooHigh(2, 1));
    }

    // ─── Logins and signers ─────────────────────────────────────────

    /// A session by proof alone is below a threshold of 2, even within its rules; two reach it.
    function test_aProofSessionAloneIsBelowTheThreshold() public {
        IIdentityAdmin.Policy memory adminHit = _hitGas();
        adminHit.admin = true;
        address w = _claimWith(adminHit);
        _link(w, GITHUB, BOB, _key(CAROL_PK), _admin());
        _threshold(w, 2);
        _addByLogin(mallory, GITHUB, BOB, w, _key(BOB_PK), adminHit);
        vm.warp(_now() + 48 hours + 1);
        assertTrue(IWebWallet(w).sessionOf(_key(BOB_PK)).byProof, "not marked");
        assertFalse(IWebWallet(w).sessionOf(_key(ALICE_PK)).byProof, "the genesis session is marked");
        _refused(_signed(_op(w, _hitCall()), _pks(BOB_PK)), "an ordinary call by one proof session");
        _refused(_hitBy(w, _pks(BOB_PK)), "a proof session within its rules");
        bytes32 h = keccak256("message");
        assertFalse(
            _isValid1271(w, h, BOB_PK, _belowQuorum(_wrapped(w, h), 0, _key(BOB_PK))), "ERC-1271 by one proof session"
        );
        _handle(_hitBy(w, _pks(ALICE_PK)));
        assertEq(target.calls(), 1, "the genesis session's call");
        _addByLogin(mallory, X, ALICE, w, _key(ALICE2_PK), _admin());
        vm.warp(_now() + 48 hours + 1);
        _handle(_signed(_op(w, _hitCall()), _pks(BOB_PK, ALICE2_PK)));
        assertEq(target.calls(), 2, "two proof sessions reach the threshold");
        bytes memory both = _sigs(_pks(BOB_PK, ALICE2_PK), _wrapped(w, h));
        assertEq(IWebWallet(w).isValidSignature(h, both), MAGIC, "ERC-1271 by two proof sessions");
    }

    function test_atThresholdOneAProofSessionHasFullControl() public {
        address w = _claim();
        _addByLogin(mallory, X, ALICE, w, _key(ALICE2_PK), _admin());
        vm.warp(_now() + 48 hours + 1);
        _handle(_signed(_op(w, _hitCall()), _pks(ALICE2_PK)));
        assertEq(target.calls(), 1, "an ordinary call");
        _handle(_signed(_op(w, _exec(w, abi.encodeCall(IIdentityAdmin.queueRoot, (_raise())))), _pks(ALICE2_PK)));
        assertEq(IWebWallet(w).rootDelay(), 0, "raised at once");
        assertNotEq(IWebWallet(w).rootReadyAt(keccak256(_raise())), 0, "an admin operation");
        bytes32 h = keccak256("message");
        assertTrue(_isValid1271(w, h, ALICE2_PK, _wrapped(w, h)), "ERC-1271");
    }

    /// Alice's wallet with Bob's GitHub identity linked, an app session of his, and an app session `pk` of
    /// `identity` scoped to `hit()` and `APP`, needing `signers`.
    function _governed(address w, bytes32 identity, uint256 pk, uint8 signers) internal {
        IIdentityAdmin.Policy memory p = _hitGas();
        p.signers = signers;
        p.rules.domainsRoot = _domainLeaf(APP);
        _addSession(w, identity, _key(pk), p);
        vm.warp(_now() + 1);
    }

    function _signersWallet() internal returns (address w) {
        w = _claim();
        _link(w, GITHUB, BOB, _key(BOB_PK), _app());
    }

    function _pks(uint256 a, uint256 b, uint256 c) internal pure returns (uint256[] memory r) {
        r = new uint256[](3);
        (r[0], r[1], r[2]) = (a, b, c);
    }

    /// `auth` with its first two signatures swapped.
    function _swapped(bytes memory auth) internal pure returns (bytes memory) {
        IWalletCore.Authorization memory a = abi.decode(auth, (IWalletCore.Authorization));
        (a.signatures[0], a.signatures[1]) = (a.signatures[1], a.signatures[0]);
        return abi.encode(a);
    }

    /// Below quorum the first signer's `signers` is how many distinct platforms sign, UserOperation and ERC-1271.
    function test_twoSignersNeedTwoPlatforms() public {
        address w = _signersWallet();
        _governed(w, _alice(), APP_PK, 2);
        assertEq(IWebWallet(w).sessionOf(_key(APP_PK)).signers, 2, "signers");
        _refused(_hitBy(w, _pks(APP_PK)), "one signer of two");
        _refused(_hitBy(w, _pks(BOB_PK, APP_PK)), "Bob's session governs, needing one");
        _addSession(w, _alice(), _key(ALICE2_PK), _app());
        _refused(_hitBy(w, _pks(APP_PK, ALICE2_PK)), "two X sessions");
        _refused(_hitBy(w, _pks(APP_PK, ALICE2_PK, BOB_PK)), "three signers for two");
        (bytes32 h, bytes memory sig) = _typedSigBy(w, _pks(APP_PK), APP, new bytes32[](0));
        assertEq(IWebWallet(w).isValidSignature(h, sig), bytes4(0xffffffff), "ERC-1271, one signer of two");
        (h, sig) = _typedSigBy(w, _pks(APP_PK, BOB_PK), APP, new bytes32[](0));
        assertEq(IWebWallet(w).isValidSignature(h, sig), MAGIC, "ERC-1271, two platforms");
        // Bob's app session has no scope: Alice's rules govern.
        _handle(_hitBy(w, _pks(APP_PK, BOB_PK)));
        assertEq(target.calls(), 1, "two platforms");
    }

    /// Above threshold 1 a session by proof never counts as a co-signer.
    function test_aSessionByProofNeverCounts() public {
        address w = _signersWallet();
        _addSession(w, _bob(), _key(ALICE2_PK), _admin());
        _threshold(w, 2);
        _governed(w, _alice(), APP_PK, 2);
        _addByLogin(mallory, GITHUB, BOB, w, _key(MALLORY_PK), _app());
        vm.warp(_now() + 48 hours + 1);
        assertTrue(IWebWallet(w).sessionOf(_key(MALLORY_PK)).byProof, "not by proof");
        _refused(_hitBy(w, _pks(APP_PK, MALLORY_PK)), "a GitHub session by proof");
        _handle(_hitBy(w, _pks(APP_PK, BOB_PK)));
        assertEq(target.calls(), 1, "control");
    }

    function test_oneSignerActsAlone() public {
        address w = _signersWallet();
        for (uint8 signers; signers <= 1; ++signers) {
            uint256 state = vm.snapshotState();
            _governed(w, _alice(), APP_PK, signers);
            _refused(_hitBy(w, _pks(APP_PK, BOB_PK)), "a second signer");
            _handle(_hitBy(w, _pks(APP_PK)));
            assertEq(target.calls(), 1, "alone");
            vm.revertToStateAndDelete(state);
        }
    }

    /// Either session could govern, but the signatures name the first: reordered, they are refused.
    function test_theSignatureOrderIsSigned() public {
        address w = _signersWallet();
        _governed(w, _alice(), APP_PK, 2);
        _governed(w, _bob(), CAROL_PK, 2);
        PackedUserOperation memory reordered = _hitBy(w, _pks(APP_PK, CAROL_PK));
        reordered.signature = _swapped(reordered.signature);
        _refused(reordered, "the signatures reordered");
        _handle(_hitBy(w, _pks(APP_PK, CAROL_PK)));
        _handle(_hitBy(w, _pks(CAROL_PK, APP_PK)));
        assertEq(target.calls(), 2, "either order, as signed");

        (bytes32 h, bytes memory sig) = _typedSigBy(w, _pks(APP_PK, CAROL_PK), APP, new bytes32[](0));
        assertEq(IWebWallet(w).isValidSignature(h, sig), MAGIC, "ERC-1271 as signed");
        (h, sig) = _typedSigBy(w, _pks(CAROL_PK, APP_PK), APP, new bytes32[](0));
        assertEq(IWebWallet(w).isValidSignature(h, sig), MAGIC, "ERC-1271, Carol governing");
        bytes32 signed = _belowQuorum(_typedHash(w, APP), 0, _key(APP_PK));
        bytes memory auth = _auth(_pks(APP_PK, CAROL_PK), signed, 0, new IWalletCore.CallProof[](0), new bytes32[](0));
        (h, sig) = _typedSigOf(APP, _swapped(auth));
        assertEq(IWebWallet(w).isValidSignature(h, sig), bytes4(0xffffffff), "ERC-1271 reordered");
    }

    // ─── ERC-1271 ───────────────────────────────────────────────────

    function test_erc1271OnlyAdminsInWindowBoundToTheWallet() public {
        bytes32 h = keccak256("a message");
        address w = _claim();
        (,,, uint256 chainId, address verifying,,) = IWebWallet(w).eip712Domain();
        assertEq(verifying, w, "domain names another contract");
        assertEq(chainId, block.chainid, "domain chain");
        assertTrue(_isValid1271(w, h, ALICE_PK, _wrapped(w, h)), "admin");
        assertFalse(_isValid1271(w, h, ALICE_PK, h), "a bare hash, not ERC-7739");
        _addSession(w, _alice(), _key(APP_PK), _app());
        _addSession(w, _alice(), _key(BOB_PK), _admin());
        _addSession(
            w, _alice(), _key(MALLORY_PK), IIdentityAdmin.Policy(uint48(_now() + 1 hours), 0, true, 0, _noRules())
        );
        vm.warp(_now() + 1);
        assertFalse(_isValid1271(w, h, APP_PK, _belowQuorum(_wrapped(w, h), 0, _key(APP_PK))), "non-admin");
        assertFalse(_isValid1271(w, h, MALLORY_PK, _wrapped(w, h)), "before validAfter");
        assertTrue(_isValid1271(w, h, BOB_PK, _wrapped(w, h)), "in window");

        address w2 = _claimAs(GITHUB, BOB, 0, ALICE_PK);
        assertTrue(_isValid1271(w2, h, ALICE_PK, _wrapped(w2, h)), "control: the other wallet");
        assertFalse(_isValid1271(w2, h, ALICE_PK, _wrapped(w, h)), "replayed from another wallet");
    }

    /// `validUntil` is the last valid second and `validAfter` the last second before, as the EntryPoint reads them.
    function test_erc1271WindowIsTheEntryPoints() public {
        address w = _claim();
        uint48 t = uint48(_now());
        IIdentityAdmin.Policy memory p = _hitGas();
        p.validUntil = t + 20;
        bytes32 app = keccak256("an app's domain separator");
        p.rules.domainsRoot = _domainLeaf(app);
        _addSession(w, _alice(), _key(BOB_PK), p);
        _addSession(w, _alice(), _key(CAROL_PK), IIdentityAdmin.Policy(t + 10, 0, true, 0, _noRules()));
        bytes32 m = keccak256("a message");
        vm.warp(t + 10);
        _refused(_signed(_op(w, _hitCall()), _pks(CAROL_PK)), "at validAfter");
        assertFalse(_isValid1271(w, m, CAROL_PK, _wrapped(w, m)), "ERC-1271 at validAfter");
        vm.warp(t + 11);
        assertTrue(_isValid1271(w, m, CAROL_PK, _wrapped(w, m)), "after validAfter");
        _handle(_signed(_op(w, _hitCall()), _pks(CAROL_PK)));

        vm.warp(t + 20);
        (bytes32 h, bytes memory sig) = _typedSigBy(w, _pks(BOB_PK), app, new bytes32[](0));
        assertEq(IWebWallet(w).isValidSignature(h, sig), MAGIC, "at validUntil");
        _handle(_hitBy(w, _pks(BOB_PK)));
        vm.warp(t + 21);
        assertEq(IWebWallet(w).isValidSignature(h, sig), bytes4(0xffffffff), "after validUntil");
        _refused(_hitBy(w, _pks(BOB_PK)), "after validUntil");
    }

    /// ERC-7739 `TypedDataSign`: the app's hash nested under the wallet's domain, signed by an admin; the probe.
    function test_erc1271TypedDataSignAndProbe() public {
        address w = _claim();
        _addSession(w, _alice(), _key(APP_PK), _app());
        vm.warp(_now() + 1);
        bytes32 app = keccak256("an app's domain separator");
        (bytes32 h, bytes memory sig) = _typedSigOf(app, _sigs(_pks(ALICE_PK), _typedHash(w, app)));
        assertEq(IWebWallet(w).isValidSignature(h, sig), MAGIC, "an admin");
        (bytes32 hApp, bytes memory byApp) = _typedSigBy(w, _pks(APP_PK), app, new bytes32[](0));
        assertEq(IWebWallet(w).isValidSignature(hApp, byApp), bytes4(0xffffffff), "an app session, no domains");
        assertEq(IWebWallet(w).isValidSignature(keccak256("other"), sig), bytes4(0xffffffff), "another hash");
        // An empty contents type gives a zero struct hash, which binds nothing.
        bytes memory unbound = abi.encodePacked(
            _sigs(_pks(ALICE_PK), keccak256(abi.encodePacked(hex"1901", app, bytes32(0)))), app, MAIL, uint16(0)
        );
        assertEq(IWebWallet(w).isValidSignature(h, unbound), bytes4(0xffffffff), "zero struct hash");
        assertEq(IWebWallet(w).isValidSignature(PROBE, ""), bytes4(0x77390001), "standard probe");
        assertEq(IWebWallet(w).isValidSignature(keccak256("other"), ""), bytes4(0xffffffff), "empty signature");
    }

    // ─── Passkeys ───────────────────────────────────────────────────

    uint256 internal constant PASSKEY_PK = 0x9A55;

    function _passkey() internal returns (bytes memory) {
        (uint256 qx, uint256 qy) = vm.publicKeyP256(PASSKEY_PK);
        return abi.encodePacked(address(new ERC7913WebAuthnVerifier()), qx, qy);
    }

    /// A WebAuthn assertion over `h`, with user presence and verification, by `passkey`.
    function _passkeySigs(bytes memory passkey, bytes32 h) internal view returns (bytes memory) {
        bytes memory authenticatorData =
            abi.encodePacked(bytes32(0), WebAuthn.AUTH_DATA_FLAGS_UP | WebAuthn.AUTH_DATA_FLAGS_UV, bytes4(0));
        string memory clientDataJSON =
            string.concat('{"type":"webauthn.get","challenge":"', Base64.encodeURL(abi.encodePacked(h)), '"}');
        (bytes32 r, bytes32 s) =
            vm.signP256(PASSKEY_PK, sha256(abi.encodePacked(authenticatorData, sha256(bytes(clientDataJSON)))));
        if (uint256(s) > P256.N / 2) s = bytes32(P256.N - uint256(s));
        IWalletCore.SessionSignature[] memory sigs = new IWalletCore.SessionSignature[](1);
        // The verifier reads WebAuthnAuth's fields as a bare tuple, with no leading offset word.
        sigs[0] = IWalletCore.SessionSignature({
            key: passkey, signature: abi.encode(r, s, 23, 1, authenticatorData, clientDataJSON)
        });
        return _wrap(sigs);
    }

    /// D21: a WebAuthn P-256 key as an ERC-7913 admin session, through the EntryPoint and ERC-1271.
    function test_aPasskeyAdminSigns() public {
        address w = _claim();
        bytes memory passkey = _passkey();
        _addSession(w, _alice(), passkey, _admin());
        uint48 added = uint48(_now());
        vm.warp(_now() + 1);
        bytes memory callData =
            _exec(w, abi.encodeCall(IIdentityAdmin.addSession, (_alice(), _key(ALICE2_PK), _admin())));
        PackedUserOperation memory op = _op(w, callData);
        op.signature = _passkeySigs(passkey, _signable(w, IUserOpHash(EP).getUserOpHash(op)));
        _handle(op);
        IIdentityAdmin.Session memory s = IWebWallet(w).sessionOf(_key(ALICE2_PK));
        assertEq(s.identity, _alice(), "no session added");
        assertEq(s.activeAt, _now(), "the new session waits past its second");
        // The answer, and its cost with OZ's Solidity P-256 (no precompile under cancun).
        bytes32 h = keccak256("user op");
        op.signature = _passkeySigs(passkey, _signable(w, h));
        vm.prank(EP);
        uint256 before = gasleft();
        uint256 result = IWebWallet(w).validateUserOp(op, h, 0);
        emit log_named_uint("validateUserOp gas, passkey", before - gasleft());
        assertEq(result, _window(added, 0), "passkey refused");
        op.signature = _passkeySigs(passkey, _signable(w, keccak256("another op")));
        vm.prank(EP);
        assertEq(IWebWallet(w).validateUserOp(op, h, 0), 1, "a signature over another hash passed");

        bytes32 m = keccak256("a message");
        assertEq(IWebWallet(w).isValidSignature(m, _passkeySigs(passkey, _wrapped(w, m))), MAGIC, "ERC-1271");
        assertEq(IWebWallet(w).isValidSignature(m, _passkeySigs(passkey, m)), bytes4(0xffffffff), "unwrapped");
    }
}
