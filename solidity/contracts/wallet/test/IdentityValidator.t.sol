// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IERC7579ModuleConfig} from "@openzeppelin/contracts/interfaces/draft-IERC7579.sol";
import {PackedUserOperation} from "@openzeppelin/contracts/interfaces/IERC4337.sol";

import {IIdentityValidator} from "../IIdentityValidator.sol";
import {IWebWallet} from "../IWebWallet.sol";
import {AcceptingVerifier, WalletTestBase} from "./WalletTestBase.sol";

/// @notice Sessions, threshold, root timelock, ERC-1271 and ERC-7562 rules of the validator.
contract IdentityValidatorTest is WalletTestBase {
    function test_registryOnlyEntries() public {
        assertEq(validator.walletRegistry(), address(registry));
        assertEq(validator.MIN_RECOVERY_DELAY(), 48 hours);
        assertEq(validator.ROOT_DELAY(), 48 hours);
        address w = _claim();
        vm.startPrank(mallory);
        vm.expectRevert(abi.encodeWithSelector(IIdentityValidator.NotRegistry.selector, mallory));
        validator.link(w, X, MALLORY);
        vm.expectRevert(abi.encodeWithSelector(IIdentityValidator.NotRegistry.selector, mallory));
        validator.addSessionByProof(w, _identity(X, ALICE), _key(MALLORY_PK), _admin());
        vm.stopPrank();
    }

    // ─── Validation data (R2) ───────────────────────────────────────

    /// The window comes back packed; `activeAt` folds into `validAfter`.
    function test_validationReturnsThePackedWindow() public {
        uint48 start = uint48(_now() + 10);
        uint48 end = uint48(_now() + 1000);
        address w = _claimWith(IIdentityValidator.Policy({validAfter: start, validUntil: end, admin: true}));
        assertEq(_validate(w, _hit(), _pks(ALICE_PK)), _window(start, end), "policy window");

        _addByProof(relayer, X, ALICE, w, _key(ALICE2_PK), _admin());
        assertEq(_validate(w, _hit(), _pks(ALICE2_PK)), _window(uint48(_now() + 48 hours), 0), "pending window");
    }

    /// Validation reads no TIMESTAMP: the answer is the same at any time.
    function test_validationDoesNotReadTheClock() public {
        address w =
            _claimWith(IIdentityValidator.Policy({validAfter: 0, validUntil: uint48(_now() + 1 hours), admin: true}));
        uint256 early = _validate(w, _hit(), _pks(ALICE_PK));
        vm.warp(_now() + 3650 days);
        assertEq(_validate(w, _hit(), _pks(ALICE_PK)), early, "expired session answered differently");
    }

    function test_unknownAndRevokedKeysFail() public {
        address w = _claim();
        assertEq(_validate(w, _hit(), _pks(MALLORY_PK)), 1, "unknown key");
        vm.startPrank(w);
        validator.addSession(_identity(X, ALICE), _key(ALICE2_PK), _admin());
        validator.revokeSession(_key(ALICE2_PK));
        vm.stopPrank();
        assertEq(_validate(w, _hit(), _pks(ALICE2_PK)), 1, "revoked key");
    }

    /// ERC-7562: every slot read in validation is `A` or `keccak(A || x) + n`, n <= 128,
    /// including for a 64-byte ERC-7913 key.
    function test_validationReadsOnlyAccountAssociatedStorage() public {
        address w = _claim();
        bytes memory key = abi.encodePacked(address(new AcceptingVerifier()), keccak256("x"), keccak256("y"));
        vm.prank(w);
        validator.addSession(_identity(X, ALICE), key, _app());

        IIdentityValidator.SessionSignature[] memory s = new IIdentityValidator.SessionSignature[](1);
        s[0] = IIdentityValidator.SessionSignature({key: key, signature: hex"1234"});
        PackedUserOperation memory op = _op(w, 0, _hit());
        op.signature = abi.encode(s);

        vm.startMappingRecording();
        vm.record();
        vm.prank(w);
        assertEq(validator.validateUserOp(op, keccak256("op")), 0, "the 7913 key did not validate");
        (bytes32[] memory reads,) = vm.accesses(address(validator));
        for (uint256 i; i < reads.length; ++i) {
            assertTrue(_associated(w, reads[i]), "validation read a slot not associated with the account");
        }
    }

    function _associated(address account, bytes32 slot) internal view returns (bool) {
        bytes32 a = bytes32(uint256(uint160(account)));
        if (slot == a) return true;
        for (uint256 n; n <= 128 && n <= uint256(slot); ++n) {
            (bool found, bytes32 key,) = vm.getMappingKeyAndParentOf(address(validator), bytes32(uint256(slot) - n));
            if (found && key == a) return true;
        }
        return false;
    }

    // ─── Threshold (R8) ─────────────────────────────────────────────

    function test_thresholdCountsDistinctAdminIdentities() public {
        address w = _claim();
        _link(w, GITHUB, BOB, w, "", _admin());
        vm.startPrank(w);
        validator.addSession(_identity(GITHUB, BOB), _key(BOB_PK), _admin());
        validator.addSession(_identity(X, ALICE), _key(ALICE2_PK), _admin());
        validator.addSession(_identity(GITHUB, BOB), _key(APP_PK), _app());
        vm.stopPrank();
        _root(w, address(validator), abi.encodeCall(IIdentityValidator.setThreshold, (2)));
        assertEq(validator.threshold(w), 2, "threshold");

        bytes memory adminOp =
            _exec(address(validator), abi.encodeCall(IIdentityValidator.setRecoveryDelay, (72 hours)));
        assertEq(_validate(w, adminOp, _pks(ALICE_PK)), 1, "one identity");
        assertEq(_validate(w, adminOp, _pks(ALICE_PK, ALICE_PK)), 1, "one key twice");
        assertEq(_validate(w, adminOp, _pks(ALICE_PK, ALICE2_PK)), 1, "two keys of one identity");
        assertEq(_validate(w, adminOp, _pks(ALICE_PK, APP_PK)), 1, "a non-admin session counted");
        assertEq(_validate(w, adminOp, _pks(ALICE_PK, BOB_PK)), 0, "two admin identities");
        assertEq(_validate(w, _hit(), _pks(ALICE_PK)), 0, "an ordinary call needs no quorum");
    }

    // ─── Root operations (D16) ──────────────────────────────────────

    function test_rootOperationWaitsThenRunsOnce() public {
        address w = _claim();
        address impl2 = deployCode("WebWallet.sol:WebWallet", abi.encode(address(validator)));
        bytes memory data = abi.encodeCall(IWebWallet.upgradeToAndCall, (impl2, ""));
        bytes32 opId = keccak256(abi.encode(w, w, data));

        vm.prank(w);
        assertEq(validator.queueRoot(w, data), opId, "op id");
        uint48 ready = uint48(_now() + 48 hours);
        assertEq(validator.rootReadyAt(w, opId), ready, "ready time");

        vm.warp(ready - 1);
        vm.expectRevert(abi.encodeWithSelector(IIdentityValidator.RootNotReady.selector, opId));
        validator.executeRoot(w, w, data);

        vm.warp(ready);
        vm.prank(mallory);
        validator.executeRoot(w, w, data);
        assertEq(address(uint160(uint256(vm.load(w, IMPL_SLOT)))), impl2, "not upgraded");
        assertEq(validator.rootReadyAt(w, opId), 0, "op kept");
        vm.expectRevert(abi.encodeWithSelector(IIdentityValidator.RootNotReady.selector, opId));
        validator.executeRoot(w, w, data);
    }

    function test_onlyTheAccountCancelsItsRootOperation() public {
        address w = _claim();
        bytes memory data = abi.encodeCall(IIdentityValidator.setThreshold, (1));
        vm.prank(w);
        bytes32 opId = validator.queueRoot(address(validator), data);

        vm.prank(mallory);
        try validator.cancelRoot(opId) {} catch {}
        assertGt(validator.rootReadyAt(w, opId), 0, "a stranger cancelled");

        vm.prank(w);
        validator.cancelRoot(opId);
        assertEq(validator.rootReadyAt(w, opId), 0, "not cancelled");
        vm.warp(_now() + 48 hours);
        vm.expectRevert(abi.encodeWithSelector(IIdentityValidator.RootNotReady.selector, opId));
        validator.executeRoot(w, address(validator), data);
    }

    /// Root changes have no path around the timelock.
    function test_rootChangesRefusedOutsideTheTimelock() public {
        address w = _claim();
        address impl2 = deployCode("WebWallet.sol:WebWallet", abi.encode(address(validator)));
        bytes[3] memory calls = [
            abi.encodeCall(IERC7579ModuleConfig.installModule, (1, address(0xBEEF), "")),
            abi.encodeCall(IERC7579ModuleConfig.uninstallModule, (1, address(validator), "")),
            abi.encodeCall(IWebWallet.upgradeToAndCall, (impl2, ""))
        ];
        address[2] memory callers = [EP, w];
        for (uint256 i; i < calls.length; ++i) {
            for (uint256 j; j < callers.length; ++j) {
                vm.prank(callers[j]);
                (bool ok,) = w.call(calls[i]);
                assertFalse(ok, "a root change ran without the timelock");
            }
        }
        vm.startPrank(w);
        vm.expectRevert(IIdentityValidator.RootOperationRequired.selector);
        validator.setThreshold(2);
        vm.expectRevert(IIdentityValidator.RootOperationRequired.selector);
        validator.revokeSession(_key(ALICE_PK));
        vm.stopPrank();
    }

    /// R7: only the IdentityValidator, even through a matured root operation.
    function test_moduleAllowlist() public {
        address w = _claim();
        for (uint256 t = 2; t <= 4; ++t) {
            assertFalse(IWebWallet(w).supportsModule(t), "a non-validator module type");
        }
        assertTrue(IWebWallet(w).supportsModule(1), "validators");

        address other = deployCode("IdentityValidator.sol:IdentityValidator", abi.encode(address(registry)));
        bytes memory data = abi.encodeCall(IERC7579ModuleConfig.installModule, (1, other, abi.encode(X, ALICE)));
        vm.prank(w);
        validator.queueRoot(w, data);
        vm.warp(_now() + 48 hours);
        vm.expectRevert();
        validator.executeRoot(w, w, data);
    }

    function test_revokingTheLastAdminIsARootOperation() public {
        address w = _claim();
        _root(w, address(validator), abi.encodeCall(IIdentityValidator.revokeSession, (_key(ALICE_PK))));
        assertEq(validator.sessionOf(w, _key(ALICE_PK)).identity, bytes32(0), "not revoked");

        _addByProof(relayer, X, ALICE, w, _key(ALICE2_PK), _admin());
        assertEq(validator.sessionOf(w, _key(ALICE2_PK)).activeAt, _now() + 48 hours, "no session left skips the wait");
    }

    function test_recoveryDelayOnlyGrows() public {
        address w = _claim();
        vm.startPrank(w);
        vm.expectRevert(abi.encodeWithSelector(IIdentityValidator.RecoveryDelayTooShort.selector, 47 hours));
        validator.setRecoveryDelay(47 hours);
        validator.setRecoveryDelay(72 hours);
        vm.expectRevert(abi.encodeWithSelector(IIdentityValidator.RecoveryDelayTooShort.selector, 60 hours));
        validator.setRecoveryDelay(60 hours);
        vm.stopPrank();
        assertEq(validator.recoveryDelay(w), 72 hours);

        _addByProof(relayer, X, ALICE, w, _key(ALICE2_PK), _admin());
        assertEq(validator.sessionOf(w, _key(ALICE2_PK)).activeAt, _now() + 72 hours, "raised delay ignored");
    }

    /// R6: state is keyed by install, so a reinstall starts empty.
    function test_reinstallDoesNotRestoreSessions() public {
        address w = _claim();
        vm.startPrank(w);
        validator.onUninstall("");
        validator.onInstall(abi.encode(X, ALICE));
        vm.stopPrank();
        assertEq(validator.sessionOf(w, _key(ALICE_PK)).identity, bytes32(0), "session came back");
        assertFalse(validator.isLinked(w, _identity(X, ALICE)), "link came back");
        assertEq(_validate(w, _hit(), _pks(ALICE_PK)), 1, "old key validates");
    }

    // ─── ERC-1271 (R3) ──────────────────────────────────────────────

    function test_erc1271OnlyAdminsInWindowBoundToTheAccount() public {
        bytes32 h = keccak256("a message");
        address w = _claim();
        (,,, uint256 chainId, address verifying,,) = IWebWallet(w).eip712Domain();
        assertEq(verifying, w, "domain names another contract");
        assertEq(chainId, block.chainid, "domain chain");

        assertTrue(_isValid1271(w, h, ALICE_PK, _wrapped(w, h)), "admin");
        assertFalse(_isValid1271(w, h, ALICE_PK, h), "a bare hash, not ERC-7739");

        vm.startPrank(w);
        validator.addSession(_identity(X, ALICE), _key(APP_PK), _app());
        validator.addSession(
            _identity(X, ALICE),
            _key(BOB_PK),
            IIdentityValidator.Policy({validAfter: 0, validUntil: uint48(_now() + 1 hours), admin: true})
        );
        validator.addSession(
            _identity(X, ALICE),
            _key(MALLORY_PK),
            IIdentityValidator.Policy({validAfter: uint48(_now() + 1 hours), validUntil: 0, admin: true})
        );
        vm.stopPrank();
        _addByProof(relayer, X, ALICE, w, _key(ALICE2_PK), _admin());

        assertFalse(_isValid1271(w, h, APP_PK, _wrapped(w, h)), "non-admin");
        assertFalse(_isValid1271(w, h, MALLORY_PK, _wrapped(w, h)), "before validAfter");
        assertFalse(_isValid1271(w, h, ALICE2_PK, _wrapped(w, h)), "pending");
        assertTrue(_isValid1271(w, h, BOB_PK, _wrapped(w, h)), "in window");
        vm.warp(_now() + 2 hours);
        assertFalse(_isValid1271(w, h, BOB_PK, _wrapped(w, h)), "expired");
    }

    function test_erc1271SignatureDoesNotReplayOnAnotherAccount() public {
        bytes32 h = keccak256("a message");
        address w = _claim();
        address w2 = factory.createWallet(GITHUB, BOB, 0);
        _link(relayer, GITHUB, BOB, w2, _key(ALICE_PK), _admin());

        assertTrue(_isValid1271(w2, h, ALICE_PK, _wrapped(w2, h)), "control");
        assertFalse(_isValid1271(w2, h, ALICE_PK, _wrapped(w, h)), "replayed from another account");
    }
}
