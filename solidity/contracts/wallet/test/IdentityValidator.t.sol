// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {
    Execution,
    IERC7579AccountConfig,
    IERC7579Execution,
    IERC7579Module,
    IERC7579ModuleConfig
} from "@openzeppelin/contracts/interfaces/draft-IERC7579.sol";
import {PackedUserOperation} from "@openzeppelin/contracts/interfaces/IERC4337.sol";

import {IIdentityValidator} from "../IIdentityValidator.sol";
import {IWebWallet} from "../IWebWallet.sol";
import {AcceptingVerifier, WalletTestBase} from "./WalletTestBase.sol";

/// An ERC-1271 signer that accepts every signature.
contract Accepting1271 {
    function isValidSignature(bytes32, bytes calldata) external pure returns (bytes4) {
        return 0x1626ba7e;
    }
}

/// An account whose EIP-712 domain has a salt; it passes ERC-1271 to the validator as WebWallet does.
contract SaltedAccount {
    IIdentityValidator private immutable VALIDATOR;

    constructor(IIdentityValidator validator) {
        VALIDATOR = validator;
    }

    function eip712Domain()
        external
        view
        returns (bytes1, string memory, string memory, uint256, address, bytes32, uint256[] memory)
    {
        return (0x1f, "Salted", "1", block.chainid, address(this), keccak256("salt"), new uint256[](0));
    }

    function isValidSignature(bytes32 hash, bytes calldata signature) external view returns (bytes4) {
        return VALIDATOR.isValidSignatureWithSender(msg.sender, hash, signature[20:]);
    }
}

/// @notice Sessions, threshold, root timelock, ERC-1271 and ERC-7562 rules of the validator.
contract IdentityValidatorTest is WalletTestBase {
    function test_registryOnlyEntries() public {
        assertEq(validator.walletRegistry(), address(registry));
        assertEq(validator.MIN_RECOVERY_DELAY(), 48 hours);
        address w = _claim();
        vm.startPrank(mallory);
        vm.expectRevert(abi.encodeWithSelector(IIdentityValidator.NotRegistry.selector, mallory));
        validator.link(w, X, MALLORY);
        vm.expectRevert(abi.encodeWithSelector(IIdentityValidator.NotRegistry.selector, mallory));
        validator.addSessionByProof(w, _identity(X, ALICE), _key(MALLORY_PK), _admin());
        vm.stopPrank();
    }

    function test_accountEntriesRefuseBadInput() public {
        address w = _claim();
        bytes memory short = hex"0102";
        vm.startPrank(w);
        vm.expectRevert(abi.encodeWithSelector(IIdentityValidator.BadRootOperation.selector, mallory));
        validator.queueRoot(mallory, "");
        vm.expectRevert(abi.encodeWithSelector(IIdentityValidator.BadRootOperation.selector, mallory));
        validator.queueRoot(mallory, abi.encodeCall(IIdentityValidator.setThreshold, (2)));
        vm.expectRevert(abi.encodeWithSelector(IIdentityValidator.BadRootOperation.selector, address(validator)));
        validator.queueRoot(address(validator), abi.encodeCall(IIdentityValidator.setRecoveryDelay, (72 hours)));
        vm.expectRevert(abi.encodeWithSelector(IIdentityValidator.RootNotReady.selector, keccak256("never queued")));
        validator.cancelRoot(keccak256("never queued"));
        vm.expectRevert(abi.encodeWithSelector(IIdentityValidator.InvalidKey.selector, short));
        validator.addSession(_identity(X, ALICE), short, _app());
        bytes memory key19 = hex"00112233445566778899aabbccddeeff001122";
        vm.expectRevert(abi.encodeWithSelector(IIdentityValidator.InvalidKey.selector, key19));
        validator.addSession(_identity(X, ALICE), key19, _app());
        vm.expectRevert(abi.encodeWithSelector(IIdentityValidator.SessionExists.selector, _key(ALICE_PK)));
        validator.addSession(_identity(X, ALICE), _key(ALICE_PK), _app());
        vm.expectRevert(abi.encodeWithSelector(IIdentityValidator.NoSession.selector, _key(APP_PK)));
        validator.revokeSession(_key(APP_PK));
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

    /// Co-signers' windows intersect, whatever their order.
    function test_windowIsTheIntersectionOfAllSigners() public {
        address w = _claim();
        uint48 t = uint48(_now());
        vm.startPrank(w);
        validator.addSession(_identity(X, ALICE), _key(ALICE2_PK), IIdentityValidator.Policy(t + 10, t + 2000, true));
        validator.addSession(_identity(X, ALICE), _key(BOB_PK), IIdentityValidator.Policy(t + 20, t + 1000, true));
        vm.stopPrank();
        assertEq(_validate(w, _hit(), _pks(ALICE2_PK, BOB_PK)), _window(t + 20, t + 1000), "wide first");
        assertEq(_validate(w, _hit(), _pks(BOB_PK, ALICE2_PK)), _window(t + 20, t + 1000), "narrow first");
    }

    /// A 20-byte key is an ECDSA address: never asked through ERC-1271, and no signature recovers to zero.
    function test_twentyByteKeysAreRecovered() public {
        address w = _claim();
        bytes[2] memory keys = [abi.encodePacked(address(new Accepting1271())), abi.encodePacked(address(0))];
        IIdentityValidator.SessionSignature[] memory s = new IIdentityValidator.SessionSignature[](1);
        PackedUserOperation memory op = _op(w, 0, _hit());
        for (uint256 i; i < keys.length; ++i) {
            vm.prank(w);
            validator.addSession(_identity(X, ALICE), keys[i], _app());
            s[0] = IIdentityValidator.SessionSignature({key: keys[i], signature: hex"1234"});
            op.signature = abi.encode(s);
            vm.prank(w);
            assertEq(validator.validateUserOp(op, keccak256("op")), 1, "a 20-byte key accepted a bad signature");
        }
    }

    function test_anEmptySignatureListFails() public {
        address w = _claim();
        PackedUserOperation memory op = _op(w, 0, _hit());
        op.signature = abi.encode(new IIdentityValidator.SessionSignature[](0));
        vm.prank(w);
        assertEq(validator.validateUserOp(op, keccak256("h")), 1);
    }

    /// A signature that is not a session list fails validation instead of reverting it.
    function test_aMalformedSignatureFails() public {
        address w = _claim();
        PackedUserOperation memory op = _op(w, 0, _hit());
        bytes[3] memory sigs =
            [bytes(""), abi.encodePacked(bytes32(type(uint256).max), bytes32(0), bytes1(0)), new bytes(65)];
        sigs[2][64] = 0x1b;
        for (uint256 i; i < sigs.length; ++i) {
            op.signature = sigs[i];
            vm.prank(w);
            assertEq(validator.validateUserOp(op, keccak256("h")), 1);
        }
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
    /// including for a 64-byte ERC-7913 admin key, whose identity's platform is read.
    function test_validationReadsOnlyAccountAssociatedStorage() public {
        address w = _claim();
        bytes memory key = abi.encodePacked(address(new AcceptingVerifier()), keccak256("x"), keccak256("y"));
        vm.prank(w);
        validator.addSession(_identity(X, ALICE), key, _admin());

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

    // ─── Scope (R9) ─────────────────────────────────────────────────

    /// Module hooks are refused even to admins; self, zero-address and registry targets are admin;
    /// a batch takes its widest call; the execution is read where the account's decoder reads it.
    function test_outerCallScope() public {
        address w = _claim();
        vm.prank(w);
        validator.addSession(_identity(X, ALICE), _key(APP_PK), _app());
        bytes memory toWallet = abi.encodeCall(IERC7579AccountConfig.supportsModule, (2));

        Execution[] memory batch = new Execution[](2);
        batch[0] = Execution({
            target: address(validator), value: 0, callData: abi.encodeCall(IERC7579Module.onUninstall, (""))
        });
        batch[1] = Execution({target: address(target), value: 0, callData: ""});
        Execution[] memory appBatch = new Execution[](2);
        appBatch[0] = Execution({target: w, value: 0, callData: toWallet});
        appBatch[1] = batch[1];

        // A decoy outside call where a canonical encoding puts the execution; the real one where the offset points.
        bytes memory decoy = abi.encodePacked(address(target), uint256(0), abi.encodeCall(this.setUp, ()));
        bytes memory real = abi.encodePacked(w, uint256(0), toWallet);
        bytes memory offset = abi.encodePacked(
            IERC7579Execution.execute.selector, MODE_SINGLE, uint256(0xa0), decoy.length, decoy, bytes8(0)
        );

        bytes[8] memory calls = [
            _exec(address(validator), abi.encodeCall(IERC7579Module.onUninstall, (""))),
            _exec(address(validator), abi.encodeCall(IERC7579Module.onInstall, (abi.encode(X, MALLORY)))),
            abi.encodeCall(IERC7579Execution.execute, (MODE_BATCH, abi.encode(batch))),
            abi.encodeCall(IWebWallet.upgradeToAndCall, (address(target), "")),
            _exec(address(0), _hit()),
            _exec(address(registry), ""),
            abi.encodeCall(IERC7579Execution.execute, (MODE_BATCH, abi.encode(appBatch))),
            abi.encodePacked(offset, real.length, real)
        ];
        for (uint256 i; i < calls.length; ++i) {
            assertEq(_validate(w, calls[i], _pks(i < 4 ? ALICE_PK : APP_PK)), 1, vm.toString(i));
        }
    }

    // ─── Threshold (R8) ─────────────────────────────────────────────

    function test_thresholdCountsDistinctAdminPlatforms() public {
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
        assertEq(_validate(w, adminOp, _pks(ALICE_PK, BOB_PK)), 0, "two admin platforms");
        assertEq(_validate(w, _hit(), _pks(ALICE_PK)), 0, "an ordinary call needs no quorum");
    }

    /// Admin sessions of two identities on one platform count once toward the quorum.
    function test_identitiesOfOnePlatformCountOnce() public {
        address w = _claim();
        _link(w, X, MALLORY, w, _key(MALLORY_PK), _admin());
        _link(w, GOOGLE, CAROL, w, _key(CAROL_PK), _admin());
        _root(w, address(validator), abi.encodeCall(IIdentityValidator.setThreshold, (2)));
        bytes memory adminOp =
            _exec(address(validator), abi.encodeCall(IIdentityValidator.setRecoveryDelay, (72 hours)));
        assertEq(_validate(w, adminOp, _pks(ALICE_PK, MALLORY_PK)), 1, "two X identities met the threshold");
        assertEq(_validate(w, adminOp, _pks(MALLORY_PK, CAROL_PK)), 0, "X and Google missed the threshold");
    }

    /// The threshold may not exceed the platforms with a linked identity, however many identities there are.
    function test_thresholdIsBoundedByLinkedPlatforms() public {
        address w = _claim();
        _link(w, X, MALLORY, w, "", _admin());
        bytes memory threshold2 = abi.encodeCall(IIdentityValidator.setThreshold, (2));
        _rootReverts(
            w,
            address(validator),
            threshold2,
            abi.encodeWithSelector(IIdentityValidator.ThresholdTooHigh.selector, uint8(2), uint32(1))
        );
        _link(w, GOOGLE, CAROL, w, "", _admin());
        _root(w, address(validator), threshold2);
        assertEq(validator.threshold(w), 2, "threshold");
    }

    /// An unlink may not drop the last identity of a platform the threshold needs; a re-link counts it again.
    function test_unlinkKeepsThePlatformsTheThresholdNeeds() public {
        address w = _claim();
        bytes32 mallory_ = _identity(X, MALLORY);
        bytes32 carol = _identity(GOOGLE, CAROL);
        bytes memory threshold2 = abi.encodeCall(IIdentityValidator.setThreshold, (2));
        bytes memory tooHigh = abi.encodeWithSelector(IIdentityValidator.ThresholdTooHigh.selector, uint8(2), uint32(1));
        _link(w, X, MALLORY, w, "", _admin());
        _link(w, GOOGLE, CAROL, w, "", _admin());
        _root(w, address(validator), threshold2);

        _unlinkReverts(w, carol, tooHigh);
        _root(w, address(validator), abi.encodeCall(IIdentityValidator.unlink, (mallory_)));

        _root(w, address(validator), abi.encodeCall(IIdentityValidator.setThreshold, (1)));
        _root(w, address(validator), abi.encodeCall(IIdentityValidator.unlink, (carol)));
        _rootReverts(w, address(validator), threshold2, tooHigh);
        _link(w, GOOGLE, CAROL, w, "", _admin());
        _root(w, address(validator), threshold2);
        assertEq(validator.threshold(w), 2, "a re-link did not count its platform again");
    }

    // ─── Root operations (D16) ──────────────────────────────────────

    function test_rootOperationWaitsThenRunsOnce() public {
        address w = _claim();
        address impl2 = _walletImpl();
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
        address impl2 = _walletImpl();
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
        vm.expectRevert(IIdentityValidator.RootOperationRequired.selector);
        validator.unlink(_identity(X, ALICE));
        vm.stopPrank();
    }

    /// R7: only the IdentityValidator and the ClaimExecutor, even through a matured root operation.
    function test_moduleAllowlist() public {
        address w = _claim();
        for (uint256 t = 3; t <= 4; ++t) {
            assertFalse(IWebWallet(w).supportsModule(t), "a fallback or hook module type");
        }
        assertTrue(IWebWallet(w).supportsModule(1), "validators");
        assertTrue(IWebWallet(w).supportsModule(2), "executors");
        assertTrue(IWebWallet(w).isModuleInstalled(2, address(executor), ""), "executor not installed at genesis");

        // The executor leaves and comes back only by root operation; no other executor comes in.
        _root(w, w, abi.encodeCall(IERC7579ModuleConfig.uninstallModule, (2, address(executor), "")));
        assertFalse(IWebWallet(w).isModuleInstalled(2, address(executor), ""), "executor not uninstalled");
        _root(w, w, abi.encodeCall(IERC7579ModuleConfig.installModule, (2, address(executor), "")));
        assertTrue(IWebWallet(w).isModuleInstalled(2, address(executor), ""), "executor not reinstalled");
        _rootReverts(
            w,
            w,
            abi.encodeCall(IERC7579ModuleConfig.installModule, (2, address(target), "")),
            abi.encodeWithSelector(IWebWallet.ModuleNotAllowed.selector, address(target))
        );

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
        vm.startPrank(w);
        validator.addSession(_identity(X, ALICE), _key(ALICE2_PK), _admin());
        validator.revokeSession(_key(ALICE2_PK));
        vm.expectRevert(IIdentityValidator.RootOperationRequired.selector);
        validator.revokeSession(_key(ALICE_PK));
        vm.stopPrank();
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
        validator.setRecoveryDelay(72 hours);
        vm.expectRevert(abi.encodeWithSelector(IIdentityValidator.RecoveryDelayTooShort.selector, 60 hours));
        validator.setRecoveryDelay(60 hours);
        vm.stopPrank();
        assertEq(validator.recoveryDelay(w), 72 hours);

        uint48 max = validator.MAX_RECOVERY_DELAY();
        vm.prank(w);
        vm.expectRevert(abi.encodeWithSelector(IIdentityValidator.RecoveryDelayTooLong.selector, max + 1));
        validator.setRecoveryDelay(max + 1);

        _addByProof(relayer, X, ALICE, w, _key(ALICE2_PK), _admin());
        assertEq(validator.sessionOf(w, _key(ALICE2_PK)).activeAt, _now() + 72 hours, "raised delay ignored");
    }

    /// The threshold may not exceed the linked platforms, or no admin operation could pass again.
    function test_thresholdAboveTheLinkedPlatformsIsRefused() public {
        address w = _claim();
        _rootReverts(
            w,
            address(validator),
            abi.encodeCall(IIdentityValidator.setThreshold, (2)),
            abi.encodeWithSelector(IIdentityValidator.ThresholdTooHigh.selector, uint8(2), uint32(1))
        );
    }

    /// After the timelock, every session of the identity stops validating, and no proof adds one.
    function test_unlinkStopsTheIdentitysSessions() public {
        address w = _claim();
        bytes32 bob = _identity(GITHUB, BOB);
        _link(w, GITHUB, BOB, w, _key(BOB_PK), _admin());
        _addByProof(relayer, GITHUB, BOB, w, _key(APP_PK), _admin());

        bytes memory data = abi.encodeCall(IIdentityValidator.unlink, (bob));
        vm.prank(w);
        validator.queueRoot(address(validator), data);
        vm.warp(_now() + 48 hours - 1);
        vm.expectRevert(
            abi.encodeWithSelector(
                IIdentityValidator.RootNotReady.selector, keccak256(abi.encode(w, address(validator), data))
            )
        );
        validator.executeRoot(w, address(validator), data);
        vm.warp(_now() + 1);
        bytes32 h = keccak256("a message");
        assertEq(_validate(w, _hit(), _pks(APP_PK)), _window(uint48(_now()), 0), "pending control");
        assertTrue(_isValid1271(w, h, BOB_PK, _wrapped(w, h)), "active control");

        vm.expectEmit(true, true, false, false, address(validator));
        emit IIdentityValidator.IdentityUnlinked(w, bob);
        validator.executeRoot(w, address(validator), data);
        assertFalse(validator.isLinked(w, bob), "still linked");
        assertEq(_validate(w, _hit(), _pks(BOB_PK)), 1, "active session validates");
        assertEq(_validate(w, _hit(), _pks(APP_PK)), 1, "pending session validates");
        assertFalse(_isValid1271(w, h, BOB_PK, _wrapped(w, h)), "ERC-1271 accepts an unlinked identity");
        assertTrue(_isValid1271(w, h, ALICE_PK, _wrapped(w, h)), "the other identity stopped");

        bytes memory payload = _payload(GITHUB, BOB, ADD, _txData(w, _key(MALLORY_PK), _ph(_admin())));
        vm.expectRevert(abi.encodeWithSelector(IIdentityValidator.NotLinked.selector, w, bob));
        registry.addSessionByProof(GITHUB, V1, payload, _admin());
    }

    /// A re-link starts a new generation: sessions of the earlier link stay dead.
    function test_relinkDoesNotReviveSessions() public {
        address w = _claim();
        bytes32 bob = _identity(GITHUB, BOB);
        bytes32 h = keccak256("a message");
        _link(w, GITHUB, BOB, w, _key(BOB_PK), _admin());
        _addByProof(mallory, GITHUB, BOB, w, _key(MALLORY_PK), _admin());
        _root(w, address(validator), abi.encodeCall(IIdentityValidator.unlink, (bob)));
        _link(w, GITHUB, BOB, w, "", _admin());

        uint256[2] memory old = [BOB_PK, MALLORY_PK];
        for (uint256 i; i < old.length; ++i) {
            assertEq(_validate(w, _hit(), _pks(old[i])), 1, "an old session revived");
            assertFalse(_isValid1271(w, h, old[i], _wrapped(w, h)), "an old session signs ERC-1271");
        }
        vm.prank(w);
        validator.addSession(bob, _key(APP_PK), _admin());
        assertEq(_validate(w, _hit(), _pks(APP_PK)), 0, "a fresh session fails");
        assertTrue(_isValid1271(w, h, APP_PK, _wrapped(w, h)), "a fresh session fails ERC-1271");
    }

    /// An unlink keeps one identity and enough platforms for the threshold.
    function test_unlinkRefusals() public {
        address w = _claim();
        bytes32 bob = _identity(GITHUB, BOB);
        _unlinkReverts(w, bob, abi.encodeWithSelector(IIdentityValidator.NotLinked.selector, w, bob));
        bytes32 alice = _identity(X, ALICE);
        _unlinkReverts(w, alice, abi.encodeWithSelector(IIdentityValidator.LastIdentity.selector, alice));

        _link(w, GITHUB, BOB, w, "", _admin());
        _root(w, address(validator), abi.encodeCall(IIdentityValidator.setThreshold, (2)));
        _unlinkReverts(
            w, bob, abi.encodeWithSelector(IIdentityValidator.ThresholdTooHigh.selector, uint8(2), uint32(1))
        );
        assertTrue(validator.isLinked(w, bob), "unlinked anyway");
    }

    function _unlinkReverts(address w, bytes32 identity, bytes memory err) internal {
        _rootReverts(w, address(validator), abi.encodeCall(IIdentityValidator.unlink, (identity)), err);
    }

    /// An unlink may not take the account's last admin session with it.
    function test_unlinkOfTheLastAdminIsRefused() public {
        address w = _claim();
        bytes32 alice = _identity(X, ALICE);
        _link(w, GITHUB, BOB, w, _key(BOB_PK), _app());
        _unlinkReverts(w, alice, abi.encodeWithSelector(IIdentityValidator.LastAdmin.selector, alice));
    }

    /// An unlinked identity's admin sessions stop counting, even after a re-link or a revoke.
    function test_deadAdminSessionsDoNotCount() public {
        address w = _claim();
        bytes32 bob = _identity(GITHUB, BOB);
        bytes32 alice = _identity(X, ALICE);
        _link(w, GITHUB, BOB, w, _key(BOB_PK), _admin());
        _root(w, address(validator), abi.encodeCall(IIdentityValidator.unlink, (bob)));
        _link(w, GITHUB, BOB, w, "", _admin());
        _unlinkReverts(w, alice, abi.encodeWithSelector(IIdentityValidator.LastAdmin.selector, alice));

        vm.startPrank(w);
        validator.revokeSession(_key(BOB_PK));
        vm.expectRevert(IIdentityValidator.RootOperationRequired.selector);
        validator.revokeSession(_key(ALICE_PK));
        vm.stopPrank();
    }

    /// Admin and identity counts follow revokes, repeated links and unlinks; a threshold equal to what is left stays.
    function test_countsFollowRevokesLinksAndUnlinks() public {
        address w = _claim();
        bytes32 bob = _identity(GITHUB, BOB);
        bytes memory unlinkBob = abi.encodeCall(IIdentityValidator.unlink, (bob));
        _root(w, address(validator), abi.encodeCall(IIdentityValidator.setThreshold, (1)));

        // Bob's revoked admin session no longer counts as his.
        _link(w, GITHUB, BOB, w, _key(BOB_PK), _admin());
        vm.prank(w);
        validator.revokeSession(_key(BOB_PK));
        _root(w, address(validator), unlinkBob);

        // An unlink clears Bob's admin count, so a later link starts from none.
        _link(w, GITHUB, BOB, w, _key(APP_PK), _admin());
        _root(w, address(validator), unlinkBob);
        _link(w, GITHUB, BOB, w, "", _admin());
        _root(w, address(validator), unlinkBob);

        // A repeated link counts once, and an unlink takes its identity off the count.
        _link(w, X, ALICE, w, "", _admin());
        _rootReverts(
            w,
            address(validator),
            abi.encodeCall(IIdentityValidator.setThreshold, (2)),
            abi.encodeWithSelector(IIdentityValidator.ThresholdTooHigh.selector, uint8(2), uint32(1))
        );
    }

    /// `generationOf` tells a dead session from a live one, and a dead session's key can be added again.
    function test_aDeadSessionsKeyCanBeReused() public {
        address w = _claim();
        bytes32 bob = _identity(GITHUB, BOB);
        bytes32 alice = _identity(X, ALICE);
        _link(w, GITHUB, BOB, w, _key(BOB_PK), _admin());
        assertEq(validator.sessionOf(w, _key(BOB_PK)).generation, validator.generationOf(w, bob), "live");
        _root(w, address(validator), abi.encodeCall(IIdentityValidator.unlink, (bob)));
        assertNotEq(validator.sessionOf(w, _key(BOB_PK)).generation, validator.generationOf(w, bob), "dead");

        vm.startPrank(w);
        validator.addSession(alice, _key(BOB_PK), _app());
        vm.expectRevert(abi.encodeWithSelector(IIdentityValidator.SessionExists.selector, _key(BOB_PK)));
        validator.addSession(alice, _key(BOB_PK), _app());
        vm.stopPrank();
        assertEq(validator.sessionOf(w, _key(BOB_PK)).identity, alice, "not re-added");
        assertEq(_validate(w, _hit(), _pks(BOB_PK)), 0, "the re-added session fails");
    }

    /// A root operation queued before an unlink does not run after it.
    function test_anUnlinkSupersedesEarlierRootOperations() public {
        address w = _claim();
        _link(w, GITHUB, BOB, w, "", _admin());
        bytes memory early = abi.encodeCall(IIdentityValidator.setThreshold, (2));
        vm.prank(w);
        bytes32 opId = validator.queueRoot(address(validator), early);
        assertGt(validator.rootReadyAt(w, opId), 0, "not queued");
        _root(w, address(validator), abi.encodeCall(IIdentityValidator.unlink, (_identity(GITHUB, BOB))));
        assertEq(validator.rootReadyAt(w, opId), 0, "a superseded op reads as ready");
        vm.expectRevert(abi.encodeWithSelector(IIdentityValidator.RootSuperseded.selector, opId));
        validator.executeRoot(w, address(validator), early);
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

    /// `validUntil` is the last valid second, as the EntryPoint reads it.
    function test_erc1271WindowEndsWithTheEntryPoints() public {
        bytes32 h = keccak256("a message");
        address w = _claim();
        uint48 t = uint48(_now());
        vm.prank(w);
        validator.addSession(_identity(X, ALICE), _key(BOB_PK), IIdentityValidator.Policy(0, t + 20, true));
        vm.warp(t + 20);
        assertTrue(_isValid1271(w, h, BOB_PK, _wrapped(w, h)), "at validUntil");
        _handle(_signed(_op(w, 0, _hit()), _pks(BOB_PK)));
        vm.warp(t + 21);
        assertFalse(_isValid1271(w, h, BOB_PK, _wrapped(w, h)), "after validUntil");
        _refused(_signed(_op(w, 1, _hit()), _pks(BOB_PK)), "after validUntil");
    }

    /// `validAfter` is the last second before the window, as the EntryPoint reads it.
    function test_erc1271WindowStartsWithTheEntryPoints() public {
        bytes32 h = keccak256("a message");
        address w = _claim();
        uint48 t = uint48(_now());
        vm.prank(w);
        validator.addSession(_identity(X, ALICE), _key(BOB_PK), IIdentityValidator.Policy(t + 10, 0, true));
        vm.warp(t + 10);
        _refused(_signed(_op(w, 0, _hit()), _pks(BOB_PK)), "at validAfter");
        assertFalse(_isValid1271(w, h, BOB_PK, _wrapped(w, h)), "ERC-1271 accepts at validAfter");
        vm.warp(t + 11);
        assertTrue(_isValid1271(w, h, BOB_PK, _wrapped(w, h)), "after validAfter");
        _handle(_signed(_op(w, 0, _hit()), _pks(BOB_PK)));
    }

    /// EntryPoint v0.9 reads bit 47 of both bounds as a block-number range flag, so a session
    /// with `validAfter >= 2^47` and `validUntil == 0` is live at once: no policy may set the bit.
    function test_policyBoundsStayBelowBit47() public {
        address w = _claim();
        uint48 flag = uint48(1 << 47);
        IIdentityValidator.Policy[2] memory ps =
            [IIdentityValidator.Policy(flag, 0, false), IIdentityValidator.Policy(0, flag, false)];
        for (uint256 i; i < ps.length; ++i) {
            vm.prank(w);
            vm.expectRevert();
            validator.addSession(_identity(X, ALICE), _key(APP_PK), ps[i]);

            bytes memory payload = _payload(X, ALICE, ADD, _txData(w, _key(APP_PK), _ph(ps[i])));
            vm.expectRevert();
            registry.addSessionByProof(X, V1, payload, ps[i]);

            payload = _payload(X, ALICE, LINK, _txData(w, _key(APP_PK), _ph(ps[i])));
            vm.prank(w);
            vm.expectRevert();
            registry.linkIdentity(X, V1, payload, ps[i]);
        }
    }

    /// ERC-7739 `TypedDataSign`: the app's hash, nested under the account's domain, signed by an admin.
    function test_erc1271TypedDataSign() public {
        address w = _claim();
        vm.prank(w);
        validator.addSession(_identity(X, ALICE), _key(APP_PK), _app());
        vm.warp(_now() + 1);
        bytes32 app = keccak256("an app's domain separator");
        bytes32 contents = keccak256("a Mail");
        bytes32 h = keccak256(abi.encodePacked(hex"1901", app, contents));
        string memory descr = "Mail(address to)";

        assertEq(IWebWallet(w).isValidSignature(h, _typedSig(w, ALICE_PK, app, contents, descr)), bytes4(0x1626ba7e));
        assertEq(IWebWallet(w).isValidSignature(h, _typedSig(w, APP_PK, app, contents, descr)), bytes4(0xffffffff));
        bytes memory other = _typedSig(w, ALICE_PK, app, contents, descr);
        assertEq(IWebWallet(w).isValidSignature(keccak256("other"), other), bytes4(0xffffffff), "another hash");
        // An empty contents type gives a zero struct hash, which binds nothing.
        bytes memory unbound = abi.encodePacked(
            address(validator),
            _sigs(_pks(ALICE_PK), keccak256(abi.encodePacked(hex"1901", app, bytes32(0)))),
            app,
            contents,
            uint16(0)
        );
        assertEq(IWebWallet(w).isValidSignature(h, unbound), bytes4(0xffffffff), "zero struct hash");
    }

    function test_erc7739Probe() public {
        address w = _claim();
        bytes32 probe = 0x7739773977397739773977397739773977397739773977397739773977397739;
        assertEq(IWebWallet(w).isValidSignature(probe, ""), bytes4(0x77390001), "standard probe");
        assertEq(IWebWallet(w).isValidSignature(probe, abi.encodePacked(address(validator))), bytes4(0x77390001));
        assertEq(IWebWallet(w).isValidSignature(keccak256("other"), ""), bytes4(0xffffffff), "empty signature");
    }

    /// Both ERC-7739 forms follow the account's whole domain, salt included.
    function test_erc1271FollowsASaltedDomain() public {
        SaltedAccount a = new SaltedAccount(validator);
        vm.prank(address(a));
        validator.onInstall(abi.encode(X, ALICE));
        vm.prank(address(registry));
        validator.link(address(a), X, ALICE);
        vm.prank(address(a));
        validator.addSession(_identity(X, ALICE), _key(ALICE_PK), _admin());
        vm.warp(_now() + 1);

        bytes32 h = keccak256("a message");
        bytes32 separator = keccak256(
            abi.encode(
                keccak256(
                    "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract,bytes32 salt)"
                ),
                keccak256("Salted"),
                keccak256("1"),
                block.chainid,
                address(a),
                keccak256("salt")
            )
        );
        bytes32 signed = keccak256(abi.encodePacked(hex"1901", separator, keccak256(abi.encode(PERSONAL_SIGN, h))));
        bytes memory personal = abi.encodePacked(address(validator), _sigs(_pks(ALICE_PK), signed));
        assertEq(a.isValidSignature(h, personal), bytes4(0x1626ba7e), "PersonalSign");
        bytes memory unsalted = abi.encodePacked(address(validator), _sigs(_pks(ALICE_PK), _wrapped(address(a), h)));
        assertEq(a.isValidSignature(h, unsalted), bytes4(0xffffffff), "PersonalSign without the salt");

        bytes32 app = keccak256("an app's domain separator");
        bytes32 contents = keccak256("a Mail");
        bytes32 typed = keccak256(abi.encodePacked(hex"1901", app, contents));
        bytes memory sig = _typedSig(address(a), ALICE_PK, app, contents, "Mail(address to)");
        assertEq(a.isValidSignature(typed, sig), bytes4(0x1626ba7e), "TypedDataSign");
    }

    /// `pk`'s ERC-7739 `TypedDataSign` signature of `contents` for the app `app`, built from the spec.
    function _typedSig(address w, uint256 pk, bytes32 app, bytes32 contents, string memory descr)
        internal
        view
        returns (bytes memory)
    {
        (, string memory name, string memory version, uint256 chainId, address verifying, bytes32 salt,) =
            IWebWallet(w).eip712Domain();
        bytes32 typehash = keccak256(
            abi.encodePacked(
                "TypedDataSign(Mail contents,string name,string version,uint256 chainId,address verifyingContract,bytes32 salt)",
                descr
            )
        );
        bytes32 structHash = keccak256(
            abi.encode(typehash, contents, keccak256(bytes(name)), keccak256(bytes(version)), chainId, verifying, salt)
        );
        bytes memory sigs = _sigs(_pks(pk), keccak256(abi.encodePacked(hex"1901", app, structHash)));
        return abi.encodePacked(address(validator), sigs, app, contents, descr, uint16(bytes(descr).length));
    }

    function test_erc1271SignatureDoesNotReplayOnAnotherAccount() public {
        bytes32 h = keccak256("a message");
        address w = _claim();
        address w2 = factory.createWallet(GITHUB, BOB);
        _link(relayer, GITHUB, BOB, w2, _key(ALICE_PK), _admin());

        assertTrue(_isValid1271(w2, h, ALICE_PK, _wrapped(w2, h)), "control");
        assertFalse(_isValid1271(w2, h, ALICE_PK, _wrapped(w, h)), "replayed from another account");
    }
}
