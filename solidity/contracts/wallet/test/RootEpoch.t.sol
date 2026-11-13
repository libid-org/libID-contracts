// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IIdentityValidator} from "../IIdentityValidator.sol";
import {IWebWallet} from "../IWebWallet.sol";
import {WalletTestBase} from "./WalletTestBase.sol";

/// A queued root operation does not outlive the admin sessions that could have queued it.
contract RootEpochTest is WalletTestBase {
    /// Alice's wallet with a second admin key, which queues an upgrade through the EntryPoint.
    function _leakedUpgrade() internal returns (address w, bytes memory data, bytes32 opId) {
        w = _claim();
        vm.prank(w);
        validator.addSession(_identity(X, ALICE), _key(ALICE2_PK), _admin());
        vm.warp(_now() + 1);
        data = abi.encodeCall(IWebWallet.upgradeToAndCall, (_walletImpl(), ""));
        bytes memory queue = _exec(address(validator), abi.encodeCall(IIdentityValidator.queueRoot, (w, data)));
        _handle(_signed(_op(w, 0, queue), _pks(ALICE2_PK)));
        opId = keccak256(abi.encode(w, w, data));
        assertGt(validator.rootReadyAt(w, opId), 0, "not queued");
    }

    function _assertSuperseded(address w, bytes memory data, bytes32 opId) internal {
        vm.warp(_now() + 48 hours);
        assertEq(validator.rootReadyAt(w, opId), 0, "a superseded op reads as ready");
        vm.expectRevert(abi.encodeWithSelector(IIdentityValidator.RootSuperseded.selector, opId));
        validator.executeRoot(w, w, data);
    }

    function test_revokingTheQueuingAdminVoidsItsRootOperation() public {
        (address w, bytes memory data, bytes32 opId) = _leakedUpgrade();
        vm.prank(w);
        validator.revokeSession(_key(ALICE2_PK));
        _assertSuperseded(w, data, opId);
    }

    function test_aRootRevokeOfAnAdminVoidsEarlierRootOperations() public {
        (address w, bytes memory data, bytes32 opId) = _leakedUpgrade();
        _root(w, address(validator), abi.encodeCall(IIdentityValidator.revokeSession, (_key(ALICE2_PK))));
        vm.expectRevert(abi.encodeWithSelector(IIdentityValidator.RootSuperseded.selector, opId));
        validator.executeRoot(w, w, data);
    }

    /// Revoking an app session, or replacing a pending session by proof, keeps queued operations.
    function test_otherRevokesKeepQueuedRootOperations() public {
        (address w, bytes memory data, bytes32 opId) = _leakedUpgrade();
        vm.prank(w);
        validator.addSession(_identity(X, ALICE), _key(APP_PK), _app());
        vm.prank(w);
        validator.revokeSession(_key(APP_PK));
        _addByProof(relayer, X, ALICE, w, _key(BOB_PK), _admin());
        _addByProof(relayer, X, ALICE, w, _key(CAROL_PK), _admin());
        assertEq(validator.sessionOf(w, _key(BOB_PK)).identity, bytes32(0), "pending session not replaced");

        vm.warp(_now() + 48 hours);
        validator.executeRoot(w, w, data);
        assertEq(validator.rootReadyAt(w, opId), 0, "not executed");
    }
}
