// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IIdentityValidator} from "../IIdentityValidator.sol";
import {WalletTestBase} from "./WalletTestBase.sol";

/// A root operation freezes recovery by proof for one identity, and unfreezes it.
contract RecoveryFrozenTest is WalletTestBase {
    function _freeze(bytes32 identity, bool frozen) internal pure returns (bytes memory) {
        return abi.encodeCall(IIdentityValidator.setRecoveryFrozen, (identity, frozen));
    }

    function test_aFrozenIdentityTakesNoSessionByProof() public {
        address w = _claim();
        _link(w, GITHUB, BOB, w, "", _admin());
        bytes32 bob = _identity(GITHUB, BOB);
        vm.prank(w);
        validator.addSession(bob, _key(BOB_PK), _app());

        vm.prank(w);
        vm.expectRevert(IIdentityValidator.RootOperationRequired.selector);
        validator.setRecoveryFrozen(bob, true);
        _root(w, address(validator), _freeze(bob, true));
        assertTrue(validator.recoveryFrozen(w, bob), "not frozen");
        assertFalse(validator.recoveryFrozen(w, _identity(X, ALICE)), "another identity frozen");

        bytes memory payload = _payload(GITHUB, BOB, ADD, _txData(w, _key(MALLORY_PK), _ph(_admin())));
        vm.expectRevert(abi.encodeWithSelector(IIdentityValidator.RecoveryFrozen.selector, bob));
        registry.addSessionByProof(GITHUB, V1, payload, _admin());
        _addByProof(mallory, X, ALICE, w, _key(ALICE2_PK), _admin());

        _handle(_signed(_op(w, 0, _hit()), _pks(BOB_PK)));
        assertEq(target.calls(), 1, "an existing session of the frozen identity");

        _root(w, address(validator), _freeze(bob, false));
        assertFalse(validator.recoveryFrozen(w, bob), "still frozen");
        _addByProof(mallory, GITHUB, BOB, w, _key(MALLORY_PK), _admin());
        assertEq(validator.sessionOf(w, _key(MALLORY_PK)).identity, bob, "no session after the unfreeze");
    }
}
