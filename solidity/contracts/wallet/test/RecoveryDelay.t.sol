// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IIdentityValidator} from "../IIdentityValidator.sol";
import {WalletTestBase} from "./WalletTestBase.sol";

/// The account changes its recovery delay, up or down, only by root operation, after the current delay.
contract RecoveryDelayTest is WalletTestBase {
    function _setDelay(uint48 delay) internal pure returns (bytes memory) {
        return abi.encodeCall(IIdentityValidator.setRecoveryDelay, (delay));
    }

    /// Queues `setRecoveryDelay(delay)` and executes it once `wait` has passed, not a second earlier.
    function _change(address w, uint48 delay, uint48 wait) internal {
        vm.prank(w);
        vm.expectRevert(IIdentityValidator.RootOperationRequired.selector);
        validator.setRecoveryDelay(delay);

        vm.prank(w);
        bytes32 opId = validator.queueRoot(address(validator), _setDelay(delay));
        assertEq(validator.rootReadyAt(w, opId), _now() + wait, "not ready after the current delay");
        vm.warp(_now() + wait - 1);
        vm.expectRevert(abi.encodeWithSelector(IIdentityValidator.RootNotReady.selector, opId));
        validator.executeRoot(w, address(validator), _setDelay(delay));
        vm.warp(_now() + 1);
        validator.executeRoot(w, address(validator), _setDelay(delay));
        assertEq(validator.recoveryDelay(w), delay, "not changed");
    }

    function test_aRootOperationChangesTheDelayAfterTheCurrentOne() public {
        address w = _claim();
        _change(w, 30 days, 48 hours);
        _change(w, 72 hours, 30 days);
    }

    function test_aRootOperationKeepsTheBounds() public {
        address w = _claim();
        uint48 max = validator.MAX_RECOVERY_DELAY();
        _rootReverts(
            w,
            address(validator),
            _setDelay(47 hours),
            abi.encodeWithSelector(IIdentityValidator.RecoveryDelayTooShort.selector, 47 hours)
        );
        _rootReverts(
            w,
            address(validator),
            _setDelay(max + 1),
            abi.encodeWithSelector(IIdentityValidator.RecoveryDelayTooLong.selector, max + 1)
        );
        _root(w, address(validator), _setDelay(max));
        assertEq(validator.recoveryDelay(w), max, "a root raise");
    }
}
