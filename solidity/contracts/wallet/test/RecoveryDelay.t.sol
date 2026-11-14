// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IIdentityValidator} from "../IIdentityValidator.sol";
import {WalletTestBase} from "./WalletTestBase.sol";

/// The account raises its recovery delay at once and lowers it only by root operation.
contract RecoveryDelayTest is WalletTestBase {
    function _setDelay(uint48 delay) internal pure returns (bytes memory) {
        return abi.encodeCall(IIdentityValidator.setRecoveryDelay, (delay));
    }

    function test_aRootOperationLowersTheDelayAfterTheCurrentOne() public {
        address w = _claim();
        vm.prank(w);
        validator.setRecoveryDelay(30 days);
        vm.prank(w);
        vm.expectRevert(IIdentityValidator.RootOperationRequired.selector);
        validator.setRecoveryDelay(72 hours);

        vm.prank(w);
        bytes32 opId = validator.queueRoot(address(validator), _setDelay(72 hours));
        assertEq(validator.rootReadyAt(w, opId), _now() + 30 days, "the lowering waits the old delay");
        vm.warp(_now() + 30 days - 1);
        vm.expectRevert(abi.encodeWithSelector(IIdentityValidator.RootNotReady.selector, opId));
        validator.executeRoot(w, address(validator), _setDelay(72 hours));
        vm.warp(_now() + 1);
        validator.executeRoot(w, address(validator), _setDelay(72 hours));
        assertEq(validator.recoveryDelay(w), 72 hours, "not lowered");
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
