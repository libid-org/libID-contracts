// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Execution, IERC7579Execution, IERC7579Module} from "@openzeppelin/contracts/interfaces/draft-IERC7579.sol";

import {IIdentityValidator} from "../IIdentityValidator.sol";
import {WalletTestBase} from "./WalletTestBase.sol";

/// An account that reports the validator installed or not, as told.
contract InstallFlagAccount {
    bool public installed;

    function setInstalled(bool installed_) external {
        installed = installed_;
    }

    function isModuleInstalled(uint256, address, bytes calldata) external view returns (bool) {
        return installed;
    }
}

/// The validator's install hooks run only from the account's own install and uninstall.
contract ModuleHooksTest is WalletTestBase {
    /// One admin op that reaches `hook` on the validator through a nested `execute`, by each
    /// route to the account: its address, address(0), and a batch.
    function _nested(address w, bytes memory hook) internal view returns (bytes[3] memory) {
        bytes memory inner = _exec(address(validator), hook);
        Execution[] memory batch = new Execution[](1);
        batch[0] = Execution({target: w, value: 0, callData: inner});
        return [
            _exec(w, inner),
            _exec(address(0), inner),
            abi.encodeCall(IERC7579Execution.execute, (MODE_BATCH, abi.encode(batch)))
        ];
    }

    function _assertIntact(address w, string memory why) internal view {
        (bytes32 platformId, bytes32 idNode) = validator.genesisIdentity(w);
        assertEq(platformId, X, why);
        assertEq(idNode, ALICE, why);
        assertTrue(validator.isLinked(w, _identity(X, ALICE)), why);
        assertEq(validator.sessionOf(w, _key(ALICE_PK)).identity, _identity(X, ALICE), why);
    }

    function test_nestedInstallHookChangesNothing() public {
        address w = _claim();
        bytes[3] memory calls = _nested(w, abi.encodeCall(IERC7579Module.onInstall, (abi.encode(X, MALLORY))));
        for (uint256 i; i < calls.length; ++i) {
            _handle(_signed(_op(w, uint64(i), calls[i]), _pks(ALICE_PK)));
            _assertIntact(w, vm.toString(i));
        }
    }

    function test_nestedUninstallHookChangesNothing() public {
        address w = _claim();
        bytes[3] memory calls = _nested(w, abi.encodeCall(IERC7579Module.onUninstall, ("")));
        for (uint256 i; i < calls.length; ++i) {
            _handle(_signed(_op(w, uint64(i), calls[i]), _pks(ALICE_PK)));
            _assertIntact(w, vm.toString(i));
        }
        assertEq(_validate(w, _hit(), _pks(ALICE_PK)), 0, "the wallet stopped validating");
    }

    function test_hooksRefuseWhileInstalled() public {
        address w = _claim();
        vm.startPrank(w);
        vm.expectRevert(abi.encodeWithSelector(IIdentityValidator.InstallLive.selector, w));
        validator.onInstall(abi.encode(X, MALLORY));
        vm.expectRevert(abi.encodeWithSelector(IIdentityValidator.InstallLive.selector, w));
        validator.onUninstall("");
        vm.stopPrank();
        _assertIntact(w, "a refused hook changed state");
    }

    /// R6: state is keyed by install, so a reinstall starts empty.
    function test_reinstallDoesNotRestoreSessions() public {
        InstallFlagAccount a = new InstallFlagAccount();
        address w = address(a);
        vm.prank(w);
        validator.onInstall(abi.encode(X, ALICE));
        vm.prank(w);
        validator.addSession(_identity(X, ALICE), _key(ALICE_PK), _admin());

        vm.expectRevert(abi.encodeWithSelector(IIdentityValidator.NotInstalled.selector, address(this)));
        validator.onUninstall("");

        // The account drops the module before it calls the hook.
        a.setInstalled(false);
        vm.startPrank(w);
        validator.onUninstall("");
        assertFalse(validator.isLinked(w, _identity(X, ALICE)), "link kept by an uninstall");
        vm.expectRevert(abi.encodeWithSelector(IIdentityValidator.NotInstalled.selector, w));
        validator.onUninstall("");
        validator.onInstall(abi.encode(GITHUB, BOB));
        vm.stopPrank();
        assertEq(validator.sessionOf(w, _key(ALICE_PK)).identity, bytes32(0), "session came back");
        assertFalse(validator.isLinked(w, _identity(X, ALICE)), "link came back");
        assertTrue(validator.isLinked(w, _identity(GITHUB, BOB)), "the new genesis not linked");
        assertEq(_validate(w, _hit(), _pks(ALICE_PK)), 1, "old key validates");
    }
}
