// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IIdentityValidator} from "../IIdentityValidator.sol";
import {WalletTestBase} from "./WalletTestBase.sol";

contract RegistryEntriesTest is WalletTestBase {
    /// Neither a stranger nor the account itself adds a session as if it came from a proof it submitted.
    function test_addSessionByRegistryIsRegistryOnly() public {
        address w = _claim();
        address[2] memory callers = [mallory, w];
        for (uint256 i; i < callers.length; ++i) {
            vm.prank(callers[i]);
            vm.expectRevert(abi.encodeWithSelector(IIdentityValidator.NotRegistry.selector, callers[i]));
            validator.addSessionByRegistry(w, _identity(X, ALICE), _key(MALLORY_PK), _admin(), false);
        }
        assertEq(validator.sessionOf(w, _key(MALLORY_PK)).identity, bytes32(0), "session added");
    }
}
