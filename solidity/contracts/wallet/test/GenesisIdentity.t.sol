// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IIdentityValidator} from "../IIdentityValidator.sol";
import {WalletTestBase} from "./WalletTestBase.sol";

/// The identity a wallet's factory address is derived from stays linked to it.
contract GenesisIdentityTest is WalletTestBase {
    function test_theGenesisIdentityCannotBeUnlinked() public {
        address w = _claim();
        _link(w, GITHUB, BOB, w, _key(BOB_PK), _admin());
        bytes32 alice = _identity(X, ALICE);
        _rootReverts(
            w,
            address(validator),
            abi.encodeCall(IIdentityValidator.unlink, (alice)),
            abi.encodeWithSelector(IIdentityValidator.GenesisIdentity.selector, alice)
        );
        assertTrue(validator.isLinked(w, alice), "genesis unlinked");

        _root(w, address(validator), abi.encodeCall(IIdentityValidator.unlink, (_identity(GITHUB, BOB))));
        assertFalse(validator.isLinked(w, _identity(GITHUB, BOB)), "another identity stays unlinkable");
    }
}
