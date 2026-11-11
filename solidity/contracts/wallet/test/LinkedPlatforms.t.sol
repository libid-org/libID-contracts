// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {WalletTestBase} from "./WalletTestBase.sol";

/// `linkedPlatforms` counts distinct platforms, through links and unlinks.
contract LinkedPlatformsTest is WalletTestBase {
    function test_linkedPlatformsCountsDistinctPlatforms() public {
        address w = _claim();
        assertEq(validator.linkedPlatforms(w), 1, "genesis");
        _link(w, X, MALLORY, w, "", _admin());
        assertEq(validator.linkedPlatforms(w), 1, "two X identities are one platform");
        _link(w, GOOGLE, CAROL, w, "", _admin());
        assertEq(validator.linkedPlatforms(w), 2, "X and Google");
        _root(w, address(validator), abi.encodeCall(validator.unlink, (_identity(GOOGLE, CAROL))));
        assertEq(validator.linkedPlatforms(w), 1, "Google unlinked");
    }
}
