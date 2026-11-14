// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {WalletTestBase} from "./WalletTestBase.sol";

/// The wallet links its genesis identity when it is created.
contract GenesisLinkTest is WalletTestBase {
    function test_creationLinksTheGenesisIdentity() public {
        vm.prank(relayer);
        address w = factory.createWallet(X, ALICE);
        assertTrue(validator.isLinked(w, _identity(X, ALICE)), "genesis not linked");
        assertFalse(validator.hadSession(w), "a session without a proof");
    }

    /// The genesis link proof still carries the first session while the wallet never had one.
    function test_theGenesisLinkProofAddsTheFirstSession() public {
        address w = _claim();
        assertLe(validator.sessionOf(w, _key(ALICE_PK)).activeAt, _now(), "the first session waits");
        assertEq(validator.linkedPlatforms(w), 1, "the genesis counted twice");
    }
}
