// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {WalletTestBase} from "./WalletTestBase.sol";

/// The wallet links its genesis identity when it is created, so a claim needs one proof.
contract GenesisLinkTest is WalletTestBase {
    function test_aClaimNeedsOnlyTheBindProof() public {
        vm.prank(relayer);
        address w = factory.createWallet(X, ALICE);
        bytes memory bind = _payload(X, ALICE, BIND, abi.encode(w));
        executor.bind(w, X, V1, bind);
        assertEq(identities.resolveId(ALICE), w, "not bound with one proof");
    }

    /// The genesis link proof still carries the first session while the wallet never had one.
    function test_theGenesisLinkProofAddsTheFirstSession() public {
        address w = _claim();
        assertLe(validator.sessionOf(w, _key(ALICE_PK)).activeAt, _now(), "the first session waits");
        assertEq(validator.linkedPlatforms(w), 1, "the genesis counted twice");
    }
}
