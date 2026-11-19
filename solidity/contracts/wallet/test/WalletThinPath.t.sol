// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {AUTHORIZED_MODE, IIdentityAdmin, IWebWallet} from "../IWebWallet.sol";
import {WalletBase} from "./WalletBase.sol";

/// @notice Stub proof, published release, one `createAndExecute` that bootstraps the genesis session, then that
///         session's batch and UserOperation run.
contract WalletThinPathTest is WalletBase {
    function test_createAndExecuteBootstrapsTheGenesisSession() public {
        address w = factory.walletAddress(X, ALICE, 0);
        assertEq(w.code.length, 0, "deployed early");
        // K signs the batch that links K: the genesis bootstrap.
        bytes memory link = _linkPayload(w, X, ALICE, _key(ALICE_PK), _admin());
        bytes memory calls = _two(_linkWith(w, X, link, _admin()), _hitX());
        bytes memory data = _signedAt(w, 1, _pks(ALICE_PK), calls, false);
        vm.prank(relayer);
        assertEq(factory.createAndExecute(X, ALICE, 0, AUTHORIZED_MODE, data), w, "wallet address");

        assertEq(target.calls(), 1, "the bootstrap batch did not run");
        assertEq(target.last(), w, "not from the wallet");
        assertTrue(registry.spentDigests(_digestOf(link)), "link digest unspent");
        assertTrue(IWebWallet(w).isLinked(_identity(X, ALICE)), "not linked");
        IIdentityAdmin.Session memory k = IWebWallet(w).sessionOf(_key(ALICE_PK));
        assertTrue(k.admin && !k.byProof && k.identity == _identity(X, ALICE), "K is not the genesis session");
        (address impl, uint64 version) = IWebWallet(w).release();
        assertEq(abi.encode(impl, version), abi.encode(impl1, uint64(1)), "release");

        _run(w, _one(_hitX()));
        assertEq(target.calls(), 2, "the session's batch did not run");
        vm.deal(w, 1 ether);
        _handle(_ops(_signOp(_op(w, _hitCall()), 1, _pks(ALICE_PK))));
        assertEq(target.calls(), 3, "the session's UserOperation did not run");
    }
}
