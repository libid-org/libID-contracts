// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {AUTHORIZED_MODE, IWalletCore, IWebWallet} from "../IWebWallet.sol";
import {WalletBase} from "./WalletBase.sol";

/// From its constructor, delegatecalls `initialize` of an implementation with a genesis that is not its own.
contract ForeignProxy {
    constructor(address impl, bytes32 platformId, bytes32 idNode) {
        (bool ok, bytes memory err) =
            impl.delegatecall(abi.encodeCall(IWalletCore.initialize, (platformId, idNode, uint256(0))));
        if (!ok) {
            assembly {
                revert(add(err, 0x20), mload(err))
            }
        }
    }
}

/// @notice The genesis: written only by a factory proxy's construction, and the only bootstrap of a key by link.
/// forge-config: default.evm_version = "prague"
contract WalletGenesisTest is WalletBase {
    /// A1: a stranger's batch cannot bootstrap her own key on someone else's genesis.
    function test_theBootstrapIsTheGenesisIdentitysOnly() public {
        vm.prank(relayer);
        address w = factory.createWallet(X, ALICE, 0);
        bytes memory data = _signed(w, _pks(MALLORY_PK), _one(_linkX(w, X, MALLORY, _key(MALLORY_PK), _admin())));
        vm.prank(mallory);
        vm.expectRevert(IWebWallet.LinkSessionRefused.selector);
        IWebWallet(w).execute(AUTHORIZED_MODE, data);
        assertEq(IWebWallet(w).sessionOf(_key(MALLORY_PK)).identity, bytes32(0), "a stranger bootstrapped");
        assertFalse(IWebWallet(w).isLinked(_identity(X, MALLORY)), "a stranger linked");
    }

    /// Acceptance 8: `initialize` refused after construction, at the implementation, on an EOA, and in a
    /// proxy the factory did not deploy for that genesis.
    function test_initializeRefusals() public {
        address w = _claim();
        uint256 keyPk = 0x7702;
        address eoa = vm.addr(keyPk);
        vm.signAndAttachDelegation(impl1, keyPk);
        vm.prank(relayer);
        (bool ok,) = eoa.call("");
        ok;
        address[3] memory at = [w, impl1, eoa];
        for (uint256 i; i < at.length; ++i) {
            vm.prank(at[i], at[i]);
            vm.expectRevert(IWebWallet.InitializeRefused.selector);
            IWebWallet(at[i]).initialize(X, MALLORY, 0);
        }
        vm.expectRevert(IWebWallet.InitializeRefused.selector);
        new ForeignProxy(impl1, X, ALICE);
        (bytes32 p, bytes32 n,) = IWebWallet(w).genesisIdentity();
        assertEq(abi.encode(p, n), abi.encode(X, ALICE), "the genesis changed");
    }
}
