// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {WalletTestBase} from "./WalletTestBase.sol";

/// Every address the wallet stack is built on can be read and checked before deployment.
contract WalletWiringTest is WalletTestBase {
    function _reads(address on, string memory getter) internal view returns (address) {
        (bool ok, bytes memory ret) = on.staticcall(abi.encodeWithSignature(getter));
        assertTrue(ok && ret.length == 32, getter);
        return abi.decode(ret, (address));
    }

    function test_registryReportsItsProofVerifier() public view {
        assertEq(_reads(address(registry), "proofVerifier()"), address(proofVerifier));
    }

    function test_executorReportsItsRegistryEscrowAndValidator() public view {
        assertEq(_reads(address(executor), "identityRegistry()"), address(identities));
        assertEq(_reads(address(executor), "handleEscrow()"), address(escrow));
        assertEq(_reads(address(executor), "identityValidator()"), address(validator));
    }

    function test_walletImplementationReportsItsModules() public view {
        assertEq(_reads(walletImpl, "identityValidator()"), address(validator));
        assertEq(_reads(walletImpl, "claimExecutor()"), address(executor));
    }

    function test_factoryReportsItsImplementation() public view {
        assertEq(_reads(address(factory), "walletImplementation()"), walletImpl);
    }
}
