// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";

import {FactoryDeployer} from "../FactoryDeployer.sol";
import {LibidFactory} from "../LibidFactory.sol";
import {Ping} from "./Create3.t.sol";

/// The bootstrap path: Arachnid's deterministic-deployment proxy is etched at
/// its well-known address, then the frozen impl and proxy init codes are
/// deployed through it as `ensure_factory` does on a real network.
contract FactoryDeployerTest is Test {
    /// The deployer key of this test's environment: the factory's owner from
    /// its first block.
    address internal constant ADMIN = address(0xAD1);

    /// The runtime bytecode at 0x4e59b4…956C on every chain that has the
    /// deterministic-deployment proxy. Calldata: 32-byte salt ++ init code;
    /// returns the 20-byte deployed address.
    bytes internal constant ARACHNID_RUNTIME =
        hex"7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe03601600081602082378035828234f58015156039578182fd5b8082525050506014600cf3";

    function setUp() public {
        vm.etch(FactoryDeployer.CREATE2_DEPLOYER, ARACHNID_RUNTIME);
    }

    function _deployVia(bytes memory data) internal returns (bool ok, address addr) {
        bytes memory ret;
        (ok, ret) = FactoryDeployer.CREATE2_DEPLOYER.call(data);
        if (ok && ret.length == 20) {
            // Casting to bytes20 is safe: the condition holds `ret` to 20 bytes.
            // forge-lint: disable-next-line(unsafe-typecast)
            addr = address(bytes20(ret));
        }
    }

    function _bootstrap() internal returns (address impl, address factoryAddr) {
        bool ok;
        (ok, impl) = _deployVia(FactoryDeployer.implDeployCalldata());
        assertTrue(ok, "impl deploy failed");
        (ok, factoryAddr) = _deployVia(FactoryDeployer.proxyDeployCalldata(ADMIN));
        assertTrue(ok, "proxy deploy failed");
    }

    function test_bootstrap_landsOnThePredictedAddresses() public {
        (address impl, address factoryAddr) = _bootstrap();
        assertEq(impl, FactoryDeployer.predictImplAddress());
        assertEq(factoryAddr, FactoryDeployer.predictFactoryAddress(ADMIN));
        assertGt(impl.code.length, 0);
        assertGt(factoryAddr.code.length, 0);
    }

    /// The proxy is initialized with its genesis admin the instant it exists,
    /// so nobody can front-run the initialization. A different admin is a
    /// different factory, at a different address.
    function test_bootstrap_ownerIsTheGenesisAdminAtomically() public {
        (, address factoryAddr) = _bootstrap();
        LibidFactory factory = LibidFactory(factoryAddr);
        assertEq(factory.owner(), ADMIN);

        // Nobody can re-initialize the proxy…
        vm.expectRevert();
        factory.initialize(address(this));

        assertTrue(FactoryDeployer.predictFactoryAddress(address(0xAD2)) != factoryAddr);
    }

    /// …and the raw implementation is bricked by _disableInitializers.
    function test_bootstrap_rawImplementationCannotBeInitialized() public {
        (address impl,) = _bootstrap();
        vm.expectRevert();
        LibidFactory(impl).initialize(address(this));
    }

    /// ERC1967Proxy's constructor refuses an implementation with no code, so
    /// the proxy cannot be deployed ahead of the impl.
    function test_bootstrap_proxyBeforeImplFails() public {
        (bool ok,) = _deployVia(FactoryDeployer.proxyDeployCalldata(ADMIN));
        assertFalse(ok);
    }

    function test_bootstrap_thenTheFactoryDeploys() public {
        (, address factoryAddr) = _bootstrap();
        LibidFactory factory = LibidFactory(factoryAddr);

        address predicted = factory.predict("libid.thing");
        vm.prank(ADMIN);
        assertEq(factory.deploy("libid.thing", type(Ping).creationCode), predicted);

        vm.prank(address(this)); // not the admin
        vm.expectRevert();
        factory.deploy("libid.other", type(Ping).creationCode);
    }
}
