// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts/proxy/utils/UUPSUpgradeable.sol";

import {LibidFactory} from "../../factory/LibidFactory.sol";
import {IWalletFactory} from "../IWalletFactory.sol";
import {WalletTestBase} from "./WalletTestBase.sol";

/// The factory proxy deployed under a `LibidFactory` name, as a deployment does.
contract WalletFactoryDeployTest is WalletTestBase {
    LibidFactory internal names;

    function setUp() public override {
        super.setUp();
        names = LibidFactory(
            address(new ERC1967Proxy(address(new LibidFactory()), abi.encodeCall(LibidFactory.initialize, (owner))))
        );
    }

    function test_aFixReachesNewWalletsAtTheirPromisedAddress() public {
        bytes memory proxy = abi.encodePacked(
            type(ERC1967Proxy).creationCode,
            abi.encode(_factoryImpl(walletImpl), abi.encodeCall(IWalletFactory.initialize, (owner)))
        );
        vm.prank(owner);
        IWalletFactory named = IWalletFactory(names.deploy("WalletFactory", proxy));
        assertEq(address(named), names.predict("WalletFactory"), "not at its name");
        address promised = named.walletAddress(X, ALICE);

        address fixedImpl = _walletImpl();
        address fixedFactory = _factoryImpl(fixedImpl);
        vm.prank(owner);
        UUPSUpgradeable(address(named)).upgradeToAndCall(fixedFactory, "");

        address w = named.createWallet(X, ALICE);
        assertEq(w, promised, "moved");
        assertEq(address(uint160(uint256(vm.load(w, IMPL_SLOT)))), fixedImpl, "new wallet runs the old implementation");
    }
}
