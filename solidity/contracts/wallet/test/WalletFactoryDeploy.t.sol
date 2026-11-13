// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Create3} from "../../factory/Create3.sol";
import {IIdentityValidator} from "../IIdentityValidator.sol";
import {IWalletFactory} from "../IWalletFactory.sol";
import {IWebWallet} from "../IWebWallet.sol";
import {WalletTestBase} from "./WalletTestBase.sol";

/// The deployment order: the registry's validator names the factory proxy by its `LibidFactory` name before the
/// proxy exists, and installs only on that factory's wallets.
contract WalletFactoryDeployTest is WalletTestBase {
    function test_theValidatorNamesTheFactoryBeforeItIsDeployed() public {
        assertEq(address(factory), names.predict(FACTORY_NAME), "the factory is not at its name");
        assertEq(validator.walletFactory(), address(factory), "the validator names another factory");
        address w = factory.createWallet(X, ALICE);
        assertTrue(IWebWallet(w).isModuleInstalled(1, address(validator), ""), "not installed");
    }

    /// A stack whose factory landed at another name than its validator was told cannot create wallets.
    function test_aFactoryAtAnotherAddressCannotCreateWallets() public {
        IIdentityValidator v = IIdentityValidator(_newRegistry(names.predict("WalletFactory-a")).identityValidator());
        address impl = deployCode("WebWallet.sol:WebWallet", abi.encode(address(v)));
        bytes memory proxy = _factoryProxy(_factoryImpl(impl));
        vm.prank(owner);
        IWalletFactory wrong = IWalletFactory(names.deploy("WalletFactory-b", proxy));
        vm.expectRevert(Create3.TargetDeployFailed.selector);
        wrong.createWallet(X, ALICE);

        // The deployed validator refuses that wallet's install.
        address w = wrong.walletAddress(X, ALICE);
        bytes memory err =
            abi.encodeWithSelector(IIdentityValidator.NotFactoryWallet.selector, w, factory.walletAddress(X, ALICE));
        vm.prank(w);
        vm.expectRevert(err);
        validator.onInstall(abi.encode(X, ALICE));
    }
}
