// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Initializable} from "@openzeppelin/contracts/proxy/utils/Initializable.sol";

import {Create3} from "../../factory/Create3.sol";
import {IWalletRegistry} from "../IWalletRegistry.sol";
import {IWebWallet} from "../IWebWallet.sol";
import {WalletTestBase} from "./WalletTestBase.sol";

/// @notice R1: addresses fixed by identity alone; genesis initialized in the creating call.
contract WalletFactoryTest is WalletTestBase {
    function test_addressIsCreate3OfTheDerivedSalt() public {
        for (uint256 index; index < 3; ++index) {
            address expected = Create3.addressOf(keccak256(abi.encode(X, ALICE, index)), address(factory));
            assertEq(factory.walletAddress(X, ALICE, index), expected, "salt is not (platformId, idNode, index)");
        }
        assertTrue(factory.walletAddress(X, ALICE, 0) != factory.walletAddress(GITHUB, ALICE, 0), "platform");
        address here = factory.walletAddress(X, ALICE, 0);
        vm.chainId(8453);
        assertEq(factory.walletAddress(X, ALICE, 0), here, "the address depends on the chain");
    }

    function test_createWalletInitializesTheGenesisIdentityInTheSameCall() public {
        vm.prank(mallory);
        address w = factory.createWallet(X, ALICE, 0);

        assertEq(w, factory.walletAddress(X, ALICE, 0), "not at the predicted address");
        (bytes32 platformId, bytes32 idNode) = validator.genesisIdentity(w);
        assertEq(platformId, X, "genesis platform");
        assertEq(idNode, ALICE, "genesis id");
        assertTrue(IWebWallet(w).isModuleInstalled(1, address(validator), ""), "validator not installed");
        assertFalse(validator.isLinked(w, _identity(X, ALICE)), "linked without a proof");
        assertFalse(validator.hadSession(w), "a session at creation");
        assertEq(validator.threshold(w), 1, "default threshold");
        assertEq(address(IWebWallet(w).entryPoint()), EP, "EntryPoint v0.9");

        vm.expectRevert(Initializable.InvalidInitialization.selector);
        IWebWallet(w).initialize(abi.encode(X, MALLORY));
    }

    function test_implementationCannotBeInitialized() public {
        vm.expectRevert(Initializable.InvalidInitialization.selector);
        IWebWallet(walletImpl).initialize(abi.encode(X, ALICE));
    }

    /// Taking the address first changes nothing, and a foreign proof cannot link first.
    function test_genesisFrontRunGainsNothing() public {
        vm.prank(mallory);
        address w = factory.createWallet(X, ALICE, 0);
        vm.expectRevert();
        factory.createWallet(X, ALICE, 0);

        bytes memory payload = _payload(X, MALLORY, LINK, _txData(w, _key(MALLORY_PK), _ph(_admin())));
        vm.prank(mallory);
        vm.expectRevert(abi.encodeWithSelector(IWalletRegistry.NotWallet.selector, w, mallory));
        registry.linkIdentity(X, V1, payload, _admin());

        _link(relayer, X, ALICE, w, _key(ALICE_PK), _admin());
        assertTrue(validator.isLinked(w, _identity(X, ALICE)), "alice could not link");
        assertFalse(validator.isLinked(w, _identity(X, MALLORY)), "mallory linked");
    }

    /// R1: an earlier prediction still deploys after the factory's code changes.
    function test_factoryUpgradeKeepsEveryPrediction() public {
        address predicted = factory.walletAddress(X, ALICE, 0);
        address impl2 = deployCode("WebWallet.sol:WebWallet", abi.encode(address(validator)));
        vm.store(address(factory), IMPL_SLOT, bytes32(uint256(uint160(_factoryImpl(impl2)))));

        assertEq(factory.walletAddress(X, ALICE, 0), predicted, "prediction moved");
        address w = factory.createWallet(X, ALICE, 0);
        assertEq(w, predicted, "deployed elsewhere");
        assertEq(address(uint160(uint256(vm.load(w, IMPL_SLOT)))), impl2, "not the new implementation");
        (, bytes32 idNode) = validator.genesisIdentity(w);
        assertEq(idNode, ALICE, "genesis lost");
    }
}
