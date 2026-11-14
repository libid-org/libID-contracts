// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Initializable} from "@openzeppelin/contracts/proxy/utils/Initializable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts/proxy/utils/UUPSUpgradeable.sol";
import {OwnableUpgradeable} from "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";

import {Create3} from "../../factory/Create3.sol";
import {IWalletFactory} from "../IWalletFactory.sol";
import {IWalletRegistry} from "../IWalletRegistry.sol";
import {IWebWallet} from "../IWebWallet.sol";
import {WalletTestBase} from "./WalletTestBase.sol";

/// @notice R1: addresses fixed by identity alone; genesis linked in the creating call.
contract WalletFactoryTest is WalletTestBase {
    function test_addressIsCreate3OfTheDerivedSalt() public {
        address expected = Create3.addressOf(keccak256(abi.encode(X, ALICE)), address(factory));
        assertEq(factory.walletAddress(X, ALICE), expected, "salt is not (platformId, idNode)");
        assertTrue(factory.walletAddress(X, ALICE) != factory.walletAddress(GITHUB, ALICE), "platform");
        address here = factory.walletAddress(X, ALICE);
        vm.chainId(8453);
        assertEq(factory.walletAddress(X, ALICE), here, "the address depends on the chain");
    }

    function test_createWalletLinksTheGenesisIdentityInTheSameCall() public {
        vm.prank(mallory);
        address w = factory.createWallet(X, ALICE);

        assertEq(w, factory.walletAddress(X, ALICE), "not at the predicted address");
        (bytes32 platformId, bytes32 idNode) = validator.genesisIdentity(w);
        assertEq(platformId, X, "genesis platform");
        assertEq(idNode, ALICE, "genesis id");
        assertTrue(IWebWallet(w).isModuleInstalled(1, address(validator), ""), "validator not installed");
        assertTrue(validator.isLinked(w, _identity(X, ALICE)), "genesis not linked");
        assertEq(validator.linkedPlatforms(w), 1, "genesis platform not counted");
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
        address w = factory.createWallet(X, ALICE);
        vm.recordLogs();
        assertEq(factory.createWallet(X, ALICE), w, "a second call moved the wallet");
        assertEq(vm.getRecordedLogs().length, 0, "a second call emitted");

        bytes memory payload = _payload(X, MALLORY, LINK, _txData(w, _key(MALLORY_PK), _ph(_admin())));
        vm.prank(mallory);
        vm.expectRevert(abi.encodeWithSelector(IWalletRegistry.NotWallet.selector, w, mallory));
        registry.linkIdentity(X, V1, payload, _admin());

        _link(w, X, ALICE, w, _key(ALICE_PK), _admin());
        assertTrue(validator.isLinked(w, _identity(X, ALICE)), "alice could not link");
        assertFalse(validator.isLinked(w, _identity(X, MALLORY)), "mallory linked");
    }

    /// R1: the address is a function of (factory proxy, platformId, idNode) only, not of
    ///     the chain or the wallet implementation the factory deploys.
    function test_anUpgradeReachesNewWalletsAtTheirPromisedAddress() public {
        address promised = factory.walletAddress(X, ALICE);
        address impl2 = _walletImpl();
        address factory2 = _factoryImpl(impl2);
        vm.prank(owner);
        UUPSUpgradeable(address(factory)).upgradeToAndCall(factory2, "");
        vm.chainId(8453);

        assertEq(factory.walletImplementation(), impl2, "not upgraded");
        assertEq(factory.walletAddress(X, ALICE), promised, "prediction moved");
        address w = factory.createWallet(X, ALICE);
        assertEq(w, promised, "deployed elsewhere");
        assertEq(address(uint160(uint256(vm.load(w, IMPL_SLOT)))), impl2, "not the new implementation");
        (, bytes32 idNode) = validator.genesisIdentity(w);
        assertEq(idNode, ALICE, "genesis lost");
    }

    function test_onlyTheOwnerUpgradesAndOwnershipStays() public {
        address impl = _factoryImpl(_walletImpl());
        vm.prank(mallory);
        vm.expectRevert(abi.encodeWithSelector(OwnableUpgradeable.OwnableUnauthorizedAccount.selector, mallory));
        UUPSUpgradeable(address(factory)).upgradeToAndCall(impl, "");

        vm.prank(owner);
        vm.expectRevert(IWalletFactory.RenounceDisabled.selector);
        OwnableUpgradeable(address(factory)).renounceOwnership();

        vm.expectRevert(Initializable.InvalidInitialization.selector);
        IWalletFactory(impl).initialize(owner);
    }
}
