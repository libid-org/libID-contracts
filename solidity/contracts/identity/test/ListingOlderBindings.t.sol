// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";

import {HandleVectors} from "../HandleVectors.sol";
import {IdentityNames} from "../IdentityNames.sol";
import {IdentityNodes} from "../IdentityNodes.sol";
import {CeremonyProofVerifier} from "../../ceremony/CeremonyProofVerifier.sol";
import {IPlatformVerifier} from "../../ceremony/IPlatformVerifier.sol";
import {IProofVerifier} from "../../ceremony/IProofVerifier.sol";
import {LegacyIdentityNames} from "./LegacyIdentityNames.sol";
import {StubPlatformVerifier} from "./StubPlatformVerifier.sol";

/// @notice Bindings written before the account lists existed, after the
///         upgrade that added them.
///
/// @dev The proxy starts on the layout that came before, takes three bindings
///      there, and is then upgraded onto the current implementation. Every
///      test runs against that proxy.
contract ListingOlderBindingsTest is Test {
    IdentityNames internal names;
    CeremonyProofVerifier internal proofVerifier;
    StubPlatformVerifier internal xVerifier;

    bytes32 internal constant X = HandleVectors.PLATFORM_X;
    uint16 internal constant V1 = 1;

    address internal owner = makeAddr("owner");
    address internal alice = makeAddr("alice");
    address internal bob = makeAddr("bob");
    address internal anyone = makeAddr("anyone");

    function setUp() public {
        LegacyIdentityNames legacy = new LegacyIdentityNames();
        address proxy =
            address(new ERC1967Proxy(address(legacy), abi.encodeCall(LegacyIdentityNames.initialize, (owner))));
        vm.prank(owner);
        LegacyIdentityNames(proxy).setPlatform(X, HandleVectors.rulesFor(X));
        vm.prank(alice);
        LegacyIdentityNames(proxy).bind(X, "123", "@Alice", 100, true);
        vm.prank(alice);
        LegacyIdentityNames(proxy).bind(X, "456", "second", 150, false);
        vm.prank(bob);
        LegacyIdentityNames(proxy).bind(X, "789", "bob", 200, false);

        IdentityNames impl = new IdentityNames();
        vm.prank(owner);
        UUPSUpgradeable(proxy).upgradeToAndCall(address(impl), "");
        names = IdentityNames(proxy);

        CeremonyProofVerifier pvImpl = new CeremonyProofVerifier();
        proofVerifier = CeremonyProofVerifier(
            address(new ERC1967Proxy(address(pvImpl), abi.encodeCall(CeremonyProofVerifier.initialize, (owner))))
        );
        xVerifier = new StubPlatformVerifier(X, 0);
        vm.startPrank(owner);
        names.setProofVerifier(IProofVerifier(address(proofVerifier)));
        proofVerifier.setVerifier(X, V1, IPlatformVerifier(address(xVerifier)));
        vm.stopPrank();
        vm.warp(1_000_000);
    }

    /// A claim through the ceremony path, made out to `who`.
    function _prove(address who, string memory userId, string memory handle, uint64 at) internal {
        xVerifier.set(userId, handle);
        xVerifier.setObservedAt(at);
        bytes memory payload = abi.encode(
            StubPlatformVerifier.StubPayload({
                ceremonyVersion: V1,
                operationDomain: keccak256(bytes("libid.claim-identity")),
                authorizationNonce: keccak256(abi.encode(who, userId, handle, at)),
                transactionData: abi.encode(who, uint256(0), address(0))
            })
        );
        vm.prank(who);
        names.claim(X, V1, payload, false);
    }

    function test_theBindingsSurviveAndTheListsStartEmpty() public view {
        assertEq(names.resolveHandle(X, "alice"), alice);
        assertEq(names.resolveId(X, "456"), alice);
        assertEq(names.primaryOf(alice, X), "alice");
        assertEq(names.accountCount(alice, X), 0);
        assertEq(names.accountCount(bob, X), 0);
    }

    function test_anyoneListsABindingFromWhatTheLogCarries() public {
        vm.prank(anyone);
        names.listAccount(X, "123", "alice");

        assertEq(names.accountCount(alice, X), 1);
        IdentityNames.Account memory a = names.accountsOf(alice, X, 0, 1)[0];
        assertEq(a.userId, "123");
        assertEq(a.handle, "alice");
        assertTrue(a.handleCurrent);
        assertEq(names.accountCount(anyone, X), 0, "listed under the wallet that proved it, not the caller");
    }

    function test_listingTakesTheHandleAsWrittenAndKeepsItNormalized() public {
        names.listAccount(X, "123", "@Alice");
        assertEq(names.accountsOf(alice, X, 0, 1)[0].handle, "alice");
    }

    function test_listingOneAccountLeavesTheOthersUnlisted() public {
        names.listAccount(X, "456", "second");
        assertEq(names.accountCount(alice, X), 1);
        assertEq(names.accountsOf(alice, X, 0, 1)[0].userId, "456");
        names.listAccount(X, "123", "alice");
        assertEq(names.accountCount(alice, X), 2);
    }

    function test_listingRefusesAHandleTheAccountDoesNotHold() public {
        bytes32 idKey = IdentityNodes.idNode(X, "123");
        bytes32 wrong = IdentityNodes.handleNode(X, "bob");
        vm.expectRevert(abi.encodeWithSelector(IdentityNames.HandleNotHeld.selector, idKey, wrong));
        names.listAccount(X, "123", "bob");
    }

    function test_listingRefusesAHandleThatDoesNotNormalize() public {
        bytes32 idKey = IdentityNodes.idNode(X, "123");
        vm.expectRevert(abi.encodeWithSelector(IdentityNames.HandleNotHeld.selector, idKey, bytes32(0)));
        names.listAccount(X, "123", "ali ce");
    }

    function test_listingRefusesAnAccountNobodyProved() public {
        bytes32 idKey = IdentityNodes.idNode(X, "999");
        vm.expectRevert(abi.encodeWithSelector(IdentityNames.UnboundAccount.selector, idKey));
        names.listAccount(X, "999", "ghost");
    }

    function test_listingTwiceIsRefused() public {
        names.listAccount(X, "123", "alice");
        bytes32 idKey = IdentityNodes.idNode(X, "123");
        vm.expectRevert(abi.encodeWithSelector(IdentityNames.AccountAlreadyListed.selector, idKey));
        names.listAccount(X, "123", "alice");
    }

    function test_listingRefusesAnUnknownPlatform() public {
        bytes32 nowhere = keccak256("nowhere");
        vm.expectRevert(abi.encodeWithSelector(IdentityNames.UnknownPlatform.selector, nowhere));
        names.listAccount(nowhere, "123", "alice");
    }

    function test_theNextProofListsAnOlderBindingByItself() public {
        _prove(alice, "123", "alice", 300);

        assertEq(names.accountCount(alice, X), 1);
        IdentityNames.Account memory a = names.accountsOf(alice, X, 0, 1)[0];
        assertEq(a.userId, "123");
        assertEq(a.handle, "alice");
        assertTrue(a.handleCurrent);
    }

    function test_aRenameOfAnOlderBindingListsItOnce() public {
        _prove(alice, "123", "alicia", 300);

        assertEq(names.accountCount(alice, X), 1);
        assertEq(names.accountsOf(alice, X, 0, 1)[0].handle, "alicia");
        assertEq(names.resolveHandle(X, "alice"), address(0), "the old handle is retired as before");
    }

    function test_anOlderBindingProvedFromANewWalletIsListedThereOnly() public {
        _prove(bob, "123", "alice", 300);

        assertEq(names.accountCount(alice, X), 0);
        assertEq(names.accountCount(bob, X), 1);
        assertEq(names.accountsOf(bob, X, 0, 1)[0].userId, "123");
        assertEq(names.resolveId(X, "123"), bob);
    }

    function test_anOlderBindingListedByHandCannotBeListedAgainByItsNextProof() public {
        names.listAccount(X, "123", "alice");
        _prove(alice, "123", "alicia", 300);

        assertEq(names.accountCount(alice, X), 1);
        assertEq(names.accountsOf(alice, X, 0, 1)[0].handle, "alicia");
    }
}
