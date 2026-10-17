// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

import {IdentityRegistry} from "../IdentityRegistry.sol";
import {IIdentityRegistry} from "../IIdentityRegistry.sol";
import {IPlatformVerifier} from "../../ceremony/IPlatformVerifier.sol";
import {IProofVerifier} from "../../ceremony/IProofVerifier.sol";
import {CeremonyProfile} from "../../ceremony/CeremonyProfile.sol";
import {CeremonyProofVerifier} from "../../ceremony/CeremonyProofVerifier.sol";
import {StubPlatformVerifier} from "./StubPlatformVerifier.sol";

/// A deployed registry knows the three platforms the ceremony profiles name, with
/// their tags, and a registered verifier makes each resolvable.
contract IdentityDeployWiringTest is Test {
    IdentityRegistry internal registry;
    CeremonyProofVerifier internal proofVerifier;
    address internal owner = makeAddr("owner");

    function setUp() public {
        IdentityRegistry impl = new IdentityRegistry();
        registry = IdentityRegistry(
            address(new ERC1967Proxy(address(impl), abi.encodeCall(IdentityRegistry.initialize, (owner))))
        );
        CeremonyProofVerifier pvImpl = new CeremonyProofVerifier();
        proofVerifier = CeremonyProofVerifier(
            address(new ERC1967Proxy(address(pvImpl), abi.encodeCall(CeremonyProofVerifier.initialize, (owner))))
        );
        vm.prank(owner);
        registry.setProofVerifier(IProofVerifier(address(proofVerifier)));
    }

    /// An unknown platform reverts rather than hashing under a default tag.
    function test_anUnknownPlatformHasNoTag() public {
        bytes32 nowhere = keccak256("nowhere");
        vm.expectRevert(abi.encodeWithSelector(CeremonyProfile.UnknownPlatform.selector, nowhere));
        this.handleTagForExternally(nowhere);
    }

    /// The ceremony profiles sit below identity, so they keep their own copy
    /// of the registry's error; the two are one error.
    function test_everyUnknownPlatformIsTheRegistrysError() public pure {
        assertEq(CeremonyProfile.UnknownPlatform.selector, IIdentityRegistry.UnknownPlatform.selector);
    }

    /// `handleTag` is an internal library call, which `expectRevert` cannot see.
    /// This gives it a call boundary to watch.
    function handleTagForExternally(bytes32 platformId) external pure returns (bytes memory) {
        return CeremonyProfile.handleTag(platformId);
    }

    /// A platform the profiles name answers "nobody" before its verifier is
    /// registered and after; only a registered verifier lets it bind.
    function test_aKnownPlatformResolvesWithOrWithoutAVerifier() public {
        assertEq(registry.resolveHandle(CeremonyProfile.PLATFORM_GOOGLE, "nobody@example.com"), address(0));
        assertFalse(registry.acceptsBindings(CeremonyProfile.PLATFORM_GOOGLE));

        vm.startPrank(owner);
        address x = _wireIdentityPlatform(CeremonyProfile.PLATFORM_X);
        address gh = _wireIdentityPlatform(CeremonyProfile.PLATFORM_GITHUB);
        address g = _wireIdentityPlatform(CeremonyProfile.PLATFORM_GOOGLE);
        vm.stopPrank();

        // The version a deployment registers its first verifier under.
        uint16 v = 1;
        assertEq(address(proofVerifier.verifierOf(CeremonyProfile.PLATFORM_X, v)), x);
        assertEq(address(proofVerifier.verifierOf(CeremonyProfile.PLATFORM_GITHUB, v)), gh);
        assertEq(address(proofVerifier.verifierOf(CeremonyProfile.PLATFORM_GOOGLE, v)), g);

        assertTrue(registry.acceptsBindings(CeremonyProfile.PLATFORM_GOOGLE));
        assertEq(registry.resolveHandle(CeremonyProfile.PLATFORM_X, "nobody"), address(0));
        assertEq(registry.resolveHandle(CeremonyProfile.PLATFORM_GITHUB, "nobody"), address(0));
        assertEq(registry.resolveHandle(CeremonyProfile.PLATFORM_GOOGLE, "nobody@example.com"), address(0));
    }

    /// Enable a platform: register a first verifier for it.
    function _wireIdentityPlatform(bytes32 platformId) internal returns (address verifier) {
        verifier = address(new StubPlatformVerifier(platformId, 0));
        proofVerifier.setVerifier(platformId, 1, IPlatformVerifier(verifier));
    }
}
