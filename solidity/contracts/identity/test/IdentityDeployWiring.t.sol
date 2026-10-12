// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

import {HandlePlatforms} from "../../handles/HandlePlatforms.sol";
import {IdentityRegistry} from "../IdentityRegistry.sol";
import {IPlatformVerifier} from "../../ceremony/IPlatformVerifier.sol";
import {IProofVerifier} from "../../ceremony/IProofVerifier.sol";
import {CeremonyProofVerifier} from "../../ceremony/CeremonyProofVerifier.sol";
import {StubPlatformVerifier} from "./StubPlatformVerifier.sol";

/// A deployed registry knows the three platforms `handles.json` names, with
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
        vm.expectRevert(abi.encodeWithSelector(HandlePlatforms.UnknownPlatform.selector, nowhere));
        this.handleTagForExternally(nowhere);
    }

    /// `handleTagFor` is an internal library call, which `expectRevert` cannot see.
    /// This gives it a call boundary to watch.
    function handleTagForExternally(bytes32 platformId) external pure returns (bytes memory) {
        return HandlePlatforms.handleTagFor(platformId);
    }

    /// Each platform resolves once a verifier is registered for it, and not before.
    function test_registeringAVerifierMakesEveryPlatformUsable() public {
        vm.expectRevert(
            abi.encodeWithSelector(IdentityRegistry.UnknownPlatform.selector, HandlePlatforms.PLATFORM_GOOGLE)
        );
        registry.resolveHandle(HandlePlatforms.PLATFORM_GOOGLE, "nobody@example.com");

        vm.startPrank(owner);
        address x = _wireIdentityPlatform(HandlePlatforms.PLATFORM_X);
        address gh = _wireIdentityPlatform(HandlePlatforms.PLATFORM_GITHUB);
        address g = _wireIdentityPlatform(HandlePlatforms.PLATFORM_GOOGLE);
        vm.stopPrank();

        // The version a deployment registers its first verifier under.
        uint16 v = 1;
        assertEq(address(proofVerifier.verifierOf(HandlePlatforms.PLATFORM_X, v)), x);
        assertEq(address(proofVerifier.verifierOf(HandlePlatforms.PLATFORM_GITHUB, v)), gh);
        assertEq(address(proofVerifier.verifierOf(HandlePlatforms.PLATFORM_GOOGLE, v)), g);

        // Resolvable means the platform answers "nobody" rather than reverting
        // `UnknownPlatform`, which is what an unwired one does.
        assertEq(registry.resolveHandle(HandlePlatforms.PLATFORM_X, "nobody"), address(0));
        assertEq(registry.resolveHandle(HandlePlatforms.PLATFORM_GITHUB, "nobody"), address(0));
        assertEq(registry.resolveHandle(HandlePlatforms.PLATFORM_GOOGLE, "nobody@example.com"), address(0));

        // The tag a disclosure and every resolver hash under is the circuit's.
        assertEq(registry.handleTagOf(HandlePlatforms.PLATFORM_X), bytes("libid.x.handle"));
        assertEq(registry.handleTagOf(HandlePlatforms.PLATFORM_GITHUB), bytes("libid.github.handle"));
        assertEq(registry.handleTagOf(HandlePlatforms.PLATFORM_GOOGLE), bytes("libid.google.handle"));
    }

    /// Enable a platform: register a first verifier for it.
    function _wireIdentityPlatform(bytes32 platformId) internal returns (address verifier) {
        verifier = address(new StubPlatformVerifier(platformId, 0));
        proofVerifier.setVerifier(platformId, 1, IPlatformVerifier(verifier));
    }
}
