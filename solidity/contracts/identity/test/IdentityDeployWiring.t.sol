// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

import {HandleNormalizer} from "../../handles/HandleNormalizer.sol";
import {HandlePlatforms} from "../../handles/HandlePlatforms.sol";
import {IdentityRegistry} from "../IdentityRegistry.sol";
import {IPlatformVerifier} from "../../ceremony/IPlatformVerifier.sol";
import {IProofVerifier} from "../../ceremony/IProofVerifier.sol";
import {CeremonyProofVerifier} from "../../ceremony/CeremonyProofVerifier.sol";
import {StubPlatformVerifier} from "./StubPlatformVerifier.sol";

/// A deployed registry knows the three platforms `handles.json` names, with the
/// rules and handle tags it states: nothing is configured per platform, so no
/// deploy step can install a wrong rule set. A wrong one would write wrong
/// nodes for every handle on that platform, and nothing later would notice:
/// the handle would simply resolve to nothing.
///
/// So the wiring is asserted rather than assumed — that the rules and tags a
/// fresh registry answers are the ones `handles.json` states, and that
/// registering a verifier is all it takes to make each platform resolvable.
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

    /// The rules come from the generated table, so a change to `handles.json`
    /// reaches the registry without anybody editing it.
    function test_theGeneratedRulesAreTheHandlesJsonOnes() public pure {
        HandleNormalizer.Rules memory x = HandlePlatforms.rulesFor(HandlePlatforms.PLATFORM_X);
        assertEq(x.maxLength, uint16(HandlePlatforms.MAX_LENGTH_X), "X length");
        assertTrue(x.allowUnderscore, "X allows underscore");
        assertFalse(x.allowHyphen, "X allows no hyphen");
        assertFalse(x.isEmail, "X is not an email");

        HandleNormalizer.Rules memory gh = HandlePlatforms.rulesFor(HandlePlatforms.PLATFORM_GITHUB);
        assertEq(gh.maxLength, uint16(HandlePlatforms.MAX_LENGTH_GITHUB), "GitHub length");
        assertTrue(gh.allowHyphen, "GitHub allows hyphen");
        assertFalse(gh.allowUnderscore, "GitHub allows no underscore");

        HandleNormalizer.Rules memory g = HandlePlatforms.rulesFor(HandlePlatforms.PLATFORM_GOOGLE);
        assertEq(g.maxLength, uint16(HandlePlatforms.MAX_LENGTH_GOOGLE), "Google length");
        assertTrue(g.isEmail, "Google is an email");
        assertFalse(g.allowUnderscore || g.allowHyphen, "an email's charset is its own");
    }

    /// An unknown platform reverts rather than returning a permissive default.
    /// A default would silently normalize with the wrong rules.
    function test_anUnknownPlatformHasNoRules() public {
        bytes32 nowhere = keccak256("nowhere");
        vm.expectRevert(abi.encodeWithSelector(HandlePlatforms.UnknownPlatform.selector, nowhere));
        this.rulesForExternally(nowhere);
    }

    /// `rulesFor` is an internal library call, which `expectRevert` cannot see.
    /// This gives it a call boundary to watch.
    function rulesForExternally(bytes32 platformId) external pure returns (HandleNormalizer.Rules memory) {
        return HandlePlatforms.rulesFor(platformId);
    }

    /// Registering a verifier for each of the three leaves each one resolvable;
    /// before that, each resolver refuses it.
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
