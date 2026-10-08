// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

import {GitHubPlatformVerifier} from "../../ceremony/GitHubPlatformVerifier.sol";
import {GooglePlatformVerifier, IGoogleJwtRoots} from "../../ceremony/GooglePlatformVerifier.sol";
import {INotaryService} from "../../ceremony/INotaryService.sol";
import {IHonkVerifier} from "../../ceremony/PlatformVerifierBase.sol";
import {XPlatformVerifier} from "../../ceremony/XPlatformVerifier.sol";

/// @notice The vendored Honk verifiers are what the Platform Verifiers pin.
///
/// @dev A bb verifier embeds its verification key as code and exposes no
///      getter, so nothing here can ask it WHICH circuit it answers for. What
///      it does say is the `logN` a wrong-length proof comes back with, and
///      what each accepts. The two bearer-link circuits differ only in their
///      platform rules and tags, so they may share a `logN`; a real proof of
///      one refused by the other is what separates them. Either check catches
///      a release whose tarballs were swapped, or a vendor run that wrote one
///      circuit's verifier under another's name.
///
///      The verifiers are deployed from their artifacts, not imported: they
///      compile on the legacy pipeline (see foundry.toml), and a test that
///      imported one would compile the Platform Verifiers beside it on that
///      pipeline too, which is not what ships.
contract HonkVerifiersTest is Test {
    /// The error a Honk verifier raises for a proof of the wrong length.
    error ProofLengthWrongWithLogN(uint256 logN, uint256 actualLength, uint256 expectedLength);

    address constant OWNER = address(0xA11CE);

    string constant X_PROOF = "contracts/circuits/test/fixtures/bearer-link-x-proof.json";
    string constant GITHUB_PROOF = "contracts/circuits/test/fixtures/bearer-link-github-proof.json";

    IHonkVerifier bearerLinkX;
    IHonkVerifier bearerLinkGithub;
    IHonkVerifier oidcGoogle;

    function setUp() public {
        bearerLinkX = IHonkVerifier(vm.deployCode("BearerLinkXHonkVerifier.sol:BearerLinkXHonkVerifier"));
        bearerLinkGithub = IHonkVerifier(vm.deployCode("BearerLinkGithubHonkVerifier.sol:BearerLinkGithubHonkVerifier"));
        oidcGoogle = IHonkVerifier(vm.deployCode("OidcGoogleHonkVerifier.sol:OidcGoogleHonkVerifier"));
    }

    /// The `logN` a verifier reports for its own circuit, read by handing
    /// it a proof of the wrong length.
    function _logN(IHonkVerifier verifier) private view returns (uint256) {
        try verifier.verify("", new bytes32[](0)) returns (bool) {
            revert("an empty proof verified");
        } catch (bytes memory reason) {
            // The first four bytes of revert data ARE the selector; the rest
            // is decoded below.
            // forge-lint: disable-next-line(unsafe-typecast)
            assertEq(bytes4(reason), ProofLengthWrongWithLogN.selector, "not a Honk verifier");
            bytes memory args = new bytes(reason.length - 4);
            for (uint256 i = 0; i < args.length; ++i) {
                args[i] = reason[i + 4];
            }
            (uint256 logN,,) = abi.decode(args, (uint256, uint256, uint256));
            return logN;
        }
    }

    /// Whether `verifier` accepts the proof in `fixture`. A Honk verifier
    /// refuses by reverting, so a revert is a no.
    function _accepts(IHonkVerifier verifier, string memory fixture) private view returns (bool) {
        string memory json = vm.readFile(fixture);
        try verifier.verify{gas: 3_000_000}(
            vm.parseJsonBytes(json, ".proof"), vm.parseJsonBytes32Array(json, ".public_inputs")
        ) returns (
            bool ok
        ) {
            return ok;
        } catch {
            return false;
        }
    }

    /// EIP-170: forge deploys under the default limit, and the sizes are
    /// asserted rather than merely survived so a release that grows past it
    /// names the number.
    function test_verifiersFitUnderTheCodeSizeLimit() public view {
        assertLe(address(bearerLinkX).code.length, 24_576, "bearer-link-x over EIP-170");
        assertLe(address(bearerLinkGithub).code.length, 24_576, "bearer-link-github over EIP-170");
        assertLe(address(oidcGoogle).code.length, 24_576, "oidc-google over EIP-170");
    }

    function test_eachVerifierAnswersForItsOwnCircuit() public view {
        uint256 x = _logN(bearerLinkX);
        uint256 github = _logN(bearerLinkGithub);
        uint256 oidc = _logN(oidcGoogle);
        assertGt(x, 0, "bearer-link-x reports no circuit size");
        assertGt(github, 0, "bearer-link-github reports no circuit size");
        assertGt(oidc, 0, "oidc-google reports no circuit size");
        assertNotEq(x, oidc, "X and Google would verify under one circuit");
        assertNotEq(github, oidc, "GitHub and Google would verify under one circuit");
    }

    /// Each bearer-link verifier accepts its own circuit's proof and refuses
    /// the other's: two verification keys, so no proof of one platform's
    /// rules passes as the other's.
    function test_eachBearerLinkVerifierRefusesTheOtherPlatformsProof() public view {
        assertTrue(_accepts(bearerLinkX, X_PROOF), "X refuses its own proof");
        assertTrue(_accepts(bearerLinkGithub, GITHUB_PROOF), "GitHub refuses its own proof");
        assertFalse(_accepts(bearerLinkX, GITHUB_PROOF), "X accepts a GitHub proof");
        assertFalse(_accepts(bearerLinkGithub, X_PROOF), "GitHub accepts an X proof");
    }

    /// A Platform Verifier pins its circuit's verifier by address and by the
    /// code hash the chain reports for it — the real artifact, not a stub.
    function test_platformVerifiersPinTheRealArtifacts() public {
        XPlatformVerifier xImpl = new XPlatformVerifier();
        XPlatformVerifier x = XPlatformVerifier(
            address(
                new ERC1967Proxy(
                    address(xImpl),
                    abi.encodeCall(
                        XPlatformVerifier.initialize,
                        (OWNER, INotaryService(address(0x0707)), bearerLinkX, address(bearerLinkX).codehash)
                    )
                )
            )
        );
        assertEq(address(x.honkVerifier()), address(bearerLinkX));
        assertEq(x.honkVerifierCodehash(), address(bearerLinkX).codehash);

        GitHubPlatformVerifier ghImpl = new GitHubPlatformVerifier();
        GitHubPlatformVerifier gh = GitHubPlatformVerifier(
            address(
                new ERC1967Proxy(
                    address(ghImpl),
                    abi.encodeCall(
                        GitHubPlatformVerifier.initialize,
                        (OWNER, INotaryService(address(0x0707)), bearerLinkGithub, address(bearerLinkGithub).codehash)
                    )
                )
            )
        );
        assertEq(address(gh.honkVerifier()), address(bearerLinkGithub));
        assertEq(gh.honkVerifierCodehash(), address(bearerLinkGithub).codehash);

        GooglePlatformVerifier gImpl = new GooglePlatformVerifier();
        GooglePlatformVerifier g = GooglePlatformVerifier(
            address(
                new ERC1967Proxy(
                    address(gImpl),
                    abi.encodeCall(
                        GooglePlatformVerifier.initialize,
                        (
                            OWNER,
                            INotaryService(address(0)),
                            oidcGoogle,
                            address(oidcGoogle).codehash,
                            IGoogleJwtRoots(address(0x2007))
                        )
                    )
                )
            )
        );
        assertEq(address(g.honkVerifier()), address(oidcGoogle));
        assertEq(g.honkVerifierCodehash(), address(oidcGoogle).codehash);
        assertNotEq(x.honkVerifierCodehash(), gh.honkVerifierCodehash(), "one artifact for X and GitHub");
        assertNotEq(x.honkVerifierCodehash(), g.honkVerifierCodehash(), "one artifact for X and Google");
        assertNotEq(gh.honkVerifierCodehash(), g.honkVerifierCodehash(), "one artifact for GitHub and Google");
    }
}
