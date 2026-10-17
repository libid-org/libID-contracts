// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

import {GitHubPlatformVerifier} from "../../ceremony/GitHubPlatformVerifier.sol";
import {GooglePlatformVerifier, IGoogleJwtRoots} from "../../ceremony/GooglePlatformVerifier.sol";
import {INotaryService} from "../../ceremony/INotaryService.sol";
import {IHonkVerifier} from "../../ceremony/PlatformVerifierBase.sol";
import {XPlatformVerifier} from "../../ceremony/XPlatformVerifier.sol";
import {PlatformVerifierBase} from "../../ceremony/PlatformVerifierBase.sol";
import {CircuitCodehashes} from "../CircuitCodehashes.sol";

/// @notice The vendored Honk verifiers are what the Platform Verifiers pin.
/// @dev Deployed from artifacts, not imported: they compile on the legacy pipeline.
contract HonkVerifiersTest is Test {
    /// The error a Honk verifier raises for a proof of the wrong length.
    error ProofLengthWrongWithLogN(uint256 logN, uint256 actualLength, uint256 expectedLength);

    address constant OWNER = address(0xA11CE);

    string constant X_PROOF = "contracts/circuits/test/fixtures/bearer-link-x-proof.json";
    string constant GITHUB_PROOF = "contracts/circuits/test/fixtures/bearer-link-github-proof.json";

    IHonkVerifier bearerLink;
    IHonkVerifier oidcGoogle;

    function setUp() public {
        bearerLink = IHonkVerifier(vm.deployCode("BearerLinkHonkVerifier.sol:BearerLinkHonkVerifier"));
        oidcGoogle = IHonkVerifier(vm.deployCode("OidcGoogleHonkVerifier.sol:OidcGoogleHonkVerifier"));
    }

    /// The `logN` a verifier reports for its own circuit, read by handing
    /// it a proof of the wrong length.
    function _logN(IHonkVerifier verifier) private view returns (uint256) {
        try verifier.verify("", new bytes32[](0)) returns (bool) {
            revert("an empty proof verified");
        } catch (bytes memory reason) {
            // The first four bytes of revert data are the selector.
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

    /// Whether `verifier` accepts the proof in `fixture` under `inputs`. A
    /// Honk verifier refuses by reverting, so a revert is a no.
    function _accepts(IHonkVerifier verifier, string memory fixture, bytes32[] memory inputs)
        private
        view
        returns (bool)
    {
        try verifier.verify{gas: 3_000_000}(vm.parseJsonBytes(vm.readFile(fixture), ".proof"), inputs) returns (
            bool ok
        ) {
            return ok;
        } catch {
            return false;
        }
    }

    function _inputs(string memory fixture) private view returns (bytes32[] memory) {
        return vm.parseJsonBytes32Array(vm.readFile(fixture), ".public_inputs");
    }

    /// EIP-170: a verifier that grows past the limit fails here with its size.
    function test_verifiersFitUnderTheCodeSizeLimit() public view {
        assertLe(address(bearerLink).code.length, 24_576, "bearer-link over EIP-170");
        assertLe(address(oidcGoogle).code.length, 24_576, "oidc-google over EIP-170");
    }

    function test_eachVerifierAnswersForItsOwnCircuit() public view {
        uint256 bearer = _logN(bearerLink);
        uint256 oidc = _logN(oidcGoogle);
        assertGt(bearer, 0, "bearer-link reports no circuit size");
        assertGt(oidc, 0, "oidc-google reports no circuit size");
        assertNotEq(bearer, oidc, "bearer-link and Google would verify under one circuit");
    }

    /// One verifier proves both platforms; each proof holds only under its
    /// own platform's tags, which the Platform Verifier supplies.
    function test_aBearerLinkProofHoldsOnlyUnderItsPlatformsTags() public view {
        bytes32[] memory x = _inputs(X_PROOF);
        bytes32[] memory github = _inputs(GITHUB_PROOF);
        assertTrue(_accepts(bearerLink, X_PROOF, x), "an X proof refused");
        assertTrue(_accepts(bearerLink, GITHUB_PROOF, github), "a GitHub proof refused");
        for (uint256 i = 12; i < 16; ++i) {
            x[i] = github[i];
        }
        assertFalse(_accepts(bearerLink, X_PROOF, x), "an X proof under GitHub's tags");
    }

    /// A Platform Verifier wires its circuit's real verifier, not a stub; X and
    /// GitHub pin bearer-link, Google its own.
    function test_platformVerifiersPinTheRealArtifacts() public {
        XPlatformVerifier xImpl = new XPlatformVerifier();
        XPlatformVerifier x = XPlatformVerifier(
            address(
                new ERC1967Proxy(
                    address(xImpl),
                    abi.encodeCall(XPlatformVerifier.initialize, (OWNER, INotaryService(address(0x0707)), bearerLink))
                )
            )
        );
        assertEq(address(x.honkVerifier()), address(bearerLink));

        GitHubPlatformVerifier ghImpl = new GitHubPlatformVerifier();
        GitHubPlatformVerifier gh = GitHubPlatformVerifier(
            address(
                new ERC1967Proxy(
                    address(ghImpl),
                    abi.encodeCall(
                        GitHubPlatformVerifier.initialize, (OWNER, INotaryService(address(0x0707)), bearerLink)
                    )
                )
            )
        );
        assertEq(address(gh.honkVerifier()), address(bearerLink));

        GooglePlatformVerifier gImpl = new GooglePlatformVerifier();
        GooglePlatformVerifier g = GooglePlatformVerifier(
            address(
                new ERC1967Proxy(
                    address(gImpl),
                    abi.encodeCall(
                        GooglePlatformVerifier.initialize,
                        (OWNER, INotaryService(address(0)), oidcGoogle, IGoogleJwtRoots(address(0x2007)))
                    )
                )
            )
        );
        assertEq(address(g.honkVerifier()), address(oidcGoogle));
        assertEq(x.circuitCodehash(), gh.circuitCodehash(), "two artifacts for X and GitHub");
        assertNotEq(x.circuitCodehash(), g.circuitCodehash(), "one artifact for X and Google");
    }

    /// @dev The pinned codehashes are those of the vendored verifiers.
    function test_theCommittedCodehashesAreTheVendoredVerifiers() public view {
        assertEq(address(bearerLink).codehash, CircuitCodehashes.BEARER_LINK, "bearer-link");
        assertEq(address(oidcGoogle).codehash, CircuitCodehashes.OIDC_GOOGLE, "oidc-google");
    }

    /// @dev Each Platform Verifier refuses every vendored verifier but its own circuit's.
    function test_eachPlatformVerifierRefusesTheOtherCircuits() public {
        _refuses(address(new XPlatformVerifier()), oidcGoogle, CircuitCodehashes.BEARER_LINK);
        _refuses(address(new GitHubPlatformVerifier()), oidcGoogle, CircuitCodehashes.BEARER_LINK);

        GooglePlatformVerifier google = new GooglePlatformVerifier();
        {
            IHonkVerifier wrong = bearerLink;
            vm.expectRevert(
                abi.encodeWithSelector(
                    PlatformVerifierBase.WrongCircuit.selector, CircuitCodehashes.OIDC_GOOGLE, address(wrong).codehash
                )
            );
            new ERC1967Proxy(
                address(google),
                abi.encodeCall(
                    GooglePlatformVerifier.initialize,
                    (OWNER, INotaryService(address(0)), wrong, IGoogleJwtRoots(address(0x0808)))
                )
            );
        }
    }

    /// An X or GitHub `impl` behind a proxy initialized with `wrong` reverts
    /// naming `expected` and `wrong`'s codehash.
    function _refuses(address impl, IHonkVerifier wrong, bytes32 expected) private {
        vm.expectRevert(
            abi.encodeWithSelector(PlatformVerifierBase.WrongCircuit.selector, expected, address(wrong).codehash)
        );
        new ERC1967Proxy(
            impl, abi.encodeCall(XPlatformVerifier.initialize, (OWNER, INotaryService(address(0x0707)), wrong))
        );
    }
}
