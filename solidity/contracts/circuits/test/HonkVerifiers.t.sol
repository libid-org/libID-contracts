// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

import {BearerLinkHonkVerifier} from "../BearerLinkHonkVerifier.sol";
import {OidcGoogleHonkVerifier} from "../OidcGoogleHonkVerifier.sol";
import {GooglePlatformVerifier, IGoogleJwtRoots} from "../../ceremony/GooglePlatformVerifier.sol";
import {INotaryService} from "../../ceremony/INotaryService.sol";
import {IHonkVerifier} from "../../ceremony/PlatformVerifierBase.sol";
import {XPlatformVerifier} from "../../ceremony/XPlatformVerifier.sol";

/// @notice The vendored Honk verifiers are what the Platform Verifiers pin.
///
/// @dev A bb verifier embeds its verification key as code and exposes no
///      getter, so nothing here can ask it WHICH circuit it answers for. What
///      it does say is the `logN` a wrong-length proof comes back with, and
///      the two circuits differ in it: that is the check that would catch a
///      release whose tarballs were swapped, or a vendor run that wrote one
///      circuit's verifier under the other's name.
contract HonkVerifiersTest is Test {
    /// `Errors.ProofLengthWrongWithLogN` from the generated sources, which
    /// only a Honk verifier raises.
    error ProofLengthWrongWithLogN(uint256 logN, uint256 actualLength, uint256 expectedLength);

    address constant OWNER = address(0xA11CE);
    uint64 constant LIFETIME = 3600;
    uint64 constant SKEW = 300;

    IHonkVerifier bearerLink;
    IHonkVerifier oidcGoogle;

    function setUp() public {
        bearerLink = IHonkVerifier(address(new BearerLinkHonkVerifier()));
        oidcGoogle = IHonkVerifier(address(new OidcGoogleHonkVerifier()));
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

    /// EIP-170: forge deploys under the default limit, and the sizes are
    /// asserted rather than merely survived so a release that grows past it
    /// names the number.
    function test_verifiersFitUnderTheCodeSizeLimit() public view {
        assertLe(address(bearerLink).code.length, 24_576, "bearer-link over EIP-170");
        assertLe(address(oidcGoogle).code.length, 24_576, "oidc-google over EIP-170");
    }

    function test_eachVerifierAnswersForItsOwnCircuit() public view {
        uint256 bearer = _logN(bearerLink);
        uint256 oidc = _logN(oidcGoogle);
        assertGt(bearer, 0, "bearer-link reports no circuit size");
        assertGt(oidc, 0, "oidc-google reports no circuit size");
        assertNotEq(bearer, oidc, "both platforms would verify under one circuit");
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
                        (
                            OWNER,
                            INotaryService(address(0x0707)),
                            bearerLink,
                            address(bearerLink).codehash,
                            LIFETIME,
                            SKEW,
                            SKEW
                        )
                    )
                )
            )
        );
        assertEq(address(x.honkVerifier()), address(bearerLink));
        assertEq(x.honkVerifierCodehash(), address(bearerLink).codehash);

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
                            SKEW,
                            IGoogleJwtRoots(address(0x2007))
                        )
                    )
                )
            )
        );
        assertEq(address(g.honkVerifier()), address(oidcGoogle));
        assertEq(g.honkVerifierCodehash(), address(oidcGoogle).codehash);
        assertNotEq(x.honkVerifierCodehash(), g.honkVerifierCodehash(), "one artifact for two circuits");
    }
}
