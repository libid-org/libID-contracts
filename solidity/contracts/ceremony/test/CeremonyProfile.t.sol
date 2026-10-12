// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {CeremonyProfile} from "../CeremonyProfile.sol";

/// @notice Pins the profile tags to fixed bytes.
/// @dev These strings are a cross-implementation agreement, not a reading of
///      the specification, which fixes no literal of its own. The notary
///      writes them and the verifier compares them; a silent disagreement
///      rejects every genuine attestation with no error that says why. The
///      expected values below were computed with `cast keccak`, independently
///      of this library.
contract CeremonyProfileTest is Test {
    function test_platformIdsArePinnedAndDistinct() public pure {
        assertEq(CeremonyProfile.PLATFORM_GOOGLE, 0x8f2f90d8304f6eb382d037c47a041d8c8b4d18bdd8b082fa32828e016a584ca7);
        assertEq(CeremonyProfile.PLATFORM_X, 0x7521d1cadbcfa91eec65aa16715b94ffc1c9654ba57ea2ef1a2127bca1127a83);
        assertEq(CeremonyProfile.PLATFORM_GITHUB, 0x07a17bd3c7c8d7b88e93a4d9007e3bc230b0a586a434de0bed6500e9f343deb7);
        assertTrue(CeremonyProfile.PLATFORM_GOOGLE != CeremonyProfile.PLATFORM_X);
        assertTrue(CeremonyProfile.PLATFORM_X != CeremonyProfile.PLATFORM_GITHUB);
        assertTrue(CeremonyProfile.PLATFORM_GOOGLE != CeremonyProfile.PLATFORM_GITHUB);
    }

    function test_authoritiesArePinned() public pure {
        assertEq(CeremonyProfile.AUTHORITY_X_API, 0x4930142f5283d4a8eab0d24c588f00b21213ae2a47e7ed6c1dc6a57044f1655d);
        assertEq(CeremonyProfile.AUTHORITY_GITHUB, 0x06785da520052bf40d5bf506fb493c41162f55d4e17dffa8b21f02598e981533);
        assertEq(
            CeremonyProfile.AUTHORITY_GITHUB_API, 0xa5d9c1d593bc385a23a2d56116aab1951e3c66296476c7a7396a515105e8b2c1
        );
    }

    /// @dev GitHub's exchange is served by github.com and its identity read by
    ///      api.github.com, so one pinned authority per profile would be wrong.
    function test_githubNotarizesTwoDifferentAuthorities() public pure {
        assertTrue(CeremonyProfile.AUTHORITY_GITHUB != CeremonyProfile.AUTHORITY_GITHUB_API);
    }

    /// @dev The precomputed header hashes are what each CRLF block parses to:
    ///      the name before the colon, and the value after it, trimmed.
    function test_theRequiredHeaderHashesAreTheBlocksParsed() public pure {
        bytes32[2] memory platforms = [CeremonyProfile.PLATFORM_X, CeremonyProfile.PLATFORM_GITHUB];
        bytes[2] memory tokens =
            [CeremonyProfile.X_TOKEN_REQUIRED_HEADERS, CeremonyProfile.GITHUB_TOKEN_REQUIRED_HEADERS];
        bytes[2] memory identities =
            [CeremonyProfile.X_IDENTITY_REQUIRED_HEADERS, CeremonyProfile.GITHUB_IDENTITY_REQUIRED_HEADERS];
        for (uint256 i = 0; i < 2; ++i) {
            (bytes32[] memory names, bytes32[] memory values) = CeremonyProfile.tokenRequiredHeaderHashes(platforms[i]);
            _assertParsesTo(tokens[i], names, values);
            (names, values) = CeremonyProfile.identityRequiredHeaderHashes(platforms[i]);
            _assertParsesTo(identities[i], names, values);
        }
    }

    function _assertParsesTo(bytes memory block_, bytes32[] memory names, bytes32[] memory values) private pure {
        uint256 line;
        uint256 from;
        for (uint256 i = 0; i <= block_.length; ++i) {
            if (i < block_.length && block_[i] != "\r") continue;
            uint256 colon = from;
            while (block_[colon] != ":") {
                ++colon;
            }
            uint256 start = colon + 1;
            uint256 end = i;
            while (block_[start] == " " || block_[start] == "\t") {
                ++start;
            }
            while (block_[end - 1] == " " || block_[end - 1] == "\t") {
                --end;
            }
            assertEq(keccak256(_slice(block_, from, colon)), names[line], "name");
            assertEq(keccak256(_slice(block_, start, end)), values[line], "value");
            ++line;
            from = i + 2;
            ++i;
        }
        assertEq(line, names.length, "line count");
    }

    function _slice(bytes memory data, uint256 from, uint256 to) private pure returns (bytes memory out) {
        out = new bytes(to - from);
        for (uint256 i = from; i < to; ++i) {
            out[i - from] = data[i];
        }
    }

    function test_attestationCountsFollowTheProfiles() public pure {
        // Google's path stops at the Platform Verifier and costs nothing.
        assertEq(CeremonyProfile.attestationCount(CeremonyProfile.PLATFORM_GOOGLE), 0);
        assertEq(CeremonyProfile.attestationCount(CeremonyProfile.PLATFORM_X), 2);
        assertEq(CeremonyProfile.attestationCount(CeremonyProfile.PLATFORM_GITHUB), 2);
    }

    function test_anUnknownPlatformHasNoCount() public {
        bytes32 unknown = keccak256("mastodon");
        vm.expectRevert(abi.encodeWithSelector(CeremonyProfile.UnknownPlatform.selector, unknown));
        this.count(unknown);
    }

    function count(bytes32 platformId) external pure returns (uint8) {
        return CeremonyProfile.attestationCount(platformId);
    }

    function test_launchVersionMatchesThePublishedValue() public pure {
        assertEq(CeremonyProfile.LAUNCH_VERSION, 1);
    }

    /// @dev A browser derives a proof's expiry from the version it ran, so a
    ///      launch window is part of `v1` like its request lines: a different
    ///      value is a new ceremonyVersion, not an edit (REQ-PARAM-01).
    function test_launchValidityWindowsArePinned() public pure {
        assertEq(CeremonyProfile.PROOF_LIFETIME_SECONDS_X, 3600);
        assertEq(CeremonyProfile.MAX_FUTURE_ATTESTATION_SKEW_SECONDS_X, 300);
        assertEq(CeremonyProfile.FUTURE_OBSERVATION_ALLOWANCE_SECONDS_X, 300);
        assertEq(CeremonyProfile.PROOF_LIFETIME_SECONDS_GITHUB, 3600);
        assertEq(CeremonyProfile.MAX_FUTURE_ATTESTATION_SKEW_SECONDS_GITHUB, 300);
        assertEq(CeremonyProfile.FUTURE_OBSERVATION_ALLOWANCE_SECONDS_GITHUB, 300);
        assertEq(CeremonyProfile.FUTURE_OBSERVATION_ALLOWANCE_SECONDS_GOOGLE, 7200);
    }

    /// @dev The ordering the allowances exist for: an OIDC claim carries the
    ///      token's `exp` and reads about an hour ahead, a notarized
    ///      observation is wall-clock and never is.
    function test_anOidcClaimIsAllowedFurtherAheadThanANotarizedOne() public pure {
        assertGt(
            CeremonyProfile.FUTURE_OBSERVATION_ALLOWANCE_SECONDS_GOOGLE,
            CeremonyProfile.FUTURE_OBSERVATION_ALLOWANCE_SECONDS_X,
            "X"
        );
        assertGt(
            CeremonyProfile.FUTURE_OBSERVATION_ALLOWANCE_SECONDS_GOOGLE,
            CeremonyProfile.FUTURE_OBSERVATION_ALLOWANCE_SECONDS_GITHUB,
            "GitHub"
        );
    }

    /// @dev `isForbiddenRequestHeader` is true for every listed name and false
    ///      for near misses: a header the verifier reads, another case, a
    ///      trailing space, the empty name, two names joined.
    function test_theForbiddenNamesAreTheListedOnes() public pure {
        bytes memory list = CeremonyProfile.FORBIDDEN_REQUEST_HEADERS;
        uint256 listed;
        uint256 from;
        for (uint256 i = 0; i <= list.length; ++i) {
            if (i < list.length && list[i] != "\r") continue;
            bytes memory name = new bytes(i - from);
            for (uint256 j = 0; j < name.length; ++j) {
                name[j] = list[from + j];
            }
            assertTrue(CeremonyProfile.isForbiddenRequestHeader(keccak256(name)), string(name));
            ++listed;
            from = i + 2;
        }
        assertEq(listed, 7);

        string[6] memory others = ["host", "content-length", "Cookie", "cookie ", "", "cookie\r\nauthorization"];
        for (uint256 i = 0; i < others.length; ++i) {
            assertFalse(CeremonyProfile.isForbiddenRequestHeader(keccak256(bytes(others[i]))), others[i]);
        }
    }

    /// @dev The pinned fixture in CeremonyAttestation.t.sol opens with the
    ///      X API authority id and nothing else names a platform. If
    ///      these constants and that fixture ever drift apart, one of them is
    ///      wrong.
    function test_theAttestationFixtureUsesTheseConstants() public pure {
        assertEq(CeremonyProfile.PLATFORM_X, keccak256(bytes("x")));
    }
}
