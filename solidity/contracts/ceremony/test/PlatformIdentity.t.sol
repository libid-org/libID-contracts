// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";

import {CeremonyProfile} from "../CeremonyProfile.sol";
import {HandlePlatforms} from "../../handles/HandlePlatforms.sol";
import {TestNodes} from "../../identity/test/TestNodes.sol";

/// @notice One platform id per platform, and libID namespaces only its own things.
///
/// @dev These two tables used to disagree. The registry keyed a platform
///      by `keccak256("dyaka.identity.platform.x")` and the ceremony profile by
///      `keccak256("x")`, so a handle bound through one path was invisible to
///      the other -- two ids for one platform, with nothing to make the
///      divergence loud. This file is what makes it loud.
contract PlatformIdentityTest is Test {
    /// @dev `platformId` is keccak256 of the platform key (REQ-PLAT-01).
    function test_theTwoTablesAgree() public pure {
        assertEq(HandlePlatforms.PLATFORM_X, CeremonyProfile.PLATFORM_X, "x");
        assertEq(HandlePlatforms.PLATFORM_GITHUB, CeremonyProfile.PLATFORM_GITHUB, "github");
        assertEq(HandlePlatforms.PLATFORM_GOOGLE, CeremonyProfile.PLATFORM_GOOGLE, "google");
    }

    function test_aPlatformIdIsTheBareName() public pure {
        assertEq(CeremonyProfile.PLATFORM_X, keccak256(bytes("x")));
        assertEq(CeremonyProfile.PLATFORM_GITHUB, keccak256(bytes("github")));
        assertEq(CeremonyProfile.PLATFORM_GOOGLE, keccak256(bytes("google")));
    }

    /// @dev Node tags are distinct per platform and kind.
    function test_theNodeTagsArePinned() public pure {
        assertEq(HandlePlatforms.USER_ID_TAG_X, bytes("libid.x.user-id"));
        assertEq(HandlePlatforms.HANDLE_TAG_X, bytes("libid.x.handle"));
        assertEq(HandlePlatforms.USER_ID_TAG_GITHUB, bytes("libid.github.user-id"));
        assertEq(HandlePlatforms.HANDLE_TAG_GITHUB, bytes("libid.github.handle"));
        assertEq(HandlePlatforms.USER_ID_TAG_GOOGLE, bytes("libid.google.user-id"));
        assertEq(HandlePlatforms.HANDLE_TAG_GOOGLE, bytes("libid.google.handle"));
    }

    /// @dev A node is `SHA256(tag || value)`, pinned against Python's hashlib:
    ///        hashlib.sha256(b"libid.x.user-id2244994945")
    ///        hashlib.sha256(b"libid.x.handlealice_1")
    function test_theNodesArePinned() public pure {
        assertEq(
            TestNodes.idNode(CeremonyProfile.PLATFORM_X, "2244994945"),
            0x68291869976ffad2abf3e933ec9ab2623395ff8b3b9242e655e1da3ef43d4f94
        );
        assertEq(
            TestNodes.handleNode(CeremonyProfile.PLATFORM_X, "alice_1"),
            0xe09c4f5bfbbc723bc35701ea9d718a1c5edb29b1ed5bb0cb0fabb3c43d8136af
        );
    }
}
