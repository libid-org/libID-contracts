// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";

import {CeremonyProfile} from "../CeremonyProfile.sol";
import {TestNodes} from "../../identity/test/TestNodes.sol";

/// @notice One platform id per platform, its node tags, and its nodes.
contract PlatformIdentityTest is Test {
    /// @dev `platformId` is keccak256 of the platform key (REQ-PLAT-01).
    function test_aPlatformIdIsTheBareName() public pure {
        assertEq(CeremonyProfile.PLATFORM_X, keccak256(bytes("x")));
        assertEq(CeremonyProfile.PLATFORM_GITHUB, keccak256(bytes("github")));
        assertEq(CeremonyProfile.PLATFORM_GOOGLE, keccak256(bytes("google")));
    }

    /// @dev Node tags are distinct per platform and kind.
    function test_theNodeTagsArePinned() public pure {
        assertEq(CeremonyProfile.X_USER_ID_TAG, bytes("libid.x.user-id"));
        assertEq(CeremonyProfile.X_HANDLE_TAG, bytes("libid.x.handle"));
        assertEq(CeremonyProfile.GITHUB_USER_ID_TAG, bytes("libid.github.user-id"));
        assertEq(CeremonyProfile.GITHUB_HANDLE_TAG, bytes("libid.github.handle"));
        assertEq(CeremonyProfile.GOOGLE_USER_ID_TAG, bytes("libid.google.user-id"));
        assertEq(CeremonyProfile.GOOGLE_HANDLE_TAG, bytes("libid.google.handle"));
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
