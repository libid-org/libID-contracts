// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {HandlePlatforms} from "../../handles/HandlePlatforms.sol";

/// @notice The nodes a binding is stored under, for tests that bind through
///         a stub verifier and must name the keys a circuit would output.
///
/// @dev `SHA256(tag || value)` with the generated tags. The circuits compute
///      these; nothing in production does from plaintext, so this lives with
///      the tests. `handleNode` takes the NORMALIZED handle, as a circuit
///      hashes it.
library TestNodes {
    function idNode(bytes32 platformId, string memory id) internal pure returns (bytes32) {
        return sha256(abi.encodePacked(HandlePlatforms.userIdTagFor(platformId), id));
    }

    function handleNode(bytes32 platformId, string memory normalized) internal pure returns (bytes32) {
        return sha256(abi.encodePacked(HandlePlatforms.handleTagFor(platformId), normalized));
    }
}
