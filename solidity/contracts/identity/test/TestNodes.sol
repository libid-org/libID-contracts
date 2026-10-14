// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {CeremonyProfile} from "../../ceremony/CeremonyProfile.sol";
import {HandleNode} from "../../handles/HandleNode.sol";

/// @notice The nodes a circuit would output: `SHA256(tag || value)` with the generated tags.
/// @dev `handleNode` takes the normalized handle.
library TestNodes {
    function idNode(bytes32 platformId, string memory id) internal pure returns (bytes32) {
        return sha256(abi.encodePacked(CeremonyProfile.userIdTag(platformId), id));
    }

    function handleNode(bytes32 platformId, string memory normalized) internal pure returns (bytes32) {
        return HandleNode.node(CeremonyProfile.handleTag(platformId), normalized);
    }
}
