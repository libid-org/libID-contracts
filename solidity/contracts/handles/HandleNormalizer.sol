// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @notice Turns a handle a caller typed into the bytes a handle node hashes.
/// @dev Folds A-Z to a-z and nothing else. The platform rules live in the circuits,
///      which bind only nodes of handles they accept, so text the rules refuse
///      folds to a node nobody holds.
library HandleNormalizer {
    /// @notice `raw` with A-Z folded to a-z; every other byte unchanged.
    function fold(string memory raw) internal pure returns (string memory) {
        bytes memory out = bytes.concat(bytes(raw));
        for (uint256 i = 0; i < out.length; i++) {
            bytes1 c = out[i];
            if (c >= 0x41 && c <= 0x5A) out[i] = bytes1(uint8(c) + 0x20);
        }
        return string(out);
    }

    /// @notice `SHA256(tag || normalized)`: the node a normalized handle is bound under.
    function node(bytes memory tag, string memory normalized) internal pure returns (bytes32) {
        return sha256(abi.encodePacked(tag, normalized));
    }
}
