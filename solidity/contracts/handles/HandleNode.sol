// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @notice The node formula: `SHA256(tag || value)`, a handle folded first.
///         The tags are `CeremonyProfile`'s; only the circuits check bytes,
///         so text they refuse folds to a node nobody holds.
library HandleNode {
    /// `raw` with A-Z folded to a-z; every other byte unchanged.
    function fold(string memory raw) internal pure returns (string memory) {
        bytes memory out = bytes.concat(bytes(raw));
        for (uint256 i = 0; i < out.length; i++) {
            bytes1 c = out[i];
            if (c >= 0x41 && c <= 0x5A) out[i] = bytes1(uint8(c) + 0x20);
        }
        return string(out);
    }

    /// `SHA256(tag || value)`.
    function node(bytes memory tag, string memory value) internal pure returns (bytes32) {
        return sha256(abi.encodePacked(tag, value));
    }

    /// `raw` folded, and its node under `tag`.
    function nodeOf(bytes memory tag, string memory raw)
        internal
        pure
        returns (string memory folded, bytes32 handleNode)
    {
        folded = fold(raw);
        handleNode = node(tag, folded);
    }
}
