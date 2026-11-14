// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// The `bytes` member of the ABI tuple `data` whose offset is the head word at `head`.
function bytesAt(bytes calldata data, uint256 head) pure returns (bytes calldata) {
    uint256 offset = uint256(bytes32(data[head:head + 32]));
    uint256 length = uint256(bytes32(data[offset:offset + 32]));
    return data[offset + 32:offset + 32 + length];
}
