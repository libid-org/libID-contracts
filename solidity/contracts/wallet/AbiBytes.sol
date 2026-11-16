// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {ERC7579Utils, Execution} from "@openzeppelin/contracts/account/utils/draft-ERC7579Utils.sol";

/// The `bytes` member of the ABI tuple `data` whose offset is the head word at `head`.
function bytesAt(bytes calldata data, uint256 head) pure returns (bytes calldata) {
    uint256 offset = uint256(bytes32(data[head:head + 32]));
    uint256 length = uint256(bytes32(data[offset:offset + 32]));
    return data[offset + 32:offset + 32 + length];
}

/// The batch `executionCalldata` decodes to, and whether it is exactly that batch's `abi.encode`: only then is
/// no call read from outside these bytes, so every decoder of them reads the same calls.
function canonicalBatch(bytes calldata executionCalldata) pure returns (Execution[] calldata batch, bool canonical) {
    batch = ERC7579Utils.decodeBatch(executionCalldata);
    uint256 free;
    assembly ("memory-safe") {
        free := mload(0x40)
    }
    canonical = keccak256(abi.encode(batch)) == keccak256(executionCalldata);
    // The encoding's memory is released.
    assembly ("memory-safe") {
        mstore(0x40, free)
    }
}
