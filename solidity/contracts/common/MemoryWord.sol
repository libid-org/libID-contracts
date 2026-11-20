// SPDX-License-Identifier: MIT
pragma solidity ^0.8.22;

/// The 32 bytes of `b` from byte `at`, zero-padded past its end.
function memoryWord(bytes memory b, uint256 at) pure returns (bytes32 w) {
    assembly ("memory-safe") {
        w := mload(add(add(b, 0x20), at))
    }
    if (b.length < at + 32) w &= ~bytes32(type(uint256).max >> (8 * (b.length > at ? b.length - at : 0)));
}
