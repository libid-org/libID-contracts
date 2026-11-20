// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// `abi.encode(Operation[])` of `(d0, keccak256(data0))` and `(d1, keccak256(data1))`.
function operationList(bytes32 d0, bytes memory data0, bytes32 d1, bytes memory data1) pure returns (bytes memory) {
    return abi.encode(uint256(0x20), uint256(2), d0, keccak256(data0), d1, keccak256(data1));
}

/// @notice The Operation List vector of chain profiles §3.3, copied from the
///         spec text word for word, and the lists derived from it.
library OperationListVector {
    bytes32 internal constant OPERATIONS = 0x60b329d7366897b03545eb9f63f4a707253258ee2e1cd0ba3a8973aa4959e967;
    bytes32 internal constant BIND = 0x4d59cd4487de0a5957f8c83addaac7a1238175aa5c29eeea2fbef57a8f5165ac;
    bytes32 internal constant TEST_A = 0x6b8fd3a153cb2bc403041d7ca7d029d031243d8143d49a248230df9dd07fb723;
    bytes32 internal constant TEST_B = 0x80b4f95cb6d89708133947b68dcfcfb49b7e1e55f8b96984b151e9c446e91a1f;
    bytes32 internal constant NONCE = 0x5555555555555555555555555555555555555555555555555555555555555555;
    bytes32 internal constant DIGEST = 0x8eb2153142c324145458f77cd7709e6375ae24b22fa59351549afc522d82c1fb;
    address internal constant TARGET = 0x1111111111111111111111111111111111111111;

    /// w0..w5 of `transactionData`.
    function words() internal pure returns (bytes32[] memory w) {
        w = new bytes32[](6);
        w[0] = bytes32(uint256(0x20));
        w[1] = bytes32(uint256(2));
        w[2] = BIND;
        w[3] = 0xaafae41182fdefb0af836c3b506e127c7f229f33360c66de1139f4b0316f09d8;
        w[4] = TEST_A;
        w[5] = 0x8b1a944cf13a9a1c08facb2c9e98623ef3254d2ddb48113885c3e8e97fec8db9;
    }

    function join(bytes32[] memory w) internal pure returns (bytes memory) {
        return abi.encodePacked(w);
    }

    function transactionData() internal pure returns (bytes memory) {
        return join(words());
    }

    // ─── Canonical lists rejected under REQ-COMMON-01I ──

    function duplicateEntry() internal pure returns (bytes memory) {
        bytes32[] memory w = words();
        w[4] = BIND;
        return join(w);
    }

    function nestedEntry() internal pure returns (bytes memory) {
        bytes32[] memory w = words();
        w[4] = OPERATIONS;
        return join(w);
    }

    function noEntry() internal pure returns (bytes memory) {
        return abi.encodePacked(bytes32(uint256(0x20)), bytes32(0));
    }

    /// Rejected by a Consumer owning `libid.test.a` and `libid.test.b`.
    function twoOwnDomains() internal pure returns (bytes memory) {
        bytes32[] memory w = words();
        w[2] = TEST_B;
        return join(w);
    }

    // ─── Noncanonical lists rejected under REQ-CHAIN-07B ──

    function trailingByte() internal pure returns (bytes memory) {
        return bytes.concat(transactionData(), hex"00");
    }

    function gap() internal pure returns (bytes memory) {
        bytes32[] memory w = words();
        bytes32[] memory g = new bytes32[](7);
        g[0] = bytes32(uint256(0x40));
        for (uint256 i = 1; i < 6; ++i) {
            g[i + 1] = w[i];
        }
        return join(g);
    }
}
