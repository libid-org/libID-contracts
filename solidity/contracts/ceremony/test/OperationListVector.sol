// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @notice The Operation List vector of ceremony-common section 5, copied
///         from the spec text word for word, and the lists derived from it.
library OperationListVector {
    bytes32 internal constant OPERATIONS = 0x60b329d7366897b03545eb9f63f4a707253258ee2e1cd0ba3a8973aa4959e967;
    bytes32 internal constant BIND = 0x4d59cd4487de0a5957f8c83addaac7a1238175aa5c29eeea2fbef57a8f5165ac;
    bytes32 internal constant TEST_A = 0x6b8fd3a153cb2bc403041d7ca7d029d031243d8143d49a248230df9dd07fb723;
    bytes32 internal constant TEST_B = 0x80b4f95cb6d89708133947b68dcfcfb49b7e1e55f8b96984b151e9c446e91a1f;
    bytes32 internal constant NONCE = 0x5555555555555555555555555555555555555555555555555555555555555555;
    bytes32 internal constant DIGEST = 0x872d461409ba5b7731cc6aaf6abe7522b5f985d69ca66eb333e02e008e3ae496;
    address internal constant TARGET = 0x1111111111111111111111111111111111111111;

    /// w0..w11 of `transactionData`.
    function words() internal pure returns (bytes32[] memory w) {
        w = new bytes32[](12);
        w[0] = bytes32(uint256(0x20));
        w[1] = bytes32(uint256(2));
        w[2] = bytes32(uint256(0x40));
        w[3] = bytes32(uint256(0xc0));
        w[4] = BIND;
        w[5] = bytes32(uint256(0x40));
        w[6] = bytes32(uint256(0x20));
        w[7] = 0x0000000000000000000000001111111111111111111111111111111111111111;
        w[8] = TEST_A;
        w[9] = bytes32(uint256(0x40));
        w[10] = bytes32(uint256(1));
        w[11] = 0xff00000000000000000000000000000000000000000000000000000000000000;
    }

    function join(bytes32[] memory w) internal pure returns (bytes memory) {
        return abi.encodePacked(w);
    }

    function transactionData() internal pure returns (bytes memory) {
        return join(words());
    }

    // ─── Canonical lists rejected under REQ-COMMON-01I (common §5) ──

    function duplicateEntry() internal pure returns (bytes memory) {
        bytes32[] memory w = words();
        w[8] = BIND;
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
        w[4] = TEST_B;
        w[6] = bytes32(uint256(1));
        w[7] = w[11];
        return join(w);
    }

    // ─── Noncanonical lists rejected under REQ-CHAIN-07B (chain profiles §3.3) ──

    function trailingByte() internal pure returns (bytes memory) {
        return bytes.concat(transactionData(), hex"00");
    }

    function gap() internal pure returns (bytes memory) {
        bytes32[] memory w = words();
        bytes32[] memory g = new bytes32[](13);
        g[0] = bytes32(uint256(0x40));
        for (uint256 i = 1; i < 12; ++i) {
            g[i + 1] = w[i];
        }
        return join(g);
    }

    function swappedBodies() internal pure returns (bytes memory) {
        bytes32[] memory w = words();
        w[2] = bytes32(uint256(0xc0));
        w[3] = bytes32(uint256(0x40));
        for (uint256 i = 4; i < 8; ++i) {
            (w[i], w[i + 4]) = (w[i + 4], w[i]);
        }
        return join(w);
    }

    function outerPadding() internal pure returns (bytes memory) {
        bytes32[] memory w = words();
        w[11] = 0xff00000000000000000000000000000000000000000000000000000000000001;
        return join(w);
    }
}
