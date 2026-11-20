// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {OperationList} from "../OperationList.sol";

/// `abi.encode(Operation[])` of one entry.
function operationList(bytes32 d0, bytes memory data0) pure returns (bytes memory) {
    OperationList.Operation[] memory entries = new OperationList.Operation[](1);
    entries[0] = OperationList.Operation(d0, data0);
    return abi.encode(entries);
}

/// `abi.encode(Operation[])` of two entries.
function operationList(bytes32 d0, bytes memory data0, bytes32 d1, bytes memory data1) pure returns (bytes memory) {
    OperationList.Operation[] memory entries = new OperationList.Operation[](2);
    entries[0] = OperationList.Operation(d0, data0);
    entries[1] = OperationList.Operation(d1, data1);
    return abi.encode(entries);
}

/// @notice The Operation List vector of chain profiles §3.3, copied from the
///         spec text word for word, and the lists derived from it.
library OperationListVector {
    bytes32 internal constant OPERATIONS = 0x60b329d7366897b03545eb9f63f4a707253258ee2e1cd0ba3a8973aa4959e967;
    bytes32 internal constant BIND = 0x4d59cd4487de0a5957f8c83addaac7a1238175aa5c29eeea2fbef57a8f5165ac;
    bytes32 internal constant TEST_A = 0x6b8fd3a153cb2bc403041d7ca7d029d031243d8143d49a248230df9dd07fb723;
    bytes32 internal constant TEST_B = 0x80b4f95cb6d89708133947b68dcfcfb49b7e1e55f8b96984b151e9c446e91a1f;
    bytes32 internal constant NONCE = 0x5555555555555555555555555555555555555555555555555555555555555555;
    bytes32 internal constant DIGEST = 0x872d461409ba5b7731cc6aaf6abe7522b5f985d69ca66eb333e02e008e3ae496;
    /// The digest of the one-entry bind list under the same nonce and version.
    bytes32 internal constant BIND_DIGEST = 0x36de6c95183d8017fd4cd613a64c0862ebf9272ff69c4d5261492d6905305fad;
    address internal constant TARGET = 0x1111111111111111111111111111111111111111;

    /// w0..w11 of `transactionData`: `libid.bind-identity` with `abi.encode(TARGET)`, then `libid.test.a` with `0xff`.
    function words() internal pure returns (bytes32[] memory w) {
        w = new bytes32[](12);
        w[0] = bytes32(uint256(0x20));
        w[1] = bytes32(uint256(2));
        w[2] = bytes32(uint256(0x40));
        w[3] = bytes32(uint256(0xc0));
        w[4] = BIND;
        w[5] = bytes32(uint256(0x40));
        w[6] = bytes32(uint256(0x20));
        w[7] = bytes32(uint256(uint160(TARGET)));
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

    /// The vector's words with word `i` replaced by `value`.
    function withWord(uint256 i, bytes32 value) internal pure returns (bytes memory) {
        bytes32[] memory w = words();
        w[i] = value;
        return join(w);
    }

    /// The one-entry bind list: `libid.bind-identity` with `abi.encode(TARGET)`.
    function bindOnly() internal pure returns (bytes memory) {
        return operationList(BIND, abi.encode(TARGET));
    }
}
