// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {memoryWord} from "../common/MemoryWord.sol";
import {IOperationLists} from "./IOperationLists.sol";

/// @title OperationList
/// @notice The Operation List of ceremony-common section 5: one ceremony's
///         Authorized Transaction Data carrying an entry for each of several
///         Consumers, as its domain and the data that domain fixes (chain
///         profiles §3.3). One action is a one-entry list.
/// @dev A Consumer passes the list and its own domain to `select` and decodes
///      the returned data. Entries under other domains are checked for their
///      encoding only.
library OperationList {
    /// @notice keccak256("libid.operations")
    bytes32 internal constant DOMAIN = keccak256("libid.operations");

    /// @notice One entry: a Consumer's operation domain and the data that domain fixes.
    struct Operation {
        bytes32 domain;
        bytes data;
    }

    /// @notice The data of the one entry under `domain` (REQ-COMMON-01I).
    function select(bytes memory list, bytes32 domain) internal pure returns (bytes memory) {
        uint256[] memory found = find(list, domain);
        if (found.length == 0) revert IOperationLists.NoOwnOperation();
        if (found.length > 1) revert IOperationLists.SeveralOwnOperations();
        return dataAt(list, found[0]);
    }

    /// @notice Where each entry under `domain` starts in `list`, after checking in one pass that
    ///         `list` is exactly `abi.encode` of the entries it decodes to (REQ-CHAIN-07B).
    /// @dev Two decoders of one byte string (the consent page's and this one) must read the same
    ///      entries, so every offset is the running position and padding is zero. `memoryWord`
    ///      reads zeros past the end, so each count and length is checked against the bytes left
    ///      before any position is computed from it.
    function find(bytes memory list, bytes32 domain) internal pure returns (uint256[] memory found) {
        // No Consumer owns `libid.operations`, so no entry under it is anyone's.
        if (domain == DOMAIN) revert IOperationLists.NoOwnOperation();
        uint256 size = list.length;
        if (size < 64 || memoryWord(list, 0) != bytes32(uint256(0x20))) {
            revert IOperationLists.NoncanonicalOperationList();
        }
        uint256 n = uint256(memoryWord(list, 32));
        if (n > (size - 64) / 32) revert IOperationLists.NoncanonicalOperationList();

        found = new uint256[](n);
        uint256 matches;
        // Tuple offsets count from the word after `n`.
        uint256 at = 64 + 32 * n;
        for (uint256 i; i < n; ++i) {
            if (uint256(memoryWord(list, 64 + 32 * i)) != at - 64 || size - at < 96) {
                revert IOperationLists.NoncanonicalOperationList();
            }
            if (uint256(memoryWord(list, at + 32)) != 0x40) revert IOperationLists.NoncanonicalOperationList();
            uint256 len = uint256(memoryWord(list, at + 64));
            uint256 room = size - at - 96;
            if (len > room) revert IOperationLists.NoncanonicalOperationList();
            uint256 padded = (len + 31) & ~uint256(31);
            if (padded > room) revert IOperationLists.NoncanonicalOperationList();
            uint256 tail = len % 32;
            if (tail != 0 && memoryWord(list, at + 96 + len - tail) << (8 * tail) != 0) {
                revert IOperationLists.NoncanonicalOperationList();
            }
            if (memoryWord(list, at) == domain) found[matches++] = at;
            at += 96 + padded;
        }
        if (at != size) revert IOperationLists.NoncanonicalOperationList();
        assembly ("memory-safe") {
            mstore(found, matches)
        }
    }

    /// @notice A copy of the data of the entry that starts at `at`, a position `find` returned.
    function dataAt(bytes memory list, uint256 at) internal pure returns (bytes memory data) {
        uint256 len = uint256(memoryWord(list, at + 64));
        data = new bytes(len);
        assembly ("memory-safe") {
            mcopy(add(data, 0x20), add(add(list, 0x20), add(at, 96)), len)
        }
    }
}
