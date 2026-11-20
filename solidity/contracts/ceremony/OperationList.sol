// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {memoryWord} from "../common/MemoryWord.sol";
import {IOperationLists} from "./IOperationLists.sol";

/// @title OperationList
/// @notice The Operation List of ceremony-common section 5: one ceremony's
///         Authorized Transaction Data committing an entry for each of several
///         Consumers, as its domain and `keccak256(data)` (chain profiles §3.3).
/// @dev A Consumer whose verified domain is `DOMAIN` passes the list and its
///      own `data` to `select`, then handles the returned domain and `data` as
///      a single operation. Other entries are read only for their domain and
///      data hash (REQ-COMMON-01J).
library OperationList {
    /// @notice keccak256("libid.operations")
    bytes32 internal constant DOMAIN = keccak256("libid.operations");

    /// @notice The domain of the one entry among `own` whose data hash is `keccak256(data)` (REQ-COMMON-01I).
    /// @param chainBound Every domain in `own` fixes data committing a chain id the Consumer checks,
    ///        so the list may hold one entry of them per chain.
    function select(bytes memory list, bytes memory data, bytes32[] memory own, bool chainBound)
        internal
        pure
        returns (bytes32 domain)
    {
        uint256 len = list.length;
        if (len < 64 || (len - 64) % 64 != 0 || memoryWord(list, 0) != bytes32(uint256(0x20))) {
            revert IOperationLists.NoncanonicalOperationList();
        }
        uint256 n = (len - 64) / 64;
        if (memoryWord(list, 32) != bytes32(n)) revert IOperationLists.NoncanonicalOperationList();

        bytes32 hash = keccak256(data);
        uint256 candidates;
        uint256 matches;
        for (uint256 i; i < n; ++i) {
            bytes32 d = memoryWord(list, 64 + 64 * i);
            if (d == DOMAIN) revert IOperationLists.NestedOperationList();
            if (!_contains(own, d)) continue;
            ++candidates;
            if (memoryWord(list, 96 + 64 * i) == hash) {
                ++matches;
                domain = d;
            }
        }
        if (matches > 1 || (candidates > 1 && !chainBound)) revert IOperationLists.SeveralOwnOperations();
        if (matches == 0) revert IOperationLists.NoOwnOperation();
    }

    function _contains(bytes32[] memory set, bytes32 d) private pure returns (bool) {
        for (uint256 i; i < set.length; ++i) {
            if (set[i] == d) return true;
        }
        return false;
    }
}
