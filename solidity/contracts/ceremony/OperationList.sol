// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title OperationList
/// @notice The Operation List of ceremony-common section 5: one ceremony's
///         Authorized Transaction Data carrying an entry for each of several
///         Consumers, `abi.encode(Operation[])` (chain profiles REQ-CHAIN-07B).
/// @dev A Consumer passes the verified domain and data through `select` and
///      handles what comes back as it handles a single operation. Only the
///      entry domains are read; other entries' `data` is never decoded
///      (REQ-COMMON-01J).
library OperationList {
    struct Operation {
        bytes32 domain;
        bytes data;
    }

    /// @notice keccak256("libid.operations")
    bytes32 internal constant DOMAIN = keccak256("libid.operations");

    /// The list is not the one `abi.encode` of the entries it decodes to (REQ-CHAIN-07B).
    error NoncanonicalOperationList();
    /// An entry is itself under `libid.operations` (REQ-COMMON-01I).
    error NestedOperationList();
    /// No entry is under a domain this Consumer owns (REQ-COMMON-01I).
    error NoOwnOperation();
    /// More than one entry is under a domain this Consumer owns (REQ-COMMON-01I).
    error SeveralOwnOperations();

    /// @notice `(domain, data)` as given, or under `libid.operations` the one
    ///         entry among `own` (REQ-COMMON-01G).
    function select(bytes32 domain, bytes memory data, bytes32[] memory own)
        internal
        pure
        returns (bytes32, bytes memory)
    {
        if (domain != DOMAIN) return (domain, data);
        Operation[] memory entries = abi.decode(data, (Operation[]));
        if (keccak256(abi.encode(entries)) != keccak256(data)) revert NoncanonicalOperationList();

        uint256 found = type(uint256).max;
        for (uint256 i; i < entries.length; ++i) {
            bytes32 d = entries[i].domain;
            if (d == DOMAIN) revert NestedOperationList();
            if (!_contains(own, d)) continue;
            if (found != type(uint256).max) revert SeveralOwnOperations();
            found = i;
        }
        if (found == type(uint256).max) revert NoOwnOperation();
        return (entries[found].domain, entries[found].data);
    }

    /// @notice `select` for a Consumer that owns one domain besides `libid.operations`.
    function select(bytes32 domain, bytes memory data, bytes32 own) internal pure returns (bytes32, bytes memory) {
        bytes32[] memory owned = new bytes32[](1);
        owned[0] = own;
        return select(domain, data, owned);
    }

    function _contains(bytes32[] memory set, bytes32 d) private pure returns (bool) {
        for (uint256 i; i < set.length; ++i) {
            if (set[i] == d) return true;
        }
        return false;
    }
}
