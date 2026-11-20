// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title IOperationLists - what a Consumer that accepts Operation Lists reverts.
/// @notice The list is `abi.encode(Operation[])` of `struct Operation { bytes32 domain; bytes32 dataHash; }`
///         (chain profiles REQ-CHAIN-07B), committed under `keccak256("libid.operations")`.
interface IOperationLists {
    /// The bytes are not the canonical encoding of an Operation List (REQ-CHAIN-07B).
    error NoncanonicalOperationList();
    /// An entry is itself under `libid.operations` (REQ-COMMON-01I).
    error NestedOperationList();
    /// No entry under a domain this Consumer owns commits the call's data (REQ-COMMON-01I).
    error NoOwnOperation();
    /// More than one entry under this Consumer's domains, where its domains commit no chain
    /// or more than one commits the call's data (REQ-COMMON-01I).
    error SeveralOwnOperations();
}
