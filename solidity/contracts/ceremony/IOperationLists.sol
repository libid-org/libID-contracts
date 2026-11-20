// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title IOperationLists - what a Consumer that accepts Operation Lists reverts.
/// @notice The list is `abi.encode(Operation[])` of `struct Operation { bytes32 domain; bytes data; }`
///         (chain profiles REQ-CHAIN-07B), committed under `keccak256("libid.operations")`.
interface IOperationLists {
    /// The proof names neither this Consumer's domain nor `libid.operations` (REQ-COMMON-06A).
    error ForeignOperationDomain(bytes32 operationDomain);
    /// The bytes are not the canonical encoding of an Operation List (REQ-CHAIN-07B).
    error NoncanonicalOperationList();
    /// No entry is under this Consumer's domain (REQ-COMMON-01I).
    error NoOwnOperation();
    /// More than one entry is under this Consumer's domain (REQ-COMMON-01I).
    error SeveralOwnOperations();
}
