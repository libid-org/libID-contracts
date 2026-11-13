// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @notice What other contracts ask the handle escrow.
interface IHandleEscrow {
    /// @notice Take everything held for a node in each of `tokens`. The caller
    ///         must be the node's holder; `recipient` is its choice.
    function claim(bytes32 handleNode, address[] calldata tokens, address recipient) external;
}
