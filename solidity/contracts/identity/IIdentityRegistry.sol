// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @notice What other contracts ask the identity registry. `HandleEscrow` asks
///         who holds a handle node, and checks once that the registry keys
///         identities by node; every other read and the registry's errors are
///         on `IdentityRegistry` itself.
interface IIdentityRegistry {
    /// @notice The holder of this handle node, and when it was last proved.
    ///         The holder is zero if never proved or retired; a retired node
    ///         keeps its `observedAt`.
    function handleBinding(bytes32 handleNode) external view returns (address holder, uint64 observedAt);

    /// @notice True: the keys `handleBinding` takes are the handle nodes a
    ///         circuit outputs. A registry without this function does not
    ///         say so.
    function nodeKeyed() external pure returns (bool);
}
