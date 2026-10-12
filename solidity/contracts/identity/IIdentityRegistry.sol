// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @notice What other contracts ask the identity registry.
interface IIdentityRegistry {
    /// @notice The holder of this handle node (zero if none), and when it was last proved.
    function handleBinding(bytes32 handleNode) external view returns (address holder, uint64 observedAt);

    /// @notice The node a handle as typed is bound under. Reverts `UnknownPlatform`
    ///         for a platform the registry does not know.
    function handleNodeOf(bytes32 platformId, string calldata handle) external view returns (bytes32 handleNode);

    /// @notice Whether a platform can be bound right now.
    function acceptsBindings(bytes32 platformId) external view returns (bool);

    /// @notice True: `handleBinding` is keyed by the handle nodes a circuit outputs.
    function nodeKeyed() external pure returns (bool);
}
