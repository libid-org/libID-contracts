// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @notice The registry functions every contract built on libID's `LibID` library calls.
/// @dev Deployed integrators rely on these through `LibID` and cannot rebuild: they must
///      never change. A new shape means a new deployment and a new library.
interface ILibIDRegistry {
    /// @notice The holder of this handle node (zero if none), and when it was last proved.
    function handleBinding(bytes32 handleNode) external view returns (address holder, uint64 observedAt);

    /// @notice The node a handle as typed is bound under. Reverts `UnknownPlatform`
    ///         for a platform the registry does not know.
    function handleNodeOf(bytes32 platformId, string calldata handle) external view returns (bytes32 handleNode);

    /// @notice The holder of a handle as typed, or zero if none.
    function resolveHandle(bytes32 platformId, string calldata handle) external view returns (address);

    /// @notice The holder of an id node, or zero if none.
    function resolveId(bytes32 idNode) external view returns (address);

    /// @notice The handle a holder disclosed and its platform, while it still holds it.
    function primaryHandleOf(address holder) external view returns (bytes32 platformId, string memory handle);
}
