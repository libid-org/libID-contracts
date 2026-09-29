// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @notice What other contracts, `HandleEscrow` among them, ask the naming
///         system.
interface IIdentityNames {
    /// This platform has no keyspace configured.
    error UnknownPlatform(bytes32 platformId);

    /// @notice The wallet that last proved this handle node, and when. Zero if
    ///         never proved or retired.
    function byHandle(bytes32 handleNode) external view returns (address owner, uint64 observedAt);

    /// @notice `keccak256` of a handle normalized under the platform's current
    ///         rules. Reverts `UnknownPlatform` or `UnusableHandle`.
    function handleHashOf(bytes32 platformId, string calldata handle) external view returns (bytes32 handleHash);

    /// @notice The node a handle keys to under the platform's current rules.
    ///         Reverts as `handleHashOf` does.
    function nodeOf(bytes32 platformId, string calldata handle) external view returns (bytes32 handleNode);

    /// @notice Whether a new identity claim can bind a holder on this platform
    ///         now.
    function acceptsClaims(bytes32 platformId) external view returns (bool);
}
