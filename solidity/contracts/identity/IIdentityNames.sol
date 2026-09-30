// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {HandleNormalizer} from "./HandleNormalizer.sol";

/// @notice What other contracts, `HandleEscrow` among them, ask the naming
///         system.
interface IIdentityNames {
    /// This platform has no keyspace configured.
    error UnknownPlatform(bytes32 platformId);
    /// Text the platform's rules refuse, with the normalizer's reason.
    error UnusableHandle(HandleNormalizer.Problem problem);

    /// @notice The wallet that holds this handle node, and when it was last
    ///         proved. The owner is zero if never proved or retired; a
    ///         retired node keeps its `observedAt`.
    function byHandle(bytes32 handleNode) external view returns (address owner, uint64 observedAt);

    /// @notice `keccak256` of a handle normalized under the platform's current
    ///         rules. Reverts `UnknownPlatform` or `UnusableHandle`.
    function handleHashOf(bytes32 platformId, string calldata handle) external view returns (bytes32 handleHash);

    /// @notice The node a handle keys to under the platform's current rules.
    ///         Reverts as `handleHashOf` does.
    function nodeOf(bytes32 platformId, string calldata handle) external view returns (bytes32 handleNode);

    /// @notice The node of a handle given as `handleHash`: the key this system
    ///         binds, for any platform id.
    function nodeOfHash(bytes32 platformId, bytes32 handleHash) external view returns (bytes32 handleNode);

    /// @notice Whether `bind` can bind a holder on this platform now.
    function acceptsBindings(bytes32 platformId) external view returns (bool);
}
