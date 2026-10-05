// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {HandleNormalizer} from "./HandleNormalizer.sol";

/// @notice What other contracts, `HandleEscrow` among them, ask the identity
///         registry.
interface IIdentityRegistry {
    /// This platform is not configured.
    error UnknownPlatform(bytes32 platformId);
    /// Text the platform's rules refuse, with the normalizer's reason.
    error UnusableHandle(HandleNormalizer.Problem problem);

    /// @notice The holder of this handle node, and when it was last proved.
    ///         The holder is zero if never proved or retired; a retired node
    ///         keeps its `observedAt`.
    function handleBinding(bytes32 handleNode) external view returns (address holder, uint64 observedAt);

    /// @notice `keccak256` of a handle normalized under the platform's current
    ///         rules. Reverts `UnknownPlatform` or `UnusableHandle`.
    function handleHashOf(bytes32 platformId, string calldata handle) external view returns (bytes32 handleHash);

    /// @notice A handle normalized under the platform's current rules. Reverts
    ///         as `handleHashOf` does.
    function normalizeHandle(bytes32 platformId, string calldata handle)
        external
        view
        returns (string memory normalized);

    /// @notice The node a handle hashes to under the platform's current rules.
    ///         Reverts as `handleHashOf` does.
    function handleNodeOf(bytes32 platformId, string calldata handle) external view returns (bytes32 handleNode);

    /// @notice The node of a handle given as `handleHash`: the node this system
    ///         binds, for any platform id.
    function handleNodeOfHash(bytes32 platformId, bytes32 handleHash) external view returns (bytes32 handleNode);

    /// @notice Whether `bind` can bind a holder on this platform now.
    function acceptsBindings(bytes32 platformId) external view returns (bool);

    /// @notice The holder of this handle, normalized on chain, and when it was
    ///         last proved. `(0, 0)` for text the rules refuse; a retired
    ///         handle keeps its `observedAt`. Reverts `UnknownPlatform` for a
    ///         platform that is not wired.
    function handleBindingOf(bytes32 platformId, string calldata handle)
        external
        view
        returns (address holder, uint64 observedAt);

    /// @notice The holder that proved this id, and when. Reverts
    ///         `UnknownPlatform` for a platform that is not wired.
    function idBindingOf(bytes32 platformId, string calldata id)
        external
        view
        returns (address holder, uint64 observedAt);

    /// @notice The handle this id proved most recently, and whether the handle
    ///         still belongs to this identity. Empty for an id never proved.
    function handleOfId(bytes32 platformId, string calldata id)
        external
        view
        returns (string memory handle, bool current);

    /// @notice The id of the identity this handle belongs to now. Empty when
    ///         none does, or for text the rules refuse.
    function idOfHandle(bytes32 platformId, string calldata handle) external view returns (string memory id);
}
