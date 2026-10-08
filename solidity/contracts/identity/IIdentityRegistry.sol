// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {HandleNormalizer} from "../handles/HandleNormalizer.sol";

/// @notice What other contracts, `HandleEscrow` among them, ask the identity
///         registry.
interface IIdentityRegistry {
    /// `handles.json` names no such platform, or a resolver was asked about
    /// one that has never bound and cannot verify now.
    error UnknownPlatform(bytes32 platformId);
    /// Text the platform's rules refuse, with the normalizer's reason.
    error UnusableHandle(HandleNormalizer.Problem problem);

    /// @notice The holder of this handle node, and when it was last proved.
    ///         The holder is zero if never proved or retired; a retired node
    ///         keeps its `observedAt`.
    function handleBinding(bytes32 handleNode) external view returns (address holder, uint64 observedAt);

    /// @notice The node a handle is bound under: normalized with the
    ///         platform's rules, then `SHA256(handle tag || handle)`. Reverts
    ///         `UnusableHandle` for text no binding can have, and
    ///         `UnknownPlatform` for a platform `handles.json` does not name.
    function handleNodeOf(bytes32 platformId, string calldata handle) external view returns (bytes32 handleNode);

    /// @notice Whether `bind` can bind a holder on this platform now.
    function acceptsBindings(bytes32 platformId) external view returns (bool);
}
