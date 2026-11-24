// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {IOperationLists} from "../ceremony/IOperationLists.sol";
import {ILibIDRegistry} from "./ILibIDRegistry.sol";

/// @notice What other contracts ask the identity registry.
interface IIdentityRegistry is ILibIDRegistry, IOperationLists {
    /// No ceremony profile names the platform.
    error UnknownPlatform(bytes32 platformId);

    /// @notice Whether a platform can be bound right now. Reverts `UnknownPlatform`
    ///         for a platform the registry does not know.
    function acceptsBindings(bytes32 platformId) external view returns (bool);

    /// @notice True: `handleBinding` is keyed by the handle nodes a circuit outputs.
    function nodeKeyed() external pure returns (bool);
}
