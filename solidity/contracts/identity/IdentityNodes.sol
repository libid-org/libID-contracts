// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @notice Turns a platform identity into the fixed-width node it is stored
///         under.
///
/// @dev The shape follows ENS: hash the parts, combine them into one `bytes32`
///      node, and index storage by the node rather than by a string. Fixed
///      width keeps a mapping cheap and a node unambiguous.
///
///      It differs from ENS in one way that matters. `abi.encode` is used
///      rather than concatenation, and a version tag leads every preimage, so
///      two node kinds can never produce the same node.
///
///      A node cannot be turned back into a string. That is a property of the
///      hash, not a shortcoming to route around: ENS answers the reverse
///      direction by storing the string, and so does this system.
library IdentityNodes {
    /// Separates an id node from a handle node.
    ///
    /// Without it, a handle that reads as a number and an id that is that
    /// number produce the same node. Numeric handles are legal on X, and an old
    /// identity's id is short, so the collision is reachable rather than
    /// theoretical.
    bytes32 internal constant ID_NODE_V1 = keccak256(bytes("libid.identity.id-node.v1"));
    bytes32 internal constant HANDLE_NODE_V1 = keccak256(bytes("libid.identity.handle-node.v1"));

    /// @notice The node an id is stored under.
    /// @param platformId Which platform, as `keccak256` of its platform key.
    /// @param id         The identity's immutable id, as the platform issued it.
    function idNode(bytes32 platformId, string memory id) internal pure returns (bytes32) {
        return keccak256(abi.encode(ID_NODE_V1, platformId, keccak256(bytes(id))));
    }

    /// @notice The node a handle is stored under.
    /// @param platformId       Which platform, as `keccak256` of its platform key.
    /// @param normalizedHandle The handle AFTER normalization. Passing a raw
    ///                         handle here writes a node no reader will find.
    function handleNode(bytes32 platformId, string memory normalizedHandle) internal pure returns (bytes32) {
        return handleNodeOfHash(platformId, keccak256(bytes(normalizedHandle)));
    }

    /// @notice `handleNode` from the handle's hash, `keccak256(normalized)`.
    function handleNodeOfHash(bytes32 platformId, bytes32 handleHash) internal pure returns (bytes32) {
        return keccak256(abi.encode(HANDLE_NODE_V1, platformId, handleHash));
    }
}
