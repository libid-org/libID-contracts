// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @notice What other contracts ask the identity registry.
interface IIdentityRegistry {
    /// @notice One identity a holder proved, as its list reports it.
    /// @dev `handleCurrent` is false once another identity proved `handleNode`.
    struct Identity {
        bytes32 platformId;
        bytes32 idNode;
        bytes32 handleNode;
        bool handleCurrent;
    }

    /// No ceremony profile names the platform.
    error UnknownPlatform(bytes32 platformId);

    /// @notice The holder of this handle node (zero if none), and when it was last proved.
    function handleBinding(bytes32 handleNode) external view returns (address holder, uint64 observedAt);

    /// @notice The node a handle as typed is bound under. Reverts `UnknownPlatform`
    ///         for a platform the registry does not know.
    function handleNodeOf(bytes32 platformId, string calldata handle) external view returns (bytes32 handleNode);

    /// @notice Whether a platform can be bound right now. Reverts `UnknownPlatform`
    ///         for a platform the registry does not know.
    function acceptsBindings(bytes32 platformId) external view returns (bool);

    /// @notice True: `handleBinding` is keyed by the handle nodes a circuit outputs.
    function nodeKeyed() external pure returns (bool);

    /// @notice Binds the proved identity to the caller, disclosing no handle.
    function bindPrivately(
        bytes32 platformId,
        uint16 verifierVersion,
        bytes calldata payload,
        uint256 feeAmount,
        address feeReceiver
    ) external payable;

    /// @notice How many identities a holder has proved.
    function identityCount(address holder) external view returns (uint256);

    /// @notice A page of a holder's identities, on every platform.
    function identitiesOf(address holder, uint256 from, uint256 limit) external view returns (Identity[] memory);
}
