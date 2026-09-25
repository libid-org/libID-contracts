// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @notice What another contract asks the naming system.
///
/// @dev `IdentityNames` declares that it implements this, so a change to one
///      of these signatures in the contract fails to compile instead of
///      leaving a caller, `HandleEscrow` among them, calling a selector that
///      no longer exists.
interface IIdentityNames {
    /// @notice The wallet that last proved this handle node, and when.
    ///
    /// @dev A zero owner means nobody holds it: never proved, or retired
    ///      because the account that held it renamed away.
    function byHandle(bytes32 handleNode) external view returns (address owner, uint64 observedAt);

    /// @notice The node a handle keys to under the platform's current rules.
    /// @dev Reverts `IdentityNames.UnknownPlatform` for a platform with no
    ///      keyspace, and `IdentityNames.UnusableHandle` for text the rules
    ///      refuse.
    function nodeOf(bytes32 platformId, string calldata handle) external view returns (bytes32 handleNode);

    /// @notice Whether a new identity claim can bind a holder on this platform
    ///         now.
    function acceptsClaims(bytes32 platformId) external view returns (bool);
}
