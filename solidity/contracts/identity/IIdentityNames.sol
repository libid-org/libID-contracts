// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {HandleNormalizer} from "./HandleNormalizer.sol";

/// @notice What another contract asks the naming system.
///
/// @dev `IdentityNames` declares that it implements this, so a change to one
///      of these signatures in the contract fails to compile instead of
///      leaving a caller, `HandleEscrow` among them, calling a selector that
///      no longer exists.
///
///      `HandleNormalizer.Rules` IS imported rather than redeclared. A copy
///      would be a second definition of the struct the naming system stores,
///      and the two would drift the first time a field is added.
interface IIdentityNames {
    /// @notice The wallet that last proved this handle node, and when.
    ///
    /// @dev A zero owner means nobody holds it: never proved, or retired
    ///      because the account that held it renamed away.
    function byHandle(bytes32 handleNode) external view returns (address owner, uint64 observedAt);

    /// @notice How this platform's handles normalize, as configured now.
    /// @dev Reverts for a platform that is not usable.
    function rulesOf(bytes32 platformId) external view returns (HandleNormalizer.Rules memory);

    /// @notice Whether a new identity claim can bind a holder on this platform
    ///         now.
    function acceptsClaims(bytes32 platformId) external view returns (bool);
}
