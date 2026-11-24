// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {IIdentityRegistry} from "../identity/IIdentityRegistry.sol";

/// @notice The escrow functions every contract built on libID's `LibID` library calls.
/// @dev Deployed integrators rely on these through `LibID` and cannot rebuild: they must
///      never change. A new shape means a new deployment and a new library. `registry` returns
///      an address in the ABI.
interface ILibIDEscrow {
    /// @notice The identity registry this escrow resolves through.
    function registry() external view returns (IIdentityRegistry);

    /// @notice Pay `amount` of `token` to a handle node: to its holder, else into escrow.
    function deposit(bytes32 platformId, bytes32 handleNode, address token, uint256 amount) external payable;

    /// @notice Return the caller's contribution to a node, once refundable, to `recipient`.
    function refund(bytes32 handleNode, address token, address recipient) external;

    /// @notice What is booked under `sender` for a node, and when `refund` opens for it.
    function contribution(bytes32 handleNode, address token, address sender)
        external
        view
        returns (uint256 amount, uint64 refundableAt);
}
