// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title IWalletForwarder
/// @notice The EIP-7702 delegate: routes by the account's release slot; `reset` is its only setup.
interface IWalletForwarder {
    /// Any call but an empty one, before `reset` filled the release slot.
    error NotSetUp();

    function FACTORY() external view returns (address);
}
