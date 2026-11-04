// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @notice A contract `IdentityRegistry.bindWithFeeCall` pays a bind's service fee to.
/// @dev The registry calls `onBindFee` once the binding is written, with the fee
///      as the call's value, and accepts only this function's selector back.
interface IBindFeeReceiver {
    /// @notice Take a bind's service fee.
    /// @param binder The address the proof bound, which sent the bind.
    /// @param platformId The platform the identity was proved on.
    /// @param handleNode The handle node the bind wrote.
    /// @param sessionId The bind's Authorization Digest, as `BindFeePaid` logs it.
    /// @param feeData What the bind's sender passed for this receiver, as given.
    /// @return `IBindFeeReceiver.onBindFee.selector`, to accept the fee.
    function onBindFee(
        address binder,
        bytes32 platformId,
        bytes32 handleNode,
        bytes32 sessionId,
        bytes calldata feeData
    ) external payable returns (bytes4);
}
