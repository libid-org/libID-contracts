// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IWalletFactory} from "./IWalletFactory.sol";
import {IWalletForwarder} from "./IWalletForwarder.sol";
import {IWalletCore, IWebWallet} from "./IWebWallet.sol";
import {WalletRelease} from "./WalletRelease.sol";

/// @title WalletForwarder - the EIP-7702 delegate of a key that runs a WebWallet.
/// @notice Empty calldata returns at once. Other calls route by the account's release slot. `reset` always goes
///         to the factory's latest release, which writes the slot, and only from the key's own top-level
///         transaction. With an empty slot they revert `NotSetUp`.
/// @dev Ownerless and never upgraded.
contract WalletForwarder is IWalletForwarder {
    address public immutable FACTORY;
    address private immutable SELF = address(this);

    constructor(address factory) {
        FACTORY = factory;
    }

    receive() external payable {
        if (address(this) == SELF) revert IWebWallet.NotDelegated();
    }

    fallback() external payable {
        _route();
    }

    function _route() private {
        if (address(this) == SELF) revert IWebWallet.NotDelegated();
        address target;
        if (msg.sig == IWalletCore.reset.selector) {
            if (msg.sender != address(this) || tx.origin != address(this)) revert IWebWallet.ResetRefused();
            (target,) = IWalletFactory(FACTORY).latest();
        } else {
            target = WalletRelease.implementation();
        }
        if (target == address(0)) revert NotSetUp();
        assembly ("memory-safe") {
            calldatacopy(0, 0, calldatasize())
            let ok := delegatecall(gas(), target, 0, calldatasize(), 0, 0)
            returndatacopy(0, 0, returndatasize())
            if iszero(ok) { revert(0, returndatasize()) }
            return(0, returndatasize())
        }
    }
}
