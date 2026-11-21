// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Proxy} from "@openzeppelin/contracts/proxy/Proxy.sol";
import {Address} from "@openzeppelin/contracts/utils/Address.sol";

import {IWalletFactory} from "./IWalletFactory.sol";
import {IWalletCore} from "./IWebWallet.sol";
import {WalletRelease} from "./WalletRelease.sol";

/// @title WalletProxy - a factory wallet: routes every call with calldata by its release slot.
/// @notice The constructor writes the factory's latest release to the slot and initializes the genesis.
contract WalletProxy is Proxy {
    constructor(address factory, bytes32 platformId, bytes32 idNode, uint256 salt) {
        (address implementation, uint64 version) = IWalletFactory(factory).latest();
        WalletRelease.write(implementation, version);
        Address.functionDelegateCall(implementation, abi.encodeCall(IWalletCore.initialize, (platformId, idNode, salt)));
    }

    /// Plain ETH arrives with the 2,300-gas stipend.
    receive() external payable {}

    function _implementation() internal view override returns (address) {
        return WalletRelease.implementation();
    }
}
