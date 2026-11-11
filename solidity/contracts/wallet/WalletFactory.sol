// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

import {Create3} from "../factory/Create3.sol";
import {identityOf} from "./IIdentityValidator.sol";
import {IWalletFactory} from "./IWalletFactory.sol";
import {IWebWallet} from "./IWebWallet.sol";

/// @title WalletFactory - deploys WebWallets at addresses fixed by identity.
/// @notice Immutable, no owner. A wallet's address depends on this factory's address and
///         `(platformId, idNode)` only.
contract WalletFactory is IWalletFactory {
    address private immutable WALLET_IMPLEMENTATION;

    constructor(address walletImplementation) {
        WALLET_IMPLEMENTATION = walletImplementation;
    }

    function createWallet(bytes32 platformId, bytes32 idNode) external returns (address wallet) {
        bytes memory init = abi.encodeCall(IWebWallet.initialize, (abi.encode(platformId, idNode)));
        wallet = Create3.deploy(
            identityOf(platformId, idNode),
            abi.encodePacked(type(ERC1967Proxy).creationCode, abi.encode(WALLET_IMPLEMENTATION, init))
        );
        emit WalletCreated(wallet, platformId, idNode);
    }

    function walletAddress(bytes32 platformId, bytes32 idNode) external view returns (address) {
        return Create3.addressOf(identityOf(platformId, idNode), address(this));
    }
}
