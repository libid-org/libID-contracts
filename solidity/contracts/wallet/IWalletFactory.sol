// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title IWalletFactory - deploys wallets at addresses fixed by identity.
/// @notice Constructor: `WalletFactory(address walletImplementation)`. Immutable, no owner, no
///         proxy; deployed under a `LibidFactory` name, so it has one address on every chain.
///         A new version is a new factory. Deploys through `Create3` with
///         `salt = keccak256(abi.encode(platformId, idNode, index))`, and initializes the
///         genesis identity in the same call. Index 0 is the identity's canonical wallet;
///         other indexes are further wallets with the same genesis identity.
interface IWalletFactory {
    event WalletCreated(address indexed wallet, bytes32 indexed platformId, bytes32 indexed idNode, uint256 index);

    /// Anyone may call. Reverts when the wallet exists.
    function createWallet(bytes32 platformId, bytes32 idNode, uint256 index) external returns (address wallet);

    function walletAddress(bytes32 platformId, bytes32 idNode, uint256 index) external view returns (address);
}
