// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title IWalletFactory - deploys wallets at addresses fixed by identity.
/// @notice Constructor: `WalletFactory(address walletImplementation)`. Immutable, no owner, no
///         proxy; deployed under a `LibidFactory` name, so it has one address on every chain.
///         A new version is a new factory. Deploys through `Create3` with
///         `salt = identityOf(platformId, idNode)` (`IIdentityValidator.sol`), and initializes the
///         genesis identity in the same call: one wallet per identity.
interface IWalletFactory {
    event WalletCreated(address indexed wallet, bytes32 indexed platformId, bytes32 indexed idNode);

    /// Anyone may call. Reverts when the wallet exists.
    function createWallet(bytes32 platformId, bytes32 idNode) external returns (address wallet);

    function walletAddress(bytes32 platformId, bytes32 idNode) external view returns (address);
}
