// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title IWalletFactory - deploys wallets at addresses fixed by identity.
/// @notice Constructor: `WalletFactory(address walletImplementation)`. Immutable, no owner, no
///         proxy; deployed under a `LibidFactory` name, so it has one address on every chain.
///         A new version is a new factory. Deploys through `Create3` with
///         `salt = identityOf(platformId, idNode)` (`IIdentityValidator.sol`), and initializes the
///         genesis identity in the same call: one wallet per identity.
///         It cannot serve as ERC-4337 `initCode`: ERC-7562 lets deployment's one CREATE2 deploy
///         only the sender, and `Create3`'s deploys an intermediate proxy. Wallets are created by
///         plain transactions.
interface IWalletFactory {
    event WalletCreated(address indexed wallet, bytes32 indexed platformId, bytes32 indexed idNode);

    /// Anyone may call. Returns the wallet's address, deploying it first if it does not exist;
    /// emits `WalletCreated` only when it deploys.
    function createWallet(bytes32 platformId, bytes32 idNode) external returns (address wallet);

    function walletAddress(bytes32 platformId, bytes32 idNode) external view returns (address);
}
