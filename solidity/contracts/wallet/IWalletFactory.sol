// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title IWalletFactory - deploys wallets at addresses fixed by identity.
/// @notice Constructor: `WalletFactory(address walletImplementation)`, the implementation of a UUPS
///         proxy initialized with `initialize(owner)` and deployed under a `LibidFactory` name, so it
///         has one address on every chain. Deploys through `Create3` with
///         `salt = identityOf(platformId, idNode)` (`IIdentityValidator.sol`) from the proxy's address,
///         and initializes the genesis identity in the same call: one wallet per identity.
///         The owner (Ownable2Step, not renounceable) upgrades the factory, and so chooses the code of
///         wallets not yet created, funds already sent to their addresses included; wallets already
///         created keep theirs. Before launch the owner belongs behind a Safe and a timelock.
///         It cannot serve as ERC-4337 `initCode`: ERC-7562 [OP-031] lets deployment's one CREATE2 deploy
///         only the sender, and `Create3`'s deploys an intermediate proxy. Wallets are created by
///         plain transactions.
interface IWalletFactory {
    event WalletCreated(address indexed wallet, bytes32 indexed platformId, bytes32 indexed idNode);

    /// Ownership cannot be renounced.
    error RenounceDisabled();

    /// Once, through the proxy.
    function initialize(address owner_) external;

    /// Anyone may call. Returns the wallet's address, deploying it first if it does not exist;
    /// emits `WalletCreated` only when it deploys.
    function createWallet(bytes32 platformId, bytes32 idNode) external returns (address wallet);

    /// The WebWallet implementation new wallets run.
    function walletImplementation() external view returns (address);

    function walletAddress(bytes32 platformId, bytes32 idNode) external view returns (address);
}
