// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title IWalletFactoryOnboarding - create a wallet and run its first direct batch in one call.
interface IWalletFactoryOnboarding {
    /// Anyone may call. Creates the wallet if needed, then calls its `execute(mode, data)`, forwarding
    /// `msg.value`. No privilege: an `AUTHORIZED_MODE` batch gets the wallet's end check.
    function createAndExecute(bytes32 platformId, bytes32 idNode, uint256 salt, bytes32 mode, bytes calldata data)
        external
        payable
        returns (address wallet);
}

/// @title IWalletFactory - deploys wallets at addresses fixed by identity.
/// @notice Constructor: `WalletFactory(address walletImplementation)`, the implementation of a UUPS
///         proxy initialized with `initialize(owner)` and deployed under a `LibidFactory` name, so it
///         has one address on every chain. Deploys through `Create3` from the proxy's address, with
///         `identityOf(platformId, idNode)` (`IIdentityValidator.sol`) as the CREATE3 salt for `salt` 0
///         and `keccak256(abi.encode(identityOf(platformId, idNode), salt))` for any other, and installs
///         the genesis identity in the same call with install data
///         `abi.encode(platformId, idNode, salt, bytes(""), Policy())`: one wallet per identity and salt.
///         A new salt gives the identity a new wallet, for one an attacker holds at quorum.
///         The owner (Ownable2Step, not renounceable) upgrades the factory, and so chooses the code of
///         wallets not yet created, funds already sent to their addresses included; wallets already
///         created keep theirs.
///         It cannot serve as ERC-4337 `initCode`: ERC-7562 [OP-031] lets deployment's one CREATE2 deploy
///         only the sender, and `Create3`'s deploys an intermediate proxy. Wallets are created by
///         plain transactions.
interface IWalletFactory is IWalletFactoryOnboarding {
    event WalletCreated(address indexed wallet, bytes32 indexed platformId, bytes32 indexed idNode, uint256 salt);

    /// Ownership cannot be renounced.
    error RenounceDisabled();

    /// Once, through the proxy.
    function initialize(address owner_) external;

    /// Anyone may call. Returns the wallet's address, deploying it first if it does not exist;
    /// emits `WalletCreated` only when it deploys.
    function createWallet(bytes32 platformId, bytes32 idNode, uint256 salt) external returns (address wallet);

    /// The WebWallet implementation new wallets run.
    function walletImplementation() external view returns (address);

    function walletAddress(bytes32 platformId, bytes32 idNode, uint256 salt) external view returns (address);
}
