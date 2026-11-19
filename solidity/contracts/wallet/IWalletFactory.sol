// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title IWalletFactory
/// @notice Publishes numbered WebWallet releases and deploys factory wallets.
/// @dev `latest()` keeps its selector and return layout across factory upgrades: WalletForwarder reads it.
interface IWalletFactory {
    event Published(uint64 indexed version, address indexed implementation);
    event WalletCreated(address indexed wallet, bytes32 indexed platformId, bytes32 indexed idNode, uint256 salt);

    error ImplementationWithoutCode(address implementation);
    error WrongReleaseVersion(uint64 expected, uint64 reported);
    error WrongReleaseFactory(address reported);
    /// Ownership cannot be renounced.
    error RenounceDisabled();

    function initialize(address owner) external;
    function owner() external view returns (address);

    /// Owner only. `implementation` has code, reports `latest().version + 1` and this factory.
    function publish(address implementation) external;
    function latest() external view returns (address implementation, uint64 version);
    function release(uint64 version) external view returns (address implementation);

    function walletAddress(bytes32 platformId, bytes32 idNode, uint256 salt) external view returns (address);
    function createWallet(bytes32 platformId, bytes32 idNode, uint256 salt) external returns (address wallet);
    function createAndExecute(bytes32 platformId, bytes32 idNode, uint256 salt, bytes32 mode, bytes calldata data)
        external
        payable
        returns (address wallet);
}
