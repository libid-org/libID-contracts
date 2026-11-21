// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {UUPSUpgradeable} from "@openzeppelin/contracts/proxy/utils/UUPSUpgradeable.sol";
import {OwnableUpgradeable} from "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import {Ownable2StepUpgradeable} from "@openzeppelin/contracts-upgradeable/access/Ownable2StepUpgradeable.sol";

import {Create3} from "../factory/Create3.sol";
import {IWalletFactory} from "./IWalletFactory.sol";
import {IWebWallet} from "./IWebWallet.sol";
import {WalletProxy} from "./WalletProxy.sol";
import {identityOf} from "./WalletStorage.sol";

/// @title WalletFactory - numbered WebWallet releases, and wallets at addresses fixed by identity.
/// @notice A wallet's address depends on this proxy's address and `(platformId, idNode, salt)` only. Salt 0 is
///         `identityOf(platformId, idNode)`, any other `keccak256(abi.encode(platformId, idNode, salt))`.
/// @dev Behind a UUPS proxy; the owner (Ownable2Step, not renounceable) publishes releases and upgrades.
contract WalletFactory is IWalletFactory, UUPSUpgradeable, Ownable2StepUpgradeable {
    /// @custom:oz-upgrades-unsafe-allow state-variable-immutable
    address public immutable REGISTRY;

    /// @custom:storage-location erc7201:libid.storage.WalletFactory
    struct WalletFactoryStorage {
        uint64 latest;
        mapping(uint64 version => address) releases;
    }

    // cast index-erc7201 libid.storage.WalletFactory
    bytes32 private constant WALLET_FACTORY_STORAGE =
        0x64fb8f6b910e30482f0332a63e56176c451f6d54f483f61b5ef32dd8e5fc7600;

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor(address registry) {
        REGISTRY = registry;
        _disableInitializers();
    }

    function initialize(address owner_) external initializer {
        __Ownable_init(owner_);
        __Ownable2Step_init();
    }

    function publish(address implementation) external onlyOwner {
        if (implementation.code.length == 0) revert ImplementationWithoutCode(implementation);
        WalletFactoryStorage storage $ = _s();
        uint64 next = $.latest + 1;
        uint64 reported = IWebWallet(implementation).VERSION();
        if (reported != next) revert WrongReleaseVersion(next, reported);
        address factory = IWebWallet(implementation).FACTORY();
        if (factory != address(this)) revert WrongReleaseFactory(factory);
        address registry = IWebWallet(implementation).REGISTRY();
        if (registry != REGISTRY) revert WrongReleaseRegistry(registry);
        $.latest = next;
        $.releases[next] = implementation;
        emit Published(next, implementation);
    }

    function latest() external view returns (address implementation, uint64 version) {
        WalletFactoryStorage storage $ = _s();
        version = $.latest;
        implementation = $.releases[version];
    }

    function release(uint64 version) external view returns (address) {
        return _s().releases[version];
    }

    function createWallet(bytes32 platformId, bytes32 idNode, uint256 salt) public returns (address wallet) {
        bytes32 create3Salt = _create3Salt(platformId, idNode, salt);
        wallet = Create3.addressOf(create3Salt, address(this));
        if (wallet.code.length != 0) return wallet;
        Create3.deploy(
            create3Salt,
            abi.encodePacked(type(WalletProxy).creationCode, abi.encode(address(this), platformId, idNode, salt))
        );
        emit WalletCreated(wallet, platformId, idNode, salt);
    }

    function createAndExecute(bytes32 platformId, bytes32 idNode, uint256 salt, bytes32 mode, bytes calldata data)
        external
        payable
        returns (address wallet)
    {
        wallet = createWallet(platformId, idNode, salt);
        IWebWallet(wallet).execute{value: msg.value}(mode, data);
    }

    function walletAddress(bytes32 platformId, bytes32 idNode, uint256 salt) external view returns (address) {
        return Create3.addressOf(_create3Salt(platformId, idNode, salt), address(this));
    }

    function owner() public view override(IWalletFactory, OwnableUpgradeable) returns (address) {
        return super.owner();
    }

    /// @dev The upgrade is the only repair lever, so ownership stays.
    function renounceOwnership() public pure override {
        revert RenounceDisabled();
    }

    /// Salt 0 is the identity alone; any other hashes three words, so it is no other genesis's salt 0.
    function _create3Salt(bytes32 platformId, bytes32 idNode, uint256 salt) private pure returns (bytes32) {
        return salt == 0 ? identityOf(platformId, idNode) : keccak256(abi.encode(platformId, idNode, salt));
    }

    function _s() private pure returns (WalletFactoryStorage storage $) {
        assembly ("memory-safe") {
            $.slot := WALLET_FACTORY_STORAGE
        }
    }

    function _authorizeUpgrade(address) internal override onlyOwner {}
}
