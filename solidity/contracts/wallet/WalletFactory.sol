// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {Initializable} from "@openzeppelin/contracts/proxy/utils/Initializable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts/proxy/utils/UUPSUpgradeable.sol";
import {Ownable2StepUpgradeable} from "@openzeppelin/contracts-upgradeable/access/Ownable2StepUpgradeable.sol";

import {Create3} from "../factory/Create3.sol";
import {IIdentityValidator, identityOf} from "./IIdentityValidator.sol";
import {IWalletFactory} from "./IWalletFactory.sol";
import {IWebWallet} from "./IWebWallet.sol";

/// @title WalletFactory - deploys WebWallets at addresses fixed by identity.
/// @notice A wallet's address depends on this factory proxy's address and `(platformId, idNode, salt)` only.
///         The owner chooses, by upgrade, the code of wallets not yet created.
/// @dev Behind a UUPS proxy. The implementation's immutable names the WebWallet implementation,
///      so the factory keeps no storage of its own.
contract WalletFactory is IWalletFactory, Initializable, UUPSUpgradeable, Ownable2StepUpgradeable {
    address private immutable WALLET_IMPLEMENTATION;

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor(address walletImplementation_) {
        WALLET_IMPLEMENTATION = walletImplementation_;
        _disableInitializers();
    }

    function initialize(address owner_) external initializer {
        __Ownable_init(owner_);
        __Ownable2Step_init();
    }

    function walletImplementation() external view returns (address) {
        return WALLET_IMPLEMENTATION;
    }

    function createWallet(bytes32 platformId, bytes32 idNode, uint256 salt) public returns (address wallet) {
        bytes32 create3Salt = _create3Salt(platformId, idNode, salt);
        wallet = Create3.addressOf(create3Salt, address(this));
        if (wallet.code.length != 0) return wallet;
        IIdentityValidator.Policy memory none;
        bytes memory init =
            abi.encodeCall(IWebWallet.initialize, (abi.encode(platformId, idNode, salt, bytes(""), none)));
        wallet = Create3.deploy(
            create3Salt, abi.encodePacked(type(ERC1967Proxy).creationCode, abi.encode(WALLET_IMPLEMENTATION, init))
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

    /// Salt 0 is the identity alone; any other hashes three words, so it is no other genesis's salt 0.
    function _create3Salt(bytes32 platformId, bytes32 idNode, uint256 salt) private pure returns (bytes32) {
        return salt == 0 ? identityOf(platformId, idNode) : keccak256(abi.encode(platformId, idNode, salt));
    }

    function _authorizeUpgrade(address) internal override onlyOwner {}

    /// @dev The upgrade is the only repair lever, so ownership stays.
    function renounceOwnership() public pure override {
        revert RenounceDisabled();
    }
}
