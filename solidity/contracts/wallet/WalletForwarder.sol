// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IERC1967} from "@openzeppelin/contracts/interfaces/IERC1967.sol";
import {ERC1967Utils} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Utils.sol";
import {Proxy} from "@openzeppelin/contracts/proxy/Proxy.sol";
import {StorageSlot} from "@openzeppelin/contracts/utils/StorageSlot.sol";

import {IWalletFactory} from "./IWalletFactory.sol";

/// @title WalletForwarder - the EIP-7702 delegate of an EOA that runs a WebWallet.
/// @notice An empty call returns. Any other call sets the account up once, writing the factory's
///         `walletImplementation()` to the ERC-1967 slot, then delegatecalls the implementation that slot
///         names. Setup takes no data: a stranger can only choose when it runs.
/// @dev Ownerless and never upgraded. Routing reads the flag, never the slot, so a slot left by an earlier
///      delegate is overwritten at setup. Compatibility rule: a later forwarder keeps the flag at
///      `erc7201:libid.webwallet.forwarder`, so a key that re-delegates to it is not set up again.
contract WalletForwarder is Proxy {
    /// @custom:storage-location erc7201:libid.webwallet.forwarder
    struct ForwarderStorage {
        bool setUp;
    }

    // keccak256(abi.encode(uint256(keccak256("libid.webwallet.forwarder")) - 1)) & ~bytes32(uint256(0xff))
    bytes32 private constant FORWARDER_STORAGE = 0xc2f8af3814a07eb6741c63b4fc041906beb0f9e67ef98cd0864a23c39b9fc100;

    address private immutable FACTORY;
    address private immutable SELF = address(this);

    /// Called at the forwarder's own address, not through a delegation.
    error NotDelegated();

    constructor(address walletFactory) {
        FACTORY = walletFactory;
    }

    receive() external payable {}

    function _fallback() internal override {
        if (address(this) == SELF) revert NotDelegated();
        ForwarderStorage storage $ = _forwarderStorage();
        if (!$.setUp) {
            address implementation = IWalletFactory(FACTORY).walletImplementation();
            StorageSlot.getAddressSlot(ERC1967Utils.IMPLEMENTATION_SLOT).value = implementation;
            emit IERC1967.Upgraded(implementation);
            $.setUp = true;
        }
        super._fallback();
    }

    function _implementation() internal view override returns (address) {
        return ERC1967Utils.getImplementation();
    }

    function _forwarderStorage() private pure returns (ForwarderStorage storage $) {
        assembly ("memory-safe") {
            $.slot := FORWARDER_STORAGE
        }
    }
}
