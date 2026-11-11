// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {IERC1271} from "@openzeppelin/contracts/interfaces/IERC1271.sol";
import {IEntryPoint} from "@openzeppelin/contracts/interfaces/IERC4337.sol";
import {
    IERC7579AccountConfig,
    IERC7579ModuleConfig,
    IERC7579Validator,
    MODULE_TYPE_EXECUTOR,
    MODULE_TYPE_VALIDATOR
} from "@openzeppelin/contracts/interfaces/draft-IERC7579.sol";
import {Account} from "@openzeppelin/contracts/account/Account.sol";
import {CallType, ERC7579Utils, Mode} from "@openzeppelin/contracts/account/utils/draft-ERC7579Utils.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts/proxy/utils/UUPSUpgradeable.sol";
import {IERC721Receiver} from "@openzeppelin/contracts/token/ERC721/IERC721Receiver.sol";
import {ERC721Holder} from "@openzeppelin/contracts/token/ERC721/utils/ERC721Holder.sol";
import {ERC1155Holder} from "@openzeppelin/contracts/token/ERC1155/utils/ERC1155Holder.sol";
import {Calldata} from "@openzeppelin/contracts/utils/Calldata.sol";
import {EIP712} from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import {IERC165} from "@openzeppelin/contracts/utils/introspection/IERC165.sol";
import {
    AccountERC7579Upgradeable
} from "@openzeppelin/contracts-upgradeable/account/extensions/draft-AccountERC7579Upgradeable.sol";

import {IWebWallet} from "./IWebWallet.sol";

/// @title WebWallet - an ERC-7579 account whose modules are the IdentityValidator and the ClaimExecutor.
/// @notice Module changes and upgrades come only from that validator, for a matured root operation.
contract WebWallet is AccountERC7579Upgradeable, UUPSUpgradeable, EIP712, ERC721Holder, ERC1155Holder, IWebWallet {
    using ERC7579Utils for Mode;

    address private immutable VALIDATOR;
    address private immutable EXECUTOR;

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor(address identityValidator, address claimExecutor) EIP712("WebWallet", "1") {
        VALIDATOR = identityValidator;
        EXECUTOR = claimExecutor;
        _disableInitializers();
    }

    function initialize(bytes calldata validatorData) external initializer {
        _installModule(MODULE_TYPE_VALIDATOR, VALIDATOR, validatorData);
        _installModule(MODULE_TYPE_EXECUTOR, EXECUTOR, "");
    }

    function supportsModule(uint256 moduleTypeId)
        public
        pure
        override(IERC7579AccountConfig, AccountERC7579Upgradeable)
        returns (bool)
    {
        return moduleTypeId == MODULE_TYPE_VALIDATOR || moduleTypeId == MODULE_TYPE_EXECUTOR;
    }

    function supportsExecutionMode(bytes32 encodedMode)
        public
        view
        override(IERC7579AccountConfig, AccountERC7579Upgradeable)
        returns (bool)
    {
        (CallType callType,,,) = Mode.wrap(encodedMode).decodeMode();
        return !(callType == ERC7579Utils.CALLTYPE_DELEGATECALL) && super.supportsExecutionMode(encodedMode);
    }

    function installModule(uint256 moduleTypeId, address module, bytes calldata initData)
        public
        override(IERC7579ModuleConfig, AccountERC7579Upgradeable)
        onlyModule(MODULE_TYPE_VALIDATOR, Calldata.emptyBytes())
    {
        _installModule(moduleTypeId, module, initData);
    }

    function uninstallModule(uint256 moduleTypeId, address module, bytes calldata deInitData)
        public
        override(IERC7579ModuleConfig, AccountERC7579Upgradeable)
        onlyModule(MODULE_TYPE_VALIDATOR, Calldata.emptyBytes())
    {
        // Nothing could install the validator again.
        if (module == VALIDATOR) revert ModuleNotAllowed(module);
        _uninstallModule(moduleTypeId, module, deInitData);
    }

    /// An empty signature goes to the validator, which answers the ERC-7739 probe.
    function isValidSignature(bytes32 hash, bytes calldata signature)
        public
        view
        override(IERC1271, AccountERC7579Upgradeable)
        returns (bytes4)
    {
        if (signature.length != 0) return super.isValidSignature(hash, signature);
        try IERC7579Validator(VALIDATOR).isValidSignatureWithSender(msg.sender, hash, signature) returns (
            bytes4 magic
        ) {
            return magic;
        } catch {
            return bytes4(0xffffffff);
        }
    }

    function upgradeToAndCall(address newImplementation, bytes memory data)
        public
        payable
        override(IWebWallet, UUPSUpgradeable)
    {
        super.upgradeToAndCall(newImplementation, data);
    }

    function entryPoint() public view override(IWebWallet, Account) returns (IEntryPoint) {
        return super.entryPoint();
    }

    function supportsInterface(bytes4 interfaceId) public view override(ERC1155Holder, IERC165) returns (bool) {
        return interfaceId == type(IERC721Receiver).interfaceId || super.supportsInterface(interfaceId);
    }

    function _installModule(uint256 moduleTypeId, address module, bytes memory initData) internal override {
        if (module != (moduleTypeId == MODULE_TYPE_EXECUTOR ? EXECUTOR : VALIDATOR)) revert ModuleNotAllowed(module);
        super._installModule(moduleTypeId, module, initData);
    }

    function _execute(Mode mode, bytes calldata executionCalldata) internal override returns (bytes[] memory) {
        (CallType callType,,,) = mode.decodeMode();
        if (callType == ERC7579Utils.CALLTYPE_DELEGATECALL) revert ERC7579Utils.ERC7579UnsupportedCallType(callType);
        return super._execute(mode, executionCalldata);
    }

    function _authorizeUpgrade(address)
        internal
        view
        override
        onlyModule(MODULE_TYPE_VALIDATOR, Calldata.emptyBytes())
    {}
}
