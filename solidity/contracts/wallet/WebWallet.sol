// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {IEntryPoint} from "@openzeppelin/contracts/interfaces/IERC4337.sol";
import {
    IERC7579AccountConfig,
    IERC7579ModuleConfig,
    MODULE_TYPE_EXECUTOR,
    MODULE_TYPE_VALIDATOR
} from "@openzeppelin/contracts/interfaces/draft-IERC7579.sol";
import {Account} from "@openzeppelin/contracts/account/Account.sol";
import {CallType, ERC7579Utils, Mode} from "@openzeppelin/contracts/account/utils/draft-ERC7579Utils.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts/proxy/utils/UUPSUpgradeable.sol";
import {Calldata} from "@openzeppelin/contracts/utils/Calldata.sol";
import {EIP712} from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import {
    AccountERC7579Upgradeable
} from "@openzeppelin/contracts-upgradeable/account/extensions/draft-AccountERC7579Upgradeable.sol";

import {IWebWallet} from "./IWebWallet.sol";

/// @title WebWallet - an ERC-7579 account whose modules are the IdentityValidator and the ClaimExecutor.
/// @notice Module changes and upgrades come only from that validator, for a matured root operation.
contract WebWallet is AccountERC7579Upgradeable, UUPSUpgradeable, EIP712, IWebWallet {
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
