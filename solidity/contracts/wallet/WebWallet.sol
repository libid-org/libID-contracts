// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {IERC1271} from "@openzeppelin/contracts/interfaces/IERC1271.sol";
import {IEntryPoint, PackedUserOperation} from "@openzeppelin/contracts/interfaces/IERC4337.sol";
import {
    IERC7579AccountConfig,
    IERC7579Execution,
    IERC7579ModuleConfig,
    IERC7579Validator,
    MODULE_TYPE_VALIDATOR
} from "@openzeppelin/contracts/interfaces/draft-IERC7579.sol";
import {Account} from "@openzeppelin/contracts/account/Account.sol";
import {ERC4337Utils} from "@openzeppelin/contracts/account/utils/ERC4337Utils.sol";
import {
    CallType,
    ERC7579Utils,
    Execution,
    Mode,
    ModeSelector
} from "@openzeppelin/contracts/account/utils/draft-ERC7579Utils.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts/proxy/utils/UUPSUpgradeable.sol";
import {IERC721Receiver} from "@openzeppelin/contracts/token/ERC721/IERC721Receiver.sol";
import {ERC721Holder} from "@openzeppelin/contracts/token/ERC721/utils/ERC721Holder.sol";
import {ERC1155Holder} from "@openzeppelin/contracts/token/ERC1155/utils/ERC1155Holder.sol";
import {Address} from "@openzeppelin/contracts/utils/Address.sol";
import {Calldata} from "@openzeppelin/contracts/utils/Calldata.sol";
import {ReentrancyGuardTransient} from "@openzeppelin/contracts/utils/ReentrancyGuardTransient.sol";
import {EIP712} from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import {IERC165} from "@openzeppelin/contracts/utils/introspection/IERC165.sol";
import {
    AccountERC7579Upgradeable
} from "@openzeppelin/contracts-upgradeable/account/extensions/draft-AccountERC7579Upgradeable.sol";

import {bytesAt} from "./AbiBytes.sol";
import {IIdentityValidator} from "./IIdentityValidator.sol";
import {AUTHORIZED_MODE, CALL_OVERHEAD, INonceIncrement, IWebWallet} from "./IWebWallet.sol";

/// @title WebWallet - an ERC-7579 account whose one module is the IdentityValidator.
/// @notice Module changes and upgrades come only from that validator, for a matured root operation.
contract WebWallet is
    AccountERC7579Upgradeable,
    UUPSUpgradeable,
    EIP712,
    ERC721Holder,
    ERC1155Holder,
    ReentrancyGuardTransient,
    IWebWallet
{
    using ERC7579Utils for Mode;
    using ERC7579Utils for bytes;

    /// The `reinitializer` version of `migrate`: each implementation that migrates raises it.
    uint64 private constant MIGRATION = 2;

    address private immutable VALIDATOR;

    modifier onlyValidator() {
        if (msg.sender != VALIDATOR) revert NotValidator(msg.sender);
        _;
    }

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor(address identityValidator) EIP712("WebWallet", "1") {
        VALIDATOR = identityValidator;
        _disableInitializers();
    }

    function initialize(bytes calldata validatorData) external initializer {
        _installModule(MODULE_TYPE_VALIDATOR, VALIDATOR, validatorData);
    }

    function migrate(bytes calldata validatorData)
        external
        reinitializer(MIGRATION)
        onlyModule(MODULE_TYPE_VALIDATOR, Calldata.emptyBytes())
    {
        _installModule(MODULE_TYPE_VALIDATOR, VALIDATOR, validatorData);
        // A session-less install would reopen the first-session rule.
        if (!IIdentityValidator(VALIDATOR).hadSession(address(this))) revert MigrationWithoutSession();
    }

    function identityValidator() external view returns (address) {
        return VALIDATOR;
    }

    /// `AUTHORIZED_MODE` from anyone, checked at the end; a default-selector mode from the EntryPoint, whose
    /// validation checked the operation.
    function execute(bytes32 mode, bytes calldata data)
        public
        payable
        override(IERC7579Execution, AccountERC7579Upgradeable)
        nonReentrant
    {
        if (mode == AUTHORIZED_MODE) return _executeAuthorized(data);
        _checkEntryPoint();
        (,, ModeSelector selector,) = Mode.wrap(mode).decodeMode();
        if (ModeSelector.unwrap(selector) != 0) revert UnsupportedModeSelector(ModeSelector.unwrap(selector));
        _execute(Mode.wrap(mode), data);
    }

    function supportsModule(uint256 moduleTypeId)
        public
        pure
        override(IERC7579AccountConfig, AccountERC7579Upgradeable)
        returns (bool)
    {
        return moduleTypeId == MODULE_TYPE_VALIDATOR;
    }

    function supportsExecutionMode(bytes32 encodedMode)
        public
        view
        override(IERC7579AccountConfig, AccountERC7579Upgradeable)
        returns (bool)
    {
        if (encodedMode == AUTHORIZED_MODE) return true;
        (CallType callType,, ModeSelector selector,) = Mode.wrap(encodedMode).decodeMode();
        return !(callType == ERC7579Utils.CALLTYPE_DELEGATECALL) && ModeSelector.unwrap(selector) == 0
            && super.supportsExecutionMode(encodedMode);
    }

    function installModule(uint256 moduleTypeId, address module, bytes calldata initData)
        public
        override(IERC7579ModuleConfig, AccountERC7579Upgradeable)
        onlyValidator
    {
        _installModule(moduleTypeId, module, initData);
    }

    function uninstallModule(uint256 moduleTypeId, address module, bytes calldata deInitData)
        public
        override(IERC7579ModuleConfig, AccountERC7579Upgradeable)
        onlyValidator
    {
        // Nothing could install the validator again.
        if (module == VALIDATOR) revert ModuleNotAllowed(module);
        _uninstallModule(moduleTypeId, module, deInitData);
    }

    /// Only the constructor's validator signs. An empty signature goes to it, which answers the
    /// ERC-7739 probe.
    function isValidSignature(bytes32 hash, bytes calldata signature)
        public
        view
        override(IERC1271, AccountERC7579Upgradeable)
        returns (bytes4)
    {
        if (signature.length != 0) {
            // forge-lint: disable-next-line(unsafe-typecast)
            if (address(bytes20(signature)) != VALIDATOR) return bytes4(0xffffffff);
            return super.isValidSignature(hash, signature);
        }
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
        if (module != VALIDATOR) revert ModuleNotAllowed(module);
        super._installModule(moduleTypeId, module, initData);
    }

    /// Only the constructor's validator validates: another still installed, such as the one a
    /// migration replaced, is refused.
    function _validateUserOp(PackedUserOperation calldata userOp, bytes32 userOpHash, bytes calldata signature)
        internal
        override
        returns (uint256)
    {
        if (_extractUserOpValidator(userOp) != VALIDATOR) return ERC4337Utils.SIG_VALIDATION_FAILED;
        return super._validateUserOp(userOp, userOpHash, signature);
    }

    function _execute(Mode mode, bytes calldata executionCalldata) internal override returns (bytes[] memory) {
        (CallType callType,,,) = mode.decodeMode();
        if (callType == ERC7579Utils.CALLTYPE_DELEGATECALL) revert ERC7579Utils.ERC7579UnsupportedCallType(callType);
        return super._execute(mode, executionCalldata);
    }

    /// The validator checks the batch once it ran, against the nonce, threshold and domain of entry.
    function _executeAuthorized(bytes calldata data) private {
        bytes calldata executionCalldata = bytesAt(data, 0);
        Execution[] calldata batch = executionCalldata.decodeBatch();
        uint256 free;
        assembly ("memory-safe") {
            free := mload(0x40)
        }
        // The signers sign these bytes alone, so no call may be read from outside them.
        if (keccak256(abi.encode(batch)) != keccak256(executionCalldata)) revert NoncanonicalBatch();
        // The calls reuse the encoding's memory, already paid for.
        assembly ("memory-safe") {
            mstore(0x40, free)
        }
        (uint256 value, uint48 deadline, uint256 callGas) = abi.decode(data[32:128], (uint256, uint48, uint256));
        if (msg.value != value) revert WrongValue(value, msg.value);
        uint192 key = uint192(uint160(VALIDATOR)) << 32;
        IEntryPoint ep = entryPoint();
        if (address(ep).code.length == 0) revert EntryPointMissing(address(ep));
        uint256 nonce = ep.getNonce(address(this), key);
        INonceIncrement(address(ep)).incrementNonce(key);
        uint8 threshold = IIdentityValidator(VALIDATOR).threshold(address(this));
        bytes32 domain = _domainSeparatorV4();
        for (uint256 i; i < batch.length; ++i) {
            _call(batch[i], callGas);
        }
        IIdentityValidator(VALIDATOR)
            .checkExecution(
                AUTHORIZED_MODE,
                executionCalldata,
                value,
                deadline,
                callGas,
                bytesAt(data, 128),
                nonce,
                threshold,
                domain
            );
    }

    /// One call of a default-exec-type batch, which bubbles its revert, given at least `callGas`.
    function _call(Execution calldata x, uint256 callGas) private {
        uint256 free;
        assembly ("memory-safe") {
            free := mload(0x40)
        }
        if (gasleft() * 63 / 64 < callGas + CALL_OVERHEAD) revert InsufficientCallGas(callGas, gasleft());
        (bool ok, bytes memory returned) =
            (x.target == address(0) ? address(this) : x.target).call{value: x.value}(x.callData);
        Address.verifyCallResult(ok, returned);
        assembly ("memory-safe") {
            mstore(0x40, free)
        }
    }

    function _authorizeUpgrade(address) internal view override onlyValidator {}
}
