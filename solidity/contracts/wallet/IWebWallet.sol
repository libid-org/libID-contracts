// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IERC1271} from "@openzeppelin/contracts/interfaces/IERC1271.sol";
import {IERC5267} from "@openzeppelin/contracts/interfaces/IERC5267.sol";
import {IEntryPoint} from "@openzeppelin/contracts/interfaces/IERC4337.sol";
import {IERC721Receiver} from "@openzeppelin/contracts/token/ERC721/IERC721Receiver.sol";
import {IERC1155Receiver} from "@openzeppelin/contracts/token/ERC1155/IERC1155Receiver.sol";
import {
    IERC7579AccountConfig,
    IERC7579Execution,
    IERC7579ModuleConfig
} from "@openzeppelin/contracts/interfaces/draft-IERC7579.sol";

// The `AUTHORIZED` execution mode's selector.
bytes4 constant AUTHORIZED_SELECTOR = bytes4(keccak256("libid.webwallet.authorized"));
// The one `AUTHORIZED` mode word: batch call type, default exec type, `AUTHORIZED_SELECTOR`, zero payload.
bytes32 constant AUTHORIZED_MODE = bytes32((uint256(0x01) << 248) | (uint256(uint32(AUTHORIZED_SELECTOR)) << 176));
// The gas between the wallet's `callGas` check before each `AUTHORIZED_MODE` call and the call, which gets 63/64 of
// what is left. Measured for a cold target with value: 9.8k with no call data, 15.8k with 64 KiB, the most
// `test_everyCallGetsTheSignedCallGas` checks.
uint256 constant CALL_OVERHEAD = 20_000;

/// EntryPoint v0.9's `incrementNonce`, which OpenZeppelin's interface leaves out.
interface INonceIncrement {
    function incrementNonce(uint192 key) external;
}

/// @title IWebWallet - the ERC-7579 account core (OpenZeppelin v5.7.0, UUPS).
/// @notice Constructor: `WebWallet(address identityValidator)`, the one module it accepts;
///         `initialize` installs it.
/// @dev `installModule`, `uninstallModule` and `upgradeToAndCall` accept only the constructor's
///      validator, which calls them for a matured root operation; another validator still installed
///      has no power. The validator cannot be uninstalled. `isModuleInstalled` reports that validator
///      alone; no executor module or fallback handler is supported, and none an earlier EIP-7702
///      delegate left in OpenZeppelin's storage is ever called.
///      `execute(mode, data)` takes a default-selector mode from the EntryPoint, or, on an EIP-7702
///      account, from the account itself (its key), and `AUTHORIZED_MODE`
///      from anyone, checked at the end: `data` is then
///      `abi.encode(bytes executionCalldata, uint256 value, uint48 deadline, uint256 callGas, bytes authorization)`,
///      sent with exactly `value`.
///      For it the wallet requires `executionCalldata` to be the canonical `abi.encode(Execution[])` of its
///      calls, consumes the EntryPoint nonce under key `uint192(uint160(validator)) << 32`,
///      reads the threshold and its EIP-712 domain separator, runs the batch, requiring
///      `gasleft() * 63 / 64 >= callGas + CALL_OVERHEAD` before each call so that every call gets at least
///      `callGas`, then calls the validator's `checkExecution`; any failure reverts everything, the nonce included. One reentrancy lock covers both modes. Any other mode
///      selector, and delegatecall execution, are refused. Only the constructor's validator validates
///      UserOperations and signs: another validator still installed, such as the one a migration
///      replaced, is refused.
///      `isValidSignature` accepts a 65-byte ECDSA signature of `hash` by `address(this)`, which only an
///      EIP-7702 account's key can make; otherwise it passes `hash` to that validator, which reads it as ERC-7739 under
///      `eip712Domain()`; an empty signature goes to it too, so the ERC-7739 probe is answered.
///      ERC-721 and ERC-1155 safe transfers are accepted; ERC-165 reports both receivers.
///      Integration notes are in README.md beside this file.
interface IWebWallet is
    IERC1271,
    IERC7579Execution,
    IERC7579AccountConfig,
    IERC7579ModuleConfig,
    IERC5267,
    IERC721Receiver,
    IERC1155Receiver
{
    /// Only the constructor's validator may be installed, and it is never uninstalled.
    error ModuleNotAllowed(address module);

    /// The caller is not the constructor's validator.
    error NotValidator(address caller);

    /// A mode selector other than zero, outside `AUTHORIZED_MODE`.
    error UnsupportedModeSelector(bytes4 selector);

    /// The batch is not `abi.encode(Execution[])` of the calls it decodes to.
    error NoncanonicalBatch();

    /// `msg.value` is not the signed `value`.
    error WrongValue(uint256 value, uint256 sent);

    /// The gas left before a call would give it less than the signed `callGas`.
    error InsufficientCallGas(uint256 callGas, uint256 left);

    /// `entryPoint` has no code: EntryPoint v0.9 must be deployed at its canonical address, which holds the
    /// direct path's nonce.
    error EntryPointMissing(address entryPoint);

    /// The migration's install data added no session.
    error MigrationWithoutSession();

    /// Installs the validator with `validatorData`. Once, by the factory.
    function initialize(bytes calldata validatorData) external;

    /// Moves the wallet to this implementation's validator: installs it with `validatorData`, which must add a
    /// session. Only an installed validator, once per implementation that migrates;
    /// the old validator calls it as the data of its matured root upgrade.
    function migrate(bytes calldata validatorData) external;

    /// The only validator this implementation installs.
    function identityValidator() external view returns (address);

    function upgradeToAndCall(address newImplementation, bytes calldata data) external payable;

    function entryPoint() external view returns (IEntryPoint);
}
