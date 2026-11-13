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

/// @title IWebWallet - the ERC-7579 account core (OpenZeppelin v5.7.0, UUPS).
/// @notice Constructor: `WebWallet(address identityValidator, address claimExecutor)`, the two
///         modules it accepts, as validator and executor; `initialize` installs both.
/// @dev `installModule`, `uninstallModule` and `upgradeToAndCall` accept only the constructor's
///      validator, which calls them for a matured root operation; another validator still installed
///      has no power. The validator cannot be uninstalled. `executeFromExecutor` accepts only the installed executor,
///      and its calls pass no validator.
///      Delegatecall execution is refused. Only the constructor's validator validates UserOperations
///      and signs: another validator still installed, such as the one a migration replaced, is refused.
///      `isValidSignature` passes `hash` to that validator, which reads it as ERC-7739 under
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
    /// Only the constructor's modules may be installed, and the validator never uninstalled.
    error ModuleNotAllowed(address module);

    /// The caller is not the constructor's validator.
    error NotValidator(address caller);

    /// Installs the validator with `validatorData`, and the executor. Once, by the factory.
    function initialize(bytes calldata validatorData) external;

    /// Moves the wallet to this implementation's validator: installs it with `validatorData`, and the
    /// executor unless installed. Only an installed validator, once per implementation that migrates;
    /// the old validator calls it as the data of its matured root upgrade.
    function migrate(bytes calldata validatorData) external;

    /// The only validator this implementation installs.
    function identityValidator() external view returns (address);
    /// The only executor this implementation installs.
    function claimExecutor() external view returns (address);

    function upgradeToAndCall(address newImplementation, bytes calldata data) external payable;

    function entryPoint() external view returns (IEntryPoint);
}
