// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IERC1271} from "@openzeppelin/contracts/interfaces/IERC1271.sol";
import {IERC5267} from "@openzeppelin/contracts/interfaces/IERC5267.sol";
import {IEntryPoint} from "@openzeppelin/contracts/interfaces/IERC4337.sol";
import {
    IERC7579AccountConfig,
    IERC7579Execution,
    IERC7579ModuleConfig
} from "@openzeppelin/contracts/interfaces/draft-IERC7579.sol";

/// @title IWebWallet - the ERC-7579 account core (OpenZeppelin v5.7.0, UUPS).
/// @notice Constructor: `WebWallet(address identityValidator, address claimExecutor)`, the two
///         modules it accepts, as validator and executor; `initialize` installs both.
/// @dev `installModule`, `uninstallModule` and `upgradeToAndCall` accept only the
///      installed validator, which calls them for a matured root operation. The validator
///      cannot be uninstalled. `executeFromExecutor` accepts only the installed executor,
///      and its calls pass no validator.
///      Delegatecall execution is refused. `isValidSignature` passes `hash` to the validator
///      the signature names, which reads it as ERC-7739 under `eip712Domain()`; an empty
///      signature goes to the constructor's validator, so the ERC-7739 probe is answered.
interface IWebWallet is IERC1271, IERC7579Execution, IERC7579AccountConfig, IERC7579ModuleConfig, IERC5267 {
    /// Only the constructor's modules may be installed, and the validator never uninstalled.
    error ModuleNotAllowed(address module);

    /// Installs the validator with `validatorData`, and the executor. Once, by the factory.
    function initialize(bytes calldata validatorData) external;

    function upgradeToAndCall(address newImplementation, bytes calldata data) external payable;

    function entryPoint() external view returns (IEntryPoint);
}
