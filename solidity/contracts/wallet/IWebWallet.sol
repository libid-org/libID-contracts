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
/// @notice Constructor: `WebWallet(address identityValidator)`, the one module it accepts.
/// @dev `installModule`, `uninstallModule` and `upgradeToAndCall` accept only the
///      installed validator, which calls them for a matured root operation.
///      Delegatecall execution is refused.
interface IWebWallet is IERC7579Execution, IERC7579AccountConfig, IERC7579ModuleConfig, IERC1271, IERC5267 {
    /// Installs the validator with `validatorData`. Once, by the factory.
    function initialize(bytes calldata validatorData) external;

    function upgradeToAndCall(address newImplementation, bytes calldata data) external payable;

    function entryPoint() external view returns (IEntryPoint);
}
