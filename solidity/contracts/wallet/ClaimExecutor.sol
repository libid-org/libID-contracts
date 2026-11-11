// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IERC7579Execution, MODULE_TYPE_EXECUTOR} from "@openzeppelin/contracts/interfaces/draft-IERC7579.sol";

import {HandleEscrow} from "../escrow/HandleEscrow.sol";
import {IdentityRegistry} from "../identity/IdentityRegistry.sol";
import {IClaimExecutor} from "./IClaimExecutor.sol";
import {IIdentityValidator, identityOf} from "./IIdentityValidator.sol";

/// @title ClaimExecutor - binds a wallet's linked identity and claims its escrow, for anyone.
contract ClaimExecutor is IClaimExecutor {
    /// ERC-7579 single call, default exec type.
    bytes32 private constant MODE_SINGLE = bytes32(0);

    IdentityRegistry private immutable IDENTITY_REGISTRY;
    HandleEscrow private immutable ESCROW;
    IIdentityValidator private immutable VALIDATOR;

    constructor(address identityRegistry, address handleEscrow, address identityValidator) {
        IDENTITY_REGISTRY = IdentityRegistry(identityRegistry);
        ESCROW = HandleEscrow(handleEscrow);
        VALIDATOR = IIdentityValidator(identityValidator);
    }

    function isModuleType(uint256 moduleTypeId) external pure returns (bool) {
        return moduleTypeId == MODULE_TYPE_EXECUTOR;
    }

    function onInstall(bytes calldata) external {}

    function onUninstall(bytes calldata) external {}

    function bind(address wallet, bytes32 platformId, uint16 verifierVersion, bytes calldata payload) external payable {
        bytes memory data =
            abi.encodeCall(IdentityRegistry.bindPrivately, (platformId, verifierVersion, payload, 0, address(0)));
        _call(wallet, address(IDENTITY_REGISTRY), msg.value, data);

        // The registry reports no bound node, and its list order is arbitrary: check every one.
        IdentityRegistry.Identity[] memory held =
            IDENTITY_REGISTRY.identitiesOf(wallet, 0, IDENTITY_REGISTRY.identityCount(wallet));
        for (uint256 i; i < held.length; ++i) {
            if (!VALIDATOR.isLinked(wallet, identityOf(held[i].platformId, held[i].idNode))) {
                revert NotLinked(wallet, held[i].platformId, held[i].idNode);
            }
        }
    }

    function claimToSelf(address wallet, bytes32 handleNode, address[] calldata tokens) external {
        _call(wallet, address(ESCROW), 0, abi.encodeCall(HandleEscrow.claim, (handleNode, tokens, wallet)));
    }

    function _call(address wallet, address target, uint256 value, bytes memory data) private {
        IERC7579Execution(wallet).executeFromExecutor{value: value}(MODE_SINGLE, abi.encodePacked(target, value, data));
    }
}
