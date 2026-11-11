// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IERC7579Execution, MODULE_TYPE_EXECUTOR} from "@openzeppelin/contracts/interfaces/draft-IERC7579.sol";
import {
    ERC7579Utils,
    Mode,
    ModePayload,
    ModeSelector
} from "@openzeppelin/contracts/account/utils/draft-ERC7579Utils.sol";

import {IHandleEscrow} from "../escrow/IHandleEscrow.sol";
import {IIdentityRegistry} from "../identity/IIdentityRegistry.sol";
import {IClaimExecutor} from "./IClaimExecutor.sol";
import {IIdentityValidator, identityOf} from "./IIdentityValidator.sol";

/// @title ClaimExecutor - binds a wallet's linked identity and claims its escrow, for anyone.
contract ClaimExecutor is IClaimExecutor {
    IIdentityRegistry private immutable IDENTITY_REGISTRY;
    IHandleEscrow private immutable ESCROW;
    IIdentityValidator private immutable VALIDATOR;

    constructor(address identityRegistry, address handleEscrow, address identityValidator) {
        IDENTITY_REGISTRY = IIdentityRegistry(identityRegistry);
        ESCROW = IHandleEscrow(handleEscrow);
        VALIDATOR = IIdentityValidator(identityValidator);
    }

    function isModuleType(uint256 moduleTypeId) external pure returns (bool) {
        return moduleTypeId == MODULE_TYPE_EXECUTOR;
    }

    function onInstall(bytes calldata) external {}

    function onUninstall(bytes calldata) external {}

    function bind(address wallet, bytes32 platformId, uint16 verifierVersion, bytes calldata payload) external payable {
        IIdentityRegistry.Identity[] memory before = _held(wallet);
        bytes memory data =
            abi.encodeCall(IIdentityRegistry.bindPrivately, (platformId, verifierVersion, payload, 0, address(0)));
        _call(wallet, address(IDENTITY_REGISTRY), msg.value, data);

        // The registry reports no bound node, and its list order is arbitrary: compare by membership.
        IIdentityRegistry.Identity[] memory held = _held(wallet);
        for (uint256 i; i < held.length; ++i) {
            if (_contains(before, held[i].idNode)) continue;
            if (!VALIDATOR.isLinked(wallet, identityOf(held[i].platformId, held[i].idNode))) {
                revert HeldIdentityNotLinked(wallet, held[i].platformId, held[i].idNode);
            }
        }
    }

    function claimToSelf(address wallet, bytes32 handleNode, address[] calldata tokens) external {
        _call(wallet, address(ESCROW), 0, abi.encodeCall(IHandleEscrow.claim, (handleNode, tokens, wallet)));
    }

    function _held(address wallet) private view returns (IIdentityRegistry.Identity[] memory) {
        return IDENTITY_REGISTRY.identitiesOf(wallet, 0, IDENTITY_REGISTRY.identityCount(wallet));
    }

    function _contains(IIdentityRegistry.Identity[] memory ids, bytes32 idNode) private pure returns (bool) {
        for (uint256 i; i < ids.length; ++i) {
            if (ids[i].idNode == idNode) return true;
        }
        return false;
    }

    /// @dev The execution calldata is `ERC7579Utils.encodeSingle`'s packing, which takes calldata only.
    function _call(address wallet, address target, uint256 value, bytes memory data) private {
        Mode mode = ERC7579Utils.encodeMode(
            ERC7579Utils.CALLTYPE_SINGLE, ERC7579Utils.EXECTYPE_DEFAULT, ModeSelector.wrap(0), ModePayload.wrap(0)
        );
        IERC7579Execution(wallet).executeFromExecutor{value: value}(
            Mode.unwrap(mode), abi.encodePacked(target, value, data)
        );
    }
}
