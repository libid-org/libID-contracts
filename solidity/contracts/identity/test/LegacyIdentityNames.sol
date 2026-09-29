// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {Ownable2StepUpgradeable} from "@openzeppelin/contracts-upgradeable/access/Ownable2StepUpgradeable.sol";
import {ReentrancyGuardUpgradeable} from "@openzeppelin/contracts-upgradeable/utils/ReentrancyGuardUpgradeable.sol";

import {IProofVerifier} from "../../ceremony/IProofVerifier.sol";
import {HandleNormalizer} from "../HandleNormalizer.sol";
import {IdentityNodes} from "../IdentityNodes.sol";

/// @notice IdentityNames as deployed before it kept account lists: the same
///         namespaced root and the same fields, ending where the lists were
///         later appended.
///
/// @dev Writes a binding the way `claim` wrote one then, without the ceremony
///      in front of it. A proxy upgraded from this onto the current
///      implementation holds bindings that no list knows about, which is the
///      state every deployment was in on the day of that upgrade.
contract LegacyIdentityNames is Initializable, UUPSUpgradeable, Ownable2StepUpgradeable, ReentrancyGuardUpgradeable {
    struct Binding {
        address owner;
        uint64 observedAt;
    }

    struct Platform {
        HandleNormalizer.Rules rules;
        bool configured;
    }

    /// @custom:storage-location erc7201:libid.storage.IdentityNames
    struct LegacyStorage {
        mapping(bytes32 => Binding) byId;
        mapping(bytes32 => Binding) byHandle;
        mapping(address => mapping(bytes32 => string)) published;
        mapping(bytes32 => Platform) platforms;
        mapping(bytes32 => bytes32) handleOfId;
        mapping(bytes32 => bytes32) idOfHandle;
        IProofVerifier proofVerifier;
        mapping(bytes32 => bool) everBound;
        mapping(bytes32 => bool) spentDigests;
    }

    bytes32 private constant IDENTITY_NAMES_STORAGE =
        0x064503501234cc9c6e116cf4a84c07475158dabb6a3dcee437a89227e23bf200;

    function _s() private pure returns (LegacyStorage storage $) {
        assembly {
            $.slot := IDENTITY_NAMES_STORAGE
        }
    }

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    function initialize(address owner_) external initializer {
        __Ownable_init(owner_);
        __Ownable2Step_init();
        __UUPSUpgradeable_init();
        __ReentrancyGuard_init();
    }

    function setPlatform(bytes32 platformId, HandleNormalizer.Rules calldata rules) external onlyOwner {
        Platform storage platform = _s().platforms[platformId];
        platform.rules = rules;
        platform.configured = true;
    }

    /// @notice A binding as `claim` wrote one, made out to the caller.
    function bind(
        bytes32 platformId,
        string calldata userId,
        string calldata rawHandle,
        uint64 observedAt,
        bool publishName
    ) external {
        Platform memory platform = _s().platforms[platformId];
        require(platform.configured, "unknown platform");
        _s().everBound[platformId] = true;

        string memory handle = HandleNormalizer.normalize(rawHandle, platform.rules);
        bytes32 idKey = IdentityNodes.idNode(platformId, userId);
        bytes32 handleKey = IdentityNodes.handleNode(platformId, handle);

        _s().byId[idKey] = Binding({owner: msg.sender, observedAt: observedAt});
        _s().byHandle[handleKey] = Binding({owner: msg.sender, observedAt: observedAt});

        bytes32 previous = _s().handleOfId[idKey];
        if (previous != bytes32(0) && previous != handleKey && _s().idOfHandle[previous] == idKey) {
            _s().byHandle[previous].owner = address(0);
        }
        _s().handleOfId[idKey] = handleKey;
        _s().idOfHandle[handleKey] = idKey;

        if (publishName) _s().published[msg.sender][platformId] = handle;
    }

    function _authorizeUpgrade(address) internal override onlyOwner {}
}
