// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {CeremonyFields} from "./CeremonyFields.sol";
import {CeremonyProfile} from "./CeremonyProfile.sol";
import {INotaryService} from "./INotaryService.sol";
import {IHonkVerifier} from "./PlatformVerifierBase.sol";
import {TlsNotaryVerifierBase} from "./TlsNotaryVerifierBase.sol";

/// @title XPlatformVerifier — the `x/v1` profile.
///
/// @dev Revealed layout (REQ-COMMON-17A): the token request whole; the
///      `"access_token":"` delimiter and closing quote; the identity request
///      except the bearer (REQ-COMMON-35); the `"id":"` and `"username":"`
///      anchors and closing quotes, with id and handle committed for the circuit.
contract XPlatformVerifier is TlsNotaryVerifierBase {
    bytes private constant GRANT_TYPE = "authorization_code";

    error WrongGrantType(bytes found);

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    function initialize(address owner_, INotaryService notary_, IHonkVerifier honkVerifier_) external initializer {
        __PlatformVerifierBase_init(owner_, notary_, honkVerifier_);
    }

    function _platform() internal pure override returns (bytes32) {
        return CeremonyProfile.PLATFORM_X;
    }

    /// @dev REQ-PLAT-56. `grant_type` is the one revealed field that changes
    ///      what X does with the request: `refresh_token` with an otherwise
    ///      valid body returns a fresh bearer. The exact-form check admits that
    ///      value, so this comparison is what refuses it.
    function _checkTokenBody(CeremonyFields.Form memory form) internal pure override {
        bytes memory grantType = CeremonyFields.valueOf(form, "grant_type");
        if (keccak256(grantType) != keccak256(GRANT_TYPE)) revert WrongGrantType(grantType);
    }
}
