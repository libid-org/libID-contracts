// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {CircuitCodehashes} from "../circuits/CircuitCodehashes.sol";
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

    /// @dev `bearer-link-x`'s verifier, and no other.
    function _circuitCodehash() internal pure virtual override returns (bytes32) {
        return CircuitCodehashes.BEARER_LINK_X;
    }

    function _platform() internal pure override returns (bytes32) {
        return CeremonyProfile.PLATFORM_X;
    }

    /// @dev REQ-PLAT-56, and X's only value check of its own. The runtime's own
    ///      comparison runs in software the prover chooses whether to run, and
    ///      `grant_type` is the one revealed field that changes what X did with
    ///      the request: a body sending `refresh_token` while still carrying a
    ///      code, a redirect_uri and a digest-derived verifier is processed as a
    ///      refresh, returns a fresh bearer, and passes every other check — so
    ///      an application holding a user's refresh token could mint identity
    ///      proofs at arbitrary addresses indefinitely from one consent.
    ///
    ///      The form admits the value -- `refresh_token` is in the serializer's
    ///      alphabet -- so it is this comparison, not the base's exact-form
    ///      check, that refuses it.
    function _checkTokenBody(CeremonyFields.Form memory form) internal pure override {
        bytes memory grantType = CeremonyFields.valueOf(form, "grant_type");
        if (keccak256(grantType) != keccak256(GRANT_TYPE)) revert WrongGrantType(grantType);
    }
}
