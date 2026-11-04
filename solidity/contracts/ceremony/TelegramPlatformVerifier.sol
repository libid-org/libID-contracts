// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {CircuitCodehashes} from "../circuits/CircuitCodehashes.sol";
import {CeremonyProfile} from "./CeremonyProfile.sol";
import {INotaryService} from "./INotaryService.sol";
import {IJwtRoots, OidcPlatformVerifierBase} from "./OidcPlatformVerifierBase.sol";
import {IHonkVerifier} from "./PlatformVerifierBase.sol";

/// @title TelegramPlatformVerifier — the `telegram/v1` profile.
///
/// @notice One proof over an ID Token Telegram signed, with no notarized
///         session and no fee.
///
/// @dev Google's input layout with `iat` in `exp`'s place. The audience is
///      the payload's `clientIdentifier`, the bot id. `iat` is the validity
///      anchor, and `metadataObservedAt` is `iat` on the shared scale.
///      A token outside its window reverts the shared `AttestationAhead` or
///      `ProofExpired`, whose `createdAt` and `validUntil` count from `iat`.
contract TelegramPlatformVerifier is OidcPlatformVerifierBase {
    // @custom:storage-location erc7201:libid.storage.TelegramPlatformVerifier
    // keccak256(abi.encode(uint256(keccak256("libid.storage.TelegramPlatformVerifier")) - 1)) & ~bytes32(uint256(0xff))
    bytes32 private constant TELEGRAM_STORAGE = 0xdbc39b430f003c3f11a780c4bae9c4d3f473abf939613bb2f756a39264692900;

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    /// @dev `notary_` must be zero (REQ-COMMON-05D).
    function initialize(address owner_, INotaryService notary_, IHonkVerifier honkVerifier_, IJwtRoots jwtRoots_)
        external
        initializer
    {
        __OidcPlatformVerifierBase_init(owner_, notary_, honkVerifier_, jwtRoots_);
    }

    function _oidcStorageRoot() internal pure override returns (bytes32) {
        return TELEGRAM_STORAGE;
    }

    /// @dev The `oidc-telegram` circuit's verifier.
    function _circuitCodehash() internal pure override returns (bytes32) {
        return CircuitCodehashes.OIDC_TELEGRAM;
    }

    function _platform() internal pure override returns (bytes32) {
        return CeremonyProfile.PLATFORM_TELEGRAM;
    }

    /// @dev `iat` opens the profile's window.
    function _requireTime(uint64 iat) internal view override returns (uint64) {
        return _requireFresh(iat);
    }
}
