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
    /// @notice The `telegram/v1` payload, as `abi.encode` of this struct.
    /// @dev Every field is authentic only once the proof verifies.
    /// @param ceremonyVersion    Checked against the verifier's own first.
    /// @param operationDomain    Into the digest; returned.
    /// @param authorizationNonce Into the digest.
    /// @param transactionData    Into the digest; returned opaque.
    /// @param clientIdentifier   The exact `aud` bytes, the bot id as a decimal string; their
    ///                           SHA-256 is a public input (REQ-PLAT-19A).
    /// @param idNode             The circuit's id node.
    /// @param handleNode         The circuit's handle node.
    /// @param iat                The signed `iat`; the proof's window counts from it.
    /// @param modulus            The signing key's 18 limbs, as the circuit takes them.
    /// @param proof              The Honk proof.
    struct TelegramProof {
        uint16 ceremonyVersion;
        bytes32 operationDomain;
        bytes32 authorizationNonce;
        bytes transactionData;
        bytes clientIdentifier;
        bytes32 idNode;
        bytes32 handleNode;
        uint64 iat;
        bytes32[18] modulus;
        bytes proof;
    }

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
