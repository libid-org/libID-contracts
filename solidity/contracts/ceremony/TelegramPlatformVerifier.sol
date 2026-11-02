// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {CircuitCodehashes} from "../circuits/CircuitCodehashes.sol";
import {CeremonyAuthorization} from "./CeremonyAuthorization.sol";
import {CeremonyProfile} from "./CeremonyProfile.sol";
import {INotaryService} from "./INotaryService.sol";
import {IPlatformVerifier} from "./IPlatformVerifier.sol";
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

    /// @custom:storage-location erc7201:libid.storage.TelegramPlatformVerifier
    struct TelegramStorage {
        IJwtRoots jwtRoots;
    }

    // keccak256(abi.encode(uint256(keccak256("libid.storage.TelegramPlatformVerifier")) - 1)) & ~bytes32(uint256(0xff))
    bytes32 private constant TELEGRAM_STORAGE = 0xdbc39b430f003c3f11a780c4bae9c4d3f473abf939613bb2f756a39264692900;

    function _t() private pure returns (TelegramStorage storage $) {
        assembly {
            $.slot := TELEGRAM_STORAGE
        }
    }

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    /// @dev `notary_` must be zero (REQ-COMMON-05D).
    function initialize(address owner_, INotaryService notary_, IHonkVerifier honkVerifier_, IJwtRoots jwtRoots_)
        external
        initializer
    {
        __PlatformVerifierBase_init(owner_, notary_, honkVerifier_);
        _setJwtRoots(jwtRoots_);
    }

    function _jwtRoots() internal view override returns (IJwtRoots) {
        return _t().jwtRoots;
    }

    function _storeJwtRoots(IJwtRoots roots) internal override {
        _t().jwtRoots = roots;
    }

    function _jwtRootsAuthority() internal pure override returns (bytes32) {
        return CeremonyProfile.AUTHORITY_TELEGRAM_OAUTH;
    }

    /// @dev The `oidc-telegram` circuit's verifier.
    function _circuitCodehash() internal pure override returns (bytes32) {
        return CircuitCodehashes.OIDC_TELEGRAM;
    }

    function _platform() internal pure override returns (bytes32) {
        return CeremonyProfile.PLATFORM_TELEGRAM;
    }

    /// @inheritdoc IPlatformVerifier
    function verify(bytes calldata payload) external payable returns (VerifiedClaim memory claimed) {
        if (msg.value != 0) revert WrongValue(0, msg.value);

        TelegramProof memory p = abi.decode(payload, (TelegramProof));
        uint16 version = _requireCeremonyVersion(p.ceremonyVersion);
        bytes32 digest =
            CeremonyAuthorization.digest(p.operationDomain, version, p.authorizationNonce, p.transactionData);
        if (p.clientIdentifier.length == 0) revert MissingClientIdentifier();
        _requireTrustedModulus(p.modulus);

        uint64 observedAt = _requireFresh(p.iat);
        _requireProof(
            p.proof, _oidcInputs(digest, sha256(p.clientIdentifier), p.idNode, p.handleNode, p.iat, p.modulus)
        );
        claimed.idNode = p.idNode;
        claimed.handleNode = p.handleNode;
        claimed.metadataObservedAt = observedAt;
        claimed.clientIdentifier = p.clientIdentifier;
        claimed.sessionId = digest;
        claimed.operationDomain = p.operationDomain;
        claimed.transactionData = p.transactionData;
        claimed.ceremonyVersion = version;
    }
}
