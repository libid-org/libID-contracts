// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {CircuitCodehashes} from "../circuits/CircuitCodehashes.sol";
import {CeremonyAuthorization} from "./CeremonyAuthorization.sol";
import {CeremonyProfile} from "./CeremonyProfile.sol";
import {INotaryService} from "./INotaryService.sol";
import {IPlatformVerifier} from "./IPlatformVerifier.sol";
import {IGoogleJwtRoots, OidcPlatformVerifierBase} from "./OidcPlatformVerifierBase.sol";
import {IHonkVerifier} from "./PlatformVerifierBase.sol";

/// @title TelegramPlatformVerifier — the `telegram/v1` profile.
///
/// @notice One proof over an ID Token Telegram signed, with no notarized
///         session and no fee.
///
/// @dev Google's input layout with `iat` in `exp`'s place. The audience is
///      the configured bot id, never a caller's, and `iat` is both the
///      validity anchor and `metadataObservedAt`.
contract TelegramPlatformVerifier is OidcPlatformVerifierBase {
    /// @notice The `telegram/v1` payload, as `abi.encode` of this struct.
    /// @dev Every field is authentic only once the proof verifies.
    struct TelegramProof {
        uint16 ceremonyVersion;
        bytes32 operationDomain;
        bytes32 authorizationNonce;
        bytes transactionData;
        bytes32 idNode;
        bytes32 handleNode;
        uint64 iat;
        bytes32[18] modulus;
        bytes proof;
    }

    /// @custom:storage-location erc7201:libid.storage.TelegramPlatformVerifier
    struct TelegramStorage {
        IGoogleJwtRoots jwtRoots;
        /// The bot id the token's `aud` must be.
        bytes botId;
    }

    // keccak256(abi.encode(uint256(keccak256("libid.storage.TelegramPlatformVerifier")) - 1)) & ~bytes32(uint256(0xff))
    bytes32 private constant TELEGRAM_STORAGE = 0xdbc39b430f003c3f11a780c4bae9c4d3f473abf939613bb2f756a39264692900;

    function _t() private pure returns (TelegramStorage storage $) {
        assembly {
            $.slot := TELEGRAM_STORAGE
        }
    }

    event JwtRootsChanged(address roots);

    error MissingClientIdentifier();
    /// @dev The signing key is not trusted now (REQ-PLAT-23).
    error UntrustedModulus(bytes32 modulusHash);

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    /// @dev `notary_` must be zero (REQ-COMMON-05D).
    function initialize(
        address owner_,
        INotaryService notary_,
        IHonkVerifier honkVerifier_,
        IGoogleJwtRoots jwtRoots_,
        bytes calldata botId_
    ) external initializer {
        __PlatformVerifierBase_init(owner_, notary_, honkVerifier_);
        _setJwtRoots(jwtRoots_);
        if (botId_.length == 0) revert MissingClientIdentifier();
        _t().botId = botId_;
    }

    function jwtRoots() external view returns (address) {
        return address(_t().jwtRoots);
    }

    function botId() external view returns (bytes memory) {
        return _t().botId;
    }

    function setJwtRoots(IGoogleJwtRoots roots) external onlyOwner {
        _setJwtRoots(roots);
    }

    function _setJwtRoots(IGoogleJwtRoots roots) private {
        if (address(roots) == address(0)) revert ZeroAddress();
        _t().jwtRoots = roots;
        emit JwtRootsChanged(address(roots));
    }

    /// @dev The `oidc-telegram` circuit's verifier.
    function _circuitCodehash() internal pure override returns (bytes32) {
        return CircuitCodehashes.OIDC_TELEGRAM;
    }

    function _platform() internal pure override returns (bytes32) {
        return CeremonyProfile.PLATFORM_TELEGRAM;
    }

    /// @inheritdoc IPlatformVerifier
    function platformId() external pure returns (bytes32) {
        return CeremonyProfile.PLATFORM_TELEGRAM;
    }

    /// @inheritdoc IPlatformVerifier
    /// @dev Zero: the Attestation Count is zero (REQ-COMMON-06E).
    function quote() public pure returns (uint256) {
        return 0;
    }

    /// @inheritdoc IPlatformVerifier
    function verify(bytes calldata payload) external payable returns (VerifiedClaim memory claimed) {
        if (msg.value != 0) revert WrongValue(0, msg.value);

        TelegramProof memory p = abi.decode(payload, (TelegramProof));
        uint16 version = _requireCeremonyVersion(p.ceremonyVersion);
        bytes32 digest =
            CeremonyAuthorization.digest(p.operationDomain, version, p.authorizationNonce, p.transactionData);
        TelegramStorage storage $ = _t();
        (bytes32 modulusHash, bool trusted) = _modulusTrust($.jwtRoots, p.modulus);
        if (!trusted) revert UntrustedModulus(modulusHash);

        // iat - skew <= Block Time <= iat + lifetime, both ends inclusive.
        uint64 blockTime = uint64(block.timestamp);
        uint64 skew = _maxFutureAttestationSkew();
        if (p.iat > blockTime + skew) revert AttestationAhead(p.iat, blockTime, skew);
        uint64 validUntil = p.iat + _proofLifetime();
        if (blockTime > validUntil) revert ProofExpired(validUntil, blockTime);

        bytes memory bot = $.botId;
        _requireProof(p.proof, _oidcInputs(digest, sha256(bot), p.idNode, p.handleNode, p.iat, p.modulus));
        claimed.idNode = p.idNode;
        claimed.handleNode = p.handleNode;
        claimed.metadataObservedAt = p.iat;
        claimed.clientIdentifier = bot;
        claimed.sessionId = digest;
        claimed.operationDomain = p.operationDomain;
        claimed.transactionData = p.transactionData;
        claimed.ceremonyVersion = version;
    }
}
