// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {CircuitCodehashes} from "../circuits/CircuitCodehashes.sol";
import {CeremonyAuthorization} from "./CeremonyAuthorization.sol";
import {CeremonyProfile} from "./CeremonyProfile.sol";
import {INotaryService} from "./INotaryService.sol";
import {IPlatformVerifier} from "./IPlatformVerifier.sol";
import {IGoogleJwtRoots, OidcPlatformVerifierBase} from "./OidcPlatformVerifierBase.sol";
import {IHonkVerifier} from "./PlatformVerifierBase.sol";

/// @title GooglePlatformVerifier — the `google/v1` profile.
///
/// @notice One proof over a signed ID Token, with no notarized session and no fee.
///
/// @dev The verifier builds the circuit's public inputs: the rebuilt digest
///      is the signed OIDC `nonce` (REQ-COMMON-02A), `sha256(aud)` the
///      audience, and the nodes, `exp` and modulus come from the payload.
///      `exp` gives both `metadataObservedAt` and `proofValidUntil`.
contract GooglePlatformVerifier is OidcPlatformVerifierBase {
    /// @notice The `google/v1` payload, as `abi.encode` of this struct.
    /// @dev Every field is authentic only once the proof verifies.
    /// @param ceremonyVersion    Checked against the verifier's own first.
    /// @param operationDomain    Into the digest; returned.
    /// @param authorizationNonce Into the digest.
    /// @param transactionData    Into the digest; returned opaque.
    /// @param clientIdentifier   The `aud` bytes; their SHA-256 is a public input (REQ-PLAT-19A).
    /// @param idNode             The circuit's id node.
    /// @param handleNode         The circuit's handle node.
    /// @param exp                The signed `exp`.
    /// @param modulus            The signing key's 18 limbs, as the circuit takes them.
    /// @param proof              The Honk proof.
    struct GoogleProof {
        uint16 ceremonyVersion;
        bytes32 operationDomain;
        bytes32 authorizationNonce;
        bytes transactionData;
        bytes clientIdentifier;
        bytes32 idNode;
        bytes32 handleNode;
        uint64 exp;
        bytes32[18] modulus;
        bytes proof;
    }

    /// @custom:storage-location erc7201:libid.storage.GooglePlatformVerifier
    struct GoogleStorage {
        IGoogleJwtRoots jwtRoots;
    }

    // keccak256(abi.encode(uint256(keccak256("libid.storage.GooglePlatformVerifier")) - 1)) & ~bytes32(uint256(0xff))
    bytes32 private constant GOOGLE_STORAGE = 0x92a7c997eeb454ceeeb8ef2d99ba7d4b830287ff966f129f9049c466a8342400;

    function _g() private pure returns (GoogleStorage storage $) {
        assembly {
            $.slot := GOOGLE_STORAGE
        }
    }

    error MissingClientIdentifier();
    /// @dev `Block Time >= proofValidUntil`, where the ceiling is the signed
    ///      `exp` itself (REQ-PLAT-22).
    error TokenExpired(uint64 exp, uint64 blockTime);

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    /// @dev `notary_` must be zero: a profile whose Attestation Count is zero
    ///      holds no Notary Service (REQ-COMMON-05D).
    function initialize(address owner_, INotaryService notary_, IHonkVerifier honkVerifier_, IGoogleJwtRoots jwtRoots_)
        external
        initializer
    {
        __PlatformVerifierBase_init(owner_, notary_, honkVerifier_);
        _setJwtRoots(jwtRoots_);
    }

    function _jwtRoots() internal view override returns (IGoogleJwtRoots) {
        return _g().jwtRoots;
    }

    function _storeJwtRoots(IGoogleJwtRoots roots) internal override {
        _g().jwtRoots = roots;
    }

    /// @dev The `oidc-google` circuit's verifier.
    function _circuitCodehash() internal pure override returns (bytes32) {
        return CircuitCodehashes.OIDC_GOOGLE;
    }

    function _platform() internal pure override returns (bytes32) {
        return CeremonyProfile.PLATFORM_GOOGLE;
    }

    /// @inheritdoc IPlatformVerifier
    function verify(bytes calldata payload) external payable returns (VerifiedClaim memory claimed) {
        // No value is accepted: nothing downstream takes it.
        if (msg.value != 0) revert WrongValue(0, msg.value);

        GoogleProof memory p = abi.decode(payload, (GoogleProof));
        uint16 version = _requireCeremonyVersion(p.ceremonyVersion);

        // REQ-COMMON-02A: the proof must carry this digest as the signed `nonce`.
        bytes32 digest =
            CeremonyAuthorization.digest(p.operationDomain, version, p.authorizationNonce, p.transactionData);

        // REQ-PLAT-19A. The proof binds the bytes' hash, and the Consumer
        // receives the readable value.
        if (p.clientIdentifier.length == 0) revert MissingClientIdentifier();

        // REQ-PLAT-23. The circuit uses the modulus that verified the JWS but
        // decides no trust; that decision is here alone.
        _requireTrustedModulus(p.modulus);

        // REQ-PLAT-22. The signed `exp` is the validity ceiling, and itself
        // capped, so a distant expiry cannot hold a name for longer.
        if (block.timestamp >= p.exp) revert TokenExpired(p.exp, uint64(block.timestamp));
        _requireNotAhead(p.exp);

        // The inputs are built here, so each value above is the one proved.
        _requireProof(
            p.proof, _oidcInputs(digest, sha256(p.clientIdentifier), p.idNode, p.handleNode, p.exp, p.modulus)
        );
        claimed.idNode = p.idNode;
        claimed.handleNode = p.handleNode;
        claimed.metadataObservedAt = _onSharedScale(p.exp, _futureObservationAllowance());
        claimed.clientIdentifier = p.clientIdentifier;
        claimed.sessionId = digest;
        claimed.operationDomain = p.operationDomain;
        claimed.transactionData = p.transactionData;
        claimed.ceremonyVersion = version;
    }
}
