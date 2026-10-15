// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {CircuitCodehashes} from "../circuits/CircuitCodehashes.sol";
import {CeremonyAuthorization} from "./CeremonyAuthorization.sol";
import {CeremonyProfile} from "./CeremonyProfile.sol";
import {INotaryService} from "./INotaryService.sol";
import {IPlatformVerifier} from "./IPlatformVerifier.sol";
import {HandleDisclosure, IHonkVerifier, PlatformVerifierBase} from "./PlatformVerifierBase.sol";

/// @dev Where the deployment keeps the Google signing keys it trusts:
///      `GoogleJwtRoots`, kept beside this verifier.
interface IGoogleJwtRoots {
    function trustedHashExpiresAt(bytes32 modulusHash) external view returns (uint256);
}

/// @title GooglePlatformVerifier — the `google/v1` profile.
///
/// @notice One proof over a signed ID Token: no notarized session, no Notary
///         Service, no fee.
///
/// @dev The verifier builds the circuit's public inputs: the digest it
///      rebuilds is the signed OIDC `nonce` (REQ-COMMON-02A), `sha256(aud)` is
///      the audience, and the nodes, `exp` and modulus come from the payload.
///      Any wrong value fails the proof. `exp` gives both `metadataObservedAt`
///      and `proofValidUntil`.
contract GooglePlatformVerifier is IPlatformVerifier, PlatformVerifierBase {
    /// @dev The public inputs REQ-PLAT-16B fixes, in the order it lists them.
    ///      The digest is 32 field elements of one byte each; the rest are
    ///      packed Fields.
    uint256 private constant OFF_DIGEST = 0;
    uint256 private constant OFF_AUDIENCE = 32; // 2 fields, 16 bytes each
    uint256 private constant OFF_ID_NODE = 34; // 2 fields, 16 bytes each
    uint256 private constant OFF_HANDLE_NODE = 36; // 2 fields, 16 bytes each
    uint256 private constant OFF_EXP = 38;
    uint256 private constant OFF_MODULUS = 39; // 18 limbs
    uint256 private constant MODULUS_LIMBS = 18;
    uint256 private constant PUBLIC_INPUTS = 57;

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
    /// @param handle             Empty, or the address to disclose; must hash to the handle node.
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
        string handle;
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

    event JwtRootsChanged(address roots);

    error MissingClientIdentifier();
    /// @dev The signing key is not in the active trusted set, or its trust has
    ///      lapsed (REQ-PLAT-23).
    error UntrustedModulus(bytes32 modulusHash);
    /// @dev `Block Time >= proofValidUntil`, where the ceiling is the signed
    ///      `exp` itself (REQ-PLAT-22).
    error TokenExpired(uint64 exp, uint64 blockTime);

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    /// @dev `notary_` is the base's; this verifier never calls it, since a
    ///      profile whose Attestation Count is zero must not reach a Notary
    ///      Service (REQ-COMMON-05D).
    function initialize(address owner_, INotaryService notary_, IHonkVerifier honkVerifier_, IGoogleJwtRoots jwtRoots_)
        external
        initializer
    {
        __PlatformVerifierBase_init(owner_, notary_, honkVerifier_);
        _setJwtRoots(jwtRoots_);
    }

    function jwtRoots() external view returns (address) {
        return address(_g().jwtRoots);
    }

    /// @dev Google rotates signing keys weekly, and every ceremony fails closed
    ///      while an active modulus is untrusted (REQ-PLAT-24).
    function setJwtRoots(IGoogleJwtRoots roots) external onlyOwner {
        _setJwtRoots(roots);
    }

    function _setJwtRoots(IGoogleJwtRoots roots) private {
        if (address(roots) == address(0)) revert ZeroAddress();
        _g().jwtRoots = roots;
        emit JwtRootsChanged(address(roots));
    }

    /// @dev `oidc-google`'s verifier, and no other.
    function _circuitCodehash() internal pure override returns (bytes32) {
        return CircuitCodehashes.OIDC_GOOGLE;
    }

    function _platform() internal pure override returns (bytes32) {
        return CeremonyProfile.PLATFORM_GOOGLE;
    }

    /// @inheritdoc IPlatformVerifier
    function platformId() external pure returns (bytes32) {
        return CeremonyProfile.PLATFORM_GOOGLE;
    }

    /// @inheritdoc IPlatformVerifier
    /// @dev Zero. Its Attestation Count is zero, so it verifies nothing that
    ///      charges (REQ-COMMON-06E).
    function quote() public pure returns (uint256) {
        return 0;
    }

    /// @inheritdoc IPlatformVerifier
    function verify(bytes calldata payload) external payable returns (VerifiedClaim memory claimed) {
        // Not merely "no fee required" but "no value accepted": there is
        // nothing downstream to forward it to, and value left here would be
        // captured in transit.
        if (msg.value != 0) revert WrongValue(0, msg.value);

        GoogleProof memory p = abi.decode(payload, (GoogleProof));
        uint16 version = _requireCeremonyVersion(p.ceremonyVersion);

        // REQ-COMMON-02A. The digest rebuilt here from the decoded payload,
        // this verifier's version and this chain is the signed `nonce` the
        // proof must carry.
        bytes32 digest =
            CeremonyAuthorization.digestFor(p.operationDomain, version, p.authorizationNonce, p.transactionData);

        // REQ-PLAT-19A. The proof binds the bytes' hash, and the Consumer
        // receives the readable value.
        if (p.clientIdentifier.length == 0) revert MissingClientIdentifier();

        // REQ-PLAT-23. The circuit uses the modulus that verified the JWS but
        // decides no trust; that decision is here alone.
        _requireTrustedModulus(p.modulus);

        // REQ-PLAT-22. The signed `exp` is the whole validity ceiling, and a
        // ceiling above it: without one, a token minted with a distant expiry
        // buys a proportionally long lock on the name.
        if (block.timestamp >= p.exp) revert TokenExpired(p.exp, uint64(block.timestamp));
        _requireNotAhead(p.exp);

        // A disclosure checked before the proof is paid for.
        claimed.handle = HandleDisclosure.check(_platform(), p.handle, p.handleNode);

        // The inputs are built, never taken, so each value above is the one proved.
        _requireProof(p.proof, _publicInputs(p, digest));
        claimed.idNode = p.idNode;
        claimed.handleNode = p.handleNode;
        claimed.metadataObservedAt = _onSharedScale(p.exp, _futureObservationAllowance());
        claimed.clientIdentifier = p.clientIdentifier;
        claimed.sessionId = digest;
        claimed.operationDomain = p.operationDomain;
        claimed.transactionData = p.transactionData;
        claimed.ceremonyVersion = version;
    }

    // ─── Building the public inputs ─────────────────────────────────

    /// @dev REQ-PLAT-16B's 57 public inputs, in its order.
    function _publicInputs(GoogleProof memory p, bytes32 digest) private pure returns (bytes32[] memory inputs) {
        inputs = new bytes32[](PUBLIC_INPUTS);
        for (uint256 i = 0; i < 32; ++i) {
            inputs[OFF_DIGEST + i] = bytes32(uint256(uint8(digest[i])));
        }
        _halves(inputs, OFF_AUDIENCE, sha256(p.clientIdentifier));
        _halves(inputs, OFF_ID_NODE, p.idNode);
        _halves(inputs, OFF_HANDLE_NODE, p.handleNode);
        inputs[OFF_EXP] = bytes32(uint256(p.exp));
        for (uint256 i = 0; i < MODULUS_LIMBS; ++i) {
            inputs[OFF_MODULUS + i] = p.modulus[i];
        }
    }

    function _requireTrustedModulus(bytes32[18] memory modulus) private view {
        bytes32 modulusHash = keccak256(abi.encodePacked(modulus));
        uint256 expiresAt = _g().jwtRoots.trustedHashExpiresAt(modulusHash);
        if (expiresAt == 0 || block.timestamp >= expiresAt) revert UntrustedModulus(modulusHash);
    }
}
