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
/// @dev The digest is the signed OIDC `nonce`, a public input compared with
///      the rebuilt digest (REQ-COMMON-02A). The circuit publishes the id node
///      and the handle node; `exp` gives both `metadataObservedAt` and
///      `proofValidUntil`.
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
    /// @dev Public inputs are carried, and authentic only once the proof verifies.
    /// @param ceremonyVersion    Checked against the verifier's own first.
    /// @param operationDomain    Into the digest; returned.
    /// @param authorizationNonce Into the digest.
    /// @param transactionData    Into the digest; returned opaque.
    /// @param clientIdentifier   The `aud` bytes, checked against their public-input hash (REQ-PLAT-19A).
    /// @param publicInputs       The circuit's 57 public inputs (REQ-PLAT-16B order).
    /// @param handle             Empty, or the address to disclose; must hash to the handle node.
    /// @param proof              The Honk proof.
    struct GoogleProof {
        uint16 ceremonyVersion;
        bytes32 operationDomain;
        bytes32 authorizationNonce;
        bytes transactionData;
        bytes clientIdentifier;
        bytes32[] publicInputs;
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

    error WrongPublicInputCount(uint256 expected, uint256 provided);
    error DigestMismatch(bytes32 proved, bytes32 recomputed);
    error AudienceMismatch();
    error MissingClientIdentifier();
    /// @dev The signing key is not in the active trusted set, or its trust has
    ///      lapsed (REQ-PLAT-23).
    error UntrustedModulus(bytes32 modulusHash);
    /// @dev `Block Time >= proofValidUntil`, where the ceiling is the signed
    ///      `exp` itself (REQ-PLAT-22).
    error TokenExpired(uint64 exp, uint64 blockTime);
    /// @dev A public input the circuit declares as a byte carried more.
    error PublicInputNotAByte(uint256 index, uint256 value);
    /// @dev A packed public input carries more bits than its slot reads.
    error PublicInputOverwide(uint256 index, uint256 value, uint256 bits);
    /// @dev The signed expiry does not fit the width every timestamp uses.
    error ExpiryNotAUint64(uint256 value);

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    /// @dev `notary_` is still required by the base, and is deliberately never
    ///      called: a profile whose Attestation Count is zero must not reach a
    ///      Notary Service (REQ-COMMON-05D).
    function initialize(
        address owner_,
        INotaryService notary_,
        IHonkVerifier honkVerifier_,
        bytes32 honkVerifierCodehash_,
        IGoogleJwtRoots jwtRoots_
    ) external initializer {
        __PlatformVerifierBase_init(owner_, notary_, honkVerifier_, honkVerifierCodehash_);
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

    function _ceremonyVersion() internal pure override returns (uint16) {
        return CeremonyProfile.LAUNCH_VERSION;
    }

    /// @dev No attestation, so no lifetime and no attestation skew: the signed
    ///      `exp` is the whole validity ceiling.
    function _proofLifetime() internal pure override returns (uint64) {
        return 0;
    }

    function _maxFutureAttestationSkew() internal pure override returns (uint64) {
        return 0;
    }

    /// @dev The allowance is real: `exp` runs an hour ahead of Block Time, and
    ///      a Consumer comparing it raw against a TLSNotary profile's near-now
    ///      evidence would let Google win every race.
    function _futureObservationAllowance() internal pure override returns (uint64) {
        return CeremonyProfile.FUTURE_OBSERVATION_ALLOWANCE_SECONDS_GOOGLE;
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
        _requireCeremonyVersion(p.ceremonyVersion);
        if (p.publicInputs.length != PUBLIC_INPUTS) {
            revert WrongPublicInputCount(PUBLIC_INPUTS, p.publicInputs.length);
        }

        // REQ-COMMON-02A. Google's binding: the digest the ceremony committed
        // as the signed `nonce` must equal the one rebuilt here from the
        // decoded payload, this verifier's version and this chain.
        bytes32 digest = CeremonyAuthorization.digestFor(
            p.operationDomain, _ceremonyVersion(), p.authorizationNonce, p.transactionData
        );
        bytes32 proved = _digestFromInputs(p.publicInputs);
        if (proved != digest) revert DigestMismatch(proved, digest);

        // REQ-PLAT-19A. The digest authenticates the bytes without the circuit
        // packing a variable-length string into public inputs, and the Consumer
        // still receives the readable value.
        if (p.clientIdentifier.length == 0) revert MissingClientIdentifier();
        bytes32 audience = sha256(p.clientIdentifier);
        if (audience != _hashFromHalves(p.publicInputs, OFF_AUDIENCE)) revert AudienceMismatch();

        // REQ-PLAT-23. The circuit exposes the modulus that verified the JWS
        // but decides no trust; that decision is here alone.
        _requireTrustedModulus(p.publicInputs);

        // REQ-PLAT-22. The signed `exp` is the whole validity ceiling, so a
        // field element that does not fit `u64` must not become one that does.
        uint256 rawExp = uint256(p.publicInputs[OFF_EXP]);
        if (rawExp > type(uint64).max) revert ExpiryNotAUint64(rawExp);
        // Casting to uint64 is safe: the line above refuses anything wider.
        // forge-lint: disable-next-line(unsafe-typecast)
        uint64 exp = uint64(rawExp);
        if (block.timestamp >= exp) revert TokenExpired(exp, uint64(block.timestamp));
        // And a ceiling above it. Without one, a token minted with a distant
        // expiry buys a proportionally long lock on the name.
        _requireNotAhead(exp);

        // The circuit's nodes, and a disclosure checked before the proof is paid for.
        claimed.idNode = _hashFromHalves(p.publicInputs, OFF_ID_NODE);
        claimed.handleNode = _hashFromHalves(p.publicInputs, OFF_HANDLE_NODE);
        claimed.handle = HandleDisclosure.check(_platform(), p.handle, claimed.handleNode);

        // Every public input read above becomes authentic here, and the whole
        // transaction reverts if it does not; that is what makes reading them
        // first safe.
        _requireProof(p.proof, p.publicInputs);
        claimed.metadataObservedAt = _onSharedScale(exp, _futureObservationAllowance());
        claimed.clientIdentifier = p.clientIdentifier;
        claimed.sessionId = digest;
        claimed.operationDomain = p.operationDomain;
        claimed.transactionData = p.transactionData;
        claimed.ceremonyVersion = _ceremonyVersion();
    }

    // ─── Reading the public inputs ──────────────────────────────────

    /// @dev 32 field elements, one byte each.
    function _digestFromInputs(bytes32[] memory publicInputs) private pure returns (bytes32 out) {
        for (uint256 i = 0; i < 32; ++i) {
            uint256 element = uint256(publicInputs[OFF_DIGEST + i]);
            // Truncating here would rest the ONLY thing binding a Google
            // ceremony to its transaction (REQ-COMMON-02A) on a range
            // constraint this contract cannot see.
            if (element > 0xff) revert PublicInputNotAByte(OFF_DIGEST + i, element);
            out |= bytes32(element << (8 * (31 - i)));
        }
    }

    /// @dev A SHA-256 digest as two big-endian 16-byte Fields: the signed
    ///      `aud`'s, and the two nodes.
    function _hashFromHalves(bytes32[] memory publicInputs, uint256 offset) private pure returns (bytes32) {
        uint256 high = uint256(publicInputs[offset]);
        uint256 low = uint256(publicInputs[offset + 1]);
        // An over-wide `low` would spill into the high half and match any digest.
        if (high >> 128 != 0) revert PublicInputOverwide(offset, high, 128);
        if (low >> 128 != 0) revert PublicInputOverwide(offset + 1, low, 128);
        return bytes32((high << 128) | low);
    }

    function _requireTrustedModulus(bytes32[] memory publicInputs) private view {
        bytes memory packed = new bytes(MODULUS_LIMBS * 32);
        for (uint256 i = 0; i < MODULUS_LIMBS; ++i) {
            bytes32 limb = publicInputs[OFF_MODULUS + i];
            assembly {
                mstore(add(add(packed, 32), mul(i, 32)), limb)
            }
        }
        bytes32 modulusHash = keccak256(packed);
        uint256 expiresAt = _g().jwtRoots.trustedHashExpiresAt(modulusHash);
        if (expiresAt == 0 || block.timestamp >= expiresAt) revert UntrustedModulus(modulusHash);
    }
}
