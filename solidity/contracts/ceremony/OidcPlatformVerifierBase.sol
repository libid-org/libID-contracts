// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {CeremonyAuthorization} from "./CeremonyAuthorization.sol";
import {CeremonyProfile} from "./CeremonyProfile.sol";
import {INotaryService} from "./INotaryService.sol";
import {IPlatformVerifier} from "./IPlatformVerifier.sol";
import {IHonkVerifier, PlatformVerifierBase} from "./PlatformVerifierBase.sol";

/// @dev The signing keys a deployment trusts, held by a JWT roots list.
interface IJwtRoots {
    /// keccak256 of the JWKS host the list reads.
    function AUTHORITY() external view returns (bytes32);
    function trustedHashExpiresAt(bytes32 modulusHash) external view returns (uint256);
}

/// @title OidcPlatformVerifierBase
/// @notice What the OIDC circuits share: one payload, one 57-input layout,
///         and a signing key trusted only while a JWT roots list lists it.
///         A profile differs only in its time rule, `_requireTime`.
abstract contract OidcPlatformVerifierBase is IPlatformVerifier, PlatformVerifierBase {
    /// @notice The `google/v1` and `telegram/v1` payload, as `abi.encode` of this struct.
    /// @dev Every field is authentic only once the proof verifies.
    /// @param ceremonyVersion    Checked against the verifier's own first.
    /// @param operationDomain    Into the digest; returned.
    /// @param authorizationNonce Into the digest.
    /// @param transactionData    Into the digest; returned opaque.
    /// @param clientIdentifier   The exact `aud` bytes (Telegram's: the bot id as a decimal
    ///                           string); their SHA-256 is a public input (REQ-PLAT-19A).
    /// @param idNode             The circuit's id node.
    /// @param handleNode         The circuit's handle node.
    /// @param time               The signed time the profile's rule reads: Google's `exp`,
    ///                           Telegram's `iat`.
    /// @param modulus            The signing key's 18 limbs, as the circuit takes them.
    /// @param proof              The Honk proof.
    struct OidcProof {
        uint16 ceremonyVersion;
        bytes32 operationDomain;
        bytes32 authorizationNonce;
        bytes transactionData;
        bytes clientIdentifier;
        bytes32 idNode;
        bytes32 handleNode;
        uint64 time;
        bytes32[18] modulus;
        bytes proof;
    }

    /// @dev The public inputs REQ-PLAT-16B fixes, in the order it lists them.
    ///      The digest is 32 field elements of one byte each; the rest are
    ///      packed Fields.
    uint256 private constant OFF_DIGEST = 0;
    uint256 private constant OFF_AUDIENCE = 32; // 2 fields, 16 bytes each
    uint256 private constant OFF_ID_NODE = 34; // 2 fields, 16 bytes each
    uint256 private constant OFF_HANDLE_NODE = 36; // 2 fields, 16 bytes each
    uint256 private constant OFF_TIME = 38; // Google's `exp`, Telegram's `iat`
    uint256 private constant OFF_MODULUS = 39; // 18 limbs
    uint256 private constant MODULUS_LIMBS = 18;
    uint256 private constant PUBLIC_INPUTS = 57;

    /// @dev REQ-PLAT-16B's 57 public inputs, in its order.
    function _oidcInputs(
        bytes32 digest,
        bytes32 audienceHash,
        bytes32 idNode,
        bytes32 handleNode,
        uint64 time,
        bytes32[18] memory modulus
    ) internal pure returns (bytes32[] memory inputs) {
        inputs = new bytes32[](PUBLIC_INPUTS);
        for (uint256 i = 0; i < 32; ++i) {
            inputs[OFF_DIGEST + i] = bytes32(uint256(uint8(digest[i])));
        }
        _halves(inputs, OFF_AUDIENCE, audienceHash);
        _halves(inputs, OFF_ID_NODE, idNode);
        _halves(inputs, OFF_HANDLE_NODE, handleNode);
        inputs[OFF_TIME] = bytes32(uint256(time));
        for (uint256 i = 0; i < MODULUS_LIMBS; ++i) {
            inputs[OFF_MODULUS + i] = modulus[i];
        }
    }

    event JwtRootsChanged(address roots);

    /// @dev The signing key is not trusted now (REQ-PLAT-23).
    error UntrustedModulus(bytes32 modulusHash);
    /// @dev An empty `clientIdentifier`, the token's `aud`.
    error MissingClientIdentifier();

    /// @dev Kept at the root `_oidcStorageRoot()` names.
    struct OidcStorage {
        IJwtRoots jwtRoots;
    }

    /// @dev The ERC-7201 root of the profile's own namespace.
    function _oidcStorageRoot() internal pure virtual returns (bytes32);

    function _o() private pure returns (OidcStorage storage $) {
        bytes32 root = _oidcStorageRoot();
        assembly {
            $.slot := root
        }
    }

    function _jwtRoots() private view returns (IJwtRoots) {
        return _o().jwtRoots;
    }

    function __OidcPlatformVerifierBase_init(
        address owner_,
        INotaryService notary_,
        IHonkVerifier honkVerifier_,
        IJwtRoots jwtRoots_
    ) internal onlyInitializing {
        __PlatformVerifierBase_init(owner_, notary_, honkVerifier_);
        _setJwtRoots(jwtRoots_);
    }

    function jwtRoots() external view returns (address) {
        return address(_jwtRoots());
    }

    /// @dev Keys rotate, and every ceremony fails closed while an active
    ///      modulus is untrusted (REQ-PLAT-24).
    function setJwtRoots(IJwtRoots roots) external onlyOwner {
        _setJwtRoots(roots);
    }

    /// @dev A list that does not answer `AUTHORITY()` with one word, an
    ///      address with no code among them, reports authority zero.
    function _setJwtRoots(IJwtRoots roots) internal {
        if (address(roots) == address(0)) revert ZeroAddress();
        // The `AUTHORITY` of the JWKS host the profile's roots list reads.
        bytes32 expected = keccak256(CeremonyProfile.jwksHost(_platform()));
        (bool ok, bytes memory ret) = address(roots).staticcall(abi.encodeCall(IJwtRoots.AUTHORITY, ()));
        bytes32 found = ok && ret.length == 32 ? abi.decode(ret, (bytes32)) : bytes32(0);
        if (found != expected) revert WrongAuthority(expected, found);
        _o().jwtRoots = roots;
        emit JwtRootsChanged(address(roots));
    }

    /// @inheritdoc IPlatformVerifier
    function platformId() external pure returns (bytes32) {
        return _platform();
    }

    /// @inheritdoc IPlatformVerifier
    /// @dev Zero: the Attestation Count is zero (REQ-COMMON-06E).
    function quote() public pure returns (uint256) {
        return 0;
    }

    function _requireTrustedModulus(bytes32[18] memory modulus) internal view {
        bytes32 modulusHash = keccak256(abi.encodePacked(modulus));
        uint256 expiresAt = _jwtRoots().trustedHashExpiresAt(modulusHash);
        if (expiresAt == 0 || block.timestamp >= expiresAt) revert UntrustedModulus(modulusHash);
    }

    /// @dev Reverts unless Block Time is inside the window the signed time
    ///      opens; returns `metadataObservedAt`.
    function _requireTime(uint64 time) internal view virtual returns (uint64 metadataObservedAt);

    /// @inheritdoc IPlatformVerifier
    function verify(bytes calldata payload) external payable returns (VerifiedClaim memory claimed) {
        // No value is accepted: nothing downstream takes it.
        if (msg.value != 0) revert WrongValue(0, msg.value);

        OidcProof memory p = abi.decode(payload, (OidcProof));
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

        uint64 observedAt = _requireTime(p.time);

        // The inputs are built here, so each value above is the one proved.
        _requireProof(
            p.proof, _oidcInputs(digest, sha256(p.clientIdentifier), p.idNode, p.handleNode, p.time, p.modulus)
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
