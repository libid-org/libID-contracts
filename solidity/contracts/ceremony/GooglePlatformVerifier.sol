// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {CircuitCodehashes} from "../circuits/CircuitCodehashes.sol";
import {CeremonyProfile} from "./CeremonyProfile.sol";
import {INotaryService} from "./INotaryService.sol";
import {IJwtRoots, OidcPlatformVerifierBase} from "./OidcPlatformVerifierBase.sol";
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

    // @custom:storage-location erc7201:libid.storage.GooglePlatformVerifier
    // keccak256(abi.encode(uint256(keccak256("libid.storage.GooglePlatformVerifier")) - 1)) & ~bytes32(uint256(0xff))
    bytes32 private constant GOOGLE_STORAGE = 0x92a7c997eeb454ceeeb8ef2d99ba7d4b830287ff966f129f9049c466a8342400;

    /// @dev `Block Time >= proofValidUntil`, where the ceiling is the signed
    ///      `exp` itself (REQ-PLAT-22).
    error TokenExpired(uint64 exp, uint64 blockTime);

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    /// @dev `notary_` must be zero: a profile whose Attestation Count is zero
    ///      holds no Notary Service (REQ-COMMON-05D).
    function initialize(address owner_, INotaryService notary_, IHonkVerifier honkVerifier_, IJwtRoots jwtRoots_)
        external
        initializer
    {
        __OidcPlatformVerifierBase_init(owner_, notary_, honkVerifier_, jwtRoots_);
    }

    function _oidcStorageRoot() internal pure override returns (bytes32) {
        return GOOGLE_STORAGE;
    }

    /// @dev The `oidc-google` circuit's verifier.
    function _circuitCodehash() internal pure override returns (bytes32) {
        return CircuitCodehashes.OIDC_GOOGLE;
    }

    function _platform() internal pure override returns (bytes32) {
        return CeremonyProfile.PLATFORM_GOOGLE;
    }

    /// @dev REQ-PLAT-22. The signed `exp` is the validity ceiling, and itself
    ///      capped, so a distant expiry cannot hold a name for longer.
    function _requireTime(uint64 exp) internal view override returns (uint64) {
        if (block.timestamp >= exp) revert TokenExpired(exp, uint64(block.timestamp));
        _requireNotAhead(exp);
        return _onSharedScale(exp, _futureObservationAllowance());
    }
}
