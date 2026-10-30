// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IPlatformVerifier} from "./IPlatformVerifier.sol";
import {PlatformVerifierBase} from "./PlatformVerifierBase.sol";

/// @dev The signing keys a deployment trusts, held by a `GoogleJwtRoots` deployment.
interface IGoogleJwtRoots {
    function trustedHashExpiresAt(bytes32 modulusHash) external view returns (uint256);
}

/// @title OidcPlatformVerifierBase
/// @notice What the OIDC circuits share: one 57-input layout, and a signing
///         key trusted only while a JWT roots list lists it.
abstract contract OidcPlatformVerifierBase is IPlatformVerifier, PlatformVerifierBase {
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
    /// @dev An empty audience: Google's `clientIdentifier`, Telegram's bot id.
    error MissingClientIdentifier();

    /// @dev The profile's own storage for its roots list.
    function _jwtRoots() internal view virtual returns (IGoogleJwtRoots);
    function _storeJwtRoots(IGoogleJwtRoots roots) internal virtual;

    function jwtRoots() external view returns (address) {
        return address(_jwtRoots());
    }

    /// @dev Keys rotate, and every ceremony fails closed while an active
    ///      modulus is untrusted (REQ-PLAT-24).
    function setJwtRoots(IGoogleJwtRoots roots) external onlyOwner {
        _setJwtRoots(roots);
    }

    function _setJwtRoots(IGoogleJwtRoots roots) internal {
        if (address(roots) == address(0)) revert ZeroAddress();
        _storeJwtRoots(roots);
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
}
