// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Base64} from "@openzeppelin/contracts/utils/Base64.sol";

/// @title CeremonyAuthorization
/// @notice The Authorization Digest of ceremony-common section 5, and the PKCE
///         construction of section 7 that carries it.
/// @dev The Platform Verifier rebuilds the digest from the payload it decoded
///      and its own ceremony version, then binds it to the evidence by one of
///      two methods its profile fixes. Google compares it against a public
///      proof input; X and GitHub recompute the revealed `code_verifier` from
///      it. This library is the one place either derivation lives, so the
///      runtime and the chain cannot disagree.
///
///      The digest commits no chain, so one ceremony verifies on every chain
///      that runs this verifier. A Consumer whose effect is bound to one
///      chain carries the chain id in its own Authorized Transaction Data and
///      checks it against `block.chainid`.
library CeremonyAuthorization {
    /// @dev Raised when the Authorized Transaction Data cannot be described by
    ///      the layout's four-byte length field.
    error TransactionDataTooLong(uint256 length);

    /// @notice Build the preimage of section 5, exactly:
    ///         `operationDomain || U16BE(ceremonyVersion) || authorizationNonce
    ///         || U32BE(len) || transactionData`.
    /// @dev `abi.encodePacked` concatenates without padding, which is what the
    ///      layout wants; every field but `transactionData` is fixed width, so
    ///      the four-byte length is what keeps the last boundary derivable.
    function preimage(
        bytes32 operationDomain,
        uint16 ceremonyVersion,
        bytes32 authorizationNonce,
        bytes memory transactionData
    ) internal pure returns (bytes memory) {
        // REQ-COMMON-01 says reject a value that does not fit its field. A
        // silent `uint32` truncation here would encode a length the data does
        // not have, and the Rust and TypeScript builders both refuse it.
        if (transactionData.length > type(uint32).max) {
            revert TransactionDataTooLong(transactionData.length);
        }
        return abi.encodePacked(
            operationDomain, ceremonyVersion, authorizationNonce, uint32(transactionData.length), transactionData
        );
    }

    /// @notice The Authorization Digest: `keccak256` of the section 5 preimage.
    function digest(
        bytes32 operationDomain,
        uint16 ceremonyVersion,
        bytes32 authorizationNonce,
        bytes memory transactionData
    ) internal pure returns (bytes32) {
        return keccak256(preimage(operationDomain, ceremonyVersion, authorizationNonce, transactionData));
    }

    /// @notice `SHA256(authorizationDigest || authorizationNonce)`.
    /// @dev Exactly 64 bytes, and the nonce is the one the digest already
    ///      commits -- not a second salt beside it (REQ-COMMON-12). One nonce
    ///      is what makes a retry a new ceremony rather than the same digest
    ///      carried under a fresh verifier.
    function verifierHash(bytes32 authorizationDigest, bytes32 authorizationNonce) internal pure returns (bytes32) {
        return sha256(abi.encodePacked(authorizationDigest, authorizationNonce));
    }

    /// @notice `BASE64URL_NOPAD(verifierHash)` -- the 43 ASCII bytes the token
    ///         request reveals, which REQ-COMMON-15A has the Platform Verifier
    ///         recompute and compare byte for byte.
    function codeVerifier(bytes32 authorizationDigest, bytes32 authorizationNonce)
        internal
        pure
        returns (bytes memory)
    {
        return _base64UrlNoPad32(verifierHash(authorizationDigest, authorizationNonce));
    }

    /// @dev Encode 32 bytes as 43 unpadded base64url characters.
    ///      `Base64.encodeURL` is the section 7 encoder exactly: the URL
    ///      alphabet, and no `=` padding, which is what RFC 4648 §5 asks for.
    function _base64UrlNoPad32(bytes32 value) private pure returns (bytes memory) {
        return bytes(Base64.encodeURL(bytes.concat(value)));
    }
}
