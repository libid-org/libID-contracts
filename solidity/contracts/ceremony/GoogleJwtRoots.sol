// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {CeremonyProfile} from "./CeremonyProfile.sol";
import {JwtRootsBase} from "./JwtRootsBase.sol";

/// @title GoogleJwtRoots - the signing keys `google/v1` trusts, read from
///        Google's JWKS.
contract GoogleJwtRoots is JwtRootsBase {
    // @custom:storage-location erc7201:libid.storage.GoogleJwtRoots
    // keccak256(abi.encode(uint256(keccak256("libid.storage.GoogleJwtRoots")) - 1)) & ~bytes32(uint256(0xff))
    bytes32 private constant GOOGLE_JWT_ROOTS_STORAGE =
        0x7f78ff13201a03086d4b08e3085224c34a9fc247d0f67d11acd0db52976eb300;

    function _storageRoot() internal pure override returns (bytes32) {
        return GOOGLE_JWT_ROOTS_STORAGE;
    }

    function _jwksHost() internal pure override returns (bytes memory) {
        return CeremonyProfile.GOOGLE_JWKS_HOST;
    }

    function _jwksRequestLine() internal pure override returns (bytes memory) {
        return CeremonyProfile.GOOGLE_JWKS_REQUEST_LINE;
    }
}
