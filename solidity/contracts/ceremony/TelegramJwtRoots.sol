// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {CeremonyProfile} from "./CeremonyProfile.sol";
import {JwtRootsBase} from "./JwtRootsBase.sol";

/// @title TelegramJwtRoots - the signing keys `telegram/v1` trusts, read
///        from Telegram's JWKS.
contract TelegramJwtRoots is JwtRootsBase {
    // @custom:storage-location erc7201:libid.storage.TelegramJwtRoots
    // keccak256(abi.encode(uint256(keccak256("libid.storage.TelegramJwtRoots")) - 1)) & ~bytes32(uint256(0xff))
    bytes32 private constant TELEGRAM_JWT_ROOTS_STORAGE =
        0xee6f2b3e40651b1e1efa8f1db9f1ee7aef357f8d6b6ea64c3dddc41d11aa7800;

    function _storageRoot() internal pure override returns (bytes32) {
        return TELEGRAM_JWT_ROOTS_STORAGE;
    }

    function _jwksHost() internal pure override returns (bytes memory) {
        return CeremonyProfile.TELEGRAM_JWKS_HOST;
    }

    function _jwksRequestLine() internal pure override returns (bytes memory) {
        return CeremonyProfile.TELEGRAM_JWKS_REQUEST_LINE;
    }
}
