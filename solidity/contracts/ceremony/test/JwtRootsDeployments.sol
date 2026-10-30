// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {GoogleJwtRoots} from "../GoogleJwtRoots.sol";

/// @notice The two deployments of the JWT roots contract, written from each
///         issuer's published JWKS location.
library JwtRootsDeployments {
    bytes32 internal constant GOOGLE_AUTHORITY = keccak256("www.googleapis.com");
    bytes internal constant GOOGLE_REQUEST_LINE = "GET /oauth2/v3/certs HTTP/1.1\r\n";
    bytes internal constant GOOGLE_HOST = "www.googleapis.com";

    bytes32 internal constant TELEGRAM_AUTHORITY = keccak256("oauth.telegram.org");
    bytes internal constant TELEGRAM_REQUEST_LINE = "GET /.well-known/jwks.json HTTP/1.1\r\n";
    bytes internal constant TELEGRAM_HOST = "oauth.telegram.org";

    function google() internal returns (GoogleJwtRoots) {
        return new GoogleJwtRoots(GOOGLE_AUTHORITY, GOOGLE_REQUEST_LINE, GOOGLE_HOST);
    }

    function telegram() internal returns (GoogleJwtRoots) {
        return new GoogleJwtRoots(TELEGRAM_AUTHORITY, TELEGRAM_REQUEST_LINE, TELEGRAM_HOST);
    }
}
