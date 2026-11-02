// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {AttestationBuilder} from "./AttestationBuilder.sol";
import {JwtRootsTestBase} from "./JwtRootsBase.t.sol";
import {CeremonyProfile} from "../CeremonyProfile.sol";
import {GoogleJwtRoots} from "../GoogleJwtRoots.sol";
import {INotaryService} from "../INotaryService.sol";
import {JwtRootsBase} from "../JwtRootsBase.sol";
import {TelegramJwtRoots} from "../TelegramJwtRoots.sol";

/// The `telegram/v1` profile's trust list: JwtRootsBase's code, read from
/// Telegram's JWKS endpoint.
contract TelegramJwtRootsTest is JwtRootsTestBase {
    /// Telegram's real body, fetched 2026-10-30 with `Accept-Encoding: identity`:
    /// RSA `oidc-1`, then EC P-256, Ed25519 and EC secp256k1 keys.
    string constant TELEGRAM_JWKS = "contracts/ceremony/test/fixtures/telegram-jwks.json";
    bytes constant TG_REQUEST = "GET /.well-known/jwks.json HTTP/1.1\r\n" "host: oauth.telegram.org\r\n"
        "connection: close\r\n" "accept-encoding: identity\r\n" "\r\n";
    bytes32 constant TG_AUTHORITY = keccak256("oauth.telegram.org");
    bytes constant TG_NON_RSA = '{"kty":"EC","crv":"P-256","kid":"es","x":"AQ","y":"Ag"},'
        '{"kty":"OKP","crv":"Ed25519","kid":"ed","x":"Aw"}';

    function _implementation() internal override returns (JwtRootsBase) {
        return new TelegramJwtRoots();
    }

    function _authority() internal pure override returns (bytes32) {
        return TG_AUTHORITY;
    }

    function _request() internal pure override returns (bytes memory) {
        return TG_REQUEST;
    }

    function _attestAt(bytes32 authority, bytes memory line, bytes memory host, bytes memory response)
        private
        view
        returns (bytes memory)
    {
        return AttestationBuilder.encode(authority, _now(), _whole(abi.encodePacked(line, host)), _whole(response));
    }

    function _rotateAt(JwtRootsBase target, bytes memory attested) private {
        target.rotate{value: FEE}(attested, AttestationBuilder.sign(NOTARY_KEY, attested));
    }

    function _refusesAt(JwtRootsBase target, bytes memory attested, bytes memory err) private {
        bytes memory sig = AttestationBuilder.sign(NOTARY_KEY, attested);
        vm.expectRevert(err);
        target.rotate{value: FEE}(attested, sig);
    }

    /// Telegram's real four-key body trusts its RSA key alone.
    function test_telegramsRealBodyTrustsOnlyItsRsaKey() public {
        string memory json = vm.readFile(TELEGRAM_JWKS);
        _rotate(_reading(bytes(json)));
        bytes32 rsa = hasher.hashOfB64url(vm.parseJsonString(json, ".keys[0].n"));
        assertEq(_current().moduli, _one(rsa));
        assertEq(roots.trustedHashExpiresAt(rsa), _now() + roots.READING_LIFETIME());
    }

    /// Non-RSA keys are skipped wherever they stand; a reading of non-RSA
    /// keys alone is refused.
    function test_nonRsaKeysAreSkippedAndNeverEnough() public {
        _refuses(_reading(_body(TG_NON_RSA)), JwtRootsBase.EmptyKeySet.selector);
        _rotate(_reading(_body(abi.encodePacked(TG_NON_RSA, ",", _jwk("oidc-1", _modulus("tg"))))));
        assertEq(_current().moduli, _one(_hash("tg")));
    }

    /// Telegram gzips unless asked not to; a gzipped reading is refused, not parsed.
    function test_aGzippedTelegramReadingIsRefused() public {
        bytes memory gz = hex"1f8b08000000000002034b4c4a0600c241243503000000";
        bytes memory response = abi.encodePacked(
            STATUS_OK, "Content-Encoding: gzip\r\nContent-Length: ", vm.toString(gz.length), "\r\n\r\n", gz
        );
        _refuses(_attest(TG_REQUEST, response, _now()), JwtRootsBase.EncodedBody.selector);
    }

    /// Telegram's list and a Google list each refuse the other's authority,
    /// request line and Host, and accept their own.
    function test_eachDeploymentRefusesTheOthersEndpoint() public {
        JwtRootsBase google = _proxy(new GoogleJwtRoots(), INotaryService(address(notary)));
        bytes memory body = _contentLength(_oneKey("kid-1", "one"));
        JwtRootsBase[2] memory target = [google, roots];
        bytes32[2] memory own = [keccak256("www.googleapis.com"), TG_AUTHORITY];
        bytes[2] memory line = [CeremonyProfile.GOOGLE_JWKS_REQUEST_LINE, CeremonyProfile.TELEGRAM_JWKS_REQUEST_LINE];
        bytes[2] memory host = [bytes("host: www.googleapis.com\r\n\r\n"), "host: oauth.telegram.org\r\n\r\n"];
        for (uint256 i = 0; i < 2; ++i) {
            uint256 o = 1 - i;
            bytes memory err = abi.encodeWithSelector(JwtRootsBase.WrongAuthority.selector, own[i], own[o]);
            _refusesAt(target[i], _attestAt(own[o], line[o], host[o], body), err);
            err = abi.encodeWithSelector(JwtRootsBase.WrongRequestLine.selector);
            _refusesAt(target[i], _attestAt(own[i], line[o], host[i], body), err);
            err = abi.encodeWithSelector(JwtRootsBase.WrongHost.selector);
            _refusesAt(target[i], _attestAt(own[i], line[i], host[o], body), err);
            _rotateAt(target[i], _attestAt(own[i], line[i], host[i], body));
        }
    }

    /// The list names Telegram's JWKS host.
    function test_namesItsHost() public view {
        assertEq(roots.AUTHORITY(), TG_AUTHORITY);
    }
}
