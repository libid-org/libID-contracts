// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, Vm} from "forge-std/Test.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

import {AttestationBuilder} from "./AttestationBuilder.sol";
import {CeremonyProfile} from "../CeremonyProfile.sol";
import {INotaryService} from "../INotaryService.sol";
import {NotaryService} from "../NotaryService.sol";
import {GoogleJwtRoots} from "../GoogleJwtRoots.sol";
import {JwtRootsBase} from "../JwtRootsBase.sol";

/// Exposes `_splitLimbs` so a test computes a key's hash from its bytes, not from the list's state.
contract LimbHasher is GoogleJwtRoots {
    function hashOf(bytes memory modulus) external pure returns (bytes32) {
        return keccak256(abi.encodePacked(_splitLimbs(modulus)));
    }

    function hashOfB64url(string memory modulus) external pure returns (bytes32) {
        return keccak256(abi.encodePacked(_splitLimbs(_b64urlDecode(bytes(modulus)))));
    }
}

/// A JWT roots list fed by notarized readings of its issuer's JWKS. A test
/// contract names the list, its authority and the keeper's request.
///
/// Readings are section 4.1 sessions signed by the anvil key and checked by a
/// real NotaryService that charges a fee.
abstract contract JwtRootsTestBase is Test {
    JwtRootsBase roots;
    NotaryService notary;
    LimbHasher hasher;

    address constant OWNER = address(0xA11CE);
    address keeper = makeAddr("keeper");
    /// The anvil key.
    uint256 constant NOTARY_KEY = 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80;
    uint256 constant FEE = 0.001 ether;
    uint64 constant T0 = 1_770_000_000;

    bytes constant STATUS_OK = "HTTP/1.1 200 OK\r\n";
    bytes constant CONTENT_TYPE = "content-type: application/json; charset=UTF-8\r\n";

    // ─── The list under test ────────────────────────────────────────

    /// A fresh implementation of the list.
    function _implementation() internal virtual returns (JwtRootsBase);

    /// keccak256 of the list's JWKS host.
    function _authority() internal pure virtual returns (bytes32);

    /// The request the keeper's prover sends.
    function _request() internal pure virtual returns (bytes memory);

    function setUp() public {
        vm.warp(T0 + 10);

        NotaryService nImpl = new NotaryService();
        notary = NotaryService(
            address(
                new ERC1967Proxy(
                    address(nImpl), abi.encodeCall(NotaryService.initialize, (OWNER, vm.addr(NOTARY_KEY), FEE))
                )
            )
        );
        roots = _proxy(_implementation(), INotaryService(address(notary)));
        hasher = new LimbHasher();

        vm.deal(address(this), 100 ether);
        vm.deal(keeper, 1 ether);
    }

    /// `impl` behind a proxy OWNER owns, reading through `service`.
    function _proxy(JwtRootsBase impl, INotaryService service) internal returns (JwtRootsBase) {
        return JwtRootsBase(
            address(new ERC1967Proxy(address(impl), abi.encodeCall(JwtRootsBase.initialize, (OWNER, service))))
        );
    }

    // ─── Building a reading ─────────────────────────────────────────

    /// The JWKS layout: one revealed range covering the whole direction,
    /// nothing committed.
    function _whole(bytes memory transcript) internal pure returns (AttestationBuilder.Direction memory) {
        return AttestationBuilder.Direction({
            revealed: AttestationBuilder.one(AttestationBuilder.Range({start: 0, value: transcript})),
            commitments: AttestationBuilder.none(),
            length: uint32(transcript.length)
        });
    }

    function _empty() internal pure returns (AttestationBuilder.Direction memory) {
        return AttestationBuilder.Direction({
            revealed: new AttestationBuilder.Range[](0), commitments: AttestationBuilder.none(), length: 0
        });
    }

    function _attest(bytes memory sent, bytes memory received, uint64 createdAt) internal pure returns (bytes memory) {
        return AttestationBuilder.encode(_authority(), createdAt, _whole(sent), _whole(received));
    }

    /// A reading of `body`, framed by `Content-Length`, observed now.
    function _reading(bytes memory body) internal view returns (bytes memory) {
        return _readingAt(body, _now());
    }

    function _readingAt(bytes memory body, uint64 createdAt) internal pure returns (bytes memory) {
        return _attest(_request(), _contentLength(body), createdAt);
    }

    function _rotate(bytes memory attested) internal {
        roots.rotate{value: FEE}(attested, AttestationBuilder.sign(NOTARY_KEY, attested));
    }

    /// Signs before `expectRevert`: `vm.sign` is an external call and would consume it.
    function _refuses(bytes memory attested, bytes memory err) internal {
        bytes memory sig = AttestationBuilder.sign(NOTARY_KEY, attested);
        vm.expectRevert(err);
        roots.rotate{value: FEE}(attested, sig);
    }

    function _refuses(bytes memory attested, bytes4 selector) internal {
        _refuses(attested, abi.encodeWithSelector(selector));
    }

    // ─── Framing the response ───────────────────────────────────────

    function _contentLength(bytes memory body) internal pure returns (bytes memory) {
        return
            abi.encodePacked(
                STATUS_OK, CONTENT_TYPE, "content-length: ", vm.toString(body.length), "\r\n", "\r\n", body
            );
    }

    /// Chunked transfer coding, `size` bytes per chunk, as Google serves it.
    function _chunked(bytes memory body, uint256 size) internal pure returns (bytes memory) {
        return abi.encodePacked(STATUS_OK, CONTENT_TYPE, "transfer-encoding: chunked\r\n", "\r\n", _chunks(body, size));
    }

    function _chunks(bytes memory body, uint256 size) internal pure returns (bytes memory out) {
        for (uint256 at = 0; at < body.length; at += size) {
            uint256 take = body.length - at < size ? body.length - at : size;
            bytes memory chunk = new bytes(take);
            for (uint256 i = 0; i < take; ++i) {
                chunk[i] = body[at + i];
            }
            out = abi.encodePacked(out, _hex(take), "\r\n", chunk, "\r\n");
        }
        out = abi.encodePacked(out, "0\r\n\r\n");
    }

    function _hex(uint256 v) internal pure returns (bytes memory out) {
        if (v == 0) return "0";
        bytes memory digits = "0123456789abcdef";
        while (v != 0) {
            out = abi.encodePacked(digits[v & 0xf], out);
            v >>= 4;
        }
    }

    // ─── Building a key set ─────────────────────────────────────────

    /// One JWK the way Google writes them, compact.
    function _jwk(string memory kid, string memory n) internal pure returns (bytes memory) {
        return abi.encodePacked('{"kty":"RSA","use":"sig","kid":"', kid, '","n":"', n, '","e":"AQAB","alg":"RS256"}');
    }

    function _body(bytes memory jwks) internal pure returns (bytes memory) {
        return abi.encodePacked('{"keys":[', jwks, "]}");
    }

    function _oneKey(string memory kid, string memory seed) internal pure returns (bytes memory) {
        return _body(_jwk(kid, _modulus(seed)));
    }

    function _twoKeys(string memory kidA, string memory seedA, string memory kidB, string memory seedB)
        internal
        pure
        returns (bytes memory)
    {
        return _body(abi.encodePacked(_jwk(kidA, _modulus(seedA)), ",", _jwk(kidB, _modulus(seedB))));
    }

    /// A 2048-bit modulus derived from `seed`: 256 bytes as 342 characters of unpadded base64url.
    function _modulus(string memory seed) internal pure returns (string memory) {
        return string(_b64url(_bytes(seed, 256)));
    }

    /// The limb hash the list writes for the key `seed` derives, computed from its bytes.
    function _hash(string memory seed) internal view returns (bytes32) {
        return hasher.hashOf(_bytes(seed, 256));
    }

    function _bytes(string memory seed, uint256 count) internal pure returns (bytes memory out) {
        out = new bytes(count);
        for (uint256 i = 0; i < count; ++i) {
            if (i % 32 == 0) {
                bytes32 word = keccak256(abi.encodePacked(seed, i / 32));
                for (uint256 j = 0; j < 32 && i + j < count; ++j) {
                    out[i + j] = word[j];
                }
            }
        }
    }

    function _b64url(bytes memory data) internal pure returns (bytes memory out) {
        bytes memory alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        uint256 full = data.length / 3;
        uint256 tail = data.length % 3;
        out = new bytes(full * 4 + (tail == 0 ? 0 : tail + 1));
        uint256 o;
        for (uint256 i = 0; i < full; ++i) {
            uint256 v = (uint256(uint8(data[3 * i])) << 16) | (uint256(uint8(data[3 * i + 1])) << 8)
                | uint256(uint8(data[3 * i + 2]));
            out[o++] = alphabet[(v >> 18) & 63];
            out[o++] = alphabet[(v >> 12) & 63];
            out[o++] = alphabet[(v >> 6) & 63];
            out[o++] = alphabet[v & 63];
        }
        if (tail == 1) {
            uint256 v = uint256(uint8(data[3 * full])) << 16;
            out[o++] = alphabet[(v >> 18) & 63];
            out[o++] = alphabet[(v >> 12) & 63];
        } else if (tail == 2) {
            uint256 v = (uint256(uint8(data[3 * full])) << 16) | (uint256(uint8(data[3 * full + 1])) << 8);
            out[o++] = alphabet[(v >> 18) & 63];
            out[o++] = alphabet[(v >> 12) & 63];
            out[o++] = alphabet[(v >> 6) & 63];
        }
    }

    /// `count` keys, `kid-0` .. `kid-<count-1>`, each with its own modulus
    /// (seeded by its kid).
    function _manyKeys(uint256 count) internal pure returns (bytes memory list) {
        for (uint256 i = 0; i < count; ++i) {
            string memory kid = string.concat("kid-", vm.toString(i));
            list = abi.encodePacked(list, i == 0 ? "" : ",", _jwk(kid, _modulus(kid)));
        }
        return _body(list);
    }

    /// Install one key `kid` derived from `seed`, observed now, and return the
    /// hash it wrote.
    function _install(string memory kid, string memory seed) internal returns (bytes32) {
        _rotate(_reading(_oneKey(kid, seed)));
        return _hash(seed);
    }

    // ─── Reading the list back ──────────────────────────────────────

    function _current() internal view returns (JwtRootsBase.Generation memory current) {
        (current,) = roots.currentKeys();
    }

    function _previous() internal view returns (JwtRootsBase.Generation memory previous) {
        (, previous) = roots.currentKeys();
    }

    function _one(bytes32 a) internal pure returns (bytes32[] memory out) {
        out = new bytes32[](1);
        out[0] = a;
    }

    function _two(bytes32 a, bytes32 b) internal pure returns (bytes32[] memory out) {
        out = new bytes32[](2);
        out[0] = a;
        out[1] = b;
    }

    function _names(string memory a, string memory b) internal pure returns (string[] memory out) {
        out = new string[](2);
        out[0] = a;
        out[1] = b;
    }

    function _assertGeneration(
        JwtRootsBase.Generation memory g,
        uint64 observedAt,
        bytes32[] memory moduli,
        string memory label
    ) internal pure {
        assertEq(g.observedAt, observedAt, string.concat(label, ": observedAt"));
        assertEq(g.moduli, moduli, string.concat(label, ": moduli"));
    }

    function _assertEmpty(JwtRootsBase.Generation memory g, string memory label) internal pure {
        _assertGeneration(g, 0, new bytes32[](0), label);
    }

    /// The one `KeysRotated` among the recorded logs, decoded.
    function _lastRotation() internal view returns (uint64 observedAt, string[] memory kids, bytes32[] memory moduli) {
        Vm.Log[] memory logs = vm.getRecordedLogs();
        bytes32 topic = keccak256("KeysRotated(uint64,string[],bytes32[])");
        uint256 seen;
        for (uint256 i = 0; i < logs.length; ++i) {
            if (logs[i].emitter != address(roots) || logs[i].topics[0] != topic) continue;
            ++seen;
            (observedAt, kids, moduli) = abi.decode(logs[i].data, (uint64, string[], bytes32[]));
        }
        assertEq(seen, 1, "one KeysRotated per rotation");
    }

    /// Reads the cheatcode: under via-IR, `block.timestamp` may be re-read after a `vm.warp`.
    function _now() internal view returns (uint64) {
        return uint64(vm.getBlockTimestamp());
    }
}

/// A list for a platform with no JWKS endpoint.
contract UnknownJwtRoots is JwtRootsBase {
    function _storageRoot() internal pure override returns (bytes32) {
        return bytes32(uint256(1));
    }

    function _platform() internal pure override returns (bytes32) {
        return keccak256("unknown");
    }
}

contract JwtRootsBaseTest is Test {
    /// A list whose platform has no JWKS endpoint cannot be initialized.
    function test_anUnknownPlatformIsRefusedAtInitialize() public {
        JwtRootsBase impl = new UnknownJwtRoots();
        vm.expectRevert(abi.encodeWithSelector(CeremonyProfile.UnknownPlatform.selector, keccak256("unknown")));
        new ERC1967Proxy(
            address(impl), abi.encodeCall(JwtRootsBase.initialize, (address(0xA11CE), INotaryService(address(1))))
        );
    }
}
