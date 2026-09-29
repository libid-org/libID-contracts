// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";

import {CeremonyAttestation} from "../CeremonyAttestation.sol";
import {CeremonyAuthorization} from "../CeremonyAuthorization.sol";
import {CeremonyFields} from "../CeremonyFields.sol";
import {GitHubPlatformVerifier} from "../GitHubPlatformVerifier.sol";
import {XPlatformVerifier} from "../XPlatformVerifier.sol";
import {RefCeremonyAttestation, RefCeremonyFields, RefTranscript} from "./TranscriptReference.sol";

/// @notice `XPlatformVerifier`'s transcript checks, one session per call.
contract XTranscripts is XPlatformVerifier {
    function tokenTranscript(CeremonyAttestation.AttestedData memory data, bytes32 digest, bytes32 nonce)
        external
        pure
        returns (bytes memory, bytes32)
    {
        return _tokenTranscript(data, digest, nonce);
    }

    function identityTranscript(CeremonyAttestation.AttestedData memory data)
        external
        pure
        returns (bytes32, string memory, string memory)
    {
        return _identityTranscript(data);
    }
}

/// @notice `GitHubPlatformVerifier`'s, likewise.
contract GitHubTranscripts is GitHubPlatformVerifier {
    function tokenTranscript(CeremonyAttestation.AttestedData memory data, bytes32 digest, bytes32 nonce)
        external
        pure
        returns (bytes memory, bytes32)
    {
        return _tokenTranscript(data, digest, nonce);
    }

    function identityTranscript(CeremonyAttestation.AttestedData memory data)
        external
        pure
        returns (bytes32, string memory, string memory)
    {
        return _identityTranscript(data);
    }
}

/// @notice The reference sessions, with the same external shape.
contract RefTranscripts {
    bool private immutable GITHUB;

    constructor(bool github) {
        GITHUB = github;
    }

    function tokenTranscript(CeremonyAttestation.AttestedData memory data, bytes32 digest, bytes32 nonce)
        external
        view
        returns (bytes memory, bytes32)
    {
        return RefTranscript.tokenTranscript(data, CeremonyAuthorization.codeVerifier(digest, nonce), _profile());
    }

    function identityTranscript(CeremonyAttestation.AttestedData memory data)
        external
        view
        returns (bytes32, string memory, string memory)
    {
        return RefTranscript.identityTranscript(data, _profile());
    }

    function _profile() private view returns (RefTranscript.Profile memory) {
        return GITHUB ? RefTranscript.github() : RefTranscript.x();
    }
}

/// @notice The library helpers other contracts and tests call, live.
contract LiveHelpers {
    function requireCrlfLineEndings(bytes memory data) external pure {
        CeremonyAttestation.requireCrlfLineEndings(data);
    }

    function normalizeHeaderBytes(bytes memory data) external pure returns (bytes memory) {
        return CeremonyAttestation.normalizeHeaderBytes(data);
    }

    function concatRevealed(CeremonyAttestation.DirectionBlock memory block_) external pure returns (bytes memory) {
        return CeremonyAttestation.concatRevealed(block_);
    }

    function requireBearerHeaderRequest(CeremonyAttestation.DirectionBlock memory block_, uint32 length)
        external
        pure
        returns (CeremonyAttestation.RangeCommitment memory commitment)
    {
        (commitment,) = CeremonyAttestation.requireBearerHeaderRequest(block_, length);
    }

    function bearerHeaderRequestJoin(CeremonyAttestation.DirectionBlock memory block_, uint32 length)
        external
        pure
        returns (bytes memory revealed)
    {
        (, revealed) = CeremonyAttestation.requireBearerHeaderRequest(block_, length);
    }

    function requireFramedCommitment(
        CeremonyAttestation.DirectionBlock memory block_,
        bytes memory prefix,
        bytes memory suffix
    ) external pure returns (CeremonyAttestation.RangeCommitment memory) {
        return CeremonyAttestation.requireFramedCommitment(block_, prefix, suffix);
    }

    function normalizeJsonBytes(bytes memory data) external pure returns (bytes memory) {
        return CeremonyFields.normalizeJsonBytes(data);
    }

    function tryJsonString(bytes memory data, string memory name)
        external
        pure
        returns (CeremonyFields.Found, bytes memory)
    {
        return CeremonyFields.tryJsonString(data, name);
    }

    function tryJsonInteger(bytes memory data, string memory name)
        external
        pure
        returns (CeremonyFields.Found, bytes memory)
    {
        return CeremonyFields.tryJsonInteger(data, name);
    }

    function formField(bytes memory data, string memory name) external pure returns (bytes memory) {
        return CeremonyFields.formField(data, name);
    }

    function requireExactForm(bytes memory body, bytes memory names) external pure {
        CeremonyFields.requireExactForm(body, names);
    }

    function exactFormValue(bytes memory body, bytes memory names, string memory name)
        external
        pure
        returns (bytes memory)
    {
        return CeremonyFields.valueOf(CeremonyFields.requireExactForm(body, names), name);
    }

    function isSerializerSafe(bytes memory value) external pure returns (bool) {
        return CeremonyFields.isSerializerSafe(value);
    }

    function occurrences(bytes memory haystack, bytes memory needle) external pure returns (uint256) {
        return CeremonyFields.occurrences(haystack, needle);
    }
}

/// @notice The same helpers, from `TranscriptReference.sol`.
contract RefHelpers {
    function requireCrlfLineEndings(bytes memory data) external pure {
        RefCeremonyAttestation.requireCrlfLineEndings(data);
    }

    function normalizeHeaderBytes(bytes memory data) external pure returns (bytes memory) {
        return RefCeremonyAttestation.normalizeHeaderBytes(data);
    }

    function concatRevealed(CeremonyAttestation.DirectionBlock memory block_) external pure returns (bytes memory) {
        return RefCeremonyAttestation.concatRevealed(block_);
    }

    function requireBearerHeaderRequest(CeremonyAttestation.DirectionBlock memory block_, uint32 length)
        external
        pure
        returns (CeremonyAttestation.RangeCommitment memory)
    {
        return RefCeremonyAttestation.requireBearerHeaderRequest(block_, length);
    }

    function requireFramedCommitment(
        CeremonyAttestation.DirectionBlock memory block_,
        bytes memory prefix,
        bytes memory suffix
    ) external pure returns (CeremonyAttestation.RangeCommitment memory) {
        return RefCeremonyAttestation.requireFramedCommitment(block_, prefix, suffix);
    }

    function normalizeJsonBytes(bytes memory data) external pure returns (bytes memory) {
        return RefCeremonyFields.normalizeJsonBytes(data);
    }

    function tryJsonString(bytes memory data, string memory name)
        external
        pure
        returns (CeremonyFields.Found, bytes memory)
    {
        return RefCeremonyFields.tryJsonString(data, name);
    }

    function tryJsonInteger(bytes memory data, string memory name)
        external
        pure
        returns (CeremonyFields.Found, bytes memory)
    {
        return RefCeremonyFields.tryJsonInteger(data, name);
    }

    function formField(bytes memory data, string memory name) external pure returns (bytes memory) {
        return RefCeremonyFields.formField(data, name);
    }

    function requireExactForm(bytes memory body, bytes memory names) external pure {
        RefCeremonyFields.requireExactForm(body, names);
    }

    function isSerializerSafe(bytes memory value) external pure returns (bool) {
        return RefCeremonyFields.isSerializerSafe(value);
    }

    function occurrences(bytes memory haystack, bytes memory needle) external pure returns (uint256) {
        return RefCeremonyAttestation._occurrences(haystack, needle);
    }
}

/// @notice Seeded transcripts: an honest session of each kind, bent by the
///         edits the checks exist to catch, so an input can pass some checks
///         and fail a later one. Random bytes rarely pass the first.
library Gen {
    struct Rng {
        uint256 state;
    }

    function next(Rng memory r) internal pure returns (uint256) {
        r.state = uint256(keccak256(abi.encode(r.state)));
        return r.state;
    }

    function pick(Rng memory r, uint256 n) internal pure returns (uint256) {
        return next(r) % n;
    }

    function chance(Rng memory r, uint256 percent) internal pure returns (bool) {
        return pick(r, 100) < percent;
    }

    function oneOf(Rng memory r, bytes[] memory options) internal pure returns (bytes memory) {
        return options[pick(r, options.length)];
    }

    function list(bytes memory a, bytes memory b) internal pure returns (bytes[] memory out) {
        out = new bytes[](2);
        (out[0], out[1]) = (a, b);
    }

    function list(bytes memory a, bytes memory b, bytes memory c) internal pure returns (bytes[] memory out) {
        out = new bytes[](3);
        (out[0], out[1], out[2]) = (a, b, c);
    }

    function list(bytes memory a, bytes memory b, bytes memory c, bytes memory d)
        internal
        pure
        returns (bytes[] memory out)
    {
        out = new bytes[](4);
        (out[0], out[1], out[2], out[3]) = (a, b, c, d);
    }

    /// @dev Bytes drawn from `alphabet`, up to `max` of them.
    function soup(Rng memory r, bytes memory alphabet, uint256 max) internal pure returns (bytes memory out) {
        out = new bytes(pick(r, max + 1));
        for (uint256 i = 0; i < out.length; ++i) {
            out[i] = alphabet[pick(r, alphabet.length)];
        }
    }

    /// @dev `data` with one of a few small edits: a byte replaced, inserted
    ///      or deleted, each drawn from `alphabet`.
    function mutate(Rng memory r, bytes memory data, bytes memory alphabet) internal pure returns (bytes memory) {
        uint256 kind = pick(r, 3);
        uint256 at = data.length == 0 ? 0 : pick(r, data.length);
        bytes1 b = alphabet[pick(r, alphabet.length)];
        if (kind == 0 && data.length != 0) {
            bytes memory copy = bytes.concat(data);
            copy[at] = b;
            return copy;
        }
        if (kind == 1 || data.length == 0) {
            return bytes.concat(_slice(data, 0, at), abi.encodePacked(b), _slice(data, at, data.length));
        }
        return bytes.concat(_slice(data, 0, at), _slice(data, at + 1, data.length));
    }

    /// @dev `word` in a random case, `-` sometimes written `_`.
    function respell(Rng memory r, bytes memory word) internal pure returns (bytes memory out) {
        out = bytes.concat(word);
        for (uint256 i = 0; i < out.length; ++i) {
            if (out[i] >= "a" && out[i] <= "z" && chance(r, 30)) out[i] = bytes1(uint8(out[i]) - 32);
            if (out[i] == "-" && chance(r, 20)) out[i] = "_";
        }
    }

    function _slice(bytes memory data, uint256 from, uint256 to) internal pure returns (bytes memory out) {
        out = new bytes(to - from);
        for (uint256 i = 0; i < out.length; ++i) {
            out[i] = data[from + i];
        }
    }

    // ─── Layouts ────────────────────────────────────────────────────

    uint8 internal constant REVEAL = 0;
    uint8 internal constant COMMIT = 1;
    uint8 internal constant GAP = 2;

    /// @dev A direction over `t`: segments `[cuts[i], cuts[i + 1])`, each
    ///      revealed, committed or left uncovered. Ascending, nonempty and
    ///      disjoint by construction, as `CeremonyAttestation.decode` leaves
    ///      every block it returns.
    function layout(bytes memory t, uint256[] memory cuts, uint8[] memory segmentKinds)
        internal
        pure
        returns (CeremonyAttestation.DirectionBlock memory b)
    {
        uint256 reveals;
        uint256 commits;
        for (uint256 i = 0; i + 1 < cuts.length; ++i) {
            if (cuts[i] == cuts[i + 1]) continue;
            if (segmentKinds[i] == REVEAL) ++reveals;
            if (segmentKinds[i] == COMMIT) ++commits;
        }
        b.revealed = new CeremonyAttestation.RevealedRange[](reveals);
        b.commitments = new CeremonyAttestation.RangeCommitment[](commits);
        (reveals, commits) = (0, 0);
        for (uint256 i = 0; i + 1 < cuts.length; ++i) {
            if (cuts[i] == cuts[i + 1]) continue;
            // Casting to uint32 is safe: every cut is an offset into a
            // transcript these generators keep far below 2**32 bytes.
            // forge-lint: disable-next-line(unsafe-typecast)
            (uint32 start, uint32 end) = (uint32(cuts[i]), uint32(cuts[i + 1]));
            if (segmentKinds[i] == REVEAL) {
                b.revealed[reveals++] =
                    CeremonyAttestation.RevealedRange({start: start, end: end, value: _slice(t, start, end)});
            } else if (segmentKinds[i] == COMMIT) {
                b.commitments[commits++] = CeremonyAttestation.RangeCommitment({
                    start: start, end: end, commitment: keccak256(abi.encode(start, end, _slice(t, start, end)))
                });
            }
        }
    }

    /// @dev `t` cut at every offset in `bounds` and at up to `extra` random
    ///      ones; the segments `bounds` makes take `boundKinds` in order and every
    ///      further cut splits a segment into two of the same kind. Now and
    ///      then a segment turns to a gap, or its kind flips.
    function split(Rng memory r, bytes memory t, uint256[] memory bounds, uint8[] memory boundKinds, uint256 extra)
        internal
        pure
        returns (CeremonyAttestation.DirectionBlock memory)
    {
        uint256 n = bounds.length + 2 + extra;
        uint256[] memory cuts = new uint256[](n);
        uint8[] memory segmentKinds = new uint8[](n);
        cuts[0] = 0;
        uint256 count = 1;
        for (uint256 i = 0; i < bounds.length; ++i) {
            cuts[count++] = bounds[i];
        }
        cuts[count++] = t.length;
        for (uint256 i = 0; i < extra; ++i) {
            cuts[count++] = t.length == 0 ? 0 : pick(r, t.length + 1);
        }
        for (uint256 i = 1; i < count; ++i) {
            uint256 v = cuts[i];
            uint256 j = i;
            while (j > 0 && cuts[j - 1] > v) {
                cuts[j] = cuts[j - 1];
                --j;
            }
            cuts[j] = v;
        }
        // Each segment takes the kind of the `bounds` segment it starts in.
        for (uint256 i = 0; i + 1 < count; ++i) {
            uint256 segment = 0;
            for (uint256 m = 0; m < bounds.length; ++m) {
                if (cuts[i] >= bounds[m]) segment = m + 1;
            }
            uint8 kind = segment < boundKinds.length ? boundKinds[segment] : REVEAL;
            if (chance(r, 1)) kind = GAP;
            else if (chance(r, 1)) kind = kind == REVEAL ? COMMIT : REVEAL;
            segmentKinds[i] = kind;
        }
        uint256[] memory trimmed = new uint256[](count);
        for (uint256 i = 0; i < count; ++i) {
            trimmed[i] = cuts[i];
        }
        return layout(t, trimmed, segmentKinds);
    }

    /// @dev The signed length of a direction over `t`: its length, or now and
    ///      then 1 to 3 bytes more.
    function length(Rng memory r, bytes memory t) internal pure returns (uint32) {
        uint256 len = t.length;
        if (chance(r, 2)) len += 1 + pick(r, 3);
        // Casting to uint32 is safe: the transcripts here are a few hundred
        // bytes long.
        // forge-lint: disable-next-line(unsafe-typecast)
        return uint32(len);
    }

    function marks(uint256 a) internal pure returns (uint256[] memory out) {
        out = new uint256[](1);
        out[0] = a;
    }

    function marks(uint256 a, uint256 b) internal pure returns (uint256[] memory out) {
        out = new uint256[](2);
        (out[0], out[1]) = (a, b);
    }

    function marks(uint256 a, uint256 b, uint256 c, uint256 d) internal pure returns (uint256[] memory out) {
        out = new uint256[](4);
        (out[0], out[1], out[2], out[3]) = (a, b, c, d);
    }

    function kinds(uint8 a) internal pure returns (uint8[] memory out) {
        out = new uint8[](1);
        out[0] = a;
    }

    function kinds(uint8 a, uint8 b) internal pure returns (uint8[] memory out) {
        out = new uint8[](2);
        (out[0], out[1]) = (a, b);
    }

    function kinds(uint8 a, uint8 b, uint8 c) internal pure returns (uint8[] memory out) {
        out = new uint8[](3);
        (out[0], out[1], out[2]) = (a, b, c);
    }

    function kinds(uint8 a, uint8 b, uint8 c, uint8 d, uint8 e) internal pure returns (uint8[] memory out) {
        out = new uint8[](5);
        (out[0], out[1], out[2], out[3], out[4]) = (a, b, c, d, e);
    }

    function kinds6(uint8 a, uint8 b, uint8 c, uint8 d, uint8 e, uint8 f) internal pure returns (uint8[] memory out) {
        out = new uint8[](6);
        (out[0], out[1], out[2], out[3], out[4], out[5]) = (a, b, c, d, e, f);
    }

    function marks(uint256 a, uint256 b, uint256 c, uint256 d, uint256 e) internal pure returns (uint256[] memory out) {
        out = new uint256[](5);
        (out[0], out[1], out[2], out[3], out[4]) = (a, b, c, d, e);
    }

    // ─── Request heads ──────────────────────────────────────────────

    bytes internal constant HEAD_ALPHABET = "aA_-: \t\r\n0z,";

    /// @dev A header name the checks care about, or one they ignore.
    function headerName(Rng memory r) internal pure returns (bytes memory) {
        bytes[] memory forbidden = new bytes[](8);
        forbidden[0] = "authorization";
        forbidden[1] = "content-encoding";
        forbidden[2] = "cookie";
        forbidden[3] = "transfer-encoding";
        forbidden[4] = "x-http-method";
        forbidden[5] = "x-http-method-override";
        forbidden[6] = "x-method-override";
        forbidden[7] = "cook ie";
        if (chance(r, 20)) return respell(r, forbidden[pick(r, forbidden.length)]);
        bytes[] memory names = new bytes[](8);
        names[0] = "host";
        names[1] = "content-type";
        names[2] = "content-length";
        names[3] = "accept";
        names[4] = "connection";
        names[5] = "user-agent";
        names[6] = "x-github-api-version";
        names[7] = "content-lengthx";
        return respell(r, names[pick(r, names.length)]);
    }

    function headerValue(Rng memory r) internal pure returns (bytes memory) {
        bytes[] memory values = new bytes[](10);
        values[0] = "api.x.com";
        values[1] = "github.com";
        values[2] = "api.github.com";
        values[3] = "application/x-www-form-urlencoded";
        values[4] = "application/json";
        values[5] = "close";
        values[6] = "Bearer abc";
        values[7] = "0";
        values[8] = "chunked";
        values[9] = "";
        return values[pick(r, values.length)];
    }

    /// @dev `name: value` in one of the spellings HTTP reads as the same
    ///      header, or now and then one it does not.
    function headerLine(Rng memory r, bytes memory name, bytes memory value) internal pure returns (bytes memory) {
        bytes memory before = chance(r, 15) ? oneOf(r, list(" ", "\t", "  ")) : bytes("");
        bytes memory afterColon = oneOf(r, list(" ", "", "\t", "  "));
        bytes memory trailing = chance(r, 10) ? oneOf(r, list(" ", "\t")) : bytes("");
        bytes memory line = abi.encodePacked(name, before, ":", afterColon, value, trailing);
        if (chance(r, 2)) line = mutate(r, line, HEAD_ALPHABET);
        if (chance(r, 1)) line = soup(r, HEAD_ALPHABET, 12);
        return line;
    }

    /// @dev The line separator: CRLF, or now and then something a lenient
    ///      parser might also end a line on.
    function eol(Rng memory r) internal pure returns (bytes memory) {
        if (!chance(r, 2)) return "\r\n";
        return oneOf(r, list("\n", "\r", "\r\n ", "\r\n\t"));
    }

    // ─── Token request ──────────────────────────────────────────────

    bytes internal constant FORM_ALPHABET = "aZ09*._-+%2F3a&=; \r\n";

    /// @dev A form value in the serializer's alphabet, escapes included.
    function formValue(Rng memory r) internal pure returns (bytes memory v) {
        bytes[] memory tokens = new bytes[](8);
        tokens[0] = "a";
        tokens[1] = "Z9";
        tokens[2] = "*._-";
        tokens[3] = "+";
        tokens[4] = "%2F";
        tokens[5] = "%3A";
        tokens[6] = "http";
        tokens[7] = "%26";
        uint256 n = 1 + pick(r, 4);
        for (uint256 i = 0; i < n; ++i) {
            v = bytes.concat(v, tokens[pick(r, tokens.length)]);
        }
    }

    /// @dev The body a profile's field list asks for, `code_verifier`
    ///      mostly the one the digest derives, then now and then bent.
    function tokenBody(Rng memory r, bytes memory names, bytes memory verifier)
        internal
        pure
        returns (bytes memory body)
    {
        uint256 from;
        bool first = true;
        while (from <= names.length) {
            uint256 to = from;
            while (to < names.length && names[to] != "&") {
                ++to;
            }
            bytes memory name = _slice(names, from, to);
            bytes memory value;
            if (keccak256(name) == keccak256("code_verifier") && chance(r, 95)) value = verifier;
            else if (keccak256(name) == keccak256("grant_type") && chance(r, 95)) value = "authorization_code";
            else if (keccak256(name) == keccak256("client_id") && chance(r, 90)) value = "myClient-1";
            else value = chance(r, 2) ? bytes("") : formValue(r);
            bytes memory pair = abi.encodePacked(name, "=", value);
            if (chance(r, 1)) pair = mutate(r, pair, FORM_ALPHABET);
            if (!chance(r, 1)) body = bytes.concat(body, first ? bytes("") : bytes("&"), pair);
            if (chance(r, 1)) body = bytes.concat(body, "&", pair);
            first = false;
            from = to + 1;
        }
        if (chance(r, 2)) body = bytes.concat(body, oneOf(r, list("&", "&x=1", ";", "&grant_type=refresh_token")));
        if (chance(r, 2)) body = mutate(r, body, FORM_ALPHABET);
    }

    /// @dev A token request: the pinned request line, a head holding the
    ///      required headers among others, the length it declares, and a
    ///      body. The length is the body's own unless the head is being bent.
    function tokenRequest(Rng memory r, bytes memory requestLine, bytes memory required, bytes memory body)
        internal
        pure
        returns (bytes memory)
    {
        bytes memory head = chance(r, 98) ? requestLine : mutate(r, requestLine, HEAD_ALPHABET);
        head = bytes.concat(head, "HTTP/1.1");

        // The required lines, in the profile's spelling or another.
        (bytes memory hostLine, bytes memory typeLine) = _requiredLines(required);
        bytes[] memory lines = new bytes[](9);
        uint256 n;
        if (!chance(r, 2)) lines[n++] = chance(r, 70) ? hostLine : _respellLine(r, hostLine);
        if (!chance(r, 2)) lines[n++] = chance(r, 70) ? typeLine : _respellLine(r, typeLine);
        if (!chance(r, 2)) {
            bytes memory declared = bytes(_decimal(body.length));
            if (chance(r, 3)) declared = oneOf(r, list("0", bytes.concat("0", declared), "12a", ""));
            else if (chance(r, 2)) declared = bytes(_decimal(body.length + 1));
            lines[n++] = headerLine(r, respell(r, "content-length"), declared);
        }
        if (chance(r, 50)) lines[n++] = "accept: application/json";
        if (chance(r, 50)) lines[n++] = "connection: close";
        uint256 extra = pick(r, 3);
        for (uint256 i = 0; i < extra && n < lines.length; ++i) {
            lines[n++] = headerLine(r, headerName(r), headerValue(r));
        }
        // Shuffled, since nothing is pinned by position.
        for (uint256 i = n; i > 1; --i) {
            uint256 j = pick(r, i);
            (lines[i - 1], lines[j]) = (lines[j], lines[i - 1]);
        }
        for (uint256 i = 0; i < n; ++i) {
            head = bytes.concat(head, eol(r), lines[i]);
        }
        bytes memory boundary = chance(r, 98) ? bytes("\r\n\r\n") : oneOf(r, list("\r\n", "\r\n\r\n\r\n", "\n\n"));
        return bytes.concat(head, boundary, body);
    }

    function _requiredLines(bytes memory required) private pure returns (bytes memory, bytes memory) {
        uint256 cut;
        while (!(required[cut] == "\r" && required[cut + 1] == "\n")) {
            ++cut;
        }
        return (_slice(required, 0, cut), _slice(required, cut + 2, required.length));
    }

    function _respellLine(Rng memory r, bytes memory line) private pure returns (bytes memory) {
        uint256 colon;
        while (line[colon] != ":") {
            ++colon;
        }
        bytes memory value = _slice(line, colon + 2, line.length);
        if (chance(r, 5)) value = headerValue(r);
        return headerLine(r, respell(r, _slice(line, 0, colon)), value);
    }

    function _decimal(uint256 v) internal pure returns (string memory) {
        if (v == 0) return "0";
        bytes memory out;
        while (v != 0) {
            // Casting to uint8 is safe: `v % 10` is a single digit.
            // forge-lint: disable-next-line(unsafe-typecast)
            out = bytes.concat(bytes1(uint8(48 + (v % 10))), out);
            v /= 10;
        }
        return string(out);
    }

    // ─── Token response ─────────────────────────────────────────────

    /// @dev A token response revealing only the bearer's anchors, the bearer
    ///      and every other byte committed -- then bent: whitespace inside the
    ///      delimiter, a second delimiter revealed, the quote hidden, a gap.
    function tokenResponse(Rng memory r) internal pure returns (CeremonyAttestation.DirectionBlock memory, uint32) {
        bytes memory prefix = oneOf(r, list('"access_token":"', '"access_token" : "', '"access_token":\n"'));
        bytes memory head = "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\n\r\n{";
        bytes memory decoy = chance(r, 10) ? bytes('"refresh_token":"R","access_token":"D",') : bytes("");
        bytes memory bearer = "gho_BEARER0123";
        bytes memory tail = chance(r, 90) ? bytes('","token_type":"bearer"}') : oneOf(r, list('"}', ' ","scope":""}'));
        bytes memory t = bytes.concat(head, decoy, prefix, bearer, tail);
        uint256 a = head.length + decoy.length;
        uint256 b = a + prefix.length;
        uint256 c = b + bearer.length;
        // The decoy, when there is one, revealed now and then: a second
        // delimiter in the open is what makes the framing ambiguous.
        uint8 decoyKind = chance(r, 50) ? REVEAL : COMMIT;
        CeremonyAttestation.DirectionBlock memory block_ = split(
            r,
            t,
            marks(head.length, a, b, c, c + 1),
            kinds6(COMMIT, decoyKind, REVEAL, COMMIT, REVEAL, COMMIT),
            chance(r, 20) ? 2 : 0
        );
        return (block_, length(r, t));
    }

    // ─── Identity request ───────────────────────────────────────────

    /// @dev An identity request: the pinned request line, headers in any
    ///      order around one `authorization: Bearer` line whose value is
    ///      committed, the rest revealed and sometimes cut into more ranges.
    function identityRequest(Rng memory r, bytes memory requestLine)
        internal
        pure
        returns (CeremonyAttestation.DirectionBlock memory, uint32)
    {
        bytes memory head = chance(r, 98) ? requestLine : mutate(r, requestLine, HEAD_ALPHABET);
        head = bytes.concat(head, "HTTP/1.1");
        bytes memory tail = "";
        bool authorizationPlaced;
        uint256 n = 1 + pick(r, 5);
        for (uint256 i = 0; i < n; ++i) {
            bytes memory line;
            if (chance(r, 4)) {
                line = headerLine(r, respell(r, "authorization"), oneOf(r, list("Bearer x", "Basic y")));
            } else if (chance(r, 75)) {
                line = headerLine(r, "accept", "application/json");
            } else {
                line = headerLine(r, headerName(r), headerValue(r));
            }
            if (!authorizationPlaced && (chance(r, 35) || i + 1 == n)) {
                authorizationPlaced = true;
                head = bytes.concat(
                    head,
                    eol(r),
                    chance(r, 96)
                        ? bytes("authorization: Bearer ")
                        : oneOf(r, list("authorization: bearer ", "Authorization: Bearer ", "authorization:Bearer "))
                );
                tail = bytes.concat(eol(r), line);
            } else if (authorizationPlaced) {
                tail = bytes.concat(tail, eol(r), line);
            } else {
                head = bytes.concat(head, eol(r), line);
            }
        }
        bytes memory end = chance(r, 95) ? bytes("\r\n\r\n") : oneOf(r, list("\r\n", "\r\n\r\ncookie: a", "\n\n"));
        tail = bytes.concat(tail, end);
        bytes memory bearer = chance(r, 98) ? bytes("TOKENTOKENTOKEN") : bytes("TOK\r\nEN");
        bytes memory t = bytes.concat(head, bearer, tail);
        uint256 s = head.length;
        uint256 e = s + bearer.length;
        CeremonyAttestation.DirectionBlock memory block_ =
            split(r, t, marks(s, e), kinds(REVEAL, COMMIT, REVEAL), chance(r, 30) ? 1 + pick(r, 3) : 0);
        return (block_, length(r, t));
    }

    // ─── Identity response ──────────────────────────────────────────

    /// @dev A JSON response carrying the two members a profile reads, among
    ///      others; revealed member by member with the rest committed, and
    ///      bent: whitespace, a duplicate, a lookalike, a cut through a
    ///      delimiter.
    function identityResponse(Rng memory r, bool integerId, bytes memory handleField)
        internal
        pure
        returns (CeremonyAttestation.DirectionBlock memory, uint32)
    {
        bytes memory ws = oneOf(r, list("", " ", "\n  ", "\t"));
        bytes memory idValue = integerId
            ? (chance(r, 80) ? bytes("293919812") : oneOf(r, list("0", "007", "12 3")))
            : (chance(r, 80) ? bytes('"1051915704843333634"') : oneOf(r, list('""', '"7', "7")));
        bytes memory idMember = abi.encodePacked('"id"', ws, ":", ws, idValue);
        bytes memory handleMember =
            abi.encodePacked('"', handleField, '"', ws, ":", ws, '"', oneOf(r, list("alice", "Bob_1", "", "a b")), '"');
        bool idFirst = chance(r, 50);
        bytes memory first = idFirst ? idMember : handleMember;
        bytes memory second = idFirst ? handleMember : idMember;
        bytes memory sep = chance(r, 85) ? oneOf(r, list(",", ", ", ",\n  ")) : oneOf(r, list(ws, "}", " "));
        bytes memory decoy = chance(r, 10)
            ? oneOf(r, list('"name":"\\"id\\":\\"1\\"",', abi.encodePacked('"', handleField, '":"x",'), '"id":5,'))
            : bytes("");
        bytes memory prefix = bytes.concat('HTTP/1.1 200 OK\r\n\r\n{"data":{', decoy);
        bytes memory t = bytes.concat(prefix, first, sep, second, ws, "}}");
        // Each member revealed with the byte after it, which is what closes
        // an integer; what lies between them committed or revealed.
        uint256 a = prefix.length;
        uint256 b = a + first.length + (sep.length == 0 ? 0 : 1);
        uint256 c = a + first.length + sep.length;
        uint256 d = c + second.length + ws.length + 1;
        if (chance(r, 3)) t = mutate(r, t, '"{}:, \n0a');
        if (d > t.length) d = t.length;
        if (c > d) c = d;
        if (b > c) b = c;
        if (a > b) a = b;
        uint8 middle = chance(r, 50) ? COMMIT : REVEAL;
        CeremonyAttestation.DirectionBlock memory block_ = split(
            r, t, marks(a, b, c, d), kinds(COMMIT, REVEAL, middle, REVEAL, COMMIT), chance(r, 25) ? 1 + pick(r, 2) : 0
        );
        return (block_, length(r, t));
    }
}

/// @notice Every transcript check the verifiers run, against its copy in
///         `TranscriptReference.sol`: equal results and equal revert data.
/// @dev Whole sessions per stage and profile, so the order of the checks is
///      compared too; and each library helper other contracts call, on its own.
contract TranscriptEquivalenceTest is Test {
    using Gen for Gen.Rng;

    XTranscripts private x;
    GitHubTranscripts private github;
    RefTranscripts private refX;
    RefTranscripts private refGitHub;
    LiveHelpers private live;
    RefHelpers private ref;

    bytes32 private constant DIGEST = keccak256("digest");
    bytes32 private constant NONCE = keccak256("nonce");

    function setUp() public {
        x = new XTranscripts();
        github = new GitHubTranscripts();
        refX = new RefTranscripts(false);
        refGitHub = new RefTranscripts(true);
        live = new LiveHelpers();
        ref = new RefHelpers();
    }

    /// @dev Both calls, the same answer: success with equal return data, or
    ///      a revert with equal revert data.
    function _same(address a, bytes memory callA, address b, bytes memory callB) private view returns (bool ok) {
        (bool okA, bytes memory retA) = a.staticcall(callA);
        (bool okB, bytes memory retB) = b.staticcall(callB);
        assertEq(okA, okB, "one implementation accepts what the other refuses");
        assertEq(retA, retB, "the implementations answer differently");
        return okA;
    }

    function _same(address a, address b, bytes memory call) private view returns (bool) {
        return _same(a, call, b, call);
    }

    // ─── Whole sessions ─────────────────────────────────────────────

    function _tokenSession(Gen.Rng memory r, bool isGitHub)
        private
        pure
        returns (CeremonyAttestation.AttestedData memory data)
    {
        RefTranscript.Profile memory p = isGitHub ? RefTranscript.github() : RefTranscript.x();
        bytes memory body = r.tokenBody(p.tokenFields, CeremonyAuthorization.codeVerifier(DIGEST, NONCE));
        bytes memory request = r.tokenRequest(p.tokenRequestLine, p.tokenRequiredHeaders, body);
        if (r.chance(90)) {
            data.sent = Gen.layout(request, Gen.marks(0, request.length), Gen.kinds(Gen.REVEAL, Gen.REVEAL));
            // Casting to uint32 is safe: a generated request is a few hundred
            // bytes long.
            // forge-lint: disable-next-line(unsafe-typecast)
            data.sentTranscriptLength = r.chance(97) ? uint32(request.length) : r.length(request);
        } else {
            data.sent = r.split(request, new uint256[](0), Gen.kinds(Gen.REVEAL), 1 + r.pick(3));
            data.sentTranscriptLength = r.length(request);
        }
        (data.received, data.recvTranscriptLength) = r.tokenResponse();
    }

    function _identitySession(Gen.Rng memory r, bool isGitHub)
        private
        pure
        returns (CeremonyAttestation.AttestedData memory data)
    {
        RefTranscript.Profile memory p = isGitHub ? RefTranscript.github() : RefTranscript.x();
        (data.sent, data.sentTranscriptLength) = r.identityRequest(p.identityRequestLine);
        (data.received, data.recvTranscriptLength) = r.identityResponse(p.idIsInteger, bytes(p.handleField));
    }

    /// forge-config: default.fuzz.runs = 3000
    function testFuzz_xTokenSessionMatchesReference(uint256 seed) public view {
        Gen.Rng memory r = Gen.Rng(seed);
        bytes memory call = abi.encodeCall(XTranscripts.tokenTranscript, (_tokenSession(r, false), DIGEST, NONCE));
        _same(address(x), address(refX), call);
    }

    /// forge-config: default.fuzz.runs = 3000
    function testFuzz_gitHubTokenSessionMatchesReference(uint256 seed) public view {
        Gen.Rng memory r = Gen.Rng(seed);
        bytes memory call = abi.encodeCall(XTranscripts.tokenTranscript, (_tokenSession(r, true), DIGEST, NONCE));
        _same(address(github), address(refGitHub), call);
    }

    /// forge-config: default.fuzz.runs = 3000
    function testFuzz_xIdentitySessionMatchesReference(uint256 seed) public view {
        Gen.Rng memory r = Gen.Rng(seed);
        bytes memory call = abi.encodeCall(XTranscripts.identityTranscript, (_identitySession(r, false)));
        _same(address(x), address(refX), call);
    }

    /// forge-config: default.fuzz.runs = 3000
    function testFuzz_gitHubIdentitySessionMatchesReference(uint256 seed) public view {
        Gen.Rng memory r = Gen.Rng(seed);
        bytes memory call = abi.encodeCall(XTranscripts.identityTranscript, (_identitySession(r, true)));
        _same(address(github), address(refGitHub), call);
    }

    // ─── Library helpers ────────────────────────────────────────────

    /// forge-config: default.fuzz.runs = 2000
    function testFuzz_crlfLineEndingsMatchReference(uint256 seed, bytes memory raw) public view {
        Gen.Rng memory r = Gen.Rng(seed);
        bytes memory data = r.chance(50) ? raw : r.soup("\r\n \ta:", 40);
        _same(address(live), address(ref), abi.encodeCall(LiveHelpers.requireCrlfLineEndings, (data)));
    }

    /// forge-config: default.fuzz.runs = 2000
    function testFuzz_headerNormalizationMatchesReference(uint256 seed, bytes memory raw) public view {
        Gen.Rng memory r = Gen.Rng(seed);
        bytes memory data = r.chance(50) ? raw : r.soup("AZaz@[`{ \t\r\n:", 70);
        _same(address(live), address(ref), abi.encodeCall(LiveHelpers.normalizeHeaderBytes, (data)));
    }

    /// forge-config: default.fuzz.runs = 2000
    function testFuzz_jsonNormalizationMatchesReference(uint256 seed, bytes memory raw) public view {
        Gen.Rng memory r = Gen.Rng(seed);
        bytes memory data = r.chance(30) ? raw : r.soup(' \t\r\n:,{}[]"a1', 70);
        _same(address(live), address(ref), abi.encodeCall(LiveHelpers.normalizeJsonBytes, (data)));
    }

    /// forge-config: default.fuzz.runs = 2000
    function testFuzz_jsonReadsMatchReference(uint256 seed) public view {
        Gen.Rng memory r = Gen.Rng(seed);
        string memory name = string(
            r.oneOf(
                Gen.list(
                    "id",
                    "login",
                    "username",
                    r.chance(50) ? bytes("") : bytes("a_member_name_long_enough_for_two_words")
                )
            )
        );
        bytes memory data = bytes.concat(
            r.soup(' "{}:,1a', 12),
            r.chance(70) ? abi.encodePacked('"', name, '"', r.soup(" :", 3), ":", r.soup(' "', 2)) : bytes(""),
            r.soup(' "{}:,0123a\\', 16),
            r.chance(30) ? abi.encodePacked('"', name, '":') : bytes(""),
            r.soup(' "{}:,1a', 8)
        );
        _same(address(live), address(ref), abi.encodeCall(LiveHelpers.tryJsonString, (data, name)));
        _same(address(live), address(ref), abi.encodeCall(LiveHelpers.tryJsonInteger, (data, name)));
    }

    /// forge-config: default.fuzz.runs = 2000
    function testFuzz_formReadsMatchReference(uint256 seed) public view {
        Gen.Rng memory r = Gen.Rng(seed);
        bytes memory names = r.oneOf(
            Gen.list(
                bytes("grant_type&client_id&code&redirect_uri&code_verifier"),
                "client_id&code&redirect_uri&code_verifier&client_secret",
                r.soup("ab_&", 8),
                "a&a"
            )
        );
        bytes memory body =
            r.chance(60) ? r.tokenBody(names, "5teBDl6cz4U77aFweV5PbMhBJ_lEFv6LLNKzqnDI5lo") : r.soup("ab_=&%2F+;", 30);
        string memory name = string(r.oneOf(Gen.list("client_id", "code_verifier", "grant_type", r.soup("ab_", 3))));
        bool exact = _same(address(live), address(ref), abi.encodeCall(LiveHelpers.requireExactForm, (body, names)));
        _same(address(live), address(ref), abi.encodeCall(LiveHelpers.formField, (body, name)));
        // On an exact body, `valueOf` answers as `formField` does, errors included.
        if (exact) {
            _same(
                address(live),
                abi.encodeCall(LiveHelpers.exactFormValue, (body, names, name)),
                address(ref),
                abi.encodeCall(RefHelpers.formField, (body, name))
            );
        }
    }

    /// forge-config: default.fuzz.runs = 2000
    function testFuzz_occurrencesMatchReference(uint256 seed) public view {
        Gen.Rng memory r = Gen.Rng(seed);
        bytes memory haystack = r.soup('ab"', 90);
        bytes memory needle = r.soup('ab"', 40);
        if (r.chance(50) && haystack.length != 0) {
            // A needle cut from the haystack, so it is found at least once.
            uint256 from = r.pick(haystack.length);
            needle = Gen._slice(haystack, from, from + r.pick(haystack.length - from + 1));
        }
        _same(address(live), address(ref), abi.encodeCall(LiveHelpers.occurrences, (haystack, needle)));
    }

    /// forge-config: default.fuzz.runs = 2000
    function testFuzz_serializerSafetyMatchesReference(uint256 seed, bytes memory raw) public view {
        Gen.Rng memory r = Gen.Rng(seed);
        bytes memory value = r.chance(50) ? raw : r.soup("Az09*._-+%/ ", 20);
        _same(address(live), address(ref), abi.encodeCall(LiveHelpers.isSerializerSafe, (value)));
    }

    /// forge-config: default.fuzz.runs = 2000
    function testFuzz_revealedJoinMatchesReference(uint256 seed) public view {
        Gen.Rng memory r = Gen.Rng(seed);
        bytes memory t = r.soup("abc\r\n", 60);
        CeremonyAttestation.DirectionBlock memory block_ =
            r.split(t, new uint256[](0), Gen.kinds(Gen.REVEAL), r.pick(6));
        _same(address(live), address(ref), abi.encodeCall(LiveHelpers.concatRevealed, (block_)));
    }

    /// forge-config: default.fuzz.runs = 2000
    function testFuzz_bearerHeaderRequestMatchesReference(uint256 seed) public view {
        Gen.Rng memory r = Gen.Rng(seed);
        (CeremonyAttestation.DirectionBlock memory block_, uint32 len) = r.identityRequest("GET /2/users/me ");
        if (!_same(address(live), address(ref), abi.encodeCall(LiveHelpers.requireBearerHeaderRequest, (block_, len))))
        {
            return;
        }
        // And the join it returns is the join of the revealed ranges.
        _same(
            address(live),
            abi.encodeCall(LiveHelpers.bearerHeaderRequestJoin, (block_, len)),
            address(ref),
            abi.encodeCall(RefHelpers.concatRevealed, (block_))
        );
    }

    /// forge-config: default.fuzz.runs = 2000
    function testFuzz_framedCommitmentMatchesReference(uint256 seed) public view {
        Gen.Rng memory r = Gen.Rng(seed);
        (CeremonyAttestation.DirectionBlock memory block_,) = r.tokenResponse();
        _same(
            address(live),
            address(ref),
            abi.encodeCall(LiveHelpers.requireFramedCommitment, (block_, '"access_token":"', '"'))
        );
    }

    // ─── The byte search ────────────────────────────────────────────

    /// @dev The bounded `indexOfByte` against a byte loop over `[from, end)`.
    /// forge-config: default.fuzz.runs = 3000
    function testFuzz_boundedIndexOfByteMatchesAByteLoop(uint256 seed, bytes memory data, uint256 from, uint256 end)
        public
        pure
    {
        Gen.Rng memory r = Gen.Rng(seed);
        if (r.chance(50)) data = r.soup("ab\r\n\x00\xff", 100);
        end = bound(end, 0, data.length);
        from = bound(from, 0, end + 40);
        bytes1 b = data.length != 0 && r.chance(70) ? data[r.pick(data.length)] : bytes1(uint8(r.pick(256)));
        uint256 expected = end;
        for (uint256 i = from; i < end; ++i) {
            if (data[i] == b) {
                expected = i;
                break;
            }
        }
        assertEq(CeremonyFields.indexOfByte(data, from, end, b), expected);
    }

    /// @dev A byte at or past `end` is never found, even inside the array.
    /// forge-config: default.fuzz.runs = 3000
    function testFuzz_boundedIndexOfByteStopsAtEnd(uint256 seed, uint256 length, uint256 end) public pure {
        Gen.Rng memory r = Gen.Rng(seed);
        length = bound(length, 0, 100);
        end = bound(end, 0, length);
        bytes1 b = bytes1(uint8(r.pick(256)));
        bytes memory data = new bytes(length);
        for (uint256 i = 0; i < length; ++i) {
            data[i] = i < end ? bytes1(uint8(b) ^ 0x01) : b;
        }
        assertEq(CeremonyFields.indexOfByte(data, 0, end, b), end);
    }

    /// @dev Lines without a colon each cost the same, however many follow.
    function test_colonlessHeaderLinesCostLinearGas() public {
        uint256 few = _identityHeadGas(200);
        uint256 many = _identityHeadGas(800);
        assertLt(many, few * 5, "four times the lines must cost under five times the gas");
    }

    function _identityHeadGas(uint256 lines) private returns (uint256 used) {
        Gen.Rng memory r = Gen.Rng(uint256(keccak256("colonless")));
        RefTranscript.Profile memory p = RefTranscript.x();
        bytes memory head = bytes.concat(p.identityRequestLine, "HTTP/1.1");
        for (uint256 i = 0; i < lines; ++i) {
            head = bytes.concat(head, "\r\nx");
        }
        head = bytes.concat(head, "\r\nauthorization: Bearer ");
        bytes memory t = bytes.concat(head, "TOKENTOKENTOKEN", "\r\naccept: application/json\r\n\r\n");
        CeremonyAttestation.AttestedData memory data;
        data.sent =
            r.split(t, Gen.marks(head.length, head.length + 15), Gen.kinds(Gen.REVEAL, Gen.COMMIT, Gen.REVEAL), 0);
        data.sentTranscriptLength = uint32(t.length);
        (data.received, data.recvTranscriptLength) = r.identityResponse(p.idIsInteger, bytes(p.handleField));
        bytes memory call = abi.encodeCall(XTranscripts.identityTranscript, (data));
        uint256 before = gasleft();
        (bool ok,) = address(x).call{gas: 30_000_000}(call);
        used = before - gasleft();
        ok;
    }

    /// @dev `indexOfByte` against a byte loop, at every alignment.
    /// forge-config: default.fuzz.runs = 5000
    function testFuzz_indexOfByteMatchesAByteLoop(uint256 seed, bytes memory data, uint256 from) public pure {
        Gen.Rng memory r = Gen.Rng(seed);
        if (r.chance(50)) data = r.soup("ab\r\n\x00\xff", 100);
        from = bound(from, 0, data.length + 40);
        bytes1 b = data.length != 0 && r.chance(70) ? data[r.pick(data.length)] : bytes1(uint8(r.pick(256)));
        uint256 expected = data.length;
        for (uint256 i = from; i < data.length; ++i) {
            if (data[i] == b) {
                expected = i;
                break;
            }
        }
        assertEq(CeremonyFields.indexOfByte(data, from, b), expected);
    }

    /// @dev And a byte equal to `b` just past the end, in the same word the
    ///      search reads, is not an answer.
    /// forge-config: default.fuzz.runs = 5000
    function testFuzz_indexOfByteIgnoresBytesPastTheEnd(uint256 seed, uint256 length, uint256 from) public pure {
        Gen.Rng memory r = Gen.Rng(seed);
        length = bound(length, 0, 70);
        from = bound(from, 0, length + 1);
        bytes1 b = bytes1(uint8(r.pick(256)));
        bytes memory data = new bytes(length + 40);
        for (uint256 i = 0; i < data.length; ++i) {
            data[i] = i < length && r.chance(90) ? bytes1(uint8(b) ^ 0x01) : b;
        }
        assembly ("memory-safe") {
            mstore(data, length)
        }
        uint256 expected = length;
        for (uint256 i = from; i < length; ++i) {
            if (data[i] == b) {
                expected = i;
                break;
            }
        }
        assertEq(CeremonyFields.indexOfByte(data, from, b), expected);
    }

    // ─── The form alphabet, a word at a time ────────────────────────

    function _passesThrough(uint256 b) private pure returns (bool) {
        return (b >= 0x30 && b <= 0x39) || (b >= 0x41 && b <= 0x5a) || (b >= 0x61 && b <= 0x7a) || b == 0x2a
            || b == 0x2d || b == 0x2e || b == 0x5f;
    }

    /// @dev What `serializerUnsafeBytes` should mark in `word`: 0x80 in
    ///      each byte outside the set, byte by byte.
    function _escapedBytes(uint256 word) private pure returns (uint256 marked) {
        for (uint256 k = 0; k < 32; ++k) {
            if (!_passesThrough(uint8(bytes32(word)[k]))) marked |= uint256(0x80) << (8 * (31 - k));
        }
    }

    /// @dev Every byte value in every position, beside neighbours in the set
    ///      and outside it: no byte's answer leaks into the next.
    function test_serializerUnsafeBytesMarksExactlyTheBytesOutsideTheSet() public pure {
        uint8[4] memory fillers = [0x61, 0x3b, 0x00, 0xff];
        for (uint256 f = 0; f < fillers.length; ++f) {
            uint256 filler = uint256(fillers[f]) * (type(uint256).max / 0xff);
            for (uint256 v = 0; v < 256; ++v) {
                for (uint256 k = 0; k < 32; ++k) {
                    uint256 shift = 8 * (31 - k);
                    uint256 word = (filler & ~(uint256(0xff) << shift)) | (v << shift);
                    assertEq(CeremonyFields.serializerUnsafeBytes(word), _escapedBytes(word));
                }
            }
        }
    }

    /// forge-config: default.fuzz.runs = 5000
    function testFuzz_serializerUnsafeBytesMatchesAByteTest(uint256 word) public pure {
        assertEq(CeremonyFields.serializerUnsafeBytes(word), _escapedBytes(word));
    }

    // ─── The real sessions ──────────────────────────────────────────

    /// @dev The two ceremonies the real-session suites verify, stage by
    ///      stage: the honest path, where a divergence would cost users.
    function test_theRealSessionsMatchReference() public view {
        _real("contracts/ceremony/test/fixtures/x-ceremony-real.json", address(x), address(refX));
        _real("contracts/ceremony/test/fixtures/github-ceremony-real.json", address(github), address(refGitHub));
    }

    function _real(string memory path, address live_, address ref_) private view {
        string memory json = vm.readFile(path);
        CeremonyAttestation.AttestedData memory token = this.decode(vm.parseJsonBytes(json, ".token.attested_data"));
        CeremonyAttestation.AttestedData memory identity =
            this.decode(vm.parseJsonBytes(json, ".identity.attested_data"));
        bytes32 digest = vm.parseJsonBytes32(json, ".authorization_digest");
        bytes32 nonce = vm.parseJsonBytes32(json, ".authorization_nonce");
        assertTrue(_same(live_, ref_, abi.encodeCall(XTranscripts.tokenTranscript, (token, digest, nonce))));
        assertTrue(_same(live_, ref_, abi.encodeCall(XTranscripts.identityTranscript, (identity))));
    }

    function decode(bytes calldata data) external pure returns (CeremonyAttestation.AttestedData memory) {
        return CeremonyAttestation.decode(data);
    }
}
