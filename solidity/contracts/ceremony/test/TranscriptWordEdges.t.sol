// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";

import {CeremonyAttestation} from "../CeremonyAttestation.sol";
import {CeremonyAuthorization} from "../CeremonyAuthorization.sol";
import {CeremonyFields} from "../CeremonyFields.sol";
import {CeremonyProfile} from "../CeremonyProfile.sol";
import {RefTranscript} from "./TranscriptReference.sol";
import {
    Gen,
    GitHubTranscripts,
    LiveHelpers,
    RefHelpers,
    RefTranscripts,
    XTranscripts
} from "./TranscriptEquivalence.t.sol";

/// @notice Inputs that put the bytes a word-at-a-time check decides on where
///         a 32-byte word begins or ends: offsets and lengths within two of
///         0, 32, 64 and 96, and bytes of every value.
library Edge {
    using Gen for Gen.Rng;

    /// @dev Within two of 0, 32, 64 or 96, capped at `max`, or now and then
    ///      any value up to `max`.
    function near(Gen.Rng memory r, uint256 max) internal pure returns (uint256 v) {
        if (r.chance(25)) return r.pick(max + 1);
        v = 32 * r.pick(4) + r.pick(5);
        v = v < 2 ? v : v - 2;
        if (v > max) v = max;
    }

    /// @dev A byte of `alphabet`, or now and then any of the 256.
    function byteOf(Gen.Rng memory r, bytes memory alphabet) internal pure returns (bytes1) {
        // Casting to uint8 is safe: `pick(256)` is below 256.
        // forge-lint: disable-next-line(unsafe-typecast)
        if (alphabet.length == 0 || r.chance(30)) return bytes1(uint8(r.pick(256)));
        return alphabet[r.pick(alphabet.length)];
    }

    /// @dev `n` bytes of `alphabet`, half the time one byte repeated.
    function fill(Gen.Rng memory r, uint256 n, bytes memory alphabet) internal pure returns (bytes memory out) {
        out = new bytes(n);
        bool uniform = r.chance(50);
        bytes1 b = byteOf(r, alphabet);
        for (uint256 i = 0; i < n; ++i) {
            out[i] = uniform ? b : byteOf(r, alphabet);
        }
    }

    /// @dev `n` bytes of `alphabet` and no other.
    function strict(Gen.Rng memory r, uint256 n, bytes memory alphabet) internal pure returns (bytes memory out) {
        out = new bytes(n);
        for (uint256 i = 0; i < n; ++i) {
            out[i] = alphabet[r.pick(alphabet.length)];
        }
    }

    function repeat(bytes1 b, uint256 n) internal pure returns (bytes memory out) {
        out = new bytes(n);
        for (uint256 i = 0; i < n; ++i) {
            out[i] = b;
        }
    }

    /// @dev `data` with `piece` inserted at `at`, or at its end.
    function insert(bytes memory data, uint256 at, bytes memory piece) internal pure returns (bytes memory) {
        if (at > data.length) at = data.length;
        return bytes.concat(Gen._slice(data, 0, at), piece, Gen._slice(data, at, data.length));
    }

    /// @dev `data` with `piece` written over it from `at`, cut at its end.
    function plant(bytes memory data, uint256 at, bytes memory piece) internal pure returns (bytes memory) {
        for (uint256 i = 0; i < piece.length && at + i < data.length; ++i) {
            data[at + i] = piece[i];
        }
        return data;
    }

    /// @dev A line `x-pad: aaa...` whose length moves every byte after it to
    ///      another offset within its word.
    function padLine(Gen.Rng memory r) internal pure returns (bytes memory) {
        return bytes.concat("x-pad: ", repeat("a", near(r, 70)));
    }
}

/// @notice The transcript checks against their reference where a word-at-a-time
///         read turns: a delimiter, an escape or a line ending across a word
///         boundary, an input ending one byte into a word, every byte value in
///         every class test, and needles of 31, 32 and 33 bytes.
contract TranscriptWordEdgesTest is Test {
    using Gen for Gen.Rng;
    using Edge for Gen.Rng;

    XTranscripts private x;
    GitHubTranscripts private github;
    RefTranscripts private refX;
    RefTranscripts private refGitHub;
    LiveHelpers private live;
    RefHelpers private ref;

    bytes32 private constant DIGEST = keccak256("digest");
    bytes32 private constant NONCE = keccak256("nonce");

    bytes private constant JSON_ALPHABET = ' \t\r\n:,{}[]"a1\\';
    bytes private constant SAFE_ALPHABET = "aZ09*._-";

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
    function _same(address a, bytes memory callA, address b, bytes memory callB) private view returns (bool) {
        (bool okA, bytes memory retA) = a.staticcall(callA);
        (bool okB, bytes memory retB) = b.staticcall(callB);
        assertEq(okA, okB, "one implementation accepts what the other refuses");
        assertEq(retA, retB, "the implementations answer differently");
        return okA;
    }

    function _same(address a, address b, bytes memory call) private view returns (bool) {
        return _same(a, call, b, call);
    }

    // ─── JSON ───────────────────────────────────────────────────────

    /// forge-config: default.fuzz.runs = 3000
    function testFuzz_jsonNormalizationAtWordEdges(uint256 seed) public view {
        Gen.Rng memory r = Gen.Rng(seed);
        bytes memory data = r.fill(r.near(130), JSON_ALPHABET);
        uint256 pieces = r.pick(5);
        for (uint256 i = 0; i < pieces; ++i) {
            bytes memory piece = r.oneOf(Gen.list(" ", "\t\n\r ", ":", " : "));
            data = Edge.plant(data, r.near(data.length), r.chance(20) ? abi.encodePacked(r.byteOf("")) : piece);
        }
        _same(address(live), address(ref), abi.encodeCall(LiveHelpers.normalizeJsonBytes, (data)));
    }

    /// @dev Every byte value, beside whitespace and beside a structural byte,
    ///      at each offset where one word ends and the next begins.
    function test_jsonNormalizationSortsEveryByteValueAtWordEdges() public view {
        uint8[6] memory offsets = [0, 1, 30, 31, 32, 33];
        bytes[3] memory fillers = [bytes("a"), bytes(":"), bytes(" ")];
        for (uint256 v = 0; v < 256; ++v) {
            for (uint256 o = 0; o < offsets.length; ++o) {
                for (uint256 f = 0; f < fillers.length; ++f) {
                    bytes memory data = Edge.repeat(fillers[f][0], 40);
                    // Casting to uint8 is safe: `v` is below 256.
                    // forge-lint: disable-next-line(unsafe-typecast)
                    data[offsets[o]] = bytes1(uint8(v));
                    data[offsets[o] + 1] = " ";
                    _same(address(live), address(ref), abi.encodeCall(LiveHelpers.normalizeJsonBytes, (data)));
                }
            }
        }
    }

    /// @dev A member placed so its delimiter, its value and its terminator
    ///      fall anywhere in a word, under names whose delimiters are 31, 32
    ///      and 33 bytes: the one-word compare, its full mask, and the hashed
    ///      compare past it.
    /// forge-config: default.fuzz.runs = 3000
    function testFuzz_jsonReadsAtWordEdges(uint256 seed) public view {
        Gen.Rng memory r = Gen.Rng(seed);
        bytes memory name = r.oneOf(Gen.list("id", "login", "username", Edge.repeat("n", 27 + r.pick(5))));
        bytes memory ws = r.oneOf(Gen.list("", " ", "\n\t", "\r\n  "));
        bytes memory value = r.chance(50)
            ? bytes.concat('"', r.fill(r.near(40), 'a1_ \\:,"'), r.chance(85) ? bytes('"') : bytes(""))
            : bytes.concat(r.fill(r.near(40), "0123456789"), r.oneOf(Gen.list(",", "}", " ", "")));
        bytes memory member = bytes.concat('"', name, '"', ws, ":", ws, value);
        bytes memory data = bytes.concat(r.fill(r.near(70), JSON_ALPHABET), member, r.fill(r.near(40), JSON_ALPHABET));
        if (r.chance(15)) data = Edge.insert(data, r.near(data.length), member);
        if (r.chance(10)) data = r.mutate(data, '"{}:, \n0a');
        _same(address(live), address(ref), abi.encodeCall(LiveHelpers.tryJsonString, (data, string(name))));
        _same(address(live), address(ref), abi.encodeCall(LiveHelpers.tryJsonInteger, (data, string(name))));
    }

    /// @dev A needle cut out of a periodic haystack at a word edge, the byte
    ///      it ends on sometimes changed: a mask one byte short or long
    ///      counts a copy that is not there or misses one that is.
    /// forge-config: default.fuzz.runs = 3000
    function testFuzz_occurrencesAtWordEdges(uint256 seed) public view {
        Gen.Rng memory r = Gen.Rng(seed);
        uint256 period = 1 + r.near(34);
        bytes memory unit = r.fill(period, 'ab"');
        bytes memory haystack;
        uint256 length = r.near(130);
        while (haystack.length < length) {
            haystack = bytes.concat(haystack, unit);
        }
        haystack = Gen._slice(haystack, 0, length);
        if (r.chance(30)) haystack = Edge.plant(haystack, r.near(length), abi.encodePacked(r.byteOf('ab"')));
        uint256 n = r.chance(60) ? uint256([uint8(1), 2, 16, 31, 32, 33, 63, 64, 65][r.pick(9)]) : r.near(70);
        bytes memory needle;
        if (length != 0 && r.chance(80)) {
            uint256 from = r.near(length - 1);
            uint256 to = from + n > length ? length : from + n;
            needle = Gen._slice(haystack, from, to);
            if (needle.length != 0 && r.chance(40)) needle[needle.length - 1] ^= 0x01;
            if (needle.length != 0 && r.chance(15)) needle[0] ^= 0x01;
        } else {
            needle = r.fill(n, 'ab"');
        }
        _same(address(live), address(ref), abi.encodeCall(LiveHelpers.occurrences, (haystack, needle)));
    }

    // ─── Forms ──────────────────────────────────────────────────────

    /// @dev A value in the serializer's alphabet with pieces set into it at
    ///      word edges: mostly escapes and `+`, now and then an escape in
    ///      lowercase, of a byte passed through or of the space, one cut
    ///      short, a delimiter, or any byte.
    function _formValue(Gen.Rng memory r) private pure returns (bytes memory v) {
        v = r.strict(r.near(70), SAFE_ALPHABET);
        if (v.length == 0 && r.chance(80)) v = "a";
        bytes[] memory canonical = new bytes[](6);
        (canonical[0], canonical[1], canonical[2]) = (bytes("%2F"), bytes("%3D"), bytes("%26"));
        (canonical[3], canonical[4], canonical[5]) = (bytes("+"), bytes("%7E"), bytes("%C3%A9"));
        bytes[] memory other = new bytes[](9);
        (other[0], other[1], other[2]) = (bytes("%2f"), bytes("%20"), bytes("%61"));
        (other[3], other[4], other[5]) = (bytes("%"), bytes("%2"), bytes("&"));
        (other[6], other[7], other[8]) = (bytes("="), bytes("%G1"), abi.encodePacked(r.byteOf("")));
        uint256 pieces = r.pick(4);
        for (uint256 i = 0; i < pieces; ++i) {
            v = Edge.insert(v, r.near(v.length), r.chance(95) ? r.oneOf(canonical) : r.oneOf(other));
        }
    }

    /// @dev The body `names` asks for with values of every length around a
    ///      word, now and then bent.
    function _formBody(Gen.Rng memory r, bytes memory names, bytes memory verifier)
        private
        pure
        returns (bytes memory body)
    {
        uint256 from;
        while (from <= names.length) {
            uint256 to = from;
            while (to < names.length && names[to] != "&") {
                ++to;
            }
            bytes memory name = Gen._slice(names, from, to);
            bytes memory value = _formValue(r);
            if (keccak256(name) == keccak256("code_verifier") && r.chance(90)) value = verifier;
            if (keccak256(name) == keccak256("grant_type") && r.chance(90)) value = "authorization_code";
            if (keccak256(name) == keccak256("client_id") && r.chance(80)) {
                value = r.strict(1 + r.near(40), SAFE_ALPHABET);
            }
            bytes memory pair = bytes.concat(name, "=", value);
            if (r.chance(1)) pair = r.mutate(pair, "a=&%+");
            body = bytes.concat(body, from == 0 ? bytes("") : bytes("&"), pair);
            from = to + 1;
        }
        if (r.chance(3)) body = bytes.concat(body, r.oneOf(Gen.list("&", "&x=1", "%", "%2")));
    }

    /// forge-config: default.fuzz.runs = 3000
    function testFuzz_exactFormAtWordEdges(uint256 seed) public view {
        Gen.Rng memory r = Gen.Rng(seed);
        bytes[] memory lists = new bytes[](6);
        lists[0] = CeremonyProfile.X_TOKEN_FIELDS;
        lists[1] = CeremonyProfile.GITHUB_TOKEN_FIELDS;
        lists[2] = bytes.concat(Edge.repeat("n", r.near(40)), "&client_id&code_verifier");
        lists[3] = bytes.concat("client_id&", Edge.repeat("n", 30 + r.pick(4)), "&grant_type");
        // Names that are each other's prefix or suffix, so a read that took
        // one name's pair for another's would answer with the wrong value.
        lists[4] = "code&code_verifier&verifier&client_id";
        lists[5] = "id&client_id&grant_type&type&code_verifier";
        bytes memory names = r.oneOf(lists);
        bytes memory body = _formBody(r, names, CeremonyAuthorization.codeVerifier(DIGEST, NONCE));
        bool exact = _same(address(live), address(ref), abi.encodeCall(LiveHelpers.requireExactForm, (body, names)));
        string[7] memory read = ["client_id", "code_verifier", "grant_type", "code", "id", "verifier", "type"];
        for (uint256 i = 0; i < read.length; ++i) {
            if (exact) {
                _same(
                    address(live),
                    abi.encodeCall(LiveHelpers.exactFormValue, (body, names, read[i])),
                    address(ref),
                    abi.encodeCall(RefHelpers.formField, (body, read[i]))
                );
            }
        }
    }

    /// @dev Every byte value, bare and escaped, at each offset where a word
    ///      ends, in a value that runs on past it or stops right there.
    function test_formValueSortsEveryByteValueAtWordEdges() public view {
        uint8[5] memory offsets = [29, 30, 31, 32, 33];
        bytes memory hex_ = "0123456789ABCDEF";
        for (uint256 v = 0; v < 256; ++v) {
            for (uint256 o = 0; o < offsets.length; ++o) {
                // `a=` then fillers, so the value's byte `k` is body byte `k + 2`.
                bytes memory before = Edge.repeat("b", offsets[o] - 2);
                // Casting to uint8 is safe: `v` is below 256.
                // forge-lint: disable-next-line(unsafe-typecast)
                bytes memory bare = abi.encodePacked(bytes1(uint8(v)));
                bytes memory escaped = abi.encodePacked("%", hex_[v >> 4], hex_[v & 15]);
                bytes[4] memory bodies = [
                    bytes.concat("a=", before, bare),
                    bytes.concat("a=", before, bare, "cc"),
                    bytes.concat("a=", before, escaped),
                    bytes.concat("a=", before, escaped, "cc")
                ];
                for (uint256 i = 0; i < bodies.length; ++i) {
                    _same(address(live), address(ref), abi.encodeCall(LiveHelpers.requireExactForm, (bodies[i], "a")));
                }
            }
        }
    }

    /// forge-config: default.fuzz.runs = 3000
    function testFuzz_serializerSafetyAtWordEdges(uint256 seed) public view {
        Gen.Rng memory r = Gen.Rng(seed);
        bytes memory value = r.fill(r.near(100), SAFE_ALPHABET);
        uint256 pieces = r.pick(3);
        for (uint256 i = 0; i < pieces; ++i) {
            value = Edge.plant(value, r.near(value.length), abi.encodePacked(r.byteOf("+%&= ")));
        }
        _same(address(live), address(ref), abi.encodeCall(LiveHelpers.isSerializerSafe, (value)));
    }

    // ─── Request heads ──────────────────────────────────────────────

    /// forge-config: default.fuzz.runs = 3000
    function testFuzz_crlfLineEndingsAtWordEdges(uint256 seed) public view {
        Gen.Rng memory r = Gen.Rng(seed);
        bytes memory data = r.fill(r.near(130), "aA: ");
        uint256 pieces = r.pick(6);
        for (uint256 i = 0; i < pieces; ++i) {
            bytes memory piece = r.oneOf(Gen.list("\r\n", "\r", "\n", "\r\n "));
            if (r.chance(20)) piece = r.oneOf(Gen.list("\r\n\t", "\n\r", "\r\r\n"));
            data = Edge.plant(data, r.near(data.length), piece);
        }
        _same(address(live), address(ref), abi.encodeCall(LiveHelpers.requireCrlfLineEndings, (data)));
    }

    /// @dev A header line that spells `authorization` or a prefix of it, in
    ///      any case, with spaces and tabs inside but never first; an empty
    ///      line; or a pad line. A line opening with a space or tab is a fold,
    ///      refused before the count.
    function _authorizationLike(Gen.Rng memory r) private pure returns (bytes memory) {
        uint256 kind = r.pick(5);
        if (kind == 0) return r.padLine();
        if (kind == 1) return "";
        bytes memory word = "authorization";
        if (kind == 2) word = Gen._slice(word, 0, 1 + r.pick(word.length));
        word = r.respell(word);
        uint256 spaces = r.pick(3);
        for (uint256 i = 0; i < spaces; ++i) {
            word = Edge.insert(word, 1 + r.pick(word.length), r.oneOf(Gen.list(" ", "\t")));
        }
        return
            bytes.concat(word, r.oneOf(Gen.list(":", " :", "\t:", "")), r.oneOf(Gen.list(" Bearer x", "Basic y", "")));
    }

    /// @dev An `authorization` lookalike `percent` of the time, else a pad
    ///      line, a line of any bytes, or a header the head check names.
    function _requestLine(Gen.Rng memory r, uint256 percent) private pure returns (bytes memory) {
        if (r.chance(percent)) return _authorizationLike(r);
        uint256 kind = r.pick(3);
        if (kind == 0) return r.padLine();
        if (kind == 1) return _anyHeaderLine(r);
        return r.headerLine(r.headerName(), r.headerValue());
    }

    /// @dev An identity request whose lines around the one bearer line are
    ///      padding and `authorization` lookalikes, cut into ranges through
    ///      the framing on both sides of the committed bearer.
    function _edgeIdentityRequest(Gen.Rng memory r, bytes memory requestLine, uint256 lookalikes)
        private
        pure
        returns (CeremonyAttestation.DirectionBlock memory block_, uint32 length)
    {
        bytes memory t = bytes.concat(requestLine, "HTTP/1.1");
        uint256 before = r.pick(4);
        for (uint256 i = 0; i < before; ++i) {
            t = bytes.concat(t, "\r\n", _requestLine(r, lookalikes));
        }
        t = bytes.concat(t, "\r\nauthorization: Bearer ");
        uint256 s = t.length;
        t = bytes.concat(t, Edge.repeat("T", 1 + r.near(40)));
        uint256 e = t.length;
        uint256 afterBearer = r.pick(3);
        for (uint256 i = 0; i < afterBearer; ++i) {
            t = bytes.concat(t, "\r\n", _requestLine(r, lookalikes));
        }
        t = bytes.concat(t, "\r\n\r\n");
        uint256[] memory cuts = new uint256[](6);
        (cuts[0], cuts[1], cuts[2], cuts[3], cuts[4], cuts[5]) =
        (0, s - r.pick(30 > s ? s : 30), s, e, e + r.pick(3), t.length);
        uint8[] memory kinds = new uint8[](6);
        (kinds[0], kinds[1], kinds[2], kinds[3], kinds[4]) =
        (Gen.REVEAL, Gen.REVEAL, Gen.COMMIT, Gen.REVEAL, Gen.REVEAL);
        block_ = Gen.layout(t, cuts, kinds);
        // Casting to uint32 is safe: a generated request is a few hundred
        // bytes long.
        // forge-lint: disable-next-line(unsafe-typecast)
        length = uint32(t.length);
    }

    /// forge-config: default.fuzz.runs = 3000
    function testFuzz_bearerHeaderRequestAtWordEdges(uint256 seed) public view {
        Gen.Rng memory r = Gen.Rng(seed);
        (CeremonyAttestation.DirectionBlock memory block_, uint32 len) =
            _edgeIdentityRequest(r, CeremonyProfile.X_IDENTITY_REQUEST_LINE, 60);
        if (!_same(address(live), address(ref), abi.encodeCall(LiveHelpers.requireBearerHeaderRequest, (block_, len))))
        {
            return;
        }
        _same(
            address(live),
            abi.encodeCall(LiveHelpers.bearerHeaderRequestJoin, (block_, len)),
            address(ref),
            abi.encodeCall(RefHelpers.concatRevealed, (block_))
        );
    }

    /// @dev Every pair of lines that open the `authorization` needle, break
    ///      off, spell it in another case or with a tab inside, or repeat it,
    ///      ahead of the one bearer line: the count restarts only at a
    ///      carriage return, and two needles never share a byte.
    function test_authorizationCountRestartsOnlyAtALineStart() public view {
        bytes[9] memory lines = [
            bytes("authoriz"),
            bytes("AUTHORIZATION :x"),
            bytes("authorization"),
            bytes(""),
            bytes("a\tuthorization:"),
            bytes("xauthorization: y"),
            bytes("authorization:authorization:"),
            bytes("Authorization: Basic y"),
            bytes("authorizationauthorization:")
        ];
        for (uint256 i = 0; i < lines.length; ++i) {
            for (uint256 j = 0; j < lines.length; ++j) {
                bytes memory head =
                    bytes.concat(CeremonyProfile.X_IDENTITY_REQUEST_LINE, "HTTP/1.1\r\n", lines[i], "\r\n", lines[j]);
                bytes memory t = bytes.concat(head, "\r\nauthorization: Bearer TOKEN\r\n\r\n");
                uint256 s = head.length + 24;
                CeremonyAttestation.DirectionBlock memory block_ =
                    Gen.layout(t, Gen.marks(0, s, s + 5, t.length), Gen.kinds(Gen.REVEAL, Gen.COMMIT, Gen.REVEAL));
                // Casting to uint32 is safe: the request is under a hundred
                // bytes long.
                // forge-lint: disable-next-line(unsafe-typecast)
                uint32 length = uint32(t.length);
                _same(
                    address(live),
                    address(ref),
                    abi.encodeCall(LiveHelpers.requireBearerHeaderRequest, (block_, length))
                );
            }
        }
    }

    // ─── Whole sessions ─────────────────────────────────────────────

    /// @dev A header line of any bytes but CR and LF, most of them the ones a
    ///      head is read by.
    function _anyHeaderLine(Gen.Rng memory r) private pure returns (bytes memory line) {
        line = bytes.concat(
            r.respell(r.strict(1 + r.near(40), "abc-_")), r.strict(r.pick(3), " \t"), ":", r.fill(r.near(40), "a: \t,;")
        );
        for (uint256 i = 0; i < line.length; ++i) {
            if (line[i] == "\r" || line[i] == "\n") line[i] = "x";
        }
    }

    /// @dev The token request of `p`: a pad line first, so each byte after it
    ///      lands at every offset in its word; the required lines, now and then
    ///      respelled; lines of any bytes among them.
    function _edgeTokenRequest(Gen.Rng memory r, RefTranscript.Profile memory p, bytes memory body)
        private
        pure
        returns (bytes memory request)
    {
        bytes[] memory lines = new bytes[](7);
        uint256 n;
        uint256 cut;
        while (!(p.tokenRequiredHeaders[cut] == "\r" && p.tokenRequiredHeaders[cut + 1] == "\n")) {
            ++cut;
        }
        bytes memory hostLine = Gen._slice(p.tokenRequiredHeaders, 0, cut);
        bytes memory typeLine = Gen._slice(p.tokenRequiredHeaders, cut + 2, p.tokenRequiredHeaders.length);
        lines[n++] = r.chance(92) ? hostLine : r.headerLine(r.respell("host"), r.headerValue());
        lines[n++] =
            r.chance(85) ? typeLine : r.headerLine(r.respell("content-type"), "application/x-www-form-urlencoded");
        bytes memory declared = bytes(Gen._decimal(body.length));
        if (r.chance(5)) declared = bytes.concat("0", declared);
        lines[n++] = r.headerLine(r.respell("content-length"), declared);
        uint256 extra = r.pick(4);
        for (uint256 i = 0; i < extra; ++i) {
            lines[n++] = r.chance(70) ? _anyHeaderLine(r) : r.headerLine(r.headerName(), r.headerValue());
        }
        for (uint256 i = n; i > 1; --i) {
            uint256 j = r.pick(i);
            (lines[i - 1], lines[j]) = (lines[j], lines[i - 1]);
        }
        request = bytes.concat(p.tokenRequestLine, "HTTP/1.1\r\n", r.padLine());
        for (uint256 i = 0; i < n; ++i) {
            request = bytes.concat(request, "\r\n", lines[i]);
        }
        request = bytes.concat(request, "\r\n\r\n", body);
    }

    function _edgeTokenSession(Gen.Rng memory r, bool isGitHub)
        private
        pure
        returns (CeremonyAttestation.AttestedData memory data)
    {
        RefTranscript.Profile memory p = isGitHub ? RefTranscript.github() : RefTranscript.x();
        bytes memory body = _formBody(r, p.tokenFields, CeremonyAuthorization.codeVerifier(DIGEST, NONCE));
        bytes memory request = _edgeTokenRequest(r, p, body);
        data.sent = Gen.layout(request, Gen.marks(0, request.length), Gen.kinds(Gen.REVEAL, Gen.REVEAL));
        // Casting to uint32 is safe: a generated request is a few hundred
        // bytes long.
        // forge-lint: disable-next-line(unsafe-typecast)
        data.sentTranscriptLength = uint32(request.length);
        (data.received, data.recvTranscriptLength) = _edgeTokenResponse(r);
    }

    /// @dev A token response whose bearer anchor ends anywhere in a word, in a
    ///      revealed range as short as the anchor or shorter.
    function _edgeTokenResponse(Gen.Rng memory r)
        private
        pure
        returns (CeremonyAttestation.DirectionBlock memory block_, uint32 length)
    {
        bytes memory prefix = r.oneOf(Gen.list('"access_token":"', '"access_token" : "', ' "access_token":\n"'));
        bytes memory head =
            bytes.concat("HTTP/1.1 200 OK\r\n\r\n{", r.chance(80) ? bytes("") : bytes('"access_token":"D",'));
        bytes memory pad = bytes.concat('"pad":"', Edge.repeat("p", r.near(70)), '",');
        bytes memory t = bytes.concat(head, pad, prefix, "gho_BEARER", '","token_type":"bearer"}');
        uint256 b = head.length + pad.length + prefix.length;
        // The anchor's range: from anywhere in the pad, or exactly the anchor,
        // or one byte short of it.
        uint256 a = r.chance(60) ? head.length + r.pick(pad.length + 1) : b - prefix.length + r.pick(2);
        uint256 c = b + 10;
        uint256[] memory cuts = new uint256[](6);
        (cuts[0], cuts[1], cuts[2], cuts[3], cuts[4], cuts[5]) = (0, a, b, c, c + 1, t.length);
        uint8[] memory kinds = new uint8[](6);
        (kinds[0], kinds[1], kinds[2], kinds[3], kinds[4]) =
        (Gen.COMMIT, Gen.REVEAL, Gen.COMMIT, Gen.REVEAL, Gen.COMMIT);
        block_ = Gen.layout(t, cuts, kinds);
        // Casting to uint32 is safe: a generated response is a few hundred
        // bytes long.
        // forge-lint: disable-next-line(unsafe-typecast)
        length = uint32(t.length);
    }

    /// @dev An identity response with a pad member revealed with the first
    ///      read member, so both members' delimiters move through a word.
    function _edgeIdentityResponse(Gen.Rng memory r, bool integerId, bytes memory handleField)
        private
        pure
        returns (CeremonyAttestation.DirectionBlock memory block_, uint32 length)
    {
        bytes memory ws = r.oneOf(Gen.list("", " ", "\n  ", "\t"));
        bytes memory idValue = integerId
            ? (r.chance(80) ? bytes("293919812") : r.oneOf(Gen.list("0", "007", "12 3")))
            : (r.chance(80) ? bytes('"1051915704843333634"') : r.oneOf(Gen.list('""', '"7', "7")));
        bytes memory idMember = bytes.concat('"id"', ws, ":", ws, idValue);
        bytes memory handleMember = bytes.concat(
            '"',
            handleField,
            '"',
            ws,
            ":",
            ws,
            '"',
            r.fill(1 + r.near(40), "aB_1"),
            r.chance(95) ? bytes('"') : bytes("")
        );
        bool idFirst = r.chance(50);
        bytes memory pad = bytes.concat('"pad":"', Edge.repeat("p", r.near(70)), '",', ws);
        if (r.chance(10)) pad = bytes.concat(pad, r.oneOf(Gen.list('"xid":1,', '"id_":2,', '"id":3,')));
        bytes memory first = bytes.concat(pad, idFirst ? idMember : handleMember);
        bytes memory second = idFirst ? handleMember : idMember;
        bytes memory sep = r.oneOf(Gen.list(",", ", ", ",\n  "));
        bytes memory prefix = 'HTTP/1.1 200 OK\r\n\r\n{"data":{';
        bytes memory t = bytes.concat(prefix, first, sep, second, ws, "}}");
        uint256 a = prefix.length;
        uint256 b = a + first.length + 1;
        uint256 c = a + first.length + sep.length;
        uint256 d = c + second.length + ws.length + 1;
        uint8 middle = r.chance(50) ? Gen.COMMIT : Gen.REVEAL;
        block_ = r.split(
            t,
            Gen.marks(a, b, c, d),
            Gen.kinds(Gen.COMMIT, Gen.REVEAL, middle, Gen.REVEAL, Gen.COMMIT),
            r.chance(20) ? 1 + r.pick(2) : 0
        );
        // Casting to uint32 is safe: a generated response is a few hundred
        // bytes long.
        // forge-lint: disable-next-line(unsafe-typecast)
        length = uint32(t.length);
    }

    function _edgeIdentitySession(Gen.Rng memory r, bool isGitHub)
        private
        pure
        returns (CeremonyAttestation.AttestedData memory data)
    {
        RefTranscript.Profile memory p = isGitHub ? RefTranscript.github() : RefTranscript.x();
        (data.sent, data.sentTranscriptLength) = _edgeIdentityRequest(r, p.identityRequestLine, 10);
        (data.received, data.recvTranscriptLength) = _edgeIdentityResponse(r, p.idIsInteger, bytes(p.handleField));
    }

    /// @dev Every byte value inside a header name, at the last byte of a
    ///      word and the first of the next, where the head check lowercases
    ///      it, reads `_` as `-`, trims it before the colon, or keeps it.
    function test_headerNamesSortEveryByteValueAtWordEdges() public view {
        bytes memory response = 'HTTP/1.1 200 OK\r\n\r\n{"id":"1","username":"a"}';
        CeremonyAttestation.AttestedData memory data;
        data.received = Gen.layout(response, Gen.marks(0, response.length), Gen.kinds(Gen.REVEAL, Gen.REVEAL));
        // Casting to uint32 is safe: the response is under a hundred bytes.
        // forge-lint: disable-next-line(unsafe-typecast)
        data.recvTranscriptLength = uint32(response.length);
        for (uint256 v = 0; v < 256; ++v) {
            // Casting to uint8 is safe: `v` is below 256.
            // forge-lint: disable-next-line(unsafe-typecast)
            bytes1 b = bytes1(uint8(v));
            // After `GET /2/users/me HTTP/1.1\r\n`, byte 31 of the request is
            // the sixth of the line and byte 32 the seventh.
            bytes[3] memory lines = [
                bytes.concat("cooki", b, ": a"),
                bytes.concat("cookie", b, ": a"),
                bytes.concat("x", b, "http", b, "method: a")
            ];
            for (uint256 i = 0; i < lines.length; ++i) {
                bytes memory head = bytes.concat(CeremonyProfile.X_IDENTITY_REQUEST_LINE, "HTTP/1.1\r\n", lines[i]);
                bytes memory t = bytes.concat(head, "\r\nauthorization: Bearer TOKEN\r\n\r\n");
                uint256 s = head.length + 24;
                data.sent =
                    Gen.layout(t, Gen.marks(0, s, s + 5, t.length), Gen.kinds(Gen.REVEAL, Gen.COMMIT, Gen.REVEAL));
                // Casting to uint32 is safe: the request is under a hundred
                // bytes long.
                // forge-lint: disable-next-line(unsafe-typecast)
                data.sentTranscriptLength = uint32(t.length);
                _same(address(x), address(refX), abi.encodeCall(XTranscripts.identityTranscript, (data)));
            }
        }
    }

    /// forge-config: default.fuzz.runs = 3000
    function testFuzz_tokenSessionAtWordEdges(uint256 seed) public view {
        Gen.Rng memory r = Gen.Rng(seed);
        bool isGitHub = r.chance(50);
        bytes memory call =
            abi.encodeCall(XTranscripts.tokenTranscript, (_edgeTokenSession(r, isGitHub), DIGEST, NONCE));
        if (isGitHub) _same(address(github), address(refGitHub), call);
        else _same(address(x), address(refX), call);
    }

    /// forge-config: default.fuzz.runs = 3000
    function testFuzz_identitySessionAtWordEdges(uint256 seed) public view {
        Gen.Rng memory r = Gen.Rng(seed);
        bool isGitHub = r.chance(50);
        bytes memory call = abi.encodeCall(XTranscripts.identityTranscript, (_edgeIdentitySession(r, isGitHub)));
        if (isGitHub) _same(address(github), address(refGitHub), call);
        else _same(address(x), address(refX), call);
    }

    /// forge-config: default.fuzz.runs = 3000
    function testFuzz_framedCommitmentAtWordEdges(uint256 seed) public view {
        Gen.Rng memory r = Gen.Rng(seed);
        (CeremonyAttestation.DirectionBlock memory block_,) = _edgeTokenResponse(r);
        _same(
            address(live),
            address(ref),
            abi.encodeCall(LiveHelpers.requireFramedCommitment, (block_, '"access_token":"', '"'))
        );
    }

    // ─── The byte search ────────────────────────────────────────────

    /// @dev Every byte value at every offset of inputs 31 to 65 bytes long,
    ///      with the same byte filling the word past the end: found where it
    ///      is, from every start at or before it, and not after.
    function test_indexOfByteFindsEveryByteValueAtEveryOffset() public pure {
        uint8[5] memory lengths = [31, 32, 33, 64, 65];
        bytes memory data = new bytes(97);
        for (uint256 v = 0; v < 256; ++v) {
            // Casting to uint8 is safe: `v` is below 256.
            // forge-lint: disable-next-line(unsafe-typecast)
            bytes1 b = bytes1(uint8(v));
            for (uint256 l = 0; l < lengths.length; ++l) {
                uint256 length = lengths[l];
                assembly ("memory-safe") {
                    mstore(data, 97)
                }
                for (uint256 i = 0; i < 97; ++i) {
                    data[i] = i >= length ? b : b ^ 0x01;
                }
                assembly ("memory-safe") {
                    mstore(data, length)
                }
                for (uint256 at = 0; at < length; ++at) {
                    data[at] = b;
                    assertEq(CeremonyFields.indexOfByte(data, 0, b), at);
                    assertEq(CeremonyFields.indexOfByte(data, at, b), at);
                    assertEq(CeremonyFields.indexOfByte(data, at + 1, b), length);
                    data[at] = b ^ 0x01;
                }
            }
        }
    }
}
