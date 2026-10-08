// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {CeremonyAttestation} from "../CeremonyAttestation.sol";
import {CeremonyProfile} from "../CeremonyProfile.sol";

/// @notice A reference implementation of the transcript checks of
///         `CeremonyAttestation` in plain byte loops, for the differential
///         tests in `TranscriptEquivalence.t.sol`.
/// @dev Errors are declared here with the signatures of the originals, so a
///      revert carries the same data. Types are the live library's, so one
///      input feeds both implementations.
library RefCeremonyAttestation {
    error CoverageGap(uint32 from, uint32 to);
    error SpansOverlap(uint32 at);
    error NotOneCommitment(uint256 count);
    error ObsoleteLineFold(uint256 at);
    error BareLineFeed(uint256 at);
    error BareCarriageReturn(uint256 at);
    error NotOneAuthorizationHeader(uint256 count);
    error BadBearerFraming();
    error NoFramedCommitment();
    error AmbiguousFraming();
    error NotOneRequest(uint256 heads);
    error BytesAfterRequest(uint256 count);

    bytes internal constant BEARER_PREFIX = "\r\nauthorization: Bearer ";
    bytes internal constant BEARER_SUFFIX = "\r\n";
    bytes internal constant AUTHORIZATION_NEEDLE = "\r\nauthorization:";

    // ─── Framing, over the transcript rebuilt ───────────────────────
    //
    // Not the production algorithm in byte loops: production walks the list
    // of ranges, finds the one ending at a commitment, normalizes it and
    // compares its tail. This rebuilds the transcript as a byte map -- each
    // offset revealed (with its byte and its range), committed, or unknown --
    // and reads every rule off the map with a forward, streaming
    // normalization. Both read the same rule, stated in
    // `CeremonyAttestation.requireFramedCommitment`:
    //
    //   - the prefix occurs at most once in the revealed bytes joined, JSON
    //     whitespace removed;
    //   - a commitment is framed when the revealed range that ends exactly at
    //     its start ends, whitespace removed, with the prefix -- one range,
    //     never a join -- and, for a string, the suffix is revealed right
    //     after it, joins allowed; for an integer, the range that starts
    //     exactly at its end begins, whitespace aside, with `,` or `}`;
    //   - exactly one commitment is framed.
    //
    // Blocks are ascending, nonempty and disjoint, as `decode` returns them.

    uint8 private constant UNKNOWN = 0;
    uint8 private constant REVEALED = 1;
    uint8 private constant COMMITTED = 2;

    /// @dev The transcript as far as the block covers it.
    struct ByteMap {
        uint8[] kind;
        bytes text;
        /// The revealed range or the commitment an offset belongs to.
        uint256[] owner;
    }

    function requireFramedCommitment(
        CeremonyAttestation.DirectionBlock memory block_,
        bytes memory prefix,
        bytes memory suffix
    ) internal pure returns (CeremonyAttestation.RangeCommitment memory framed) {
        return _framed(block_, prefix, suffix, false);
    }

    function requireFramedInteger(CeremonyAttestation.DirectionBlock memory block_, bytes memory prefix)
        internal
        pure
        returns (CeremonyAttestation.RangeCommitment memory framed)
    {
        return _framed(block_, prefix, "", true);
    }

    function _framed(
        CeremonyAttestation.DirectionBlock memory block_,
        bytes memory prefix,
        bytes memory suffix,
        bool integer
    ) private pure returns (CeremonyAttestation.RangeCommitment memory) {
        ByteMap memory m = _map(block_);
        if (_countIn(RefCeremonyFields.normalizeJsonBytes(_revealedText(m)), prefix) > 1) revert AmbiguousFraming();

        uint256 framedCount;
        uint256 which;
        for (uint256 ci = 0; ci < block_.commitments.length; ++ci) {
            CeremonyAttestation.RangeCommitment memory c = block_.commitments[ci];
            bool closed = integer ? _numberEndsAt(m, c.end) : _revealedAt(m, c.end, suffix);
            if (closed && _anchorEndsWith(m, c.start, prefix)) {
                ++framedCount;
                if (framedCount == 1) which = ci;
            }
        }
        if (framedCount == 0) revert NoFramedCommitment();
        if (framedCount > 1) revert AmbiguousFraming();
        return block_.commitments[which];
    }

    function _map(CeremonyAttestation.DirectionBlock memory block_) private pure returns (ByteMap memory m) {
        uint256 size;
        for (uint256 i = 0; i < block_.revealed.length; ++i) {
            if (block_.revealed[i].end > size) size = block_.revealed[i].end;
        }
        for (uint256 i = 0; i < block_.commitments.length; ++i) {
            if (block_.commitments[i].end > size) size = block_.commitments[i].end;
        }
        m.kind = new uint8[](size);
        m.text = new bytes(size);
        m.owner = new uint256[](size);
        for (uint256 i = 0; i < block_.revealed.length; ++i) {
            CeremonyAttestation.RevealedRange memory r = block_.revealed[i];
            for (uint256 p = r.start; p < r.end; ++p) {
                (m.kind[p], m.text[p], m.owner[p]) = (REVEALED, r.value[p - r.start], i);
            }
        }
        for (uint256 i = 0; i < block_.commitments.length; ++i) {
            CeremonyAttestation.RangeCommitment memory c = block_.commitments[i];
            for (uint256 p = c.start; p < c.end; ++p) {
                (m.kind[p], m.owner[p]) = (COMMITTED, i);
            }
        }
    }

    /// @dev Every revealed byte, in transcript order.
    function _revealedText(ByteMap memory m) private pure returns (bytes memory out) {
        out = new bytes(m.text.length);
        uint256 n;
        for (uint256 p = 0; p < m.text.length; ++p) {
            if (m.kind[p] == REVEALED) out[n++] = m.text[p];
        }
        assembly ("memory-safe") {
            mstore(out, n)
        }
    }

    /// @dev Whether the revealed range whose last byte sits right before `at`
    ///      -- and that range alone -- ends, whitespace removed, with `prefix`.
    function _anchorEndsWith(ByteMap memory m, uint256 at, bytes memory prefix) private pure returns (bool) {
        if (at == 0 || at > m.kind.length || m.kind[at - 1] != REVEALED) return false;
        uint256 range = m.owner[at - 1];
        // The range has to END here, not run on past the commitment's start.
        if (at < m.kind.length && m.kind[at] == REVEALED && m.owner[at] == range) return false;
        uint256 from = at - 1;
        while (from > 0 && m.kind[from - 1] == REVEALED && m.owner[from - 1] == range) {
            --from;
        }
        bytes memory text = new bytes(at - from);
        for (uint256 p = from; p < at; ++p) {
            text[p - from] = m.text[p];
        }
        bytes memory normalized = RefCeremonyFields.normalizeJsonBytes(text);
        if (normalized.length < prefix.length) return false;
        uint256 offset = normalized.length - prefix.length;
        for (uint256 k = 0; k < prefix.length; ++k) {
            if (normalized[offset + k] != prefix[k]) return false;
        }
        return true;
    }

    /// @dev Whether `expected` is revealed, byte for byte, from `at` on.
    function _revealedAt(ByteMap memory m, uint256 at, bytes memory expected) private pure returns (bool) {
        for (uint256 k = 0; k < expected.length; ++k) {
            uint256 p = at + k;
            if (p >= m.kind.length || m.kind[p] != REVEALED || m.text[p] != expected[k]) return false;
        }
        return true;
    }

    /// @dev Whether a revealed range begins exactly at `at` and its first
    ///      byte that is not JSON whitespace is `,` or `}`.
    function _numberEndsAt(ByteMap memory m, uint256 at) private pure returns (bool) {
        if (at >= m.kind.length || m.kind[at] != REVEALED) return false;
        uint256 range = m.owner[at];
        if (at > 0 && m.kind[at - 1] == REVEALED && m.owner[at - 1] == range) return false;
        for (uint256 p = at; p < m.kind.length && m.kind[p] == REVEALED && m.owner[p] == range; ++p) {
            bytes1 b = m.text[p];
            if (b == " " || b == "\t" || b == "\n" || b == "\r") continue;
            return b == "," || b == "}";
        }
        return false;
    }

    /// @dev Copies of `needle` in `haystack`, overlapping ones included.
    function _countIn(bytes memory haystack, bytes memory needle) private pure returns (uint256 count) {
        if (needle.length == 0) return haystack.length + 1;
        uint256 matched;
        // Each start offset is tracked by how far its match has got; a match
        // that fails is dropped, and one that completes is counted.
        uint256[] memory progress = new uint256[](haystack.length);
        uint256 live;
        for (uint256 i = 0; i < haystack.length; ++i) {
            progress[live++] = 0;
            uint256 kept;
            for (uint256 j = 0; j < live; ++j) {
                if (haystack[i] != needle[progress[j]]) continue;
                uint256 next = progress[j] + 1;
                if (next == needle.length) {
                    ++matched;
                } else {
                    progress[kept++] = next;
                }
            }
            live = kept;
        }
        return matched;
    }

    function _occurrences(bytes memory haystack, bytes memory needle) internal pure returns (uint256 count) {
        for (uint256 i = 0; i + needle.length <= haystack.length; ++i) {
            bool hit = true;
            for (uint256 j = 0; j < needle.length; ++j) {
                if (haystack[i + j] != needle[j]) {
                    hit = false;
                    break;
                }
            }
            if (hit) ++count;
        }
    }

    function requireBearerHeaderRequest(CeremonyAttestation.DirectionBlock memory block_, uint32 length)
        internal
        pure
        returns (CeremonyAttestation.RangeCommitment memory commitment)
    {
        if (block_.commitments.length != 1) revert NotOneCommitment(block_.commitments.length);
        commitment = block_.commitments[0];

        requireExactCoverage(block_, length);

        bytes memory revealed = concatRevealed(block_);
        requireCrlfLineEndings(revealed);
        _requireOneBodilessRequest(block_, revealed, length);

        uint256 headers = _countNeedle(normalizeHeaderBytes(revealed));
        if (headers != 1) revert NotOneAuthorizationHeader(headers);

        if (commitment.start < BEARER_PREFIX.length) revert BadBearerFraming();
        bytes memory before_ = _revealedSlice(block_, commitment.start - uint32(BEARER_PREFIX.length), commitment.start);
        bytes memory after_ = _revealedSlice(block_, commitment.end, commitment.end + uint32(BEARER_SUFFIX.length));
        if (keccak256(before_) != keccak256(BEARER_PREFIX) || keccak256(after_) != keccak256(BEARER_SUFFIX)) {
            revert BadBearerFraming();
        }
    }

    /// @dev One `\r\n\r\n` in the revealed bytes joined, ending them, and
    ///      the transcript ending where the last revealed byte does. A plain
    ///      byte loop over every offset, where production tries only the CRs.
    function _requireOneBodilessRequest(
        CeremonyAttestation.DirectionBlock memory block_,
        bytes memory revealed,
        uint32 length
    ) private pure {
        uint256 heads;
        uint256 at;
        for (uint256 i = 0; i + 4 <= revealed.length; ++i) {
            if (revealed[i] == 0x0d && revealed[i + 1] == 0x0a && revealed[i + 2] == 0x0d && revealed[i + 3] == 0x0a) {
                ++heads;
                at = i;
            }
        }
        if (heads != 1) revert NotOneRequest(heads);
        if (at + 4 != revealed.length) revert BytesAfterRequest(revealed.length - at - 4);
        uint32 end = block_.revealed[block_.revealed.length - 1].end;
        if (end != length) revert BytesAfterRequest(length - end);
    }

    function requireCrlfLineEndings(bytes memory revealed) internal pure {
        for (uint256 i = 0; i + 2 < revealed.length; ++i) {
            if (revealed[i] == 0x0d && revealed[i + 1] == 0x0a && (revealed[i + 2] == 0x20 || revealed[i + 2] == 0x09))
            {
                revert ObsoleteLineFold(i);
            }
        }
        for (uint256 i = 0; i < revealed.length; ++i) {
            if (revealed[i] == 0x0a && (i == 0 || revealed[i - 1] != 0x0d)) {
                revert BareLineFeed(i);
            }
            if (revealed[i] == 0x0d && (i + 1 == revealed.length || revealed[i + 1] != 0x0a)) {
                revert BareCarriageReturn(i);
            }
        }
    }

    function normalizeHeaderBytes(bytes memory raw) internal pure returns (bytes memory out) {
        out = new bytes(raw.length);
        uint256 n;
        for (uint256 i = 0; i < raw.length; ++i) {
            bytes1 c = raw[i];
            if (c == 0x20 || c == 0x09) continue;
            if (c >= 0x41 && c <= 0x5a) c = bytes1(uint8(c) + 0x20);
            out[n++] = c;
        }
        assembly ("memory-safe") {
            mstore(out, n)
        }
    }

    function _countNeedle(bytes memory haystack) private pure returns (uint256 count) {
        bytes memory needle = AUTHORIZATION_NEEDLE;
        if (haystack.length < needle.length) return 0;
        for (uint256 i = 0; i + needle.length <= haystack.length; ++i) {
            bool hit = true;
            for (uint256 j = 0; j < needle.length; ++j) {
                if (haystack[i + j] != needle[j]) {
                    hit = false;
                    break;
                }
            }
            if (hit) ++count;
        }
    }

    function concatRevealed(CeremonyAttestation.DirectionBlock memory block_) internal pure returns (bytes memory out) {
        uint256 total;
        for (uint256 i = 0; i < block_.revealed.length; ++i) {
            total += block_.revealed[i].value.length;
        }
        out = new bytes(total);
        uint256 n;
        for (uint256 i = 0; i < block_.revealed.length; ++i) {
            bytes memory v = block_.revealed[i].value;
            for (uint256 j = 0; j < v.length; ++j) {
                out[n++] = v[j];
            }
        }
    }

    function _revealedSlice(CeremonyAttestation.DirectionBlock memory block_, uint32 from, uint32 to)
        private
        pure
        returns (bytes memory out)
    {
        if (to <= from) return "";
        out = new bytes(to - from);
        uint256 n;
        uint32 at = from;
        while (at < to) {
            bool found;
            for (uint256 i = 0; i < block_.revealed.length; ++i) {
                CeremonyAttestation.RevealedRange memory r = block_.revealed[i];
                if (r.start <= at && at < r.end) {
                    uint256 offset = at - r.start;
                    uint256 take = r.value.length - offset;
                    if (take > to - at) take = to - at;
                    for (uint256 j = 0; j < take; ++j) {
                        out[n++] = r.value[offset + j];
                    }
                    // Casting to uint32 is safe: `take` is clamped to `to - at`
                    // above, and both of those are uint32.
                    // forge-lint: disable-next-line(unsafe-typecast)
                    at += uint32(take);
                    found = true;
                    break;
                }
            }
            if (!found) return "";
        }
    }

    function requireExactCoverage(CeremonyAttestation.DirectionBlock memory block_, uint32 length) internal pure {
        uint256 r = 0;
        uint256 c = 0;
        uint32 at = 0;

        while (r < block_.revealed.length || c < block_.commitments.length) {
            bool takeRevealed;
            if (r < block_.revealed.length && c < block_.commitments.length) {
                takeRevealed = block_.revealed[r].start <= block_.commitments[c].start;
            } else {
                takeRevealed = r < block_.revealed.length;
            }

            uint32 start;
            uint32 end;
            if (takeRevealed) {
                start = block_.revealed[r].start;
                end = block_.revealed[r].end;
                ++r;
            } else {
                start = block_.commitments[c].start;
                end = block_.commitments[c].end;
                ++c;
            }

            if (start < at) revert SpansOverlap(start);
            if (start != at) revert CoverageGap(at, start);
            at = end;
        }

        if (at != length) revert CoverageGap(at, length);
    }
}

/// @notice The JSON normalization and form checks of `CeremonyFields`,
///         modelled byte by byte.
library RefCeremonyFields {
    error AmbiguousField(string name);
    error FieldNotFound(string name);
    error MalformedForm(uint256 at);
    error EmptyFormValue(string name);

    /// @dev Streaming: a whitespace run is held back until the byte after it
    ///      decides it. It goes when that byte, or the last byte kept before
    ///      it, is structural; a run the data ends on goes when the last byte
    ///      kept is structural.
    function normalizeJsonBytes(bytes memory data) internal pure returns (bytes memory out) {
        out = new bytes(data.length);
        uint256 n;
        uint256 heldFrom;
        uint256 held;
        bool lastStructural;
        for (uint256 i = 0; i < data.length; ++i) {
            bytes1 c = data[i];
            if (_isJsonWhitespace(c)) {
                if (held == 0) heldFrom = i;
                ++held;
                continue;
            }
            if (held != 0 && !lastStructural && !_isStructural(c)) {
                for (uint256 k = heldFrom; k < heldFrom + held; ++k) {
                    out[n++] = data[k];
                }
            }
            held = 0;
            out[n++] = c;
            lastStructural = _isStructural(c);
        }
        if (held != 0 && !lastStructural) {
            for (uint256 k = heldFrom; k < heldFrom + held; ++k) {
                out[n++] = data[k];
            }
        }
        assembly ("memory-safe") {
            mstore(out, n)
        }
    }

    function _isJsonWhitespace(bytes1 c) private pure returns (bool) {
        return c == 0x20 || c == 0x09 || c == 0x0a || c == 0x0d;
    }

    function _isStructural(bytes1 c) private pure returns (bool) {
        return c == ":" || c == "," || c == "{" || c == "}" || c == "[" || c == "]";
    }

    function formField(bytes memory data, string memory name) internal pure returns (bytes memory value) {
        bytes memory needle = abi.encodePacked(name, "=");
        uint256 found = type(uint256).max;

        for (uint256 i = 0; i + needle.length <= data.length; ++i) {
            if (i != 0 && data[i - 1] != "&") continue;
            if (!_matchesAt(data, needle, i)) continue;
            if (found != type(uint256).max) revert AmbiguousField(name);
            found = i;
        }
        if (found == type(uint256).max) revert FieldNotFound(name);

        uint256 at = found + needle.length;
        uint256 end = at;
        while (end < data.length && data[end] != "&") {
            ++end;
        }

        value = new bytes(end - at);
        for (uint256 i = 0; i < value.length; ++i) {
            value[i] = data[at + i];
        }
    }

    function requireExactForm(bytes memory body, bytes memory names) internal pure {
        uint256 at;
        uint256 from;
        while (true) {
            uint256 to = from;
            while (to < names.length && names[to] != "&") {
                ++to;
            }

            uint256 start = at;
            for (uint256 i = from; i < to; ++i) {
                if (at >= body.length || body[at] != names[i]) revert MalformedForm(start);
                ++at;
            }
            if (at >= body.length || body[at] != "=") revert MalformedForm(start);
            ++at;

            uint256 valueStart = at;
            while (at < body.length && body[at] != "&") {
                at = _formValueToken(body, at);
            }
            if (at == valueStart) revert EmptyFormValue(string(_slice(names, from, to)));

            if (to == names.length) {
                if (at != body.length) revert MalformedForm(at);
                return;
            }
            if (at >= body.length) revert MalformedForm(at);
            ++at;
            from = to + 1;
        }
    }

    function _formValueToken(bytes memory body, uint256 at) private pure returns (uint256) {
        bytes1 c = body[at];
        if (c == "%") {
            if (at + 2 >= body.length) revert MalformedForm(at);
            (bool ok, bytes1 decoded) = _hexByte(body[at + 1], body[at + 2]);
            if (!ok || decoded == 0x20 || _isSerializerSafe(decoded)) revert MalformedForm(at);
            return at + 3;
        }
        if (c == "+" || _isSerializerSafe(c)) return at + 1;
        revert MalformedForm(at);
    }

    function _hexByte(bytes1 hi, bytes1 lo) private pure returns (bool ok, bytes1 value) {
        (bool hiOk, uint8 h) = _hexNibble(hi);
        (bool loOk, uint8 l) = _hexNibble(lo);
        if (!hiOk || !loOk) return (false, 0);
        return (true, bytes1((h << 4) | l));
    }

    function _hexNibble(bytes1 c) private pure returns (bool, uint8) {
        uint8 b = uint8(c);
        if (c >= "0" && c <= "9") return (true, b - 0x30);
        if (c >= "A" && c <= "F") return (true, b - 0x41 + 10);
        return (false, 0);
    }

    function _slice(bytes memory data, uint256 from, uint256 to) private pure returns (bytes memory out) {
        out = new bytes(to - from);
        for (uint256 i = 0; i < out.length; ++i) {
            out[i] = data[from + i];
        }
    }

    function isSerializerSafe(bytes memory value) internal pure returns (bool) {
        if (value.length == 0) return false;
        for (uint256 i = 0; i < value.length; ++i) {
            if (!_isSerializerSafe(value[i])) return false;
        }
        return true;
    }

    function _isSerializerSafe(bytes1 c) private pure returns (bool) {
        return (c >= "A" && c <= "Z") || (c >= "a" && c <= "z") || (c >= "0" && c <= "9") || c == "*" || c == "."
            || c == "_" || c == "-";
    }

    function _matchesAt(bytes memory data, bytes memory needle, uint256 at) private pure returns (bool) {
        for (uint256 j = 0; j < needle.length; ++j) {
            if (data[at + j] != needle[j]) return false;
        }
        return true;
    }
}

/// @notice The transcript checks `TlsNotaryVerifierBase` runs on each session:
///         everything between authenticating an attestation and reading its
///         time, in the same order, so a revert carries the same data.
/// @dev A profile's hooks are parameters here: `Profile` carries the
///      constants `XPlatformVerifier` and `GitHubPlatformVerifier` return.
library RefTranscript {
    error WrongRequestLine();
    error CodeVerifierMismatch();
    error ClientIdentifierNotSerializerSafe(bytes found);
    error RequestLineNotAtOrigin(uint32 start);
    error WrongTokenRequestLayout(uint256 revealedRanges, uint256 commitments);
    error NoHeadBoundary(uint256 occurrences);
    error WrongTokenRequestHead();
    error ForbiddenRequestHeader(bytes name);
    error WrongDeclaredBodyLength(uint256 declared, uint256 signed);
    error WrongGrantType(bytes found);

    bytes private constant LENGTH_HEADER = "content-length";
    bytes private constant AUTHORIZATION = "authorization";
    bytes internal constant ACCESS_TOKEN_PREFIX = '"access_token":"';
    bytes internal constant ACCESS_TOKEN_SUFFIX = '"';
    bytes private constant GRANT_TYPE = "authorization_code";

    struct Profile {
        bytes tokenRequestLine;
        bytes identityRequestLine;
        bytes tokenRequiredHeaders;
        bytes tokenFields;
        /// X compares `grant_type`; GitHub adds no value check.
        bool checksGrantType;
        string idField;
        bool idIsInteger;
        string handleField;
    }

    function x() internal pure returns (Profile memory) {
        return Profile({
            tokenRequestLine: CeremonyProfile.X_TOKEN_REQUEST_LINE,
            identityRequestLine: CeremonyProfile.X_IDENTITY_REQUEST_LINE,
            tokenRequiredHeaders: CeremonyProfile.X_TOKEN_REQUIRED_HEADERS,
            tokenFields: CeremonyProfile.X_TOKEN_FIELDS,
            checksGrantType: true,
            idField: CeremonyProfile.X_ID_FIELD,
            idIsInteger: false,
            handleField: CeremonyProfile.X_HANDLE_FIELD
        });
    }

    function github() internal pure returns (Profile memory) {
        return Profile({
            tokenRequestLine: CeremonyProfile.GITHUB_TOKEN_REQUEST_LINE,
            identityRequestLine: CeremonyProfile.GITHUB_IDENTITY_REQUEST_LINE,
            tokenRequiredHeaders: CeremonyProfile.GITHUB_TOKEN_REQUIRED_HEADERS,
            tokenFields: CeremonyProfile.GITHUB_TOKEN_FIELDS,
            checksGrantType: false,
            idField: CeremonyProfile.GITHUB_ID_FIELD,
            idIsInteger: true,
            handleField: CeremonyProfile.GITHUB_HANDLE_FIELD
        });
    }

    /// @dev `_tokenSession` between `_authenticate` and `_requireFresh`, with
    ///      `expected` the code verifier `CeremonyAuthorization` derives.
    function tokenTranscript(
        CeremonyAttestation.AttestedData memory data,
        bytes memory expected,
        Profile memory profile
    ) internal pure returns (bytes memory clientId, bytes32 tokenCommitment) {
        RefCeremonyAttestation.requireExactCoverage(data.sent, data.sentTranscriptLength);

        if (data.sent.revealed.length == 0) revert RequestLineNotAtOrigin(type(uint32).max);
        if (data.sent.revealed[0].start != 0) {
            revert RequestLineNotAtOrigin(data.sent.revealed[0].start);
        }
        if (!_startsWith(data.sent.revealed[0].value, profile.tokenRequestLine)) revert WrongRequestLine();

        bytes memory body = _tokenBody(data.sent, profile.tokenRequiredHeaders);

        RefCeremonyFields.requireExactForm(body, profile.tokenFields);
        if (profile.checksGrantType) {
            bytes memory grantType = RefCeremonyFields.formField(body, "grant_type");
            if (keccak256(grantType) != keccak256(GRANT_TYPE)) revert WrongGrantType(grantType);
        }

        bytes memory revealedVerifier = RefCeremonyFields.formField(body, "code_verifier");
        if (keccak256(revealedVerifier) != keccak256(expected)) revert CodeVerifierMismatch();

        clientId = RefCeremonyFields.formField(body, "client_id");
        if (!RefCeremonyFields.isSerializerSafe(clientId)) {
            revert ClientIdentifierNotSerializerSafe(clientId);
        }

        RefCeremonyAttestation.requireExactCoverage(data.received, data.recvTranscriptLength);

        CeremonyAttestation.RangeCommitment memory bearer =
            RefCeremonyAttestation.requireFramedCommitment(data.received, ACCESS_TOKEN_PREFIX, ACCESS_TOKEN_SUFFIX);
        tokenCommitment = bearer.commitment;
    }

    /// @dev `_identitySession` after `_authenticate`: the committed bearer,
    ///      id and handle, each found by its framing.
    function identityTranscript(CeremonyAttestation.AttestedData memory data, Profile memory profile)
        internal
        pure
        returns (bytes32 bearerCommitment, bytes32 idCommitment, bytes32 handleCommitment)
    {
        if (data.sent.revealed.length == 0 || data.sent.revealed[0].start != 0) {
            revert RequestLineNotAtOrigin(data.sent.revealed.length == 0
                    ? type(uint32).max
                    : data.sent.revealed[0].start);
        }
        if (!_startsWith(data.sent.revealed[0].value, profile.identityRequestLine)) {
            revert WrongRequestLine();
        }

        CeremonyAttestation.RangeCommitment memory bearer =
            RefCeremonyAttestation.requireBearerHeaderRequest(data.sent, data.sentTranscriptLength);
        bearerCommitment = bearer.commitment;
        _checkIdentityHead(RefCeremonyAttestation.concatRevealed(data.sent));

        RefCeremonyAttestation.requireExactCoverage(data.received, data.recvTranscriptLength);
        idCommitment = profile.idIsInteger
            ? RefCeremonyAttestation.requireFramedInteger(data.received, abi.encodePacked('"', profile.idField, '":'))
            .commitment
            : RefCeremonyAttestation.requireFramedCommitment(
                data.received, abi.encodePacked('"', profile.idField, '":"'), '"'
            )
            .commitment;
        handleCommitment =
        RefCeremonyAttestation.requireFramedCommitment(
            data.received, abi.encodePacked('"', profile.handleField, '":"'), '"'
        )
        .commitment;
    }

    // `1 << i` is the mask for line i. The lint's heuristic reads a literal on
    // the left of a shift as swapped operands, which is what building a mask
    // looks like.
    // forge-lint: disable-next-item(incorrect-shift)
    function _checkTokenHead(bytes memory head, bytes memory required) internal pure returns (uint256 declared) {
        RefCeremonyAttestation.requireCrlfLineEndings(head);

        uint256 found;
        bool lengths;

        uint256 from = _lineEnd(head, 0) + 2;
        while (from < head.length) {
            uint256 to = _lineEnd(head, from);
            (found, lengths, declared) = _tokenHeaderLine(_slice(head, from, to), required, found, lengths, declared);
            from = to + 2;
        }

        if (!lengths) revert WrongTokenRequestHead();
        if (found != (1 << _countLines(required)) - 1) revert WrongTokenRequestHead();
    }

    // forge-lint: disable-next-item(incorrect-shift)
    function _tokenHeaderLine(bytes memory line, bytes memory required, uint256 found, bool lengths, uint256 declared)
        private
        pure
        returns (uint256, bool, uint256)
    {
        (bool isHeader, bytes memory name, bytes memory value) = _field(line);
        if (!isHeader) revert WrongTokenRequestHead();

        if (_indexOfLine(CeremonyProfile.FORBIDDEN_REQUEST_HEADERS, name) != type(uint256).max) {
            revert ForbiddenRequestHeader(name);
        }
        if (_equal(name, LENGTH_HEADER)) {
            if (lengths) revert WrongTokenRequestHead();
            return (found, true, _decimal(value, 0));
        }
        uint256 i = _indexOfName(required, name);
        if (i == type(uint256).max) return (found, lengths, declared);
        if (!_equal(value, _valueOf(required, i))) revert WrongTokenRequestHead();
        if (found & (1 << i) != 0) revert WrongTokenRequestHead();
        return (found | (1 << i), lengths, declared);
    }

    function _field(bytes memory line) internal pure returns (bool isHeader, bytes memory name, bytes memory value) {
        uint256 colon;
        while (colon < line.length && line[colon] != ":") {
            ++colon;
        }
        if (colon == line.length) return (false, name, value);
        bytes memory kept = new bytes(colon);
        uint256 n;
        for (uint256 i = 0; i < colon; ++i) {
            bytes1 c = line[i];
            if (c == " " || c == "\t") continue;
            if (c >= "A" && c <= "Z") c = bytes1(uint8(c) + 32);
            if (c == "_") c = "-";
            kept[n++] = c;
        }
        if (n == 0) return (false, name, value);
        name = _slice(kept, 0, n);
        isHeader = true;
        uint256 start = colon + 1;
        uint256 end = line.length;
        while (start < end && (line[start] == " " || line[start] == "\t")) {
            ++start;
        }
        while (end > start && (line[end - 1] == " " || line[end - 1] == "\t")) {
            --end;
        }
        value = _slice(line, start, end);
    }

    function _indexOfName(bytes memory block_, bytes memory name) private pure returns (uint256 index) {
        uint256 from;
        while (from <= block_.length) {
            uint256 to = _lineEnd(block_, from);
            (, bytes memory lineName,) = _field(_slice(block_, from, to));
            if (_equal(lineName, name)) return index;
            ++index;
            from = to + 2;
        }
        return type(uint256).max;
    }

    function _valueOf(bytes memory block_, uint256 index) private pure returns (bytes memory value) {
        uint256 from;
        for (uint256 i = 0; i < index; ++i) {
            from = _lineEnd(block_, from) + 2;
        }
        (,, value) = _field(_slice(block_, from, _lineEnd(block_, from)));
    }

    function _checkIdentityHead(bytes memory revealed) internal pure {
        uint256 from = _lineEnd(revealed, 0) + 2;
        while (from < revealed.length) {
            uint256 to = _lineEnd(revealed, from);
            if (to > from) {
                (bool isHeader, bytes memory name,) = _field(_slice(revealed, from, to));
                if (
                    isHeader && !_equal(name, AUTHORIZATION)
                        && _indexOfLine(CeremonyProfile.FORBIDDEN_REQUEST_HEADERS, name) != type(uint256).max
                ) {
                    revert ForbiddenRequestHeader(name);
                }
            }
            from = to + 2;
        }
    }

    function _lineEnd(bytes memory data, uint256 from) private pure returns (uint256) {
        for (uint256 i = from; i + 1 < data.length; ++i) {
            if (data[i] == 0x0d && data[i + 1] == 0x0a) return i;
        }
        return data.length;
    }

    function _countLines(bytes memory block_) private pure returns (uint256 count) {
        count = 1;
        for (uint256 i = 0; i + 1 < block_.length; ++i) {
            if (block_[i] == 0x0d && block_[i + 1] == 0x0a) ++count;
        }
    }

    function _indexOfLine(bytes memory block_, bytes memory line) internal pure returns (uint256) {
        uint256 index;
        uint256 from;
        while (from <= block_.length) {
            uint256 to = from;
            while (to + 1 < block_.length && !(block_[to] == 0x0d && block_[to + 1] == 0x0a)) {
                ++to;
            }
            if (to + 1 >= block_.length) to = block_.length;
            if (_equal(_slice(block_, from, to), line)) return index;
            ++index;
            from = to + 2;
        }
        return type(uint256).max;
    }

    function _decimal(bytes memory line, uint256 from) private pure returns (uint256 value) {
        uint256 width = line.length - from;
        if (width == 0 || width > 10) revert WrongTokenRequestHead();
        if (width > 1 && line[from] == "0") revert WrongTokenRequestHead();
        for (uint256 i = from; i < line.length; ++i) {
            if (line[i] < "0" || line[i] > "9") revert WrongTokenRequestHead();
            value = value * 10 + (uint8(line[i]) - 0x30);
        }
    }

    function _slice(bytes memory data, uint256 from, uint256 to) private pure returns (bytes memory out) {
        out = new bytes(to - from);
        for (uint256 i = 0; i < out.length; ++i) {
            out[i] = data[from + i];
        }
    }

    function _equal(bytes memory a, bytes memory b) private pure returns (bool) {
        return a.length == b.length && keccak256(a) == keccak256(b);
    }

    function _tokenBody(CeremonyAttestation.DirectionBlock memory block_, bytes memory required)
        internal
        pure
        returns (bytes memory body)
    {
        if (block_.revealed.length != 1 || block_.commitments.length != 0) {
            revert WrongTokenRequestLayout(block_.revealed.length, block_.commitments.length);
        }
        bytes memory whole = block_.revealed[0].value;

        uint256 at = type(uint256).max;
        uint256 seen;
        for (uint256 i = 0; i + 4 <= whole.length; ++i) {
            if (whole[i] == 0x0d && whole[i + 1] == 0x0a && whole[i + 2] == 0x0d && whole[i + 3] == 0x0a) {
                ++seen;
                if (at == type(uint256).max) at = i;
            }
        }
        if (seen != 1) revert NoHeadBoundary(seen);

        uint256 declared = _checkTokenHead(_slice(whole, 0, at), required);

        at += 4;
        if (declared != whole.length - at) revert WrongDeclaredBodyLength(declared, whole.length - at);

        body = new bytes(whole.length - at);
        for (uint256 i = 0; i < body.length; ++i) {
            body[i] = whole[at + i];
        }
    }

    function _startsWith(bytes memory data, bytes memory prefix) internal pure returns (bool) {
        if (data.length < prefix.length) return false;
        for (uint256 i = 0; i < prefix.length; ++i) {
            if (data[i] != prefix[i]) return false;
        }
        return true;
    }
}
