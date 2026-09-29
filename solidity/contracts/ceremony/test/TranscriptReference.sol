// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {CeremonyAttestation} from "../CeremonyAttestation.sol";
import {CeremonyFields} from "../CeremonyFields.sol";
import {CeremonyProfile} from "../CeremonyProfile.sol";

/// @notice The transcript checks of `CeremonyAttestation` as of commit 7a63c20,
///         for the differential tests in `TranscriptEquivalence.t.sol`. Code
///         unchanged except `_field`, whose header names drop every space and
///         tab as REQ-PLAT-56A and REQ-COMMON-39B require.
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

    bytes internal constant BEARER_PREFIX = "\r\nauthorization: Bearer ";
    bytes internal constant BEARER_SUFFIX = "\r\n";
    bytes internal constant AUTHORIZATION_NEEDLE = "\r\nauthorization:";

    function requireFramedCommitment(
        CeremonyAttestation.DirectionBlock memory block_,
        bytes memory prefix,
        bytes memory suffix
    ) internal pure returns (CeremonyAttestation.RangeCommitment memory framed) {
        if (_occurrences(RefCeremonyFields.normalizeJsonBytes(concatRevealed(block_)), prefix) > 1) {
            revert AmbiguousFraming();
        }

        uint256 found = type(uint256).max;
        for (uint256 i = 0; i < block_.commitments.length; ++i) {
            CeremonyAttestation.RangeCommitment memory c = block_.commitments[i];
            if (!_anchoredBy(block_, c.start, prefix)) continue;
            bytes memory after_ = _revealedSlice(block_, c.end, c.end + uint32(suffix.length));
            if (keccak256(after_) != keccak256(suffix)) continue;

            if (found != type(uint256).max) revert AmbiguousFraming();
            found = i;
        }
        if (found == type(uint256).max) revert NoFramedCommitment();
        return block_.commitments[found];
    }

    function _anchoredBy(CeremonyAttestation.DirectionBlock memory block_, uint32 at, bytes memory prefix)
        private
        pure
        returns (bool)
    {
        for (uint256 i = 0; i < block_.revealed.length; ++i) {
            CeremonyAttestation.RevealedRange memory range = block_.revealed[i];
            if (range.end != at) continue;
            bytes memory normalized = RefCeremonyFields.normalizeJsonBytes(range.value);
            if (normalized.length < prefix.length) return false;
            for (uint256 j = 0; j < prefix.length; ++j) {
                if (normalized[normalized.length - prefix.length + j] != prefix[j]) return false;
            }
            return true;
        }
        return false;
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

        uint256 headers = _countNeedle(normalizeHeaderBytes(revealed));
        if (headers != 1) revert NotOneAuthorizationHeader(headers);

        if (commitment.start < BEARER_PREFIX.length) revert BadBearerFraming();
        bytes memory before_ = _revealedSlice(block_, commitment.start - uint32(BEARER_PREFIX.length), commitment.start);
        bytes memory after_ = _revealedSlice(block_, commitment.end, commitment.end + uint32(BEARER_SUFFIX.length));
        if (keccak256(before_) != keccak256(BEARER_PREFIX) || keccak256(after_) != keccak256(BEARER_SUFFIX)) {
            revert BadBearerFraming();
        }
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

/// @notice The field readers of `CeremonyFields` as of commit 7a63c20, code
///         unchanged.
library RefCeremonyFields {
    error AmbiguousField(string name);
    error FieldNotFound(string name);
    error BadIntegerTerminator(string name, bytes1 found);
    error NoncanonicalInteger(string name);
    error MalformedForm(uint256 at);
    error EmptyFormValue(string name);

    function tryJsonString(bytes memory data, string memory name)
        internal
        pure
        returns (CeremonyFields.Found found, bytes memory value)
    {
        data = normalizeJsonBytes(data);
        bytes memory needle = abi.encodePacked('"', name, '":"');
        uint256 at;
        (found, at) = _findUnique(data, needle);
        if (found != CeremonyFields.Found.One) return (found, "");

        at += needle.length;
        uint256 end = at;
        while (end < data.length && data[end] != '"') {
            ++end;
        }
        if (end == data.length) return (CeremonyFields.Found.Unterminated, "");

        value = new bytes(end - at);
        for (uint256 i = 0; i < value.length; ++i) {
            value[i] = data[at + i];
        }
        return (CeremonyFields.Found.One, value);
    }

    function tryJsonInteger(bytes memory data, string memory name)
        internal
        pure
        returns (CeremonyFields.Found found, bytes memory digits)
    {
        data = normalizeJsonBytes(data);
        bytes memory needle = abi.encodePacked('"', name, '":');
        uint256 at;
        (found, at) = _findUnique(data, needle);
        if (found != CeremonyFields.Found.One) return (found, "");

        at += needle.length;
        uint256 end = at;
        while (end < data.length && data[end] >= "0" && data[end] <= "9") {
            ++end;
        }
        if (end == at) revert NoncanonicalInteger(name);
        if (end - at > 1 && data[at] == "0") revert NoncanonicalInteger(name);
        if (end == data.length) return (CeremonyFields.Found.None, "");
        if (data[end] != "," && data[end] != "}") revert BadIntegerTerminator(name, data[end]);

        digits = new bytes(end - at);
        for (uint256 i = 0; i < digits.length; ++i) {
            digits[i] = data[at + i];
        }
        return (CeremonyFields.Found.One, digits);
    }

    function normalizeJsonBytes(bytes memory data) internal pure returns (bytes memory out) {
        out = new bytes(data.length);
        uint256 n;
        uint256 i;
        while (i < data.length) {
            if (!_isJsonWhitespace(data[i])) {
                out[n++] = data[i];
                ++i;
                continue;
            }
            uint256 j = i;
            while (j < data.length && _isJsonWhitespace(data[j])) {
                ++j;
            }
            bool touches = (n != 0 && _isStructural(out[n - 1])) || (j < data.length && _isStructural(data[j]));
            if (!touches) {
                for (uint256 k = i; k < j; ++k) {
                    out[n++] = data[k];
                }
            }
            i = j;
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

    function _findUnique(bytes memory data, bytes memory needle)
        private
        pure
        returns (CeremonyFields.Found found, uint256 at)
    {
        uint256 hit = type(uint256).max;
        for (uint256 i = 0; i + needle.length <= data.length; ++i) {
            if (!_matchesAt(data, needle, i)) continue;
            if (hit != type(uint256).max) return (CeremonyFields.Found.Several, 0);
            hit = i;
        }
        if (hit == type(uint256).max) return (CeremonyFields.Found.None, 0);
        return (CeremonyFields.Found.One, hit);
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

/// @notice The transcript checks `TlsNotaryVerifierBase` ran on each session
///         as of commit 7a63c20, code unchanged: everything between
///         authenticating an attestation and reading its time.
/// @dev A profile's hooks are parameters here: `Profile` carries the
///      constants `XPlatformVerifier` and `GitHubPlatformVerifier` return.
library RefTranscript {
    error WrongRequestLine();
    error CodeVerifierMismatch();
    error ClientIdentifierNotSerializerSafe(bytes found);
    error FieldNotUnique(string name, uint256 rangesMatching);
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

    /// @dev `_identitySession` after `_authenticate`.
    function identityTranscript(CeremonyAttestation.AttestedData memory data, Profile memory profile)
        internal
        pure
        returns (bytes32 identityCommitment, string memory userId, string memory handle)
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
        identityCommitment = bearer.commitment;
        _checkIdentityHead(RefCeremonyAttestation.concatRevealed(data.sent));

        RefCeremonyAttestation.requireExactCoverage(data.received, data.recvTranscriptLength);
        bytes memory joined = RefCeremonyAttestation.concatRevealed(data.received);
        userId = string(
            !profile.idIsInteger
                ? _uniqueJsonString(data.received, joined, profile.idField)
                : _uniqueJsonInteger(data.received, joined, profile.idField)
        );
        handle = string(_uniqueJsonString(data.received, joined, profile.handleField));
    }

    function _delimiterCount(bytes memory joined, bytes memory delimiter) private pure returns (uint256 count) {
        for (uint256 i = 0; i + delimiter.length <= joined.length; ++i) {
            bool hit = true;
            for (uint256 j = 0; j < delimiter.length; ++j) {
                if (joined[i + j] != delimiter[j]) {
                    hit = false;
                    break;
                }
            }
            if (hit) ++count;
        }
    }

    function _uniqueJsonString(
        CeremonyAttestation.DirectionBlock memory block_,
        bytes memory joined,
        string memory name
    ) internal pure returns (bytes memory value) {
        uint256 matches;
        for (uint256 i = 0; i < block_.revealed.length; ++i) {
            (CeremonyFields.Found found, bytes memory v) =
                RefCeremonyFields.tryJsonString(block_.revealed[i].value, name);
            if (found == CeremonyFields.Found.Several) revert FieldNotUnique(name, 2);
            if (found == CeremonyFields.Found.One) {
                ++matches;
                value = v;
            }
        }
        if (matches != 1) revert FieldNotUnique(name, matches);
        uint256 seen = _delimiterCount(RefCeremonyFields.normalizeJsonBytes(joined), abi.encodePacked('"', name, '":"'));
        if (seen != 1) revert FieldNotUnique(name, seen);
    }

    function _uniqueJsonInteger(
        CeremonyAttestation.DirectionBlock memory block_,
        bytes memory joined,
        string memory name
    ) internal pure returns (bytes memory digits) {
        uint256 matches;
        for (uint256 i = 0; i < block_.revealed.length; ++i) {
            (CeremonyFields.Found found, bytes memory v) =
                RefCeremonyFields.tryJsonInteger(block_.revealed[i].value, name);
            if (found == CeremonyFields.Found.Several) revert FieldNotUnique(name, 2);
            if (found == CeremonyFields.Found.One) {
                ++matches;
                digits = v;
            }
        }
        if (matches != 1) revert FieldNotUnique(name, matches);
        uint256 seen = _delimiterCount(RefCeremonyFields.normalizeJsonBytes(joined), abi.encodePacked('"', name, '":'));
        if (seen != 1) revert FieldNotUnique(name, seen);
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
