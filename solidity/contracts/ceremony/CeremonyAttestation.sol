// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {CeremonyFields} from "./CeremonyFields.sol";

/// @title CeremonyAttestation
/// @notice Decoder for the attested-data layout the X and GitHub profiles pin.
/// @dev The profile fixes the layout (REQ-COMMON-18, platform-ceremonies
///      section 4.1). This library, `libid-ceremony` in libid-rs, the
///      TypeScript mirror and the notary must agree byte for byte: a
///      divergence recovers a key nobody trusts and rejects every genuine
///      attestation with no error saying why.
///
///      Every boundary follows from the bytes before it, so `decode` is one
///      forward pass. It checks shape only; which ranges a profile expects is
///      the Platform Verifier's rule.
///
///      `decode` accepts transcript bytes covered by neither a revealed range
///      nor a commitment. The Platform Verifier of an identity session MUST
///      call `requireExactCoverage` and run the needle scan of REQ-COMMON-39
///      and the framing check of REQ-COMMON-40, so the committed range is the
///      only hidden region.
library CeremonyAttestation {
    /// @dev The authority, `createdAt`, and the two transcript lengths.
    uint256 internal constant HEADER_LEN = 48;

    struct RevealedRange {
        uint32 start;
        uint32 end;
        bytes value;
    }

    struct RangeCommitment {
        uint32 start;
        uint32 end;
        bytes32 commitment;
    }

    struct DirectionBlock {
        RevealedRange[] revealed;
        RangeCommitment[] commitments;
    }

    struct AttestedData {
        /// @dev The hashed TLS server name the notary authenticated, the one
        ///      field it observed rather than was told. The session is read
        ///      from the revealed request line.
        bytes32 authorityId;
        uint64 createdAt;
        uint32 sentTranscriptLength;
        uint32 recvTranscriptLength;
        DirectionBlock sent;
        DirectionBlock received;
    }

    error Truncated();
    error TrailingBytes(uint256 count);
    error EmptyRange(uint32 start);
    error OutOfOrder(uint32 start, uint32 previousEnd);
    error PastTranscriptEnd(uint32 end, uint32 length);
    error CommitmentOverlapsRevealed(uint32 start, uint32 end);
    /// @dev Transcript bytes `[from, to)` are covered by neither a revealed
    ///      range nor a commitment.
    error CoverageGap(uint32 from, uint32 to);
    /// @dev Spans overlap in a block that did not come from `decode`.
    error SpansOverlap(uint32 at);
    /// @dev The request must commit exactly one credential, so the framed
    ///      range and the proved range are the same.
    error NotOneCommitment(uint256 count);
    /// @dev An obsolete line fold in the revealed request bytes.
    error ObsoleteLineFold(uint256 at);
    /// @dev A line feed not preceded by a carriage return: it starts a header
    ///      line the CRLF-anchored needle cannot see.
    error BareLineFeed(uint256 at);
    /// @dev A carriage return not followed by a line feed: some parsers end
    ///      a line on it, so the head could end elsewhere for the platform.
    error BareCarriageReturn(uint256 at);
    error NotOneAuthorizationHeader(uint256 count);
    error BadBearerFraming();
    /// @dev No commitment in this direction is framed by the delimiters the
    ///      profile pins, so nothing identifies which range holds the bearer.
    error NoFramedCommitment();
    /// @dev More than one is, so the framing identifies nothing.
    error AmbiguousFraming();
    /// @dev The revealed request bytes hold `heads` head boundaries, not one.
    error NotOneRequest(uint256 heads);
    /// @dev `count` bytes follow the head of a bodiless request.
    error BytesAfterRequest(uint256 count);

    /// @notice Parse and shape-check the attested data.
    /// @dev Trailing bytes are refused: the layout accounts for every byte.
    function decode(bytes calldata data) internal pure returns (AttestedData memory attested) {
        uint256 at = 0;

        attested.authorityId = _bytes32(data, at);
        attested.createdAt = uint64(_uint(data, at + 32, 8));
        attested.sentTranscriptLength = uint32(_uint(data, at + 40, 4));
        attested.recvTranscriptLength = uint32(_uint(data, at + 44, 4));
        at = HEADER_LEN;

        (attested.sent, at) = _direction(data, at);
        (attested.received, at) = _direction(data, at);

        if (at != data.length) revert TrailingBytes(data.length - at);

        _check(attested.sent, attested.sentTranscriptLength);
        _check(attested.received, attested.recvTranscriptLength);
    }

    /// @dev The raw bytes REQ-COMMON-40 requires immediately before the
    ///      committed range.
    bytes internal constant BEARER_PREFIX = "\r\nauthorization: Bearer ";
    /// @dev The raw bytes REQ-COMMON-40 requires immediately after it.
    bytes internal constant BEARER_SUFFIX = "\r\n";
    /// @dev The normalized, line-anchored needle REQ-COMMON-39 counts: the
    ///      credential header under any scheme.
    bytes internal constant AUTHORIZATION_NEEDLE = "\r\nauthorization:";

    /// @dev What ends a framed commitment: exact suffix bytes, or the `,` or `}`
    ///      closing a bare JSON integer.
    enum Terminator {
        Suffix,
        JsonIntegerEnd
    }

    /// @notice A direction's block and its revealed bytes, joined, without JSON whitespace.
    /// @dev `anchors[i]`: the revealed range ending where commitment `i`
    ///      starts, without JSON whitespace, if `anchored[i]`.
    struct Framing {
        DirectionBlock block_;
        bytes normalized;
        bytes[] anchors;
        bool[] anchored;
    }

    function framing(DirectionBlock memory block_) internal pure returns (Framing memory f) {
        f.block_ = block_;
        f.normalized = _normalizedRevealed(block_);
        uint256 n = block_.commitments.length;
        f.anchors = new bytes[](n);
        f.anchored = new bool[](n);
        for (uint256 i = 0; i < n; ++i) {
            (f.anchored[i], f.anchors[i]) = _anchor(block_, block_.commitments[i].start);
        }
    }

    function _normalizedRevealed(DirectionBlock memory block_) private pure returns (bytes memory) {
        return CeremonyFields.normalizeJsonBytes(concatRevealed(block_));
    }

    /// @notice The one commitment framed by revealed `prefix` and `suffix`, JSON
    ///         whitespace aside; the framing identifies it (REQ-PLAT-57, REQ-PLAT-58).
    function requireFramedCommitment(DirectionBlock memory block_, bytes memory prefix, bytes memory suffix)
        internal
        pure
        returns (RangeCommitment memory framed)
    {
        return _framed(framing(block_), prefix, Terminator.Suffix, suffix);
    }

    /// @notice `requireFramedCommitment`, for several reads of one `framing`.
    function requireFramedCommitment(Framing memory f, bytes memory prefix, bytes memory suffix)
        internal
        pure
        returns (RangeCommitment memory framed)
    {
        return _framed(f, prefix, Terminator.Suffix, suffix);
    }

    /// @notice The one commitment after revealed `prefix` and before a revealed
    ///         `,` or `}`, so the committed digits are the whole number.
    function requireFramedInteger(Framing memory f, bytes memory prefix)
        internal
        pure
        returns (RangeCommitment memory framed)
    {
        return _framed(f, prefix, Terminator.JsonIntegerEnd, "");
    }

    /// @dev The prefix at most once in `normalized`, then exactly one commitment
    ///      anchored by it and ended by the terminator.
    function _framed(Framing memory f, bytes memory prefix, Terminator terminator, bytes memory suffix)
        private
        pure
        returns (RangeCommitment memory)
    {
        if (CeremonyFields.occurrences(f.normalized, prefix) > 1) revert AmbiguousFraming();
        DirectionBlock memory block_ = f.block_;

        bytes32 prefixHash = keccak256(prefix);
        bytes32 suffixHash = keccak256(suffix);
        uint256 found = type(uint256).max;
        for (uint256 i = 0; i < block_.commitments.length; ++i) {
            RangeCommitment memory c = block_.commitments[i];
            // The prefix must end the one revealed range ending where the
            // commitment starts, never a join across ranges.
            if (!f.anchored[i] || !_endsWith(f.anchors[i], prefixHash, prefix.length)) continue;
            if (terminator == Terminator.Suffix) {
                bytes memory after_ = _revealedSlice(block_, c.end, c.end + uint32(suffix.length));
                if (keccak256(after_) != suffixHash) continue;
            } else if (!_terminatedAt(block_, c.end)) {
                continue;
            }

            if (found != type(uint256).max) revert AmbiguousFraming();
            found = i;
        }
        if (found == type(uint256).max) revert NoFramedCommitment();
        return block_.commitments[found];
    }

    /// @dev Whether a revealed range starts exactly at `at` and its first byte
    ///      after JSON whitespace is `,` or `}`.
    function _terminatedAt(DirectionBlock memory block_, uint32 at) private pure returns (bool) {
        for (uint256 i = 0; i < block_.revealed.length; ++i) {
            RevealedRange memory range = block_.revealed[i];
            if (range.start != at) continue;
            bytes memory v = range.value;
            for (uint256 j = 0; j < v.length; ++j) {
                bytes1 b = v[j];
                if (b == 0x20 || b == 0x09 || b == 0x0a || b == 0x0d) continue;
                return b == 0x2c || b == 0x7d;
            }
            return false;
        }
        return false;
    }

    /// @dev The first revealed range ending exactly at `at`, JSON whitespace
    ///      removed for comparison.
    function _anchor(DirectionBlock memory block_, uint32 at) private pure returns (bool, bytes memory) {
        for (uint256 i = 0; i < block_.revealed.length; ++i) {
            RevealedRange memory range = block_.revealed[i];
            if (range.end == at) return (true, CeremonyFields.normalizeJsonBytes(range.value));
        }
        return (false, "");
    }

    function _endsWith(bytes memory normalized, bytes32 prefixHash, uint256 size) private pure returns (bool) {
        if (normalized.length < size) return false;
        bytes32 tail;
        // The last `size` bytes, in bounds by the length check above.
        assembly ("memory-safe") {
            tail := keccak256(add(add(normalized, 0x20), sub(mload(normalized), size)), size)
        }
        return tail == prefixHash;
    }

    /// @notice REQ-COMMON-35, -39 and -40 for an identity request that commits
    ///         its credential in one `Authorization` header, and nothing after it.
    /// @dev Coverage first: the header count reads revealed bytes only.
    /// @return commitment The committed bearer range.
    /// @return revealed   `concatRevealed(block_)`, the bytes the count read.
    function requireBearerHeaderRequest(DirectionBlock memory block_, uint32 length)
        internal
        pure
        returns (RangeCommitment memory commitment, bytes memory revealed)
    {
        // One committed range, so the range REQ-COMMON-40 frames is the one
        // the circuit opens.
        if (block_.commitments.length != 1) revert NotOneCommitment(block_.commitments.length);
        commitment = block_.commitments[0];

        requireExactCoverage(block_, length);

        revealed = concatRevealed(block_);
        requireCrlfLineEndings(revealed);
        requireOneBodilessRequest(block_, revealed, length);

        // Counted over the join, so a reveal cut through a header cannot hide
        // it. A false match at a seam fails closed.
        uint256 headers = _countNeedle(revealed);
        if (headers != 1) revert NotOneAuthorizationHeader(headers);

        // Raw bytes on both sides make the committed range one header line's value.
        if (commitment.start < BEARER_PREFIX.length) revert BadBearerFraming();
        bytes memory before_ = _revealedSlice(block_, commitment.start - uint32(BEARER_PREFIX.length), commitment.start);
        bytes memory after_ = _revealedSlice(block_, commitment.end, commitment.end + uint32(BEARER_SUFFIX.length));
        if (keccak256(before_) != keccak256(BEARER_PREFIX) || keccak256(after_) != keccak256(BEARER_SUFFIX)) {
            revert BadBearerFraming();
        }
    }

    /// @notice The direction carries exactly one bodiless HTTP request.
    /// @dev `revealed` is `concatRevealed(block_)`, covered and CRLF-checked: one
    ///      head boundary, nothing revealed after it, and the last range ending
    ///      the transcript.
    function requireOneBodilessRequest(DirectionBlock memory block_, bytes memory revealed, uint32 length)
        internal
        pure
    {
        (uint256 heads, uint256 at) = headBoundaries(revealed);
        if (heads != 1) revert NotOneRequest(heads);
        uint256 trailing = revealed.length - (at + 4);
        if (trailing != 0) revert BytesAfterRequest(trailing);
        // In bounds: one boundary means at least four revealed bytes, so at
        // least one revealed range.
        uint32 lastEnd = block_.revealed[block_.revealed.length - 1].end;
        if (lastEnd != length) revert BytesAfterRequest(length - lastEnd);
    }

    /// @notice How many head boundaries (`\r\n\r\n`) `data` holds, overlapping
    ///         ones included, and the offset of the first, or `max` for none.
    function headBoundaries(bytes memory data) internal pure returns (uint256 count, uint256 first) {
        first = type(uint256).max;
        // Every boundary begins with a CR, so only those offsets are tried.
        for (
            uint256 cr = CeremonyFields.indexOfByte(data, 0, 0x0d);
            cr + 4 <= data.length;
            cr = CeremonyFields.indexOfByte(data, cr + 1, 0x0d)
        ) {
            uint256 four;
            // The four bytes at `cr`, inside `data` by the loop condition;
            // the shift drops what the word holds past them.
            assembly ("memory-safe") {
                four := shr(224, mload(add(add(data, 0x20), cr)))
            }
            if (four == 0x0d0a0d0a) {
                ++count;
                if (first == type(uint256).max) first = cr;
            }
        }
    }

    /// @notice Every line ending in the revealed request bytes is a CRLF, and
    ///         no line continues the one before it.
    ///
    /// @dev A CRLF-anchored header count misses two shapes lenient HTTP/1.1
    ///      parsers accept. A fold `authorization:\r\n Bearer x` normalizes
    ///      to `authorization:\r\nbearer`, which the needle never counts. A
    ///      bare LF starts a header line the needle never sees.
    ///
    ///      Shared by every header count: the bearer header here and the
    ///      `Host` count in `GoogleJwtRoots`. Runs before the count, over raw
    ///      bytes, so the offsets it reports are offsets into `revealed`.
    ///      A fold anywhere is reported before the first bare CR or LF.
    function requireCrlfLineEndings(bytes memory revealed) internal pure {
        uint256 bare = type(uint256).max;
        bool bareLineFeed;
        // Only CR and LF bytes decide anything, so the pass visits those
        // alone, in offset order: `cr` and `lf` are the next of each.
        uint256 cr = CeremonyFields.indexOfByte(revealed, 0, 0x0d);
        uint256 lf = CeremonyFields.indexOfByte(revealed, 0, 0x0a);
        while (cr < revealed.length || lf < revealed.length) {
            if (cr < lf) {
                if (cr + 1 < revealed.length && revealed[cr + 1] == 0x0a) {
                    if (cr + 2 < revealed.length && (revealed[cr + 2] == 0x20 || revealed[cr + 2] == 0x09)) {
                        revert ObsoleteLineFold(cr);
                    }
                } else if (bare == type(uint256).max) {
                    bare = cr;
                }
                cr = CeremonyFields.indexOfByte(revealed, cr + 1, 0x0d);
            } else {
                if ((lf == 0 || revealed[lf - 1] != 0x0d) && bare == type(uint256).max) {
                    bare = lf;
                    bareLineFeed = true;
                }
                lf = CeremonyFields.indexOfByte(revealed, lf + 1, 0x0a);
            }
        }
        if (bare == type(uint256).max) return;
        if (bareLineFeed) revert BareLineFeed(bare);
        revert BareCarriageReturn(bare);
    }

    /// @notice Lowercase ASCII and drop every space and horizontal tab, keeping
    ///         CR and LF (REQ-COMMON-39).
    ///
    /// @dev Field names and the scheme are case-insensitive and the colon
    ///      admits whitespace. Removing only bytes absent from the needle can
    ///      create a spurious match, which over-rejects, but never hides a real
    ///      one. `_countNeedle` strips the same bytes inline, so the two must
    ///      change together.
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

    /// @dev How often `AUTHORIZATION_NEEDLE` occurs in `normalizeHeaderBytes(raw)`.
    ///      Relies on the needle's first byte, CR, occurring nowhere else in it:
    ///      after a mismatch the only match left open starts at the current
    ///      byte, and matches never overlap.
    function _countNeedle(bytes memory raw) private pure returns (uint256 count) {
        bytes memory needle = AUTHORIZATION_NEEDLE;
        // Reads `raw[i]` only below its length. The needle is sixteen bytes,
        // so one word holds it and byte `k` of that word is `needle[k]`.
        assembly ("memory-safe") {
            let want := mload(add(needle, 0x20))
            let size := mload(needle)
            let p := add(raw, 0x20)
            let len := mload(raw)
            let matched := 0
            for { let i := 0 } lt(i, len) { i := add(i, 1) } {
                let c := byte(0, mload(add(p, i)))
                if or(eq(c, 0x20), eq(c, 0x09)) { continue }
                if and(gt(c, 0x40), lt(c, 0x5b)) { c := add(c, 0x20) }
                switch eq(c, byte(matched, want))
                case 1 {
                    matched := add(matched, 1)
                    if eq(matched, size) {
                        count := add(count, 1)
                        matched := 0
                    }
                }
                default { matched := eq(c, byte(0, want)) }
            }
        }
    }

    /// @notice The revealed bytes of one direction, in offset order.
    /// @dev Cross-range header counts read this join; a seam may only over-count.
    function concatRevealed(DirectionBlock memory block_) internal pure returns (bytes memory out) {
        uint256 total;
        for (uint256 i = 0; i < block_.revealed.length; ++i) {
            total += block_.revealed[i].value.length;
        }
        out = new bytes(total);
        uint256 n;
        for (uint256 i = 0; i < block_.revealed.length; ++i) {
            bytes memory v = block_.revealed[i].value;
            // In bounds: `n + v.length` never exceeds `total`, `out`'s length.
            assembly ("memory-safe") {
                mcopy(add(add(out, 0x20), n), add(v, 0x20), mload(v))
            }
            n += v.length;
        }
    }

    /// @dev Read `[from, to)` of the transcript out of the revealed ranges.
    ///      Returns an empty result if any byte of it is not revealed, which
    ///      the caller treats as a framing failure.
    function _revealedSlice(DirectionBlock memory block_, uint32 from, uint32 to)
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
                RevealedRange memory r = block_.revealed[i];
                if (r.start <= at && at < r.end) {
                    uint256 offset = at - r.start;
                    uint256 take = r.value.length - offset;
                    if (take > to - at) take = to - at;
                    bytes memory v = r.value;
                    // Reads stay in `v`: `take <= v.length - offset`. Writes
                    // stay in `out`: `n == at - from` and `take <= to - at`.
                    assembly ("memory-safe") {
                        mcopy(add(add(out, 0x20), n), add(add(v, 0x20), offset), take)
                    }
                    n += take;
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

    /// @notice Require the revealed ranges and commitments of one direction to
    ///         tile `[0, length)` exactly, with no gap and no overlap
    ///         (REQ-COMMON-35).
    /// @dev Walks both ascending lists as one merge: each span begins where
    ///      the previous ended, and the last ends at `length`. The committed
    ///      range is then the only unread region, its offsets fixed by its
    ///      neighbours.
    function requireExactCoverage(DirectionBlock memory block_, uint32 length) internal pure {
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

            // Only a block not built by `decode` can overlap here.
            if (start < at) revert SpansOverlap(start);
            if (start != at) revert CoverageGap(at, start);
            at = end;
        }

        if (at != length) revert CoverageGap(at, length);
    }

    /// @notice `keccak256(attestedData)`, the preimage the notary signs.
    function digest(bytes calldata data) internal pure returns (bytes32) {
        return keccak256(data);
    }

    // --- Reading -----------------------------------------------------------

    function _direction(bytes calldata data, uint256 at)
        private
        pure
        returns (DirectionBlock memory block_, uint256 next)
    {
        // Counts are eight bytes, the encoder's `Vec` length.
        uint256 count = _uint(data, at, 8);
        at += 8;
        block_.revealed = new RevealedRange[](count);
        for (uint256 i = 0; i < count; ++i) {
            uint32 start = uint32(_uint(data, at, 4));
            // The encoding carries no `end`: it is `start` plus the value's length.
            uint256 len = _uint(data, at + 4, 8);
            at += 12;
            if (at + len > data.length) revert Truncated();
            if (start + len > type(uint32).max) revert Truncated();
            // Casting to uint32 is safe: the line above refuses a sum past
            // type(uint32).max.
            // forge-lint: disable-next-line(unsafe-typecast)
            block_.revealed[i] = RevealedRange({start: start, end: uint32(start + len), value: data[at:at + len]});
            at += len;
        }

        count = _uint(data, at, 8);
        at += 8;
        block_.commitments = new RangeCommitment[](count);
        for (uint256 i = 0; i < count; ++i) {
            block_.commitments[i] = RangeCommitment({
                start: uint32(_uint(data, at, 4)),
                end: uint32(_uint(data, at + 4, 4)),
                commitment: _bytes32(data, at + 8)
            });
            at += 40;
        }
        next = at;
    }

    function _bytes32(bytes calldata data, uint256 at) private pure returns (bytes32 out) {
        if (at + 32 > data.length) revert Truncated();
        out = bytes32(data[at:at + 32]);
    }

    /// @dev Big-endian read of `width` bytes, `width <= 32`.
    function _uint(bytes calldata data, uint256 at, uint256 width) private pure returns (uint256 out) {
        if (at + width > data.length) revert Truncated();
        for (uint256 i = 0; i < width; ++i) {
            out = (out << 8) | uint8(data[at + i]);
        }
    }

    // --- Shape -------------------------------------------------------------

    /// @dev Ranges ascend, are nonempty, do not overlap, and end inside the
    ///      signed transcript length; commitments additionally never overlap a
    ///      revealed range.
    function _check(DirectionBlock memory block_, uint32 length) private pure {
        uint32 previousEnd = 0;
        for (uint256 i = 0; i < block_.revealed.length; ++i) {
            RevealedRange memory range = block_.revealed[i];
            _span(range.start, range.end, length, previousEnd);
            previousEnd = range.end;
        }

        previousEnd = 0;
        for (uint256 i = 0; i < block_.commitments.length; ++i) {
            RangeCommitment memory commitment = block_.commitments[i];
            _span(commitment.start, commitment.end, length, previousEnd);
            previousEnd = commitment.end;
        }

        // Both lists are ascending and disjoint, so one merge pass sees every
        // adjacent pair in linear time.
        uint256 r = 0;
        uint256 c = 0;
        while (r < block_.revealed.length && c < block_.commitments.length) {
            RevealedRange memory range = block_.revealed[r];
            RangeCommitment memory commitment = block_.commitments[c];
            if (commitment.start < range.end && range.start < commitment.end) {
                revert CommitmentOverlapsRevealed(commitment.start, commitment.end);
            }
            if (range.end <= commitment.end) ++r;
            else ++c;
        }
    }

    function _span(uint32 start, uint32 end, uint32 length, uint32 previousEnd) private pure {
        if (end <= start) revert EmptyRange(start);
        if (start < previousEnd) revert OutOfOrder(start, previousEnd);
        if (end > length) revert PastTranscriptEnd(end, length);
    }
}
