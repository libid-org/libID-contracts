// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title CeremonyFields
/// @notice The byte searches and the JSON whitespace removal the transcript
///         checks run over revealed bytes, and holding a form body to exactly
///         the fields it should carry.
///
/// @dev Nothing here parses a document. ceremony-common section 9 says so
///      plainly: no complete HTTP request grammar, no complete HTTP response
///      grammar, no complete JSON grammar is proved or parsed anywhere in the
///      protocol. A JSON delimiter is matched by its exact template, a form
///      field by its own boundary template, and that is all.
///
///      What makes a template safe to trust is REQ-COMMON-19A: the Platform
///      Verifier must reject a transcript in which a field's full delimiter
///      matches at more than one position. An authenticated response carries
///      text the account holder chooses -- a display name, a bio -- and that
///      text can embed a lookalike field. Reading the first match would let it
///      answer for the real one; reading the last would too. Refusing to answer
///      at all is what closes it, which `occurrences` lets a caller do.
library CeremonyFields {
    /// @dev The form names the field more than once, so no reading of it is
    ///      authoritative (REQ-COMMON-19A).
    error AmbiguousField(string name);
    /// @dev The form does not name the field.
    error FieldNotFound(string name);
    /// @dev The body stops being the exact form at byte `at`: the pair that
    ///      begins there is not the name expected next, a value byte is outside
    ///      the serializer's alphabet, an escape is not two uppercase hex
    ///      digits or spells a byte the serializer writes bare or as `+`, a
    ///      `&` stands where the body should end or the body ends where a `&`
    ///      should stand (REQ-PLAT-61).
    error MalformedForm(uint256 at);
    /// @dev A field the form must carry once carries nothing.
    error EmptyFormValue(string name);

    /// @notice A body `requireExactForm` accepted: per listed field, in list
    ///         order, its name's hash and its value's offsets in `body`.
    struct Form {
        bytes body;
        bytes32[] names;
        uint256[] starts;
        uint256[] ends;
    }

    // Byte classes as 256-bit sets: byte `c` is a member when bit `c` is set.
    // The lint misreads each member's `1 << c` as swapped shift operands.
    // forge-lint: disable-next-line(incorrect-shift)
    uint256 private constant JSON_WHITESPACE = (1 << 0x20) | (1 << 0x09) | (1 << 0x0a) | (1 << 0x0d);
    /// @dev `:` `,` `{` `}` `[` `]`.
    // forge-lint: disable-next-line(incorrect-shift)
    uint256 private constant JSON_STRUCTURAL =
        (1 << 0x3a) | (1 << 0x2c) | (1 << 0x7b) | (1 << 0x7d) | (1 << 0x5b) | (1 << 0x5d);
    /// @dev `[A-Za-z0-9*._-]`, the bytes the form serializer passes through.
    // forge-lint: disable-next-line(incorrect-shift)
    uint256 private constant SERIALIZER_SAFE = (((1 << 26) - 1) << 0x41) | (((1 << 26) - 1) << 0x61)
        | (((1 << 10) - 1) << 0x30) | (1 << 0x2a) | (1 << 0x2e) | (1 << 0x5f) | (1 << 0x2d);

    /// @notice `data` with the JSON whitespace that touches a structural
    ///         byte removed.
    ///
    /// @dev The four bytes JSON lets a writer put between tokens (RFC 8259
    ///      section 2): space, tab, line feed, carriage return. GitHub
    ///      pretty-prints `/user` for the media type the profile pins, so the
    ///      compact delimiters `CeremonyAttestation`'s framing checks match
    ///      are a grammar, not the bytes on the wire. Removing the whitespace
    ///      first, the way `CeremonyAttestation.normalizeHeaderBytes` does for
    ///      a request head, leaves every check its one exact template and
    ///      makes a member in any spelling the same member -- so a duplicate
    ///      spelled with spaces is still counted as one.
    ///
    ///      Only a run that touches `:` `,` `{` `}` `[` or `]` on either side
    ///      goes, which is exactly where JSON puts insignificant whitespace.
    ///      A run between two tokens stays: `123 456` must not read as
    ///      `123456`, and a trailing space after digits must still be the
    ///      byte the terminator check judges. Stateless on purpose, with no
    ///      notion of being inside a string: a reader with one is a reader a
    ///      prover desynchronises by cutting a revealed range mid-value, and a
    ///      needle then hides where the reader believes a string is open. No
    ///      needle can be manufactured by this either -- one needs unescaped
    ///      quotes, and this removes none -- and nothing this reads carries
    ///      whitespace beside a structural byte inside its value.
    function normalizeJsonBytes(bytes memory data) internal pure returns (bytes memory out) {
        out = new bytes(data.length);
        uint256 n;
        uint256 i;
        while (i < data.length) {
            // `j`: the first whitespace byte at or after `i`, or the end.
            uint256 j = i;
            while (j < data.length) {
                uint256 marked = _jsonWhitespaceBytes(_word(data, j));
                if (j + 32 > data.length) marked &= _leading(data.length - j);
                if (marked != 0) {
                    j += _firstMarked(marked);
                    break;
                }
                j = j + 32 < data.length ? j + 32 : data.length;
            }
            _append(out, n, data, i, j);
            n += j - i;
            if (j == data.length) break;

            // Whitespace [j, k) goes if the last kept byte or `data[k]` is structural.
            uint256 k = j + 1;
            while (k < data.length && (JSON_WHITESPACE >> uint8(data[k])) & 1 == 1) {
                ++k;
            }
            bool touches = (n != 0 && (JSON_STRUCTURAL >> uint8(out[n - 1])) & 1 == 1)
                || (k < data.length && (JSON_STRUCTURAL >> uint8(data[k])) & 1 == 1);
            if (!touches) {
                _append(out, n, data, j, k);
                n += k - j;
            }
            i = k;
        }
        assembly ("memory-safe") {
            mstore(out, n)
        }
    }

    /// @dev `data[from:to]` written into `out` at `at`.
    function _append(bytes memory out, uint256 at, bytes memory data, uint256 from, uint256 to) private pure {
        // Both ranges in bounds, so the copy stays inside both arrays.
        assert(from <= to && to <= data.length && at + (to - from) <= out.length);
        assembly ("memory-safe") {
            mcopy(add(add(out, 0x20), at), add(add(data, 0x20), from), sub(to, from))
        }
    }

    /// @dev 0x80 in each byte of `word` that is space, tab, LF or CR; 0 elsewhere.
    function _jsonWhitespaceBytes(uint256 word) private pure returns (uint256 marked) {
        assembly ("memory-safe") {
            // Bytes equal to `v`, marked as `indexOfByte` marks them.
            function equal(w, v) -> f {
                let low7 := 0x7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f
                let x := xor(w, mul(0x0101010101010101010101010101010101010101010101010101010101010101, v))
                f := not(or(or(add(and(x, low7), low7), x), low7))
            }
            marked := or(or(equal(word, 0x20), equal(word, 0x09)), or(equal(word, 0x0a), equal(word, 0x0d)))
        }
    }

    /// @notice How many offsets of `haystack` begin a copy of `needle`,
    ///         overlapping copies included.
    function occurrences(bytes memory haystack, bytes memory needle) internal pure returns (uint256 count) {
        for (
            uint256 at = _indexOf(haystack, needle, 0);
            at != type(uint256).max;
            at = _indexOf(haystack, needle, at + 1)
        ) {
            ++count;
        }
    }

    /// @dev The first offset at or after `from` that begins a copy of
    ///      `needle` in `data`, or `max`.
    function _indexOf(bytes memory data, bytes memory needle, uint256 from) private pure returns (uint256 at) {
        at = type(uint256).max;
        uint256 n = needle.length;
        if (n > data.length) return at;
        // Each comparison covers `data[i:i + n]` with `i <= last`: inside `data`.
        uint256 last = data.length - n;
        assembly ("memory-safe") {
            let p := add(data, 0x20)
            switch gt(n, 32)
            case 0 {
                // `mask` keeps a word's first `n` bytes; the rest is not compared.
                let mask := not(shr(mul(n, 8), not(0)))
                let want := and(mload(add(needle, 0x20)), mask)
                for { let i := from } iszero(gt(i, last)) { i := add(i, 1) } {
                    if eq(and(mload(add(p, i)), mask), want) {
                        at := i
                        break
                    }
                }
            }
            default {
                let want := keccak256(add(needle, 0x20), n)
                for { let i := from } iszero(gt(i, last)) { i := add(i, 1) } {
                    if eq(keccak256(add(p, i), n), want) {
                        at := i
                        break
                    }
                }
            }
        }
    }

    /// @notice The first offset at or after `from` holding byte `b`, or
    ///         `data.length` when none does.
    function indexOfByte(bytes memory data, uint256 from, bytes1 b) internal pure returns (uint256) {
        return _indexOfByte(data, from, data.length, b);
    }

    /// @notice The first offset in `[from, end)` holding byte `b`, or `end`
    ///         when none does.
    function indexOfByte(bytes memory data, uint256 from, uint256 end, bytes1 b) internal pure returns (uint256) {
        assert(end <= data.length);
        return _indexOfByte(data, from, end, b);
    }

    /// @dev `end <= data.length`. After XOR with `b` in every byte, a byte `x`
    ///      is zero iff neither `(x & 0x7f) + 0x7f` nor `x` sets its top bit;
    ///      the sum stays below 0x100, so no byte carries into the next. A word
    ///      may extend past `end`; a hit there returns `end`.
    function _indexOfByte(bytes memory data, uint256 from, uint256 end, bytes1 b) private pure returns (uint256 at) {
        assembly ("memory-safe") {
            let low7 := 0x7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f
            let pattern := mul(byte(0, b), 0x0101010101010101010101010101010101010101010101010101010101010101)
            let p := add(data, 0x20)
            let len := end
            at := len
            for { let i := from } lt(i, len) { i := add(i, 32) } {
                let x := xor(mload(add(p, i)), pattern)
                let hits := not(or(or(add(and(x, low7), low7), x), low7))
                if hits {
                    let j := 0
                    if iszero(shr(128, hits)) {
                        j := 16
                        hits := shl(128, hits)
                    }
                    if iszero(shr(192, hits)) {
                        j := add(j, 8)
                        hits := shl(64, hits)
                    }
                    if iszero(shr(224, hits)) {
                        j := add(j, 4)
                        hits := shl(32, hits)
                    }
                    if iszero(shr(240, hits)) {
                        j := add(j, 2)
                        hits := shl(16, hits)
                    }
                    if iszero(shr(248, hits)) { j := add(j, 1) }
                    if lt(add(i, j), len) { at := add(i, j) }
                    break
                }
            }
        }
    }

    /// @notice The value of field `name` in a body `requireExactForm` accepted.
    ///
    /// @dev Listed names carry no form delimiter (the generator refuses one),
    ///      so each recorded value is the one a form parser reads for its name.
    function valueOf(Form memory form, string memory name) internal pure returns (bytes memory) {
        bytes32 wanted = keccak256(bytes(name));
        uint256 found = type(uint256).max;
        for (uint256 i = 0; i < form.names.length; ++i) {
            if (form.names[i] != wanted) continue;
            if (found != type(uint256).max) revert AmbiguousField(name);
            found = i;
        }
        if (found == type(uint256).max) revert FieldNotFound(name);
        return _slice(form.body, form.starts[found], form.ends[found]);
    }

    /// @notice `body` is the WHATWG form serialization of exactly the fields
    ///         `names` lists, `&`-joined, in that order, each once with a
    ///         nonempty value -- and nothing else.
    ///
    /// @dev REQ-PLAT-61. Reading one field by its literal name cannot answer
    ///      "what else is here": an encoded spelling (`code%5Fverifier=`) is
    ///      invisible to a literal match, and a value read to the next `&` lets
    ///      a raw `;` or `=` be a pair to some parsers and a value to others.
    ///      Resting on that alone rests on the platform refusing what was not
    ///      counted (ASM-PROV-07). This check removes the assumption: one
    ///      cursor walks the body once, and
    ///      every byte of it is accounted for -- a literal name, `=`, a value
    ///      in the serializer's output alphabet, `&` between pairs, the end
    ///      of the body after the last. A sixth pair, a duplicate, a reordering,
    ///      a name in another spelling and a delimiter smuggled into a value
    ///      all put a byte where the grammar allows no such byte.
    ///
    ///      The alphabet is the serializer's OUTPUT, not the input's: the bytes
    ///      it passes through (`[A-Za-z0-9*._-]`), `+` for a space, and `%`
    ///      followed by two UPPERCASE hex digits for everything else. Every
    ///      byte has exactly one spelling under that serializer, so any other
    ///      spelling of the same byte is refused: an escape in lowercase, an
    ///      escape of a byte the serializer passes through (`%61` for `a`),
    ///      an escape of the space it writes as `+` (`%20`). A truncated one
    ///      is not an escape at all. This is the specification's "serialize
    ///      the decoded tuple and compare byte for byte", done without the
    ///      round trip: a body every token of which is canonical IS the
    ///      serialization of what it decodes to. Values are validated, never
    ///      decoded, so the bytes GitHub parsed are the bytes judged, and an
    ///      encoded delimiter stays one value's byte (`%26`) rather than
    ///      becoming a pair. What a value decodes TO is not judged: a value
    ///      in this alphabet cannot become another field, and a verifier
    ///      reads only the values it compares.
    ///
    /// @return form Where each listed field's value lies, for `valueOf`.
    function requireExactForm(bytes memory body, bytes memory names) internal pure returns (Form memory form) {
        uint256 fields = 1;
        for (uint256 i = indexOfByte(names, 0, "&"); i < names.length; i = indexOfByte(names, i + 1, "&")) {
            ++fields;
        }
        form.body = body;
        form.names = new bytes32[](fields);
        form.starts = new uint256[](fields);
        form.ends = new uint256[](fields);

        uint256 at;
        uint256 from;
        for (uint256 field = 0;; ++field) {
            uint256 to = indexOfByte(names, from, "&");

            // The pair begins with the literal name and `=`, or it is not the
            // pair expected here: a reordering, a duplicate, another spelling.
            uint256 start = at;
            at += to - from;
            if (at > body.length || _hash(body, start, at) != _hash(names, from, to)) revert MalformedForm(start);
            if (at >= body.length || body[at] != "=") revert MalformedForm(start);
            ++at;

            uint256 valueStart = at;
            bool malformed;
            (at, malformed) = _formValue(body, at);
            if (malformed) revert MalformedForm(at);
            if (at == valueStart) revert EmptyFormValue(string(_slice(names, from, to)));
            form.names[field] = _hash(names, from, to);
            form.starts[field] = valueStart;
            form.ends[field] = at;

            // After the last value the body ends. After any other, exactly one
            // `&` and the next pair.
            if (to == names.length) {
                if (at != body.length) revert MalformedForm(at);
                return form;
            }
            if (at >= body.length) revert MalformedForm(at);
            ++at;
            from = to + 1;
        }
    }

    /// @dev The end of the form value from `at`: the next `&` or the end of
    ///      `body`. With `malformed`, the first token that is not a pass-through
    ///      byte, `+`, or an uppercase `%XX` of a byte the serializer escapes.
    function _formValue(bytes memory body, uint256 at) private pure returns (uint256, bool malformed) {
        while (at < body.length) {
            uint256 escaped = serializerUnsafeBytes(_word(body, at));
            if (at + 32 > body.length) escaped &= _leading(body.length - at);
            if (escaped == 0) {
                at = at + 32 < body.length ? at + 32 : body.length;
                continue;
            }
            at += _firstMarked(escaped);
            bytes1 c = body[at];
            if (c == "&") break;
            if (c == "+") {
                ++at;
                continue;
            }
            if (c != "%" || at + 2 >= body.length) return (at, true);
            (bool hiOk, uint8 hi) = _hexDigit(body[at + 1]);
            (bool loOk, uint8 lo) = _hexDigit(body[at + 2]);
            if (!hiOk || !loOk) return (at, true);
            uint8 decoded = (hi << 4) | lo;
            if (decoded == 0x20 || (SERIALIZER_SAFE >> decoded) & 1 == 1) return (at, true);
            at += 3;
        }
        return (at, false);
    }

    /// @dev The value of an UPPERCASE hex digit, and whether `c` is one.
    function _hexDigit(bytes1 c) private pure returns (bool, uint8) {
        if (c >= "0" && c <= "9") return (true, uint8(c) - 0x30);
        if (c >= "A" && c <= "F") return (true, uint8(c) - 0x37);
        return (false, 0);
    }

    /// @notice 0x80 in every byte of `word` outside the serializer's
    ///         pass-through set `[A-Za-z0-9*._-]`, and 0 in every byte in it.
    ///
    /// @dev For a byte `x < 0x80`, with `t = x & 0x7f`: `t + (0x7f - m)` sets
    ///      the top bit iff `x > m`, and `(0x7f + n) - t` iff `x < n`; neither
    ///      carries or borrows out of the byte. `~x` excludes bytes at or above
    ///      0x80.
    function serializerUnsafeBytes(uint256 word) internal pure returns (uint256 escaped) {
        assembly ("memory-safe") {
            // Bytes `x` with `m < x < n`, for `m < n <= 0x80`.
            function between(w, m, n) -> f {
                let ones := 0x0101010101010101010101010101010101010101010101010101010101010101
                let t := and(w, mul(ones, 0x7f))
                let above := add(t, mul(ones, sub(0x7f, m)))
                let below := sub(mul(ones, add(0x7f, n)), t)
                f := and(and(above, below), and(not(w), mul(ones, 0x80)))
            }
            // Bytes equal to `v`, marked as `indexOfByte` marks them.
            function equal(w, v) -> f {
                let ones := 0x0101010101010101010101010101010101010101010101010101010101010101
                let low7 := mul(ones, 0x7f)
                let x := xor(w, mul(ones, v))
                f := not(or(or(add(and(x, low7), low7), x), low7))
            }
            let digits := between(word, 0x2f, 0x3a)
            let letters := or(between(word, 0x40, 0x5b), between(word, 0x60, 0x7b))
            let marks := or(or(between(word, 0x2c, 0x2f), equal(word, 0x2a)), equal(word, 0x5f))
            escaped := and(
                not(or(or(digits, letters), marks)),
                0x8080808080808080808080808080808080808080808080808080808080808080
            )
        }
    }

    /// @dev The 32 bytes of `data` from `at`. Only the ones below
    ///      `data.length` are the data's; a caller masks the rest.
    function _word(bytes memory data, uint256 at) private pure returns (uint256 w) {
        assembly ("memory-safe") {
            w := mload(add(add(data, 0x20), at))
        }
    }

    /// @dev A mask of the first `count` bytes of a word, `count` below 32.
    function _leading(uint256 count) private pure returns (uint256) {
        return ~(type(uint256).max >> (count * 8));
    }

    /// @dev The index of the first byte of `marked` with its top bit set,
    ///      reading from the most significant; `marked` is not zero.
    function _firstMarked(uint256 marked) private pure returns (uint256 j) {
        assembly ("memory-safe") {
            if iszero(shr(128, marked)) {
                j := 16
                marked := shl(128, marked)
            }
            if iszero(shr(192, marked)) {
                j := add(j, 8)
                marked := shl(64, marked)
            }
            if iszero(shr(224, marked)) {
                j := add(j, 4)
                marked := shl(32, marked)
            }
            if iszero(shr(240, marked)) {
                j := add(j, 2)
                marked := shl(16, marked)
            }
            if iszero(shr(248, marked)) { j := add(j, 1) }
        }
    }

    /// @dev `data[from:to]`, copied.
    function _slice(bytes memory data, uint256 from, uint256 to) private pure returns (bytes memory out) {
        // In bounds, so the copy reads only bytes `data` holds.
        assert(from <= to && to <= data.length);
        out = new bytes(to - from);
        assembly ("memory-safe") {
            mcopy(add(out, 0x20), add(add(data, 0x20), from), sub(to, from))
        }
    }

    /// @dev keccak256 of `data[from:to]`, read in place.
    function _hash(bytes memory data, uint256 from, uint256 to) private pure returns (bytes32 hash) {
        // In bounds, so the hash reads only bytes `data` holds.
        assert(from <= to && to <= data.length);
        assembly ("memory-safe") {
            hash := keccak256(add(add(data, 0x20), from), sub(to, from))
        }
    }

    /// @notice Whether every byte lies in the serializer's byte-identical ASCII
    ///         subset, `[A-Za-z0-9*._-]`.
    ///
    /// @dev REQ-COMMON-16B. The WHATWG form serializer passes exactly this set
    ///      through unchanged and percent-encodes everything else, so bytes
    ///      outside it are the SERIALIZATION rather than the identifier.
    ///      Returning those would hand a Consumer `my%2Bapp` where the client is
    ///      `my+app`.
    function isSerializerSafe(bytes memory value) internal pure returns (bool) {
        if (value.length == 0) return false;
        for (uint256 i = 0; i < value.length; i += 32) {
            uint256 escaped = serializerUnsafeBytes(_word(value, i));
            if (i + 32 > value.length) escaped &= _leading(value.length - i);
            if (escaped != 0) return false;
        }
        return true;
    }
}
