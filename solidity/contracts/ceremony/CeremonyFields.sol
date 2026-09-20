// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title CeremonyFields
/// @notice Reading one field out of the revealed bytes of an attestation, and
///         holding a form body to exactly the fields it should carry.
///
/// @dev Nothing here parses a document. ceremony-common section 9 says so
///      plainly: no complete HTTP request grammar, no complete HTTP response
///      grammar, no complete JSON grammar is proved or parsed anywhere in the
///      protocol. A JSON field is matched by its exact delimiter template, a
///      form field by its own boundary template, and that is all.
///
///      What makes a template safe to trust is REQ-COMMON-19A: the Platform
///      Verifier must reject a transcript in which a field's full delimiter
///      matches at more than one position. An authenticated response carries
///      text the account holder chooses -- a display name, a bio -- and that
///      text can embed a lookalike field. Reading the first match would let it
///      answer for the real one; reading the last would too. Refusing to answer
///      at all is what closes it.
library CeremonyFields {
    /// @dev The delimiter appears more than once, so no reading of it is
    ///      authoritative (REQ-COMMON-19A).
    error AmbiguousField(string name);
    error FieldNotFound(string name);
    /// @dev A GitHub `id` must be followed by `,` or `}` and no other byte: the
    ///      terminator is what proves the revealed digits are the whole number
    ///      rather than a prefix of a longer one (REQ-PLAT-51).
    error BadIntegerTerminator(string name, bytes1 found);
    /// @dev Leading zeros, a sign, a fraction, an exponent, or no digits at all.
    error NoncanonicalInteger(string name);
    /// @dev The body stops being the exact form at byte `at`: the pair that
    ///      begins there is not the name expected next, a value byte is outside
    ///      the serializer's alphabet or an escape is not two uppercase hex
    ///      digits, a `&` stands where the body should end or the body ends
    ///      where a `&` should stand (REQ-PLAT-61).
    error MalformedForm(uint256 at);
    /// @dev A field the form must carry once carries nothing.
    error EmptyFormValue(string name);

    /// @notice What a field lookup found in one range.
    enum Found {
        None,
        One,
        Several,
        /// The delimiter is here, but the value has no end inside this range.
        /// A caller scanning range by range treats it as `None` -- a value
        /// with no established extent is one it must not read, and splicing
        /// the rest out of a neighbouring range is what these reads forbid.
        Unterminated
    }

    /// @notice `jsonString`, reporting instead of reverting.
    ///
    /// @dev A caller searching several revealed ranges needs to distinguish
    ///      "not in this range" from "malformed", because a field legitimately
    ///      lives in exactly one of them.
    function tryJsonString(bytes memory data, string memory name)
        internal
        pure
        returns (Found found, bytes memory value)
    {
        data = normalizeJsonBytes(data);
        bytes memory needle = abi.encodePacked('"', name, '":"');
        uint256 at;
        (found, at) = _findUnique(data, needle);
        if (found != Found.One) return (found, "");

        at += needle.length;
        uint256 end = at;
        while (end < data.length && data[end] != '"') {
            ++end;
        }
        // A value with no closing quote inside THIS range has no established
        // extent, and splicing the rest from a neighbouring range is exactly
        // what these reads must not do.
        if (end == data.length) return (Found.Unterminated, "");

        value = new bytes(end - at);
        for (uint256 i = 0; i < value.length; ++i) {
            value[i] = data[at + i];
        }
        return (Found.One, value);
    }

    /// @notice `jsonInteger`, reporting ABSENCE and still refusing malformation.
    ///
    /// @dev Not symmetric with [`tryJsonString`], deliberately. Absence is
    ///      reported, because a field lives in exactly one revealed range and
    ///      the others must be able to say "not here". A malformed match still
    ///      reverts, because the needle `"id":` is the full delimiter -- it
    ///      cannot match inside a neighbouring member such as `"node_id":"`,
    ///      whose `i` is preceded by `_` rather than a quote -- so a second
    ///      occurrence is a duplicate delimiter, which REQ-COMMON-19A wants
    ///      rejected rather than skipped past to whichever copy parses.
    function tryJsonInteger(bytes memory data, string memory name)
        internal
        pure
        returns (Found found, bytes memory digits)
    {
        data = normalizeJsonBytes(data);
        bytes memory needle = abi.encodePacked('"', name, '":');
        uint256 at;
        (found, at) = _findUnique(data, needle);
        if (found != Found.One) return (found, "");

        at += needle.length;
        uint256 end = at;
        while (end < data.length && data[end] >= "0" && data[end] <= "9") {
            ++end;
        }
        if (end == at) revert NoncanonicalInteger(name);
        if (end - at > 1 && data[at] == "0") revert NoncanonicalInteger(name);
        if (end == data.length) return (Found.None, "");
        if (data[end] != "," && data[end] != "}") revert BadIntegerTerminator(name, data[end]);

        digits = new bytes(end - at);
        for (uint256 i = 0; i < digits.length; ++i) {
            digits[i] = data[at + i];
        }
        return (Found.One, digits);
    }

    /// @notice `data` with the JSON whitespace that touches a structural
    ///         byte removed.
    ///
    /// @dev The four bytes JSON lets a writer put between tokens (RFC 8259
    ///      section 2): space, tab, line feed, carriage return. GitHub
    ///      pretty-prints `/user` for the media type the profile pins, so the
    ///      compact delimiters the readers above match are a grammar, not the
    ///      bytes on the wire. Removing the whitespace first, the way
    ///      `CeremonyAttestation.normalizeHeaderBytes` does for a request head,
    ///      leaves every reader its one exact template and makes a member in
    ///      any spelling the same member -- so a duplicate spelled with spaces
    ///      is still counted as one.
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

    function _findUnique(bytes memory data, bytes memory needle) private pure returns (Found found, uint256 at) {
        uint256 hit = type(uint256).max;
        for (uint256 i = 0; i + needle.length <= data.length; ++i) {
            if (!_matchesAt(data, needle, i)) continue;
            if (hit != type(uint256).max) return (Found.Several, 0);
            hit = i;
        }
        if (hit == type(uint256).max) return (Found.None, 0);
        return (Found.One, hit);
    }

    /// @notice The value of `name=value` in an `application/x-www-form-urlencoded`
    ///         body.
    ///
    /// @dev The match must begin at byte zero or immediately after `&`, and the
    ///      value must end at `&` or the end of the revealed bytes. Without the
    ///      leading boundary, `client_id=` would also match inside
    ///      `evil_client_id=`.
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

    /// @notice `body` is the WHATWG form serialization of exactly the fields
    ///         `names` lists, `&`-joined, in that order, each once with a
    ///         nonempty value -- and nothing else.
    ///
    /// @dev REQ-PLAT-61. `formField` answers "what is `code_verifier` here" and
    ///      cannot answer "what else is here": it matches a literal name, so an
    ///      encoded spelling (`code%5Fverifier=`) is invisible to it, and it
    ///      reads a value to the next `&`, so a raw `;` or `=` inside one is a
    ///      pair to some parsers and a value to this one. A verifier that
    ///      accepts a body on `formField` alone therefore rests on the platform
    ///      refusing what it did not count (ASM-PROV-07). This is the check
    ///      that removes the assumption: one cursor walks the body once, and
    ///      every byte of it is accounted for -- a literal name, `=`, a value
    ///      in the serializer's output alphabet, `&` between pairs, the end
    ///      of the body after the last. A sixth pair, a duplicate, a reordering,
    ///      a name in another spelling and a delimiter smuggled into a value
    ///      all put a byte where the grammar allows no such byte.
    ///
    ///      The alphabet is the serializer's OUTPUT, not the input's: the bytes
    ///      it passes through (`[A-Za-z0-9*._-]`), `+` for a space, and `%`
    ///      followed by two UPPERCASE hex digits for everything else. An
    ///      escape in lowercase decodes the same and serializes differently,
    ///      so it is a second spelling and refused; a truncated one is not an
    ///      escape at all. Values are validated, never decoded: the bytes GitHub
    ///      parsed are the bytes judged, and an encoded delimiter stays one
    ///      value's byte (`%26`) rather than becoming a pair.
    function requireExactForm(bytes memory body, bytes memory names) internal pure {
        uint256 at;
        uint256 from;
        while (true) {
            uint256 to = from;
            while (to < names.length && names[to] != "&") {
                ++to;
            }

            // The pair begins with the literal name and `=`, or it is not the
            // pair expected here: a reordering, a duplicate, another spelling.
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

            // After the last value the body ends. After any other, exactly one
            // `&` and the next pair.
            if (to == names.length) {
                if (at != body.length) revert MalformedForm(at);
                return;
            }
            if (at >= body.length) revert MalformedForm(at);
            ++at;
            from = to + 1;
        }
    }

    /// @dev One token of a form value at `at` -- a pass-through byte, a `+`,
    ///      or a `%XX` escape in uppercase -- and the offset after it.
    function _formValueToken(bytes memory body, uint256 at) private pure returns (uint256) {
        bytes1 c = body[at];
        if (c == "%") {
            if (at + 2 >= body.length || !_isUpperHex(body[at + 1]) || !_isUpperHex(body[at + 2])) {
                revert MalformedForm(at);
            }
            return at + 3;
        }
        if (c == "+" || _isSerializerSafe(c)) return at + 1;
        revert MalformedForm(at);
    }

    function _isUpperHex(bytes1 c) private pure returns (bool) {
        return (c >= "0" && c <= "9") || (c >= "A" && c <= "F");
    }

    function _slice(bytes memory data, uint256 from, uint256 to) private pure returns (bytes memory out) {
        out = new bytes(to - from);
        for (uint256 i = 0; i < out.length; ++i) {
            out[i] = data[from + i];
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
