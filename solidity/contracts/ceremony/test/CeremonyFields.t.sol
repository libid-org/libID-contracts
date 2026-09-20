// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {CeremonyFields} from "../CeremonyFields.sol";

contract CeremonyFieldsTest is Test {
    /// @dev The verifiers read through the `try*` readers and map every
    ///      non-`One` outcome themselves; these wrappers give the tests the
    ///      same one-result-or-revert shape over the same readers.
    error Refused(CeremonyFields.Found found, string name);

    function jsonString(bytes calldata d, string calldata n) external pure returns (bytes memory) {
        (CeremonyFields.Found found, bytes memory v) = CeremonyFields.tryJsonString(d, n);
        if (found == CeremonyFields.Found.None) revert CeremonyFields.FieldNotFound(n);
        if (found == CeremonyFields.Found.Several) revert CeremonyFields.AmbiguousField(n);
        if (found != CeremonyFields.Found.One) revert Refused(found, n);
        return v;
    }

    function jsonInteger(bytes calldata d, string calldata n) external pure returns (bytes memory) {
        (CeremonyFields.Found found, bytes memory v) = CeremonyFields.tryJsonInteger(d, n);
        if (found == CeremonyFields.Found.None) revert CeremonyFields.FieldNotFound(n);
        if (found == CeremonyFields.Found.Several) revert CeremonyFields.AmbiguousField(n);
        if (found != CeremonyFields.Found.One) revert Refused(found, n);
        return v;
    }

    function formField(bytes calldata d, string calldata n) external pure returns (bytes memory) {
        return CeremonyFields.formField(d, n);
    }

    function requireExactForm(bytes calldata body, bytes calldata names) external pure {
        CeremonyFields.requireExactForm(body, names);
    }

    // ─── JSON strings ───────────────────────────────────────────────

    function test_readsAnXIdentityResponse() public view {
        bytes memory body = bytes('{"data":{"id":"2244994945","username":"alice"}}');
        assertEq(string(this.jsonString(body, "id")), "2244994945");
        assertEq(string(this.jsonString(body, "username")), "alice");
    }

    /// @dev A display name carrying a lookalike field does NOT match, and the
    ///      reason is ASM-PROV-06 rather than anything this library does: the
    ///      platform returns well-formed JSON, so a quote inside a string value
    ///      is escaped, and `\\"username\\":\\"` is not the unescaped delimiter
    ///      `"username":"`. The real field still reads. Pinned because the
    ///      whole template approach rests on it.
    function test_anEscapedLookalikeIsNotAMatch() public view {
        bytes memory body = bytes('{"name":"hi \\"username\\":\\"victim\\" ok","username":"alice"}');
        assertEq(string(this.jsonString(body, "username")), "alice");
    }

    /// @dev The case REQ-COMMON-19A actually closes: the same field name at two
    ///      nesting levels, both unescaped. Reading the first would let an
    ///      envelope answer for the payload; reading the last would too.
    ///      Refusing to answer is what closes it.
    function test_refusesAFieldThatAppearsTwice() public {
        bytes memory body = bytes('{"data":{"username":"alice"},"includes":{"username":"attacker"}}');
        vm.expectRevert(abi.encodeWithSelector(CeremonyFields.AmbiguousField.selector, "username"));
        this.jsonString(body, "username");
    }

    function test_refusesAMissingField() public {
        vm.expectRevert(abi.encodeWithSelector(CeremonyFields.FieldNotFound.selector, "username"));
        this.jsonString(bytes('{"id":"7"}'), "username");
    }

    function test_refusesAValueWithNoClosingQuote() public {
        vm.expectRevert(abi.encodeWithSelector(Refused.selector, CeremonyFields.Found.Unterminated, "username"));
        this.jsonString(bytes('{"username":"alice'), "username");
    }

    /// @dev The full delimiter includes the opening quote of the value, so a
    ///      numeric `id` is simply not a match for the string template.
    function test_aBareIntegerIsNotAStringField() public {
        vm.expectRevert(abi.encodeWithSelector(CeremonyFields.FieldNotFound.selector, "id"));
        this.jsonString(bytes('{"id":7}'), "id");
    }

    function test_readsAnEmptyValue() public view {
        assertEq(this.jsonString(bytes('{"username":""}'), "username").length, 0);
    }

    // ─── JSON integers ──────────────────────────────────────────────

    /// @dev GitHub's `/user.id` is a bare integer, and the terminator is what
    ///      proves the revealed digits are the whole number rather than a
    ///      prefix of a longer one.
    function test_readsAGitHubIdWithEitherTerminator() public view {
        assertEq(string(this.jsonInteger(bytes('{"id":1,"login":"octocat"}'), "id")), "1");
        assertEq(string(this.jsonInteger(bytes('{"login":"octocat","id":583231}'), "id")), "583231");
    }

    function test_refusesAnyOtherTerminator() public {
        // A space would let `123 456` read as `123`. Casting the literal to
        // bytes1 is safe: one longer than a byte would not compile.
        // forge-lint: disable-next-line(unsafe-typecast)
        vm.expectRevert(abi.encodeWithSelector(CeremonyFields.BadIntegerTerminator.selector, "id", bytes1(" ")));
        this.jsonInteger(bytes('{"id":123 456}'), "id");
    }

    function test_refusesANoncanonicalInteger() public {
        vm.expectRevert(abi.encodeWithSelector(CeremonyFields.NoncanonicalInteger.selector, "id"));
        this.jsonInteger(bytes('{"id":007,"a":1}'), "id");

        // `-1`, `1.5` and `1e3` all fail: the first byte is not a digit, or the
        // terminator is not `,`/`}`.
        vm.expectRevert(abi.encodeWithSelector(CeremonyFields.NoncanonicalInteger.selector, "id"));
        this.jsonInteger(bytes('{"id":-1}'), "id");
        // Casting to bytes1 is safe, as above.
        // forge-lint: disable-next-line(unsafe-typecast)
        vm.expectRevert(abi.encodeWithSelector(CeremonyFields.BadIntegerTerminator.selector, "id", bytes1(".")));
        this.jsonInteger(bytes('{"id":1.5}'), "id");
    }

    function test_zeroIsCanonical() public view {
        assertEq(string(this.jsonInteger(bytes('{"id":0}'), "id")), "0");
    }

    function test_refusesAQuotedIntegerForTheIntegerTemplate() public {
        // `"id":"1"` — the digits scan finds none after the delimiter.
        vm.expectRevert(abi.encodeWithSelector(CeremonyFields.NoncanonicalInteger.selector, "id"));
        this.jsonInteger(bytes('{"id":"1"}'), "id");
    }

    // ─── Form fields ────────────────────────────────────────────────

    function test_readsAnXTokenRequestBody() public view {
        bytes memory body = bytes(
            "grant_type=authorization_code&client_id=abc123&code=xyz&redirect_uri=https%3A%2F%2Fa.example&code_verifier=5teBDl6cz4U77aFweV5PbMhBJ_lEFv6LLNKzqnDI5lo"
        );
        assertEq(string(this.formField(body, "grant_type")), "authorization_code");
        assertEq(string(this.formField(body, "client_id")), "abc123");
        assertEq(string(this.formField(body, "code_verifier")), "5teBDl6cz4U77aFweV5PbMhBJ_lEFv6LLNKzqnDI5lo");
    }

    /// @dev Without the leading boundary, `client_id=` matches inside
    ///      `evil_client_id=` and the attacker's value answers.
    function test_aFieldNameMustStartAtABoundary() public view {
        bytes memory body = bytes("evil_client_id=attacker&client_id=real");
        assertEq(string(this.formField(body, "client_id")), "real");
    }

    /// @dev The duplicate-field case ASM-PROV-07 leaves open in HIDDEN ranges is
    ///      closed here for revealed ones: two `code_verifier` fields make the
    ///      read ambiguous rather than letting the first or last answer.
    function test_refusesADuplicateFormField() public {
        bytes memory body = bytes("code_verifier=GOOD&code_verifier=EVIL");
        vm.expectRevert(abi.encodeWithSelector(CeremonyFields.AmbiguousField.selector, "code_verifier"));
        this.formField(body, "code_verifier");
    }

    function test_readsTheFirstAndLastFieldOfABody() public view {
        bytes memory body = bytes("a=1&b=2&c=3");
        assertEq(string(this.formField(body, "a")), "1");
        assertEq(string(this.formField(body, "c")), "3");
    }

    // ─── The exact form (REQ-PLAT-61) ───────────────────────────────

    bytes constant ABC = "a&b&c";

    /// @dev The serialization of exactly the listed fields, in order, each
    ///      once with a nonempty value, passes -- for three fields, for one,
    ///      and for a value spelled with every token the serializer emits.
    function test_acceptsTheExactForm() public view {
        this.requireExactForm("a=1&b=2&c=3", ABC);
        this.requireExactForm("a=1", "a");
        this.requireExactForm("a=AZaz09*._-+%2F%26%3D%00%FF", "a");
    }

    /// @dev The same fields in another order are another body. The first
    ///      pair is not `a=`, so it fails at byte 0.
    function test_refusesThePairsOutOfOrder() public {
        vm.expectRevert(abi.encodeWithSelector(CeremonyFields.MalformedForm.selector, 0));
        this.requireExactForm("b=2&a=1&c=3", ABC);
    }

    /// @dev A name is matched literally, so its encoded spelling is not it.
    ///      To a form parser `%62=2` is `b=2`; here the pair at byte 4 is
    ///      simply not `b=`, which is what keeps an encoded duplicate out.
    function test_refusesANameInAnotherSpelling() public {
        vm.expectRevert(abi.encodeWithSelector(CeremonyFields.MalformedForm.selector, 4));
        this.requireExactForm("a=1&%62=2&c=3", ABC);
    }

    function test_refusesADuplicatePair() public {
        vm.expectRevert(abi.encodeWithSelector(CeremonyFields.MalformedForm.selector, 4));
        this.requireExactForm("a=1&a=1&b=2&c=3", ABC);
    }

    /// @dev The body ends where the `&` before the next pair should stand.
    function test_refusesAMissingPair() public {
        vm.expectRevert(abi.encodeWithSelector(CeremonyFields.MalformedForm.selector, 7));
        this.requireExactForm("a=1&b=2", ABC);
    }

    /// @dev And a `&` stands where the body should end.
    function test_refusesAnExtraPair() public {
        vm.expectRevert(abi.encodeWithSelector(CeremonyFields.MalformedForm.selector, 11));
        this.requireExactForm("a=1&b=2&c=3&d=4", ABC);
    }

    function test_refusesATrailingAmpersand() public {
        vm.expectRevert(abi.encodeWithSelector(CeremonyFields.MalformedForm.selector, 11));
        this.requireExactForm("a=1&b=2&c=3&", ABC);
    }

    function test_refusesAnEmptyValue() public {
        vm.expectRevert(abi.encodeWithSelector(CeremonyFields.EmptyFormValue.selector, "a"));
        this.requireExactForm("a=&b=2&c=3", ABC);
        vm.expectRevert(abi.encodeWithSelector(CeremonyFields.EmptyFormValue.selector, "c"));
        this.requireExactForm("a=1&b=2&c=", ABC);
    }

    function test_refusesAnEmptyBody() public {
        vm.expectRevert(abi.encodeWithSelector(CeremonyFields.MalformedForm.selector, 0));
        this.requireExactForm("", ABC);
    }

    /// @dev A value byte the serializer would have escaped. `;` and `=` are
    ///      the two some parsers read as structure, and a space is the byte
    ///      the serializer spells `+`; none of them is a value byte here.
    function test_refusesADelimiterInsideAValue() public {
        vm.expectRevert(abi.encodeWithSelector(CeremonyFields.MalformedForm.selector, 3));
        this.requireExactForm("a=1;x=9&b=2&c=3", ABC);
        vm.expectRevert(abi.encodeWithSelector(CeremonyFields.MalformedForm.selector, 3));
        this.requireExactForm("a=1=9&b=2&c=3", ABC);
        vm.expectRevert(abi.encodeWithSelector(CeremonyFields.MalformedForm.selector, 3));
        this.requireExactForm("a=1 2&b=2&c=3", ABC);
        vm.expectRevert(abi.encodeWithSelector(CeremonyFields.MalformedForm.selector, 2));
        this.requireExactForm(bytes.concat(bytes("a="), hex"c3a9"), "a");
    }

    /// @dev An escape is `%` and two UPPERCASE hex digits. Lowercase decodes
    ///      the same and is a second spelling; one digit, or none, is no
    ///      escape. Each is refused at the `%`.
    function test_refusesAnEscapeTheSerializerWouldNotWrite() public {
        vm.expectRevert(abi.encodeWithSelector(CeremonyFields.MalformedForm.selector, 2));
        this.requireExactForm("a=%2f&b=2&c=3", ABC);
        vm.expectRevert(abi.encodeWithSelector(CeremonyFields.MalformedForm.selector, 2));
        this.requireExactForm("a=%2&b=2&c=3", ABC);
        vm.expectRevert(abi.encodeWithSelector(CeremonyFields.MalformedForm.selector, 3));
        this.requireExactForm("a=1%", "a");
        vm.expectRevert(abi.encodeWithSelector(CeremonyFields.MalformedForm.selector, 3));
        this.requireExactForm("a=1%2", "a");
    }

    /// @dev An escape of a byte the serializer never escapes is a second
    ///      spelling too: `%61` decodes to the `a` the serializer writes bare,
    ///      `%20` to the space it writes `+`. One vector per pass-through
    ///      class -- a letter, a digit, each of `*._-` -- and the space.
    function test_refusesAnEscapeOfAByteTheSerializerWritesBare() public {
        bytes[7] memory escapes = [bytes("%61"), "%30", "%2A", "%2E", "%5F", "%2D", "%20"];
        for (uint256 i = 0; i < escapes.length; ++i) {
            vm.expectRevert(abi.encodeWithSelector(CeremonyFields.MalformedForm.selector, 3));
            this.requireExactForm(abi.encodePacked("a=1", escapes[i], "&b=2&c=3"), ABC);
        }
    }

    // ─── The client-identifier charset ──────────────────────────────

    /// @dev REQ-COMMON-16B. Real identifiers fit: GitHub's `Iv1.` prefix needs
    ///      the dot, X's are base64url-ish.
    function test_acceptsRealClientIdentifiers() public pure {
        assertTrue(CeremonyFields.isSerializerSafe(bytes("Iv1.8a61f9b3a7aba766")));
        assertTrue(CeremonyFields.isSerializerSafe(bytes("Ov23liABCDEfghij")));
        assertTrue(CeremonyFields.isSerializerSafe(bytes("a-b_c.d*e")));
    }

    /// @dev Anything outside the set means the revealed bytes are the
    ///      SERIALIZATION, not the identifier -- returning them would hand a
    ///      Consumer `my%2Bapp` where the client is `my+app`.
    function test_refusesPercentEncodedAndDelimiterBytes() public pure {
        assertFalse(CeremonyFields.isSerializerSafe(bytes("my%2Bapp")));
        assertFalse(CeremonyFields.isSerializerSafe(bytes("my+app")));
        assertFalse(CeremonyFields.isSerializerSafe(bytes("a&b")));
        assertFalse(CeremonyFields.isSerializerSafe(bytes("a=b")));
        assertFalse(CeremonyFields.isSerializerSafe(bytes("")));
        assertFalse(CeremonyFields.isSerializerSafe(hex"c3a9")); // non-ASCII
    }

    // ─── JSON whitespace ────────────────────────────────────────────

    /// @dev JSON whitespace between tokens is not part of any token. The
    ///      readers remove it before they look, so a pretty-printed member
    ///      reads as its compact spelling does.
    function test_readsMembersThroughJsonWhitespace() public view {
        bytes memory body = bytes('{\n  "login" \t: "alice",\r\n  "id" : 123 \n}');
        assertEq(string(this.jsonString(body, "login")), "alice");
        assertEq(string(this.jsonInteger(body, "id")), "123");
    }

    /// @dev And a duplicate in another spelling is still a duplicate, for a
    ///      string and for an integer alike.
    function test_countsADuplicateInAnotherWhitespaceSpelling() public {
        vm.expectRevert(abi.encodeWithSelector(CeremonyFields.AmbiguousField.selector, "login"));
        this.jsonString(bytes('{"login":"alice","login" : "bob"}'), "login");
        vm.expectRevert(abi.encodeWithSelector(CeremonyFields.AmbiguousField.selector, "id"));
        this.jsonInteger(bytes('{"id":123,"id" : 456}'), "id");
    }

    /// @dev Only the four bytes JSON calls whitespace are removed. A vertical
    ///      tab is not one of them, and a member spelled with it is no member.
    function test_removesOnlyJsonWhitespace() public {
        vm.expectRevert(abi.encodeWithSelector(CeremonyFields.FieldNotFound.selector, "login"));
        this.jsonString(bytes.concat(bytes('{"login":'), hex"0b", bytes('"alice"}')), "login");
    }

    /// @dev Whitespace before a brace is JSON's and goes; whitespace between
    ///      two runs of digits touches no structural byte, stays, and is the
    ///      terminator the reader then refuses. `123 4` does not read as
    ///      `1234`.
    function test_stillRefusesDigitsAfterWhitespace() public {
        assertEq(string(this.jsonInteger(bytes('{"id":123 }'), "id")), "123");
        vm.expectRevert(abi.encodeWithSelector(CeremonyFields.BadIntegerTerminator.selector, "id", bytes1(0x20)));
        this.jsonInteger(bytes('{"id":123 4}'), "id");
    }
}
