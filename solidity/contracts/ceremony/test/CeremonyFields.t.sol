// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {CeremonyFields} from "../CeremonyFields.sol";

contract CeremonyFieldsTest is Test {
    function valueOf(bytes calldata body, bytes calldata names, string calldata n)
        external
        pure
        returns (bytes memory)
    {
        return CeremonyFields.valueOf(CeremonyFields.requireExactForm(body, names), n);
    }

    function requireExactForm(bytes calldata body, bytes calldata names) external pure {
        CeremonyFields.requireExactForm(body, names);
    }

    // ─── Form fields ────────────────────────────────────────────────

    function test_readsAnXTokenRequestBody() public view {
        bytes memory body = bytes(
            "grant_type=authorization_code&client_id=abc123&code=xyz&redirect_uri=https%3A%2F%2Fa.example&code_verifier=5teBDl6cz4U77aFweV5PbMhBJ_lEFv6LLNKzqnDI5lo"
        );
        bytes memory names = "grant_type&client_id&code&redirect_uri&code_verifier";
        assertEq(string(this.valueOf(body, names, "grant_type")), "authorization_code");
        assertEq(string(this.valueOf(body, names, "client_id")), "abc123");
        assertEq(string(this.valueOf(body, names, "code_verifier")), "5teBDl6cz4U77aFweV5PbMhBJ_lEFv6LLNKzqnDI5lo");
    }

    /// @dev A name is matched whole at its own pair, never as the tail of a
    ///      longer one: `client_id` does not answer from `evil_client_id=`.
    function test_aFieldNameMustStartAtABoundary() public view {
        bytes memory body = bytes("evil_client_id=attacker&client_id=real");
        assertEq(string(this.valueOf(body, "evil_client_id&client_id", "client_id")), "real");
    }

    function test_readsTheFirstAndLastFieldOfABody() public view {
        bytes memory body = bytes("a=1&b=2&c=3");
        assertEq(string(this.valueOf(body, ABC, "a")), "1");
        assertEq(string(this.valueOf(body, ABC, "c")), "3");
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

    // ─── JSON whitespace ───────────────────────────────────────────

    function normalizeJsonBytes(bytes calldata d) external pure returns (bytes memory) {
        return CeremonyFields.normalizeJsonBytes(d);
    }

    /// @dev JSON whitespace touching a structural byte is not part of any
    ///      token and goes, so a pretty-printed member reads as its compact
    ///      spelling does.
    function test_removesWhitespaceTouchingAStructuralByte() public view {
        bytes memory body = bytes('{\n  "login" \t: "alice",\r\n  "id" : 123 \n}');
        assertEq(this.normalizeJsonBytes(body), bytes('{"login":"alice","id":123}'));
    }

    /// @dev And a duplicate in another spelling is still a duplicate: the
    ///      count the framing checks run sees two.
    function test_countsADuplicateInAnotherWhitespaceSpelling() public view {
        bytes memory body = this.normalizeJsonBytes(bytes('{"login":"alice","login" : "bob"}'));
        assertEq(CeremonyFields.occurrences(body, bytes('"login":"')), 2);
        body = this.normalizeJsonBytes(bytes('{"id":123,"id" : 456}'));
        assertEq(CeremonyFields.occurrences(body, bytes('"id":')), 2);
    }

    /// @dev Only the four bytes JSON calls whitespace are removed. A vertical
    ///      tab is not one of them, and a member spelled with it stays
    ///      spelled with it.
    function test_removesOnlyJsonWhitespace() public view {
        bytes memory body = bytes.concat(bytes('{"login":'), hex"0b", bytes('"alice"}'));
        assertEq(this.normalizeJsonBytes(body), body);
        assertEq(CeremonyFields.occurrences(this.normalizeJsonBytes(body), bytes('"login":"')), 0);
    }

    /// @dev Whitespace before a brace is JSON's and goes; whitespace between
    ///      two runs of digits touches no structural byte and stays. `123 4`
    ///      does not read as `1234`.
    function test_keepsWhitespaceBetweenTwoTokens() public view {
        assertEq(this.normalizeJsonBytes(bytes('{"id":123 }')), bytes('{"id":123}'));
        assertEq(this.normalizeJsonBytes(bytes('{"id":123 4}')), bytes('{"id":123 4}'));
        assertEq(this.normalizeJsonBytes(bytes(" 1 ")), bytes(" 1 "));
    }
}
