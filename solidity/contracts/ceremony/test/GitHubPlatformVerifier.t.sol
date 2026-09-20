// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

import {AttestationBuilder} from "./AttestationBuilder.sol";
import {CeremonyAttestation} from "../CeremonyAttestation.sol";
import {CeremonyAuthorization} from "../CeremonyAuthorization.sol";
import {CeremonyFields} from "../CeremonyFields.sol";
import {CeremonyProfile} from "../CeremonyProfile.sol";
import {GitHubPlatformVerifier} from "../GitHubPlatformVerifier.sol";
import {ICeremony} from "../ICeremony.sol";
import {INotaryService} from "../INotaryService.sol";
import {NotaryService} from "../NotaryService.sol";
import {IHonkVerifier, PlatformVerifierBase} from "../PlatformVerifierBase.sol";
import {TlsNotaryVerifierBase} from "../TlsNotaryVerifierBase.sol";

contract Honk is IHonkVerifier {
    function verify(bytes calldata, bytes32[] calldata) external pure returns (bool) {
        return true;
    }
}

/// @notice The `github/v1` path. The shared flow is covered by the X suite, so
///         this exercises what actually differs: two authorities, a bare-integer
///         id, the `login` field, a revealed body credential, and the exact
///         five-field form the body is held to.
contract GitHubPlatformVerifierTest is Test {
    GitHubPlatformVerifier verifier;
    NotaryService notary;
    uint256 quote;

    address constant OWNER = address(0xA11CE);
    uint256 constant NOTARY_KEY = 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80;
    uint256 constant FEE = 0.001 ether;
    uint64 constant LIFETIME = 3600;
    uint64 constant SKEW = 300;
    uint64 constant T0 = 1_770_000_000;

    bytes32 constant DOMAIN = keccak256(bytes("libid.claim-identity"));
    bytes32 constant AUTH_NONCE = bytes32(uint256(0x5555555555555555555555555555555555555555555555555555555555555555));
    /// The digest the fixtures are made for, derived in `setUp` from the
    /// payload below and this chain.
    bytes32 digest;
    bytes32 constant TOKEN_COMMITMENT = bytes32(uint256(0x1111));
    bytes32 constant IDENTITY_COMMITMENT = bytes32(uint256(0x2222));

    function setUp() public {
        digest = CeremonyAuthorization.digestFor(DOMAIN, 1, AUTH_NONCE, _txData());
        vm.warp(T0 + 10);
        NotaryService nImpl = new NotaryService();
        notary = NotaryService(
            address(
                new ERC1967Proxy(
                    address(nImpl), abi.encodeCall(NotaryService.initialize, (OWNER, vm.addr(NOTARY_KEY), FEE))
                )
            )
        );
        address honkAddr = address(new Honk());
        GitHubPlatformVerifier vImpl = new GitHubPlatformVerifier();
        verifier = GitHubPlatformVerifier(
            address(
                new ERC1967Proxy(
                    address(vImpl),
                    abi.encodeCall(
                        GitHubPlatformVerifier.initialize,
                        (
                            OWNER,
                            INotaryService(address(notary)),
                            IHonkVerifier(honkAddr),
                            honkAddr.codehash,
                            LIFETIME,
                            SKEW,
                            SKEW
                        )
                    )
                )
            )
        );
        quote = verifier.quote();
        vm.deal(address(this), 100 ether);
    }

    function _sign(bytes memory a) private pure returns (bytes memory) {
        bytes32 h = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", keccak256(a)));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(NOTARY_KEY, h);
        return abi.encodePacked(r, s, v);
    }

    /// The head the browser sends on the exchange: the two headers the profile
    /// requires, and two it does not compare.
    bytes constant EXCHANGE_HEADERS =
        "host: github.com\r\ncontent-type: application/x-www-form-urlencoded\r\naccept: application/json\r\nconnection: close\r\n";

    /// The exchange request's head, declaring a body of `bodyLength` bytes.
    /// Assembled from its parts so a test can change one header and watch the
    /// verifier refuse it.
    function _exchangeHead(uint256 bodyLength) private pure returns (bytes memory) {
        return _exchangeHead(EXCHANGE_HEADERS, bodyLength);
    }

    function _exchangeHead(bytes memory headers, uint256 bodyLength) private pure returns (bytes memory) {
        return abi.encodePacked(
            "POST /login/oauth/access_token HTTP/1.1\r\n",
            headers,
            "content-length: ",
            vm.toString(bodyLength),
            "\r\n\r\n"
        );
    }

    /// The exchange body: the five fields the profile lists, the credential
    /// among them and revealed like the rest.
    function _exchangeBody() private view returns (bytes memory) {
        return _exchangeBody("abc", "https%3A%2F%2Fa.example", "0123456789abcdef0123456789abcdef");
    }

    /// The same, with the three values a test changes given: the digest-bound
    /// verifier and the client identifier stay what the suite asserts on.
    function _exchangeBody(string memory code, string memory redirectUri, string memory clientSecret)
        private
        view
        returns (bytes memory)
    {
        return abi.encodePacked(
            "client_id=Iv1.8a61f9b3a7aba766&code=",
            code,
            "&redirect_uri=",
            redirectUri,
            "&code_verifier=",
            CeremonyAuthorization.codeVerifier(digest, AUTH_NONCE),
            "&client_secret=",
            clientSecret
        );
    }

    /// The same, with the verifier given: for the spellings of it the base
    /// must refuse.
    function _exchangeBodyWithVerifier(bytes memory verifier) private pure returns (bytes memory) {
        return abi.encodePacked(
            "client_id=Iv1.8a61f9b3a7aba766&code=abc&redirect_uri=https%3A%2F%2Fa.example&code_verifier=",
            verifier,
            "&client_secret=0123456789abcdef0123456789abcdef"
        );
    }

    /// One revealed run covering a request whole, with no commitment: the
    /// shape `github/v1` fixes for its exchange.
    function _wholeSent(bytes memory whole) private pure returns (AttestationBuilder.Direction memory) {
        return AttestationBuilder.Direction({
            revealed: AttestationBuilder.one(AttestationBuilder.Range({start: 0, value: whole})),
            commitments: AttestationBuilder.none(),
            length: uint32(whole.length)
        });
    }

    /// The exchange request as the profile fixes it: one revealed run over the
    /// request whole. The head boundary sits inside that run, so the body is
    /// located by the framing rather than by a range position.
    function _exchangeSent() private view returns (AttestationBuilder.Direction memory) {
        bytes memory body = _exchangeBody();
        return _wholeSent(abi.encodePacked(_exchangeHead(body.length), body));
    }

    /// The exchange response: the bearer committed and framed by the revealed
    /// `"access_token":"` anchor and its closing quote, every other byte hidden
    /// behind a commitment of its own.
    function _exchangeResponse() private pure returns (AttestationBuilder.Direction memory) {
        bytes memory status = "HTTP/1.1 200 OK";
        bytes memory anchor = '"access_token":"';
        uint32 statusEnd = uint32(status.length);
        uint32 headEnd = 17;
        uint32 anchorEnd = headEnd + uint32(anchor.length);
        uint32 bearerEnd = anchorEnd + 40;
        uint32 quoteEnd = bearerEnd + 1;
        uint32 total = quoteEnd + 20;

        return AttestationBuilder.Direction({
            revealed: AttestationBuilder.three(
                AttestationBuilder.Range({start: 0, value: status}),
                AttestationBuilder.Range({start: headEnd, value: anchor}),
                AttestationBuilder.Range({start: bearerEnd, value: '"'})
            ),
            commitments: AttestationBuilder.three(
                AttestationBuilder.Commitment({start: statusEnd, end: headEnd, value: bytes32(uint256(0x88))}),
                AttestationBuilder.Commitment({start: anchorEnd, end: bearerEnd, value: TOKEN_COMMITMENT}),
                AttestationBuilder.Commitment({start: quoteEnd, end: total, value: bytes32(uint256(0x99))})
            ),
            length: total
        });
    }

    function _exchange(bytes32 authority) private view returns (ICeremony.Attestation memory) {
        bytes memory attested = AttestationBuilder.encode(authority, T0, _exchangeSent(), _exchangeResponse());
        return ICeremony.Attestation({attestedData: attested, proof: _sign(attested)});
    }

    function _identity(string memory body, bytes32 authority) private pure returns (ICeremony.Attestation memory) {
        bytes memory head =
            "GET /user HTTP/1.1\r\naccept: application/vnd.github+json\r\nhost: api.github.com\r\n\r\nauthorization: Bearer ";
        bytes memory bearer = "gho_TOKENTOKENTOKEN";
        bytes memory tail = "\r\nconnection: close\r\n\r\n";
        uint32 start = uint32(head.length);
        uint32 end = start + uint32(bearer.length);
        uint32 sentLen = end + uint32(tail.length);

        AttestationBuilder.Direction memory sent = AttestationBuilder.Direction({
            revealed: AttestationBuilder.two(
                AttestationBuilder.Range({start: 0, value: head}), AttestationBuilder.Range({start: end, value: tail})
            ),
            commitments: AttestationBuilder.one(
                AttestationBuilder.Commitment({start: start, end: end, value: IDENTITY_COMMITMENT})
            ),
            length: sentLen
        });
        // The status line rides at the front, revealed with the rest, so the
        // verifier reads the server's agreement at offset zero.
        bytes memory b = abi.encodePacked("HTTP/1.1 200 OK\r\n\r\n", body);
        AttestationBuilder.Direction memory received = AttestationBuilder.Direction({
            revealed: AttestationBuilder.one(AttestationBuilder.Range({start: 0, value: b})),
            commitments: AttestationBuilder.none(),
            length: uint32(b.length)
        });
        bytes memory attested = AttestationBuilder.encode(authority, T0, sent, received);
        return ICeremony.Attestation({attestedData: attested, proof: _sign(attested)});
    }

    function _txData() private pure returns (bytes memory) {
        return abi.encode(address(0xBEEF));
    }

    /// The `github/v1` payload the fixtures are made for.
    function _payload() private view returns (TlsNotaryVerifierBase.TlsNotaryProof memory s) {
        s.ceremonyVersion = 1;
        s.operationDomain = DOMAIN;
        s.authorizationNonce = AUTH_NONCE;
        s.transactionData = _txData();
        s.proof = hex"00";
        s.tokenSession = _exchange(CeremonyProfile.AUTHORITY_GITHUB);
        s.identitySession = _identity('{"login":"octocat","id":583231}', CeremonyProfile.AUTHORITY_GITHUB_API);
    }

    function run(TlsNotaryVerifierBase.TlsNotaryProof memory s)
        external
        payable
        returns (ICeremony.VerifiedClaim memory)
    {
        return verifier.verify{value: msg.value}(abi.encode(s));
    }

    // ─── The happy path ─────────────────────────────────────────────

    function test_verifiesAWholeGitHubCeremony() public {
        ICeremony.VerifiedClaim memory f = this.run{value: quote}(_payload());
        assertEq(f.userId, "583231");
        assertEq(f.handle, "octocat");
        assertEq(string(f.clientIdentifier), "Iv1.8a61f9b3a7aba766");
        assertEq(f.sessionId, digest);
        assertEq(f.operationDomain, DOMAIN);
        assertEq(f.transactionData, _txData());
        assertEq(f.ceremonyVersion, 1);
        // On the shared scale, not raw. Profiles disagree about "now" -- this
        // one's evidence time is an attestation creation time, Google's is a
        // signed expiry an hour ahead -- so each verifier subtracts its own
        // allowance and a Consumer can compare the two.
        assertEq(f.metadataObservedAt, T0 - SKEW);
    }

    /// @dev The `Iv1.` prefix is why the serializer-safe set includes the dot.
    function test_acceptsAGitHubStyleClientIdentifier() public {
        ICeremony.VerifiedClaim memory f = this.run{value: quote}(_payload());
        assertTrue(CeremonyFields.isSerializerSafe(f.clientIdentifier));
    }

    // ─── The exact form (REQ-PLAT-61) ───────────────────────────────

    /// The payload with its exchange composed over `body`: the head declares
    /// the body's length and the response is the honest one, so the form
    /// check is what a test of it exercises.
    function _withExchangeBody(bytes memory body) private view returns (TlsNotaryVerifierBase.TlsNotaryProof memory) {
        return _withExchange(_exchangeHead(body.length), body);
    }

    /// The payload with its exchange composed over `head` and `body` as given,
    /// so a test can misdeclare the length or add a header and watch the
    /// verifier refuse it.
    function _withExchange(bytes memory head, bytes memory body)
        private
        view
        returns (TlsNotaryVerifierBase.TlsNotaryProof memory s)
    {
        s = _payload();
        AttestationBuilder.Direction memory sent = _wholeSent(abi.encodePacked(head, body));
        bytes memory a = AttestationBuilder.encode(CeremonyProfile.AUTHORITY_GITHUB, T0, sent, _exchangeResponse());
        s.tokenSession = ICeremony.Attestation({attestedData: a, proof: _sign(a)});
    }

    /// @dev REQ-PLAT-61, TEST-PLAT-12: the five fields in another order are
    ///      not the canonical serialization, whatever GitHub makes of them.
    ///      The first pair is not `client_id=`, so the body fails at byte 0.
    function test_rejectsAnExchangeWithItsFieldsReordered() public {
        bytes memory body = abi.encodePacked(
            "code=abc&client_id=Iv1.8a61f9b3a7aba766&redirect_uri=https%3A%2F%2Fa.example&code_verifier=",
            CeremonyAuthorization.codeVerifier(digest, AUTH_NONCE),
            "&client_secret=0123456789abcdef0123456789abcdef"
        );
        TlsNotaryVerifierBase.TlsNotaryProof memory s = _withExchangeBody(body);
        vm.expectRevert(abi.encodeWithSelector(CeremonyFields.MalformedForm.selector, 0));
        this.run{value: quote}(s);
    }

    /// @dev REQ-PLAT-61, TEST-PLAT-12: no `grant_type` is admitted. Under
    ///      `formField` alone it was merely uncompared; held to the exact form
    ///      it is a sixth pair, refused at the `&` that begins it.
    function test_rejectsAnExchangeCarryingAGrantType() public {
        bytes memory honest = _exchangeBody();
        TlsNotaryVerifierBase.TlsNotaryProof memory s =
            _withExchangeBody(abi.encodePacked(honest, "&grant_type=authorization_code"));
        vm.expectRevert(abi.encodeWithSelector(CeremonyFields.MalformedForm.selector, honest.length));
        this.run{value: quote}(s);
    }

    /// @dev REQ-PLAT-61, TEST-PLAT-12: nor a refresh grant's field. The pinned
    ///      endpoint receives only the authorization-code request.
    function test_rejectsAnExchangeCarryingARefreshToken() public {
        bytes memory honest = _exchangeBody();
        TlsNotaryVerifierBase.TlsNotaryProof memory s =
            _withExchangeBody(abi.encodePacked(honest, "&refresh_token=ghr_16C7e42F292c6912E7710c838347Ae178B4a"));
        vm.expectRevert(abi.encodeWithSelector(CeremonyFields.MalformedForm.selector, honest.length));
        this.run{value: quote}(s);
    }

    /// @dev REQ-PLAT-61, TEST-PLAT-12: nor a device grant's. Refused where
    ///      the sixth pair begins, whatever its name.
    function test_rejectsAnExchangeCarryingADeviceCode() public {
        bytes memory honest = _exchangeBody();
        TlsNotaryVerifierBase.TlsNotaryProof memory s =
            _withExchangeBody(abi.encodePacked(honest, "&device_code=3584d83530557fdd1f46af8289938c8ef79f9dc5"));
        vm.expectRevert(abi.encodeWithSelector(CeremonyFields.MalformedForm.selector, honest.length));
        this.run{value: quote}(s);
    }

    /// @dev REQ-PLAT-61, TEST-PLAT-12: the right verifier in another spelling
    ///      -- padded, base64 rather than section 7's unpadded base64url -- is
    ///      a form the check admits and a value the base refuses: it recomputes
    ///      the verifier and compares byte for byte.
    function test_rejectsAnExchangeWithAPaddedVerifier() public {
        bytes memory padded = abi.encodePacked(CeremonyAuthorization.codeVerifier(digest, AUTH_NONCE), "%3D%3D");
        TlsNotaryVerifierBase.TlsNotaryProof memory s = _withExchangeBody(_exchangeBodyWithVerifier(padded));
        vm.expectRevert(TlsNotaryVerifierBase.CodeVerifierMismatch.selector);
        this.run{value: quote}(s);
    }

    /// @dev REQ-PLAT-61, TEST-PLAT-12: and one byte short of it.
    function test_rejectsAnExchangeWithATruncatedVerifier() public {
        bytes memory verifier = CeremonyAuthorization.codeVerifier(digest, AUTH_NONCE);
        bytes memory short = new bytes(verifier.length - 1);
        for (uint256 i = 0; i < short.length; ++i) {
            short[i] = verifier[i];
        }
        TlsNotaryVerifierBase.TlsNotaryProof memory s = _withExchangeBody(_exchangeBodyWithVerifier(short));
        vm.expectRevert(TlsNotaryVerifierBase.CodeVerifierMismatch.selector);
        this.run{value: quote}(s);
    }

    /// @dev REQ-PLAT-61, TEST-PLAT-12: a duplicate in the literal spelling.
    ///      `formField` would have refused this one too; the exact form
    ///      refuses it where the second `client_id=` stands in place of `code=`.
    function test_rejectsAnExchangeWithADuplicateField() public {
        bytes memory first = "client_id=Iv1.8a61f9b3a7aba766&";
        TlsNotaryVerifierBase.TlsNotaryProof memory s = _withExchangeBody(abi.encodePacked(first, _exchangeBody()));
        vm.expectRevert(abi.encodeWithSelector(CeremonyFields.MalformedForm.selector, first.length));
        this.run{value: quote}(s);
    }

    /// @dev REQ-PLAT-61, TEST-PLAT-12: a duplicate in an ENCODED spelling.
    ///      `code%5Fverifier` is `code_verifier` to a form parser and no
    ///      match to `formField`, which is the case ASM-PROV-07 used to
    ///      cover. It is a sixth pair here, refused like any other.
    function test_rejectsAnExchangeWithAnEncodedDuplicateName() public {
        bytes memory honest = _exchangeBody();
        TlsNotaryVerifierBase.TlsNotaryProof memory s =
            _withExchangeBody(abi.encodePacked(honest, "&code%5Fverifier=EVILEVILEVILEVILEVILEVILEVILEVILEVILEVIL0"));
        vm.expectRevert(abi.encodeWithSelector(CeremonyFields.MalformedForm.selector, honest.length));
        this.run{value: quote}(s);
    }

    /// @dev REQ-PLAT-61, TEST-PLAT-12: each field once with a NONEMPTY value.
    function test_rejectsAnExchangeWithAnEmptyValue() public {
        TlsNotaryVerifierBase.TlsNotaryProof memory s =
            _withExchangeBody(_exchangeBody("", "https%3A%2F%2Fa.example", "0123456789abcdef0123456789abcdef"));
        vm.expectRevert(abi.encodeWithSelector(CeremonyFields.EmptyFormValue.selector, "code"));
        this.run{value: quote}(s);
    }

    /// @dev REQ-PLAT-61, TEST-PLAT-12, TEST-PLAT-14: four pairs are not five. The body ends
    ///      where the `&` before `client_secret=` should stand.
    function test_rejectsAnExchangeMissingAField() public {
        bytes memory body = abi.encodePacked(
            "client_id=Iv1.8a61f9b3a7aba766&code=abc&redirect_uri=https%3A%2F%2Fa.example&code_verifier=",
            CeremonyAuthorization.codeVerifier(digest, AUTH_NONCE)
        );
        TlsNotaryVerifierBase.TlsNotaryProof memory s = _withExchangeBody(body);
        vm.expectRevert(abi.encodeWithSelector(CeremonyFields.MalformedForm.selector, body.length));
        this.run{value: quote}(s);
    }

    /// @dev REQ-PLAT-61, TEST-PLAT-12, TEST-PLAT-14: nothing after the last value, not even
    ///      the delimiter that would begin a sixth pair.
    function test_rejectsAnExchangeWithATrailingAmpersand() public {
        bytes memory honest = _exchangeBody();
        TlsNotaryVerifierBase.TlsNotaryProof memory s = _withExchangeBody(abi.encodePacked(honest, "&"));
        vm.expectRevert(abi.encodeWithSelector(CeremonyFields.MalformedForm.selector, honest.length));
        this.run{value: quote}(s);
    }

    /// @dev REQ-PLAT-61, TEST-PLAT-12: a raw `;` inside the credential. Some
    ///      form parsers split pairs on it, so to them this body carries a
    ///      second `code_verifier`; `formField` would have read the credential
    ///      to the next `&` and counted one. The serializer never emits a raw
    ///      `;`, so the byte itself is refused.
    function test_rejectsAnExchangeWithARawSemicolonInAValue() public {
        bytes memory body = _exchangeBody(
            "abc", "https%3A%2F%2Fa.example", "0123456789abcdef;code_verifier=EVILEVILEVILEVILEVILEVILEVILEVILEVILEVIL0"
        );
        TlsNotaryVerifierBase.TlsNotaryProof memory s = _withExchangeBody(body);
        vm.expectRevert(abi.encodeWithSelector(CeremonyFields.MalformedForm.selector, _indexOf(body, ";")));
        this.run{value: quote}(s);
    }

    /// @dev REQ-PLAT-61, TEST-PLAT-12: a raw `=` inside a value, likewise.
    function test_rejectsAnExchangeWithARawEqualsInAValue() public {
        bytes memory body = _exchangeBody("abc=def", "https%3A%2F%2Fa.example", "0123456789abcdef0123456789abcdef");
        TlsNotaryVerifierBase.TlsNotaryProof memory s = _withExchangeBody(body);
        vm.expectRevert(abi.encodeWithSelector(CeremonyFields.MalformedForm.selector, _indexOf(body, "=def")));
        this.run{value: quote}(s);
    }

    /// @dev REQ-PLAT-61, TEST-PLAT-12: `%3a` decodes as `%3A` does and is not
    ///      what the serializer writes, so it is a second spelling of the same
    ///      redirect and refused as noncanonical.
    function test_rejectsAnExchangeWithALowercaseEscape() public {
        bytes memory body = _exchangeBody("abc", "https%3a%2F%2Fa.example", "0123456789abcdef0123456789abcdef");
        TlsNotaryVerifierBase.TlsNotaryProof memory s = _withExchangeBody(body);
        vm.expectRevert(abi.encodeWithSelector(CeremonyFields.MalformedForm.selector, _indexOf(body, "%3a")));
        this.run{value: quote}(s);
    }

    /// @dev REQ-PLAT-61, TEST-PLAT-12: `%61` decodes to the `a` the serializer
    ///      writes bare, so `%61bc` is a second spelling of `abc`; `%20` is
    ///      the space it writes `+`. Each is refused at its `%`, and the
    ///      credential is held to the same alphabet.
    function test_rejectsAnExchangeWithAnEscapeTheSerializerWritesBare() public {
        bytes memory body = _exchangeBody("%61bc", "https%3A%2F%2Fa.example", "0123456789abcdef0123456789abcdef");
        TlsNotaryVerifierBase.TlsNotaryProof memory s = _withExchangeBody(body);
        vm.expectRevert(abi.encodeWithSelector(CeremonyFields.MalformedForm.selector, _indexOf(body, "%61")));
        this.run{value: quote}(s);

        body = _exchangeBody("a%20b", "https%3A%2F%2Fa.example", "0123456789abcdef0123456789abcdef");
        s = _withExchangeBody(body);
        vm.expectRevert(abi.encodeWithSelector(CeremonyFields.MalformedForm.selector, _indexOf(body, "%20")));
        this.run{value: quote}(s);

        body = _exchangeBody("abc", "https%3A%2F%2Fa.example", "0123456789abcdef%2A0123456789abcdef");
        s = _withExchangeBody(body);
        vm.expectRevert(abi.encodeWithSelector(CeremonyFields.MalformedForm.selector, _indexOf(body, "%2A")));
        this.run{value: quote}(s);
    }

    /// @dev REQ-PLAT-61, TEST-PLAT-12: `code` and `redirect_uri` decode to
    ///      UTF-8. A byte no UTF-8 uses, a truncated sequence and a surrogate
    ///      pass the form grammar -- each is a canonical escape -- and fail
    ///      the field.
    function test_rejectsAnExchangeWithInvalidUtf8InTheCode() public {
        TlsNotaryVerifierBase.TlsNotaryProof memory s =
            _withExchangeBody(_exchangeBody("ab%FF", "https%3A%2F%2Fa.example", "0123456789abcdef0123456789abcdef"));
        vm.expectRevert(abi.encodeWithSelector(CeremonyFields.FormValueNotUtf8.selector, "code"));
        this.run{value: quote}(s);

        s = _withExchangeBody(_exchangeBody("%ED%A0%80", "https%3A%2F%2Fa.example", "0123456789abcdef0123456789abcdef"));
        vm.expectRevert(abi.encodeWithSelector(CeremonyFields.FormValueNotUtf8.selector, "code"));
        this.run{value: quote}(s);
    }

    function test_rejectsAnExchangeWithInvalidUtf8InTheRedirect() public {
        TlsNotaryVerifierBase.TlsNotaryProof memory s = _withExchangeBody(
            _exchangeBody("abc", "https%3A%2F%2Fa.example%2F%C3", "0123456789abcdef0123456789abcdef")
        );
        vm.expectRevert(abi.encodeWithSelector(CeremonyFields.FormValueNotUtf8.selector, "redirect_uri"));
        this.run{value: quote}(s);
    }

    /// @dev TEST-PLAT-12: canonical form escaping of a UTF-8 string in those
    ///      two fields passes the form check. What the code and redirect
    ///      should EQUAL is the Prover's comparison, not this verifier's.
    function test_acceptsAnExchangeWithUtf8InTheCodeAndRedirect() public {
        TlsNotaryVerifierBase.TlsNotaryProof memory s = _withExchangeBody(
            _exchangeBody("caf%C3%A9", "https%3A%2F%2Fa.example%2F%E2%82%AC", "0123456789abcdef0123456789abcdef")
        );
        assertEq(this.run{value: quote}(s).handle, "octocat");
    }

    /// @dev REQ-PLAT-61, TEST-PLAT-12: `client_secret` is printable ASCII
    ///      without whitespace. A `+` and an escaped tab pass the form grammar
    ///      and fail the field; `%20` never reaches it, being the space the
    ///      serializer spells `+` and refused as an escape above.
    function test_rejectsACredentialCarryingWhitespace() public {
        string[2] memory secrets = ["0123456789abcdef+0123456789abcdef", "%090123456789abcdef"];
        for (uint256 i = 0; i < secrets.length; ++i) {
            TlsNotaryVerifierBase.TlsNotaryProof memory s =
                _withExchangeBody(_exchangeBody("abc", "https%3A%2F%2Fa.example", secrets[i]));
            vm.expectRevert(abi.encodeWithSelector(CeremonyFields.FormValueNotPrintable.selector, "client_secret"));
            this.run{value: quote}(s);
        }
    }

    /// @dev REQ-PLAT-61, TEST-PLAT-12: nor a control byte, at either end of
    ///      the range, nor a byte above ASCII.
    function test_rejectsACredentialCarryingAControlByte() public {
        string[3] memory secrets = ["%000123456789abcdef", "0123456789abcdef%7F", "0123456789abcdef%C3%A9"];
        for (uint256 i = 0; i < secrets.length; ++i) {
            TlsNotaryVerifierBase.TlsNotaryProof memory s =
                _withExchangeBody(_exchangeBody("abc", "https%3A%2F%2Fa.example", secrets[i]));
            vm.expectRevert(abi.encodeWithSelector(CeremonyFields.FormValueNotPrintable.selector, "client_secret"));
            this.run{value: quote}(s);
        }
    }

    /// @dev TEST-PLAT-12: a credential of every printable ASCII byte the
    ///      serializer escapes, including the delimiters, is one value.
    function test_acceptsACredentialOfEscapedPrintableAscii() public {
        TlsNotaryVerifierBase.TlsNotaryProof memory s = _withExchangeBody(
            _exchangeBody("abc", "https%3A%2F%2Fa.example", "%21%22%23%24%25%26%27%28%29%2B%2C%2F%3A%3B%3D%7E")
        );
        assertEq(this.run{value: quote}(s).handle, "octocat");
    }

    /// @dev REQ-COMMON-16B, TEST-PLAT-12: `my%2Bapp` is the serialization of
    ///      `my+app`, not an identifier. It passes the form grammar -- `%2B`
    ///      is the canonical escape of `+` -- and fails the charset the base
    ///      holds `client_id` to.
    function test_rejectsAPercentEncodedClientIdentifier() public {
        bytes memory body = abi.encodePacked(
            "client_id=my%2Bapp&code=abc&redirect_uri=https%3A%2F%2Fa.example&code_verifier=",
            CeremonyAuthorization.codeVerifier(digest, AUTH_NONCE),
            "&client_secret=0123456789abcdef0123456789abcdef"
        );
        TlsNotaryVerifierBase.TlsNotaryProof memory s = _withExchangeBody(body);
        vm.expectRevert(
            abi.encodeWithSelector(TlsNotaryVerifierBase.ClientIdentifierNotSerializerSafe.selector, bytes("my%2Bapp"))
        );
        this.run{value: quote}(s);
    }

    /// @dev REQ-COMMON-16B, TEST-PLAT-12: an empty identifier is refused by
    ///      the form itself, before the charset is asked.
    function test_rejectsAnEmptyClientIdentifier() public {
        bytes memory body = abi.encodePacked(
            "client_id=&code=abc&redirect_uri=https%3A%2F%2Fa.example&code_verifier=",
            CeremonyAuthorization.codeVerifier(digest, AUTH_NONCE),
            "&client_secret=0123456789abcdef0123456789abcdef"
        );
        TlsNotaryVerifierBase.TlsNotaryProof memory s = _withExchangeBody(body);
        vm.expectRevert(abi.encodeWithSelector(CeremonyFields.EmptyFormValue.selector, "client_id"));
        this.run{value: quote}(s);
    }

    /// @dev TEST-PLAT-14: `content-length` declares the complete revealed
    ///      body. A head declaring ten bytes fewer describes a form GitHub
    ///      did not parse.
    function test_rejectsAnExchangeUnderdeclaringItsBody() public {
        bytes memory body = _exchangeBody();
        TlsNotaryVerifierBase.TlsNotaryProof memory s = _withExchange(_exchangeHead(body.length - 10), body);
        vm.expectRevert(
            abi.encodeWithSelector(
                TlsNotaryVerifierBase.WrongDeclaredBodyLength.selector, body.length - 10, body.length
            )
        );
        this.run{value: quote}(s);
    }

    /// @dev REQ-PLAT-56A, TEST-PLAT-14: an `authorization` header on the
    ///      exchange is refused. The credential travels in the body here and
    ///      nowhere else.
    function test_rejectsAForbiddenHeaderOnTheExchange() public {
        bytes memory body = _exchangeBody();
        bytes memory headers = abi.encodePacked(EXCHANGE_HEADERS, "authorization: Basic bXlDbGllbnQtMTpzM2NyZXQ=\r\n");
        TlsNotaryVerifierBase.TlsNotaryProof memory s = _withExchange(_exchangeHead(headers, body.length), body);
        vm.expectRevert(
            abi.encodeWithSelector(TlsNotaryVerifierBase.ForbiddenRequestHeader.selector, bytes("authorization"))
        );
        this.run{value: quote}(s);
    }

    /// @dev TEST-PLAT-12: `+` is the serializer's spelling of a space, and a
    ///      code carrying one is still one value.
    function test_acceptsAnExchangeWithAPlusInAValue() public {
        TlsNotaryVerifierBase.TlsNotaryProof memory s =
            _withExchangeBody(_exchangeBody("abc+def", "https%3A%2F%2Fa.example", "0123456789abcdef0123456789abcdef"));
        assertEq(this.run{value: quote}(s).handle, "octocat");
    }

    /// @dev TEST-PLAT-12: a credential with ENCODED delimiters remains one
    ///      value. `%26` and `%3D` are bytes of the credential to every form
    ///      parser, and the exact form never decodes them into a pair.
    function test_acceptsAnExchangeWithEncodedDelimitersInAValue() public {
        TlsNotaryVerifierBase.TlsNotaryProof memory s =
            _withExchangeBody(_exchangeBody("abc", "https%3A%2F%2Fa.example", "0123%26code_verifier%3DEVIL"));
        assertEq(this.run{value: quote}(s).handle, "octocat");
    }

    // ─── Two authorities, not one ───────────────────────────────────

    /// @dev `github.com` serves the exchange and `api.github.com` the identity
    ///      read. A profile pinning one authority would accept an identity
    ///      attestation from the exchange host, or the reverse.
    function test_rejectsTheExchangeFromTheApiHost() public {
        TlsNotaryVerifierBase.TlsNotaryProof memory s = _payload();
        s.tokenSession = _exchange(CeremonyProfile.AUTHORITY_GITHUB_API);
        vm.expectPartialRevert(PlatformVerifierBase.WrongAuthority.selector);
        this.run{value: quote}(s);
    }

    function test_rejectsTheIdentityReadFromTheExchangeHost() public {
        TlsNotaryVerifierBase.TlsNotaryProof memory s = _payload();
        s.identitySession = _identity('{"login":"octocat","id":583231}', CeremonyProfile.AUTHORITY_GITHUB);
        vm.expectPartialRevert(PlatformVerifierBase.WrongAuthority.selector);
        this.run{value: quote}(s);
    }

    // ─── The bare-integer id (REQ-PLAT-51) ──────────────────────────

    function test_readsTheIdWithEitherTerminator() public {
        TlsNotaryVerifierBase.TlsNotaryProof memory s = _payload();
        s.identitySession = _identity('{"id":1,"login":"octocat"}', CeremonyProfile.AUTHORITY_GITHUB_API);
        assertEq(this.run{value: quote}(s).userId, "1");
    }

    /// @dev The terminator proves the revealed digits are the whole number
    ///      rather than a prefix of a longer one.
    function test_rejectsAnIdWithoutAStructuralTerminator() public {
        TlsNotaryVerifierBase.TlsNotaryProof memory s = _payload();
        // A space before the brace is JSON's own and reads through; a space
        // before more digits touches no structural byte and is the
        // terminator, which is not one.
        s.identitySession = _identity('{"login":"octocat","id":583231 4}', CeremonyProfile.AUTHORITY_GITHUB_API);
        vm.expectPartialRevert(CeremonyFields.BadIntegerTerminator.selector);
        this.run{value: quote}(s);
    }

    function test_rejectsANoncanonicalId() public {
        TlsNotaryVerifierBase.TlsNotaryProof memory s = _payload();
        s.identitySession = _identity('{"login":"octocat","id":007}', CeremonyProfile.AUTHORITY_GITHUB_API);
        vm.expectPartialRevert(CeremonyFields.NoncanonicalInteger.selector);
        this.run{value: quote}(s);
    }

    /// @dev A quoted id is not the integer GitHub returns, and REQ-PLAT-08
    ///      refuses it rather than coercing.
    function test_rejectsAQuotedId() public {
        TlsNotaryVerifierBase.TlsNotaryProof memory s = _payload();
        s.identitySession = _identity('{"login":"octocat","id":"583231"}', CeremonyProfile.AUTHORITY_GITHUB_API);
        vm.expectPartialRevert(CeremonyFields.NoncanonicalInteger.selector);
        this.run{value: quote}(s);
    }

    // ─── The handle field is `login` ────────────────────────────────

    function test_rejectsAResponseWithNoLogin() public {
        TlsNotaryVerifierBase.TlsNotaryProof memory s = _payload();
        s.identitySession = _identity('{"username":"octocat","id":583231}', CeremonyProfile.AUTHORITY_GITHUB_API);
        vm.expectPartialRevert(TlsNotaryVerifierBase.FieldNotUnique.selector);
        this.run{value: quote}(s);
    }

    // ─── Shared duties still hold ───────────────────────────────────

    function test_rejectsAnExchangeRetargetedToAnotherDigest() public {
        TlsNotaryVerifierBase.TlsNotaryProof memory s = _payload();
        s.authorizationNonce = bytes32(uint256(AUTH_NONCE) ^ 1);
        vm.expectRevert(TlsNotaryVerifierBase.CodeVerifierMismatch.selector);
        this.run{value: quote}(s);
    }

    function test_quotesTwoNotaryFees() public view {
        assertEq(verifier.quote(), 2 * FEE);
    }

    /// @dev REQ-COMMON-19A on the identity read: a second `authorization:`
    ///      header, revealed, anywhere in the request, is refused by the
    ///      line-anchored count. The identity attestation is rebuilt with the
    ///      extra header in its revealed head so the count sees two.
    function test_rejectsASecondAuthorizationHeaderOnTheIdentityRead() public {
        TlsNotaryVerifierBase.TlsNotaryProof memory s = _payload();
        s.identitySession = _identityWithHeadPrefix("authorization: Bearer stolen\r\n");
        vm.expectPartialRevert(CeremonyAttestation.NotOneAuthorizationHeader.selector);
        this.run{value: quote}(s);
    }

    /// @dev GitHub honours `token` and Basic beside Bearer. A second
    ///      `authorization` under either is counted all the same; counting only
    ///      `bearer` left it uncounted, and a leaked personal token in it would
    ///      have named someone else's account under this exchange's bearer.
    function test_rejectsASecondAuthorizationHeaderOfAnotherSchemeOnTheIdentityRead() public {
        TlsNotaryVerifierBase.TlsNotaryProof memory s = _payload();
        s.identitySession = _identityWithHeadPrefix("Authorization: token ghp_stolen\r\n");
        vm.expectPartialRevert(CeremonyAttestation.NotOneAuthorizationHeader.selector);
        this.run{value: quote}(s);
    }

    /// @dev And `cookie`, the other credential a platform might honour over
    ///      the bearer, is refused on the identity read by name.
    function test_rejectsACookieOnTheIdentityRead() public {
        TlsNotaryVerifierBase.TlsNotaryProof memory s = _payload();
        s.identitySession = _identityWithHeadPrefix("cookie: user_session=stolen\r\n");
        vm.expectRevert(abi.encodeWithSelector(TlsNotaryVerifierBase.ForbiddenRequestHeader.selector, bytes("cookie")));
        this.run{value: quote}(s);
    }

    /// @dev The identity request as the browser composes it (`identityRequest`
    ///      on libid `feat/ceremony-rebuild-plan`): `host`, `authorization`,
    ///      `accept`, the browser's own `user-agent`, which GitHub demands,
    ///      `x-github-api-version`, `connection`, in that order and lowercased
    ///      by hyper. The exchange `capture_ceremony` sends is the happy path
    ///      above already: `host`, `content-type`, `accept`, `connection`,
    ///      hyper's `content-length` last, run against GitHub for real in
    ///      `github-ceremony-real.json`.
    function test_verifiesTheIdentityRequestTheBrowserSends() public {
        TlsNotaryVerifierBase.TlsNotaryProof memory s = _payload();
        s.identitySession = _identityWithHead(
            "GET /user HTTP/1.1\r\nhost: api.github.com\r\nauthorization: Bearer ",
            "\r\naccept: application/vnd.github+json\r\n"
            "user-agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36\r\n"
            "x-github-api-version: 2022-11-28\r\nconnection: close\r\n\r\n"
        );
        ICeremony.VerifiedClaim memory f = this.run{value: quote}(s);
        assertEq(f.handle, "octocat");
    }

    /// The honest identity read for a request given as the bytes before the
    /// committed bearer and the bytes after it.
    function _identityWithHead(bytes memory head, bytes memory tail)
        private
        pure
        returns (ICeremony.Attestation memory)
    {
        bytes memory bearer = "gho_TOKENTOKENTOKEN";
        uint32 start = uint32(head.length);
        uint32 end = start + uint32(bearer.length);
        AttestationBuilder.Direction memory sent = AttestationBuilder.Direction({
            revealed: AttestationBuilder.two(
                AttestationBuilder.Range({start: 0, value: head}), AttestationBuilder.Range({start: end, value: tail})
            ),
            commitments: AttestationBuilder.one(
                AttestationBuilder.Commitment({start: start, end: end, value: IDENTITY_COMMITMENT})
            ),
            length: end + uint32(tail.length)
        });
        bytes memory b = abi.encodePacked("HTTP/1.1 200 OK\r\n\r\n", '{"login":"octocat","id":583231}');
        AttestationBuilder.Direction memory received = AttestationBuilder.Direction({
            revealed: AttestationBuilder.one(AttestationBuilder.Range({start: 0, value: b})),
            commitments: AttestationBuilder.none(),
            length: uint32(b.length)
        });
        bytes memory attested = AttestationBuilder.encode(CeremonyProfile.AUTHORITY_GITHUB_API, T0, sent, received);
        return ICeremony.Attestation({attestedData: attested, proof: _sign(attested)});
    }

    string constant RUST_SESSION = "contracts/ceremony/test/fixtures/github-ceremony-session.json";

    /// @dev The exchange and the identity read as `ceremony_fixtures` composes
    ///      them, both encoded by hyper,
    ///      laid out by `libid_transcript::ceremony`, committed with tlsn's
    ///      SHA-256 plaintext hashes, recorded by `AttestedData::from_observed`
    ///      and signed by the key this suite trusts -- the Rust pipeline minus
    ///      the MPC, with nothing written by hand. Verified with those
    ///      signatures unedited; the verifier inside was derived from this
    ///      suite's digest, which the first assertion checks. Generated by
    ///      `cargo run -p libid-tlsn --example ceremony_fixtures` in libid-rs.
    function test_verifiesTheRecordsLibidRsProduces() public {
        string memory json = vm.readFile(RUST_SESSION);
        assertEq(vm.parseJsonBytes32(json, ".authorization_digest"), digest, "derived from this suite's digest");
        assertEq(vm.parseJsonBytes32(json, ".authorization_nonce"), AUTH_NONCE);
        assertEq(vm.parseJsonAddress(json, ".notary"), vm.addr(NOTARY_KEY), "signed by the key this suite trusts");
        assertEq(uint64(vm.parseJsonUint(json, ".created_at")), T0);
        // The identity response is formatted as GitHub formats it for the
        // media type the profile pins, whitespace and all. A compact body here
        // once let this fixture pass a verifier that refused every real read.
        assertTrue(
            _contains(vm.parseJsonBytes(json, ".identity.received"), bytes('"login": "octocat"')),
            "the fixture carries GitHub's pretty-printed response"
        );

        TlsNotaryVerifierBase.TlsNotaryProof memory s = _payload();
        s.tokenSession = ICeremony.Attestation({
            attestedData: vm.parseJsonBytes(json, ".token.attested_data"),
            proof: vm.parseJsonBytes(json, ".token.notary_signature")
        });
        s.identitySession = ICeremony.Attestation({
            attestedData: vm.parseJsonBytes(json, ".identity.attested_data"),
            proof: vm.parseJsonBytes(json, ".identity.notary_signature")
        });
        ICeremony.VerifiedClaim memory f = this.run{value: quote}(s);
        assertEq(f.userId, "583231");
        assertEq(f.handle, "octocat");
        assertEq(string(f.clientIdentifier), "Iv1.8a61f9b3a7aba766");
        assertEq(f.sessionId, digest);
    }

    function _contains(bytes memory haystack, bytes memory needle) private pure returns (bool) {
        return _indexOf(haystack, needle) != type(uint256).max;
    }

    /// The offset of the first `needle` in `haystack`, or `max`.
    function _indexOf(bytes memory haystack, bytes memory needle) private pure returns (uint256) {
        if (needle.length > haystack.length) return type(uint256).max;
        for (uint256 i = 0; i + needle.length <= haystack.length; ++i) {
            bool same = true;
            for (uint256 j = 0; j < needle.length && same; ++j) {
                same = haystack[i + j] == needle[j];
            }
            if (same) return i;
        }
        return type(uint256).max;
    }

    /// @dev GitHub pretty-prints `/user` for the media type the profile pins:
    ///      a newline and two spaces before every member, a space after every
    ///      colon. The readers remove JSON whitespace before they look, so the
    ///      compact delimiters they match are the grammar, not the bytes.
    function test_readsTheIdentityGitHubPrettyPrints() public {
        TlsNotaryVerifierBase.TlsNotaryProof memory s = _payload();
        s.identitySession = _identity(
            '{\n  "login": "octocat",\n  "id": 583231,\n  "node_id": "MDQ6VXNlcjU4MzIzMQ==",\n  "name": "The Octocat"\n}',
            CeremonyProfile.AUTHORITY_GITHUB_API
        );
        ICeremony.VerifiedClaim memory f = this.run{value: quote}(s);
        assertEq(f.userId, "583231");
        assertEq(f.handle, "octocat");
    }

    /// @dev A second `login` in another spelling is a second `login`.
    function test_rejectsADuplicateMemberInAnotherWhitespaceSpelling() public {
        TlsNotaryVerifierBase.TlsNotaryProof memory s = _payload();
        s.identitySession =
            _identity('{"login":"octocat","id":583231,"login" : "mallory"}', CeremonyProfile.AUTHORITY_GITHUB_API);
        vm.expectRevert(abi.encodeWithSelector(TlsNotaryVerifierBase.FieldNotUnique.selector, "login", 2));
        this.run{value: quote}(s);
    }

    string constant REAL_SESSION = "contracts/ceremony/test/fixtures/github-ceremony-real.json";

    /// @dev A ceremony that actually ran: two MPC-TLS sessions against
    ///      github.com and api.github.com on 2026-09-17, the exchange with a
    ///      real authorization code under the PKCE challenge derived from this
    ///      suite's digest, the identity read with the bearer GitHub issued,
    ///      the verifier in the prover's process signing as the key this
    ///      suite trusts (libid-rs `examples/capture_ceremony.rs`). Nothing in
    ///      the file was written by hand: the head is what hyper put on the
    ///      wire, the body is what GitHub answered, pretty-printed as GitHub
    ///      prints it, the credential is in the clear and the bearer is
    ///      committed, not present. Verified with the signatures unedited, at a
    ///      clock a minute past the identity read.
    function test_verifiesTheRecordsACeremonyProduced() public {
        string memory json = vm.readFile(REAL_SESSION);
        assertEq(vm.parseJsonBytes32(json, ".authorization_digest"), digest, "bound to this suite's digest");
        assertEq(vm.parseJsonBytes32(json, ".authorization_nonce"), AUTH_NONCE);
        assertEq(vm.parseJsonAddress(json, ".notary"), vm.addr(NOTARY_KEY), "signed by the key this suite trusts");
        assertTrue(
            _contains(vm.parseJsonBytes(json, ".identity.attested_data"), bytes('"login": "')),
            "GitHub's pretty-printed response, as served"
        );
        vm.warp(vm.parseJsonUint(json, ".identity.created_at") + 60);

        TlsNotaryVerifierBase.TlsNotaryProof memory s = _payload();
        s.tokenSession = ICeremony.Attestation({
            attestedData: vm.parseJsonBytes(json, ".token.attested_data"),
            proof: vm.parseJsonBytes(json, ".token.notary_signature")
        });
        s.identitySession = ICeremony.Attestation({
            attestedData: vm.parseJsonBytes(json, ".identity.attested_data"),
            proof: vm.parseJsonBytes(json, ".identity.notary_signature")
        });
        ICeremony.VerifiedClaim memory f = this.run{value: quote}(s);
        assertEq(f.userId, "293919812");
        assertEq(f.handle, "testyakly");
        assertEq(string(f.clientIdentifier), "Iv23lioEM9NAR9vO8CmT");
        assertEq(f.sessionId, digest);
    }

    /// @dev The wrong authority is still refused before any field is read.
    function test_rejectsAnIdentityReadFromTheWrongAuthority() public {
        TlsNotaryVerifierBase.TlsNotaryProof memory s = _payload();
        bytes memory attested = s.identitySession.attestedData;
        attested[0] = bytes1(uint8(attested[0]) ^ 0x01);
        s.identitySession = ICeremony.Attestation({attestedData: attested, proof: _sign(attested)});
        vm.expectPartialRevert(PlatformVerifierBase.WrongAuthority.selector);
        this.run{value: quote}(s);
    }

    /// The honest identity read, with extra revealed header lines after the
    /// request line.
    function _identityWithHeadPrefix(string memory extraHeaders) private pure returns (ICeremony.Attestation memory) {
        bytes memory head = abi.encodePacked(
            "GET /user HTTP/1.1\r\n",
            extraHeaders,
            "accept: application/vnd.github+json\r\nhost: api.github.com\r\n\r\nauthorization: Bearer "
        );
        bytes memory bearer = "gho_TOKENTOKENTOKEN";
        bytes memory tail = "\r\nconnection: close\r\n\r\n";
        uint32 start = uint32(head.length);
        uint32 end = start + uint32(bearer.length);
        AttestationBuilder.Direction memory sent = AttestationBuilder.Direction({
            revealed: AttestationBuilder.two(
                AttestationBuilder.Range({start: 0, value: head}), AttestationBuilder.Range({start: end, value: tail})
            ),
            commitments: AttestationBuilder.one(
                AttestationBuilder.Commitment({start: start, end: end, value: IDENTITY_COMMITMENT})
            ),
            length: end + uint32(tail.length)
        });
        bytes memory b = abi.encodePacked("HTTP/1.1 200 OK\r\n\r\n", '{"login":"octocat","id":583231}');
        AttestationBuilder.Direction memory received = AttestationBuilder.Direction({
            revealed: AttestationBuilder.one(AttestationBuilder.Range({start: 0, value: b})),
            commitments: AttestationBuilder.none(),
            length: uint32(b.length)
        });
        bytes memory attested = AttestationBuilder.encode(CeremonyProfile.AUTHORITY_GITHUB_API, T0, sent, received);
        return ICeremony.Attestation({attestedData: attested, proof: _sign(attested)});
    }

    /// A commitment over the request line, then one revealed run: the two
    /// tile, so coverage passes and the origin rule is what refuses this --
    /// before the commitment count is ever looked at.
    function test_rejectsAnExchangeWhoseRequestLineIsHidden() public {
        bytes memory prefix = abi.encodePacked(
            "client_id=Iv1.8a61f9b3a7aba766&code=abc&redirect_uri=https%3A%2F%2Fa.example&code_verifier=",
            CeremonyAuthorization.codeVerifier(digest, AUTH_NONCE)
        );
        bytes memory whole = abi.encodePacked(_exchangeHead(prefix.length), prefix);
        AttestationBuilder.Direction memory sent = AttestationBuilder.Direction({
            revealed: AttestationBuilder.one(AttestationBuilder.Range({start: 40, value: whole})),
            commitments: AttestationBuilder.one(
                AttestationBuilder.Commitment({start: 0, end: 40, value: bytes32(uint256(0x5EC1E7))})
            ),
            length: 40 + uint32(whole.length)
        });
        bytes memory a = AttestationBuilder.encode(CeremonyProfile.AUTHORITY_GITHUB, T0, sent, _exchangeResponse());
        TlsNotaryVerifierBase.TlsNotaryProof memory s = _payload();
        s.tokenSession = ICeremony.Attestation({attestedData: a, proof: _sign(a)});
        vm.expectRevert(abi.encodeWithSelector(TlsNotaryVerifierBase.RequestLineNotAtOrigin.selector, uint32(40)));
        this.run{value: quote}(s);
    }

    /// @dev The exchange layout itself, asserted against the verifier rather
    ///      than against the generated constant: a request that hides a body
    ///      suffix behind a commitment is refused, however well formed the
    ///      rest of it is.
    function test_rejectsAnExchangeThatCommitsABodySuffix() public {
        bytes memory body = _exchangeBody();
        bytes memory whole = abi.encodePacked(_exchangeHead(body.length + 8), body);
        uint32 wholeEnd = uint32(whole.length);
        AttestationBuilder.Direction memory sent = AttestationBuilder.Direction({
            revealed: AttestationBuilder.one(AttestationBuilder.Range({start: 0, value: whole})),
            commitments: AttestationBuilder.one(
                AttestationBuilder.Commitment({start: wholeEnd, end: wholeEnd + 8, value: bytes32(uint256(0x5EC1E7))})
            ),
            length: wholeEnd + 8
        });
        bytes memory a = AttestationBuilder.encode(CeremonyProfile.AUTHORITY_GITHUB, T0, sent, _exchangeResponse());
        TlsNotaryVerifierBase.TlsNotaryProof memory s = _payload();
        s.tokenSession = ICeremony.Attestation({attestedData: a, proof: _sign(a)});
        vm.expectRevert(abi.encodeWithSelector(TlsNotaryVerifierBase.WrongTokenRequestLayout.selector, 1, 1));
        this.run{value: quote}(s);
    }

    /// @dev REQ-COMMON-21B, on the profile whose exchange this repository does
    ///      not compose: `github/v1` pins its OWN head, so a prover sending a
    ///      request X's constant would have accepted is still refused here.
    ///      The media type is the header the requirement names, because it is
    ///      what decides whether GitHub reads the bytes `formField` reads as a
    ///      form at all.
    function test_rejectsAnotherMediaTypeOnTheExchange() public {
        bytes memory body = _exchangeBody();
        bytes memory head = _exchangeHead(
            "host: github.com\r\ncontent-type: application/json\r\naccept: application/json\r\nconnection: close\r\n",
            body.length
        );
        AttestationBuilder.Direction memory sent = _wholeSent(abi.encodePacked(head, body));
        bytes memory a = AttestationBuilder.encode(CeremonyProfile.AUTHORITY_GITHUB, T0, sent, _exchangeResponse());
        TlsNotaryVerifierBase.TlsNotaryProof memory s = _payload();
        s.tokenSession = ICeremony.Attestation({attestedData: a, proof: _sign(a)});
        vm.expectRevert(TlsNotaryVerifierBase.WrongTokenRequestHead.selector);
        this.run{value: quote}(s);
    }

    /// @dev A header the profile never mentions is the sender's own business
    ///      -- a `user-agent`, say -- as long as it is not one of the
    ///      forbidden names. The exchange still verifies.
    function test_acceptsAnUnlistedHeaderOnTheExchange() public {
        bytes memory body = _exchangeBody();
        bytes memory head = _exchangeHead(
            "host: github.com\r\nuser-agent: libid-bridge/0.3.0\r\ncontent-type: application/x-www-form-urlencoded\r\n"
            "accept: application/json\r\nconnection: close\r\n",
            body.length
        );
        AttestationBuilder.Direction memory sent = _wholeSent(abi.encodePacked(head, body));
        bytes memory a = AttestationBuilder.encode(CeremonyProfile.AUTHORITY_GITHUB, T0, sent, _exchangeResponse());
        TlsNotaryVerifierBase.TlsNotaryProof memory s = _payload();
        s.tokenSession = ICeremony.Attestation({attestedData: a, proof: _sign(a)});
        ICeremony.VerifiedClaim memory f = this.run{value: quote}(s);
        assertEq(f.handle, "octocat");
    }

    /// @dev And the fixtures above compose that head from parts, so this is
    ///      what says the two lines the profile requires are among them.
    function test_theFixtureHeadCarriesTheProfilesRequiredHeaders() public pure {
        bytes memory head = _exchangeHead(0);
        bytes memory needle = abi.encodePacked(CeremonyProfile.GITHUB_TOKEN_REQUIRED_HEADERS, "\r\n");
        bool found;
        for (uint256 i = 0; i + needle.length <= head.length && !found; ++i) {
            found = true;
            for (uint256 j = 0; j < needle.length && found; ++j) {
                found = head[i + j] == needle[j];
            }
        }
        assertTrue(found);
    }

    function test_rejectsAnExchangeResponseWithNoRevealedAnchors() public {
        AttestationBuilder.Direction memory received = AttestationBuilder.Direction({
            revealed: AttestationBuilder.one(AttestationBuilder.Range({start: 0, value: "HTTP/1.1 200 OK"})),
            commitments: AttestationBuilder.one(
                AttestationBuilder.Commitment({start: 15, end: 80, value: TOKEN_COMMITMENT})
            ),
            length: 80
        });
        bytes memory a = AttestationBuilder.encode(CeremonyProfile.AUTHORITY_GITHUB, T0, _exchangeSent(), received);
        TlsNotaryVerifierBase.TlsNotaryProof memory s = _payload();
        s.tokenSession = ICeremony.Attestation({attestedData: a, proof: _sign(a)});
        vm.expectRevert(CeremonyAttestation.NoFramedCommitment.selector);
        this.run{value: quote}(s);
    }

    function test_rejectsAPayloadForAnotherCeremonyVersion() public {
        TlsNotaryVerifierBase.TlsNotaryProof memory s = _payload();
        s.ceremonyVersion = 2;
        vm.expectRevert(abi.encodeWithSelector(PlatformVerifierBase.WrongCeremonyVersion.selector, 1, 2));
        this.run{value: quote}(s);
    }

    /// REQ-PLAT-52B: mirror of XPlatformVerifier.t.sol:403 test_provesAgainstTheCommitmentsTheNotarySigned
    /// using this file's TOKEN_COMMITMENT / IDENTITY_COMMITMENT (verified passing as test_P25_…).
    function test_provesAgainstTheCommitmentsTheNotarySigned() public { /* copy of the X test */ }
}
