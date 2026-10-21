// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {GitHubTranscripts} from "./TranscriptEquivalence.t.sol";
import {HonkStub} from "./HonkStub.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

import {AttestationBuilder} from "./AttestationBuilder.sol";
import {CeremonyAttestation} from "../CeremonyAttestation.sol";
import {CeremonyAuthorization} from "../CeremonyAuthorization.sol";
import {CeremonyFields} from "../CeremonyFields.sol";
import {CeremonyProfile} from "../CeremonyProfile.sol";
import {GitHubPlatformVerifier} from "../GitHubPlatformVerifier.sol";
import {ICeremony} from "../ICeremony.sol";
import {INotaryService} from "../INotaryService.sol";
import {RealTlsNotaryProofTest} from "./RealTlsNotaryProof.sol";
import {NotaryService} from "../NotaryService.sol";
import {IHonkVerifier, PlatformVerifierBase} from "../PlatformVerifierBase.sol";
import {TlsNotaryVerifierBase} from "../TlsNotaryVerifierBase.sol";
import {XPlatformVerifier} from "../XPlatformVerifier.sol";

/// @notice The `github/v1` path beyond the flow the X suite covers: two authorities,
///         a bare-integer id, the `login` field, a revealed body credential, and
///         the exact five-field form.
contract GitHubPlatformVerifierTest is RealTlsNotaryProofTest {
    using AttestationBuilder for AttestationBuilder.Direction;

    GitHubPlatformVerifier verifier;
    address honk;
    NotaryService notary;
    uint256 quote;

    uint256 constant FEE = 0.001 ether;
    uint64 constant ALLOWANCE = CeremonyProfile.FUTURE_OBSERVATION_ALLOWANCE_SECONDS_GITHUB;
    uint64 constant T0 = 1_770_000_000;

    bytes32 constant DOMAIN = keccak256(bytes("libid.bind-identity"));
    bytes32 constant AUTH_NONCE = bytes32(uint256(0x5555555555555555555555555555555555555555555555555555555555555555));
    /// The digest the fixtures are made for; set in `setUp`.
    bytes32 digest;
    bytes32 constant TOKEN_COMMITMENT = bytes32(uint256(0x1111));
    bytes32 constant IDENTITY_COMMITMENT = bytes32(uint256(0x2222));
    bytes32 constant ID_COMMITMENT = bytes32(uint256(0x3333));
    bytes32 constant HANDLE_COMMITMENT = bytes32(uint256(0x4444));
    /// Whatever else the response hides: the status, the other members.
    bytes32 constant OTHER = bytes32(uint256(0x5555));

    /// The fixture account's nodes, from Python's hashlib:
    ///   hashlib.sha256(b"libid.github.user-id583231")
    ///   hashlib.sha256(b"libid.github.handleoctocat")  (`OctoCat`, folded)
    bytes32 constant ID_NODE = 0x475902b27989feb395b9b0cd3156aa573a9676c13155b8e7e3ddaf3e77181847;
    bytes32 constant HANDLE_NODE = 0x381fb9d7d3b01214e58b94202ea10f78e169adef68bcc20d40c130deca6dfe74;

    function setUp() public {
        digest = CeremonyAuthorization.digest(DOMAIN, 1, AUTH_NONCE, _txData());
        vm.warp(T0 + 10);
        NotaryService nImpl = new NotaryService();
        notary = NotaryService(
            address(
                new ERC1967Proxy(
                    address(nImpl), abi.encodeCall(NotaryService.initialize, (OWNER, vm.addr(NOTARY_KEY), FEE))
                )
            )
        );
        honk = HonkStub.deploy(HonkStub.BEARER_LINK);
        address honkAddr = honk;
        GitHubPlatformVerifier vImpl = new GitHubPlatformVerifier();
        verifier = GitHubPlatformVerifier(
            address(
                new ERC1967Proxy(
                    address(vImpl),
                    abi.encodeCall(
                        GitHubPlatformVerifier.initialize,
                        (OWNER, INotaryService(address(notary)), IHonkVerifier(honkAddr))
                    )
                )
            )
        );
        quote = verifier.quote();
        vm.deal(address(this), 100 ether);
    }

    /// The head the browser sends on the exchange: the two headers the profile
    /// requires, and two it does not compare.
    bytes constant EXCHANGE_HEADERS =
        "host: github.com\r\ncontent-type: application/x-www-form-urlencoded\r\naccept: application/json\r\nconnection: close\r\n";

    /// The exchange request's head, declaring a body of `bodyLength` bytes.
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

    /// The exchange body with `code`, `redirect_uri` and `client_secret` given.
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

    /// The exchange body with `code_verifier` given.
    function _exchangeBodyWithVerifier(bytes memory codeVerifier) private pure returns (bytes memory) {
        return abi.encodePacked(
            "client_id=Iv1.8a61f9b3a7aba766&code=abc&redirect_uri=https%3A%2F%2Fa.example&code_verifier=",
            codeVerifier,
            "&client_secret=0123456789abcdef0123456789abcdef"
        );
    }

    /// One revealed run over the whole request, the shape `github/v1` fixes for its exchange.
    function _wholeSent(bytes memory whole) private pure returns (AttestationBuilder.Direction memory) {
        return AttestationBuilder.Direction({
            revealed: AttestationBuilder.one(AttestationBuilder.Range({start: 0, value: whole})),
            commitments: AttestationBuilder.none(),
            length: uint32(whole.length)
        });
    }

    /// The honest exchange request; the verifier locates its body by the HTTP framing.
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
        return ICeremony.Attestation({attestedData: attested, proof: AttestationBuilder.sign(NOTARY_KEY, attested)});
    }

    /// The honest identity read, the bearer committed, from `authority`.
    function _identity(bytes32 authority) private pure returns (ICeremony.Attestation memory) {
        return _identityReceiving(_identityResponse(), authority);
    }

    /// The pretty-printed identity response: anchors revealed, login and id
    /// each committed, every other byte committed.
    function _identityResponse() private pure returns (AttestationBuilder.Direction memory received) {
        received.commit("HTTP/1.1 200 OK\r\ncontent-type: application/json\r\n\r\n{\n  ", OTHER)
            .reveal('"login": "')
            .commit("OctoCat", HANDLE_COMMITMENT)
            .reveal('"')
            .commit(",\n  ", OTHER)
            .reveal('"id": ')
            .commit("583231", ID_COMMITMENT)
            .reveal(",")
            .commit('\n  "node_id": "MDQ6VXNlcjU4MzIzMQ==",\n  "name": "The Octocat"\n}', OTHER);
    }

    /// The response up to the id's anchor, honest: the login framed.
    function _upToTheId() private pure returns (AttestationBuilder.Direction memory received) {
        received.commit("HTTP/1.1 200 OK\r\n\r\n{\n  ", OTHER)
            .reveal('"login": "')
            .commit("OctoCat", HANDLE_COMMITMENT)
            .reveal('"')
            .commit(",\n  ", OTHER);
    }

    /// The honest identity request around `received`, from `authority`.
    function _identityReceiving(AttestationBuilder.Direction memory received, bytes32 authority)
        private
        pure
        returns (ICeremony.Attestation memory)
    {
        AttestationBuilder.Direction memory sent;
        sent.reveal(
                "GET /user HTTP/1.1\r\naccept: application/vnd.github+json\r\nhost: api.github.com\r\nauthorization: Bearer "
            )
            .commit("gho_TOKENTOKENTOKEN", IDENTITY_COMMITMENT)
            .reveal("\r\nconnection: close\r\n\r\n");
        bytes memory attested = AttestationBuilder.encode(authority, T0, sent, received);
        return ICeremony.Attestation({attestedData: attested, proof: AttestationBuilder.sign(NOTARY_KEY, attested)});
    }

    function _txData() private pure returns (bytes memory) {
        return abi.encode(address(0xBEEF));
    }

    /// The `github/v1` payload the fixtures are made for.
    function _payload() internal view override returns (TlsNotaryVerifierBase.TlsNotaryProof memory s) {
        s.ceremonyVersion = 1;
        s.operationDomain = DOMAIN;
        s.authorizationNonce = AUTH_NONCE;
        s.transactionData = _txData();
        s.proof = hex"00";
        s.tokenSession = _exchange(CeremonyProfile.AUTHORITY_GITHUB);
        s.identitySession = _identity(CeremonyProfile.AUTHORITY_GITHUB_API);
        s.idNode = ID_NODE;
        s.handleNode = HANDLE_NODE;
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
        // Passed through from the payload; the stubbed proof accepts any nodes.
        assertEq(f.idNode, ID_NODE);
        assertEq(f.handleNode, HANDLE_NODE);
        assertEq(string(f.clientIdentifier), "Iv1.8a61f9b3a7aba766");
        assertEq(f.sessionId, digest);
        assertEq(f.operationDomain, DOMAIN);
        assertEq(f.transactionData, _txData());
        assertEq(f.ceremonyVersion, 1);
        // On the shared scale: each verifier subtracts its own allowance so
        // claims from different profiles compare.
        assertEq(f.metadataObservedAt, T0 - ALLOWANCE);
    }

    /// @dev The `Iv1.` prefix is why the serializer-safe set includes the dot.
    function test_acceptsAGitHubStyleClientIdentifier() public {
        ICeremony.VerifiedClaim memory f = this.run{value: quote}(_payload());
        assertTrue(CeremonyFields.isSerializerSafe(f.clientIdentifier));
    }

    // ─── The exact form (REQ-PLAT-61) ───────────────────────────────

    /// The payload with its exchange over `body`, its length declared honestly.
    function _withExchangeBody(bytes memory body) private view returns (TlsNotaryVerifierBase.TlsNotaryProof memory) {
        return _withExchange(_exchangeHead(body.length), body);
    }

    /// The payload with its exchange over `head` and `body` as given.
    function _withExchange(bytes memory head, bytes memory body)
        private
        view
        returns (TlsNotaryVerifierBase.TlsNotaryProof memory s)
    {
        s = _payload();
        AttestationBuilder.Direction memory sent = _wholeSent(abi.encodePacked(head, body));
        bytes memory a = AttestationBuilder.encode(CeremonyProfile.AUTHORITY_GITHUB, T0, sent, _exchangeResponse());
        s.tokenSession = ICeremony.Attestation({attestedData: a, proof: AttestationBuilder.sign(NOTARY_KEY, a)});
    }

    /// @dev REQ-PLAT-61, TEST-PLAT-12: fields out of order fail at byte 0,
    ///      where `client_id=` is expected.
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

    /// @dev REQ-PLAT-61, TEST-PLAT-12: a `grant_type` is a sixth pair, refused
    ///      at the `&` that begins it.
    function test_rejectsAnExchangeCarryingAGrantType() public {
        bytes memory honest = _exchangeBody();
        TlsNotaryVerifierBase.TlsNotaryProof memory s =
            _withExchangeBody(abi.encodePacked(honest, "&grant_type=authorization_code"));
        vm.expectRevert(abi.encodeWithSelector(CeremonyFields.MalformedForm.selector, honest.length));
        this.run{value: quote}(s);
    }

    /// @dev REQ-PLAT-61, TEST-PLAT-12: a refresh grant's field is a sixth pair.
    function test_rejectsAnExchangeCarryingARefreshToken() public {
        bytes memory honest = _exchangeBody();
        TlsNotaryVerifierBase.TlsNotaryProof memory s =
            _withExchangeBody(abi.encodePacked(honest, "&refresh_token=ghr_16C7e42F292c6912E7710c838347Ae178B4a"));
        vm.expectRevert(abi.encodeWithSelector(CeremonyFields.MalformedForm.selector, honest.length));
        this.run{value: quote}(s);
    }

    /// @dev REQ-PLAT-61, TEST-PLAT-12: a device grant's field is a sixth pair.
    function test_rejectsAnExchangeCarryingADeviceCode() public {
        bytes memory honest = _exchangeBody();
        TlsNotaryVerifierBase.TlsNotaryProof memory s =
            _withExchangeBody(abi.encodePacked(honest, "&device_code=3584d83530557fdd1f46af8289938c8ef79f9dc5"));
        vm.expectRevert(abi.encodeWithSelector(CeremonyFields.MalformedForm.selector, honest.length));
        this.run{value: quote}(s);
    }

    /// @dev REQ-PLAT-61, TEST-PLAT-12: a padded verifier passes the form check
    ///      but differs byte for byte from the recomputed one.
    function test_rejectsAnExchangeWithAPaddedVerifier() public {
        bytes memory padded = abi.encodePacked(CeremonyAuthorization.codeVerifier(digest, AUTH_NONCE), "%3D%3D");
        TlsNotaryVerifierBase.TlsNotaryProof memory s = _withExchangeBody(_exchangeBodyWithVerifier(padded));
        vm.expectRevert(TlsNotaryVerifierBase.CodeVerifierMismatch.selector);
        this.run{value: quote}(s);
    }

    /// @dev REQ-PLAT-61, TEST-PLAT-12: a verifier one byte short is refused.
    function test_rejectsAnExchangeWithATruncatedVerifier() public {
        bytes memory codeVerifier = CeremonyAuthorization.codeVerifier(digest, AUTH_NONCE);
        bytes memory short = new bytes(codeVerifier.length - 1);
        for (uint256 i = 0; i < short.length; ++i) {
            short[i] = codeVerifier[i];
        }
        TlsNotaryVerifierBase.TlsNotaryProof memory s = _withExchangeBody(_exchangeBodyWithVerifier(short));
        vm.expectRevert(TlsNotaryVerifierBase.CodeVerifierMismatch.selector);
        this.run{value: quote}(s);
    }

    /// @dev REQ-PLAT-61, TEST-PLAT-12: a duplicate is refused where the second
    ///      `client_id=` stands in place of `code=`.
    function test_rejectsAnExchangeWithADuplicateField() public {
        bytes memory first = "client_id=Iv1.8a61f9b3a7aba766&";
        TlsNotaryVerifierBase.TlsNotaryProof memory s = _withExchangeBody(abi.encodePacked(first, _exchangeBody()));
        vm.expectRevert(abi.encodeWithSelector(CeremonyFields.MalformedForm.selector, first.length));
        this.run{value: quote}(s);
    }

    /// @dev REQ-PLAT-61, TEST-PLAT-12: `code%5Fverifier` decodes to `code_verifier`
    ///      (ASM-PROV-07) and is refused as a sixth pair.
    function test_rejectsAnExchangeWithAnEncodedDuplicateName() public {
        bytes memory honest = _exchangeBody();
        TlsNotaryVerifierBase.TlsNotaryProof memory s =
            _withExchangeBody(abi.encodePacked(honest, "&code%5Fverifier=EVILEVILEVILEVILEVILEVILEVILEVILEVILEVIL0"));
        vm.expectRevert(abi.encodeWithSelector(CeremonyFields.MalformedForm.selector, honest.length));
        this.run{value: quote}(s);
    }

    /// @dev REQ-PLAT-61, TEST-PLAT-12: every value is nonempty.
    function test_rejectsAnExchangeWithAnEmptyValue() public {
        TlsNotaryVerifierBase.TlsNotaryProof memory s =
            _withExchangeBody(_exchangeBody("", "https%3A%2F%2Fa.example", "0123456789abcdef0123456789abcdef"));
        vm.expectRevert(abi.encodeWithSelector(CeremonyFields.EmptyFormValue.selector, "code"));
        this.run{value: quote}(s);
    }

    /// @dev REQ-PLAT-61, TEST-PLAT-12, TEST-PLAT-14: four pairs fail where the `&`
    ///      before `client_secret=` should stand.
    function test_rejectsAnExchangeMissingAField() public {
        bytes memory body = abi.encodePacked(
            "client_id=Iv1.8a61f9b3a7aba766&code=abc&redirect_uri=https%3A%2F%2Fa.example&code_verifier=",
            CeremonyAuthorization.codeVerifier(digest, AUTH_NONCE)
        );
        TlsNotaryVerifierBase.TlsNotaryProof memory s = _withExchangeBody(body);
        vm.expectRevert(abi.encodeWithSelector(CeremonyFields.MalformedForm.selector, body.length));
        this.run{value: quote}(s);
    }

    /// @dev REQ-PLAT-61, TEST-PLAT-12, TEST-PLAT-14: nothing may follow the last value.
    function test_rejectsAnExchangeWithATrailingAmpersand() public {
        bytes memory honest = _exchangeBody();
        TlsNotaryVerifierBase.TlsNotaryProof memory s = _withExchangeBody(abi.encodePacked(honest, "&"));
        vm.expectRevert(abi.encodeWithSelector(CeremonyFields.MalformedForm.selector, honest.length));
        this.run{value: quote}(s);
    }

    /// @dev REQ-PLAT-61, TEST-PLAT-12: some form parsers split pairs on `;`, and
    ///      the serializer never emits it raw, so a raw `;` is refused.
    function test_rejectsAnExchangeWithARawSemicolonInAValue() public {
        bytes memory body = _exchangeBody(
            "abc", "https%3A%2F%2Fa.example", "0123456789abcdef;code_verifier=EVILEVILEVILEVILEVILEVILEVILEVILEVILEVIL0"
        );
        TlsNotaryVerifierBase.TlsNotaryProof memory s = _withExchangeBody(body);
        vm.expectRevert(
            abi.encodeWithSelector(CeremonyFields.MalformedForm.selector, AttestationBuilder.indexOf(body, ";"))
        );
        this.run{value: quote}(s);
    }

    /// @dev REQ-PLAT-61, TEST-PLAT-12: a raw `=` inside a value, likewise.
    function test_rejectsAnExchangeWithARawEqualsInAValue() public {
        bytes memory body = _exchangeBody("abc=def", "https%3A%2F%2Fa.example", "0123456789abcdef0123456789abcdef");
        TlsNotaryVerifierBase.TlsNotaryProof memory s = _withExchangeBody(body);
        vm.expectRevert(
            abi.encodeWithSelector(CeremonyFields.MalformedForm.selector, AttestationBuilder.indexOf(body, "=def"))
        );
        this.run{value: quote}(s);
    }

    /// @dev REQ-PLAT-61, TEST-PLAT-12: `%3a` is a noncanonical spelling of `%3A`.
    function test_rejectsAnExchangeWithALowercaseEscape() public {
        bytes memory body = _exchangeBody("abc", "https%3a%2F%2Fa.example", "0123456789abcdef0123456789abcdef");
        TlsNotaryVerifierBase.TlsNotaryProof memory s = _withExchangeBody(body);
        vm.expectRevert(
            abi.encodeWithSelector(CeremonyFields.MalformedForm.selector, AttestationBuilder.indexOf(body, "%3a"))
        );
        this.run{value: quote}(s);
    }

    /// @dev REQ-PLAT-61, TEST-PLAT-12: escapes of bytes the serializer writes
    ///      bare -- `%61`, `%20` (written `+`), and `%2A` in the credential --
    ///      are refused at their `%`.
    function test_rejectsAnExchangeWithAnEscapeTheSerializerWritesBare() public {
        bytes memory body = _exchangeBody("%61bc", "https%3A%2F%2Fa.example", "0123456789abcdef0123456789abcdef");
        TlsNotaryVerifierBase.TlsNotaryProof memory s = _withExchangeBody(body);
        vm.expectRevert(
            abi.encodeWithSelector(CeremonyFields.MalformedForm.selector, AttestationBuilder.indexOf(body, "%61"))
        );
        this.run{value: quote}(s);

        body = _exchangeBody("a%20b", "https%3A%2F%2Fa.example", "0123456789abcdef0123456789abcdef");
        s = _withExchangeBody(body);
        vm.expectRevert(
            abi.encodeWithSelector(CeremonyFields.MalformedForm.selector, AttestationBuilder.indexOf(body, "%20"))
        );
        this.run{value: quote}(s);

        body = _exchangeBody("abc", "https%3A%2F%2Fa.example", "0123456789abcdef%2A0123456789abcdef");
        s = _withExchangeBody(body);
        vm.expectRevert(
            abi.encodeWithSelector(CeremonyFields.MalformedForm.selector, AttestationBuilder.indexOf(body, "%2A"))
        );
        this.run{value: quote}(s);
    }

    /// @dev TEST-PLAT-12: canonical escapes of bytes above ASCII in the code and
    ///      redirect pass the form check.
    function test_acceptsAnExchangeWithEscapedBytesInTheCodeAndRedirect() public {
        TlsNotaryVerifierBase.TlsNotaryProof memory s = _withExchangeBody(
            _exchangeBody("caf%C3%A9", "https%3A%2F%2Fa.example%2F%E2%82%AC", "0123456789abcdef0123456789abcdef")
        );
        assertEq(this.run{value: quote}(s).handleNode, HANDLE_NODE);
    }

    /// @dev TEST-PLAT-12: a `+`, an escaped tab and an escaped byte above ASCII
    ///      are accepted in the credential.
    function test_acceptsACredentialTheVerifierNeverReads() public {
        string[3] memory secrets =
            ["0123456789abcdef+0123456789abcdef", "%090123456789abcdef", "0123456789abcdef%C3%A9"];
        for (uint256 i = 0; i < secrets.length; ++i) {
            TlsNotaryVerifierBase.TlsNotaryProof memory s =
                _withExchangeBody(_exchangeBody("abc", "https%3A%2F%2Fa.example", secrets[i]));
            assertEq(this.run{value: quote}(s).handleNode, HANDLE_NODE);
        }
    }

    /// @dev TEST-PLAT-12: a credential of every ASCII byte the serializer
    ///      escapes, including the delimiters, is one value.
    function test_acceptsACredentialOfEscapedDelimiters() public {
        TlsNotaryVerifierBase.TlsNotaryProof memory s = _withExchangeBody(
            _exchangeBody("abc", "https%3A%2F%2Fa.example", "%21%22%23%24%25%26%27%28%29%2B%2C%2F%3A%3B%3D%7E")
        );
        assertEq(this.run{value: quote}(s).handleNode, HANDLE_NODE);
    }

    /// @dev REQ-COMMON-16B, TEST-PLAT-12: `my%2Bapp` passes the form check and
    ///      fails the `client_id` charset.
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

    /// @dev REQ-COMMON-16B, TEST-PLAT-12: an empty identifier fails the form check.
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

    /// @dev TEST-PLAT-14: `content-length` must declare the whole revealed body.
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

    /// @dev REQ-PLAT-56A, TEST-PLAT-14: the credential travels only in the body.
    function test_rejectsAForbiddenHeaderOnTheExchange() public {
        bytes memory body = _exchangeBody();
        bytes memory headers = abi.encodePacked(EXCHANGE_HEADERS, "authorization: Basic bXlDbGllbnQtMTpzM2NyZXQ=\r\n");
        TlsNotaryVerifierBase.TlsNotaryProof memory s = _withExchange(_exchangeHead(headers, body.length), body);
        vm.expectRevert(
            abi.encodeWithSelector(TlsNotaryVerifierBase.ForbiddenRequestHeader.selector, bytes("authorization"))
        );
        this.run{value: quote}(s);
    }

    /// @dev TEST-PLAT-12: `+`, the serializer's space, stays inside one value.
    function test_acceptsAnExchangeWithAPlusInAValue() public {
        TlsNotaryVerifierBase.TlsNotaryProof memory s =
            _withExchangeBody(_exchangeBody("abc+def", "https%3A%2F%2Fa.example", "0123456789abcdef0123456789abcdef"));
        assertEq(this.run{value: quote}(s).handleNode, HANDLE_NODE);
    }

    /// @dev TEST-PLAT-12: `%26` and `%3D` stay bytes of one value.
    function test_acceptsAnExchangeWithEncodedDelimitersInAValue() public {
        TlsNotaryVerifierBase.TlsNotaryProof memory s =
            _withExchangeBody(_exchangeBody("abc", "https%3A%2F%2Fa.example", "0123%26code_verifier%3DEVIL"));
        assertEq(this.run{value: quote}(s).handleNode, HANDLE_NODE);
    }

    // ─── Two authorities, not one ───────────────────────────────────

    /// @dev `github.com` serves the exchange and `api.github.com` the identity read.
    function test_rejectsTheExchangeFromTheApiHost() public {
        TlsNotaryVerifierBase.TlsNotaryProof memory s = _payload();
        s.tokenSession = _exchange(CeremonyProfile.AUTHORITY_GITHUB_API);
        vm.expectPartialRevert(PlatformVerifierBase.WrongAuthority.selector);
        this.run{value: quote}(s);
    }

    function test_rejectsTheIdentityReadFromTheExchangeHost() public {
        TlsNotaryVerifierBase.TlsNotaryProof memory s = _payload();
        s.identitySession = _identity(CeremonyProfile.AUTHORITY_GITHUB);
        vm.expectPartialRevert(PlatformVerifierBase.WrongAuthority.selector);
        this.run{value: quote}(s);
    }

    // ─── The bare-integer id (REQ-PLAT-51) ──────────────────────────

    function _refusedFraming(AttestationBuilder.Direction memory received, bytes4 error_) private {
        TlsNotaryVerifierBase.TlsNotaryProof memory s = _payload();
        s.identitySession = _identityReceiving(received, CeremonyProfile.AUTHORITY_GITHUB_API);
        vm.expectPartialRevert(error_);
        this.run{value: quote}(s);
    }

    function _accepted(AttestationBuilder.Direction memory received) private returns (ICeremony.VerifiedClaim memory) {
        TlsNotaryVerifierBase.TlsNotaryProof memory s = _payload();
        s.identitySession = _identityReceiving(received, CeremonyProfile.AUTHORITY_GITHUB_API);
        return this.run{value: quote}(s);
    }

    /// @dev `}` ends the id as well as `,`, with JSON whitespace before either.
    function test_framesTheIdWithEitherTerminator() public {
        AttestationBuilder.Direction memory received = _upToTheId();
        received.reveal('"id": ').commit("583231", ID_COMMITMENT).reveal("\n}");
        assertEq(_accepted(received).idNode, ID_NODE);

        received = _upToTheId();
        received.reveal('"id":').commit("583231", ID_COMMITMENT).reveal(" ,").commit('"name":"x"}', OTHER);
        assertEq(_accepted(received).idNode, ID_NODE);
    }

    /// @dev The terminator proves the committed digits are the whole number.
    function test_refusesAnIdWithoutAStructuralTerminator() public {
        AttestationBuilder.Direction memory received = _upToTheId();
        received.reveal('"id": ').commit("583231", ID_COMMITMENT).reveal(";").commit("}", OTHER);
        _refusedFraming(received, CeremonyAttestation.NoFramedCommitment.selector);
    }

    /// @dev A commitment over part of the digits, the rest revealed: the byte
    ///      after the commitment is a digit, so it frames nothing.
    function test_refusesACommitmentOverPartOfTheId() public {
        AttestationBuilder.Direction memory received = _upToTheId();
        received.reveal('"id": ').commit("5832", ID_COMMITMENT).reveal("31,").commit("}", OTHER);
        _refusedFraming(received, CeremonyAttestation.NoFramedCommitment.selector);
    }

    /// @dev The terminator committed with the digits: what follows is the next
    ///      member's quote, which ends no number.
    function test_refusesAnIdCommittedWithItsTerminator() public {
        AttestationBuilder.Direction memory received = _upToTheId();
        received.reveal('"id": ').commit("583231,", ID_COMMITMENT).reveal('\n  "node_id": ').commit('"x"}', OTHER);
        _refusedFraming(received, CeremonyAttestation.NoFramedCommitment.selector);
    }

    /// @dev Only whitespace revealed after the digits, the terminator hidden:
    ///      nothing revealed says where the number ends.
    function test_refusesAnIdWhoseTerminatorIsHidden() public {
        AttestationBuilder.Direction memory received = _upToTheId();
        received.reveal('"id": ').commit("583231", ID_COMMITMENT).reveal(" ").commit(",}", OTHER);
        _refusedFraming(received, CeremonyAttestation.NoFramedCommitment.selector);
    }

    /// @dev An id anchor escaped inside a revealed string is no anchor: with
    ///      the real member hidden, nothing frames the id.
    function test_refusesAnEscapedIdAnchorInARevealedString() public {
        bytes[2] memory decoys = [bytes('"name":"x\\"id\\":\\"999\\"y",'), bytes('"bio":"\\"id\\":999,",')];
        for (uint256 i = 0; i < decoys.length; ++i) {
            AttestationBuilder.Direction memory received = _upToTheId();
            received.reveal(decoys[i]).commit('"id": 583231\n}', OTHER);
            _refusedFraming(received, CeremonyAttestation.NoFramedCommitment.selector);
        }
    }

    /// @dev The digits revealed, nothing committed: the id is on chain and
    ///      there is no commitment for the circuit to open.
    function test_refusesARevealedId() public {
        AttestationBuilder.Direction memory received = _upToTheId();
        received.reveal('"id": 583231,').commit("}", OTHER);
        _refusedFraming(received, CeremonyAttestation.NoFramedCommitment.selector);
    }

    /// @dev REQ-PLAT-08: with the quote revealed, the anchor is `"id":"`, not
    ///      `"id":`, so nothing is framed.
    function test_rejectsAQuotedId() public {
        AttestationBuilder.Direction memory received = _upToTheId();
        received.reveal('"id": "').commit("583231", ID_COMMITMENT).reveal('",').commit("}", OTHER);
        _refusedFraming(received, CeremonyAttestation.NoFramedCommitment.selector);
    }

    /// @dev The verifier checks framing only: a framed commitment over `007` or
    ///      a quoted value reaches the proof.
    function test_leavesTheIdsDigitsToTheCircuit() public {
        AttestationBuilder.Direction memory received = _upToTheId();
        received.reveal('"id": ').commit("007", ID_COMMITMENT).reveal(",").commit("}", OTHER);
        assertEq(_accepted(received).idNode, ID_NODE);

        received = _upToTheId();
        received.reveal('"id": ').commit('"583231"', ID_COMMITMENT).reveal(",").commit("}", OTHER);
        assertEq(_accepted(received).idNode, ID_NODE);
    }

    /// @dev A key that ends like the anchor is not the anchor: `"node_id":`
    ///      frames no id, so a response revealing only it has none.
    function test_refusesALookalikeIdKey() public {
        AttestationBuilder.Direction memory received = _upToTheId();
        received.reveal('"node_id": ').commit("583231", ID_COMMITMENT).reveal(",").commit("}", OTHER);
        _refusedFraming(received, CeremonyAttestation.NoFramedCommitment.selector);
    }

    /// @dev The key cut by a hidden byte: `"i`, a commitment, `d": `.
    function test_refusesAnIdAnchorSplitAroundACommittedGap() public {
        AttestationBuilder.Direction memory received = _upToTheId();
        received.reveal('"i')
            .commit("d", OTHER)
            .reveal('": ')
            .commit("583231", ID_COMMITMENT)
            .reveal(",")
            .commit("}", OTHER);
        _refusedFraming(received, CeremonyAttestation.NoFramedCommitment.selector);
    }

    /// @dev Two id anchors revealed, each framing a commitment.
    function test_refusesTwoFramedIds() public {
        AttestationBuilder.Direction memory received = _upToTheId();
        received.reveal('"id": ')
            .commit("583231", ID_COMMITMENT)
            .reveal(",")
            .commit("\n  ", OTHER)
            .reveal('"id": ')
            .commit("1", OTHER)
            .reveal("}");
        _refusedFraming(received, CeremonyAttestation.AmbiguousFraming.selector);
    }

    // ─── The handle field is `login` ────────────────────────────────

    function test_rejectsAResponseWithNoLogin() public {
        AttestationBuilder.Direction memory received;
        received.commit("HTTP/1.1 200 OK\r\n\r\n{", OTHER)
            .reveal('"username":"')
            .commit("OctoCat", HANDLE_COMMITMENT)
            .reveal('",')
            .reveal('"id":')
            .commit("583231", ID_COMMITMENT)
            .reveal("}");
        _refusedFraming(received, CeremonyAttestation.NoFramedCommitment.selector);
    }

    /// @dev A second `login` in another spelling is a second `login`: the
    ///      count compares with JSON whitespace removed.
    function test_rejectsADuplicateMemberInAnotherWhitespaceSpelling() public {
        AttestationBuilder.Direction memory received = _upToTheId();
        received.reveal('"id": ')
            .commit("583231", ID_COMMITMENT)
            .reveal(",")
            .commit("\n  ", OTHER)
            .reveal('"login" : "')
            .commit("mallory", OTHER)
            .reveal('"}');
        _refusedFraming(received, CeremonyAttestation.AmbiguousFraming.selector);
    }

    /// @dev The login committed with its closing quote frames nothing.
    function test_refusesALoginCommittedWithItsClosingQuote() public {
        AttestationBuilder.Direction memory received;
        received.commit("HTTP/1.1 200 OK\r\n\r\n{\n  ", OTHER)
            .reveal('"login": "')
            .commit('OctoCat"', HANDLE_COMMITMENT)
            .reveal(",")
            .commit("\n  ", OTHER)
            .reveal('"id": ')
            .commit("583231", ID_COMMITMENT)
            .reveal("}");
        _refusedFraming(received, CeremonyAttestation.NoFramedCommitment.selector);
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

    /// @dev REQ-COMMON-19A: a second revealed `authorization:` header on the
    ///      identity read is refused.
    function test_rejectsASecondAuthorizationHeaderOnTheIdentityRead() public {
        TlsNotaryVerifierBase.TlsNotaryProof memory s = _payload();
        s.identitySession = _identityWithHeadPrefix("authorization: Bearer stolen\r\n");
        vm.expectPartialRevert(CeremonyAttestation.NotOneAuthorizationHeader.selector);
        this.run{value: quote}(s);
    }

    /// @dev GitHub honours `token` and Basic beside Bearer, so a second
    ///      `authorization` counts whatever its scheme.
    function test_rejectsASecondAuthorizationHeaderOfAnotherSchemeOnTheIdentityRead() public {
        TlsNotaryVerifierBase.TlsNotaryProof memory s = _payload();
        s.identitySession = _identityWithHeadPrefix("Authorization: token ghp_stolen\r\n");
        vm.expectPartialRevert(CeremonyAttestation.NotOneAuthorizationHeader.selector);
        this.run{value: quote}(s);
    }

    /// @dev The identity read carries exactly one HTTP request.
    function test_rejectsASecondRequestOnTheIdentityRead() public {
        TlsNotaryVerifierBase.TlsNotaryProof memory s = _payload();
        s.identitySession = _identityWithHead(
            "GET /user HTTP/1.1\r\nhost: api.github.com\r\nauthorization: Bearer ",
            "\r\n\r\nGET /user HTTP/1.1\r\nhost: api.github.com\r\nauthorization: token ghp_OTHER\r\n\r\n"
        );
        vm.expectRevert(abi.encodeWithSelector(CeremonyAttestation.NotOneRequest.selector, 2));
        this.run{value: quote}(s);
    }

    /// @dev `host` names the API authority, not the exchange's.
    function test_rejectsAnIdentityReadNamingAnotherHost() public {
        TlsNotaryVerifierBase.TlsNotaryProof memory s = _payload();
        s.identitySession = _identityWithHead(
            "GET /user HTTP/1.1\r\nhost: github.com\r\nauthorization: Bearer ", "\r\nconnection: close\r\n\r\n"
        );
        vm.expectRevert(TlsNotaryVerifierBase.WrongIdentityRequestHead.selector);
        this.run{value: quote}(s);
    }

    /// @dev A `cookie` on the identity read is refused by name.
    function test_rejectsACookieOnTheIdentityRead() public {
        TlsNotaryVerifierBase.TlsNotaryProof memory s = _payload();
        s.identitySession = _identityWithHeadPrefix("cookie: user_session=stolen\r\n");
        vm.expectRevert(abi.encodeWithSelector(TlsNotaryVerifierBase.ForbiddenRequestHeader.selector, bytes("cookie")));
        this.run{value: quote}(s);
    }

    /// @dev The identity request with the headers the browser sends, in its order
    ///      (`host`, `authorization`, `accept`, `user-agent`, `x-github-api-version`, `connection`).
    function test_verifiesTheIdentityRequestTheBrowserSends() public {
        TlsNotaryVerifierBase.TlsNotaryProof memory s = _payload();
        s.identitySession = _identityWithHead(
            "GET /user HTTP/1.1\r\nhost: api.github.com\r\nauthorization: Bearer ",
            "\r\naccept: application/vnd.github+json\r\n"
            "user-agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36\r\n"
            "x-github-api-version: 2022-11-28\r\nconnection: close\r\n\r\n"
        );
        ICeremony.VerifiedClaim memory f = this.run{value: quote}(s);
        assertEq(f.handleNode, HANDLE_NODE);
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
        bytes memory attested =
            AttestationBuilder.encode(CeremonyProfile.AUTHORITY_GITHUB_API, T0, sent, _identityResponse());
        return ICeremony.Attestation({attestedData: attested, proof: AttestationBuilder.sign(NOTARY_KEY, attested)});
    }

    string constant RUST_SESSION = "contracts/ceremony/test/fixtures/github-ceremony-session.json";

    /// @dev Verifies the session libid-rs's Rust pipeline produces, signatures unedited.
    ///      Generated by `cargo run -p libid-tlsn --example ceremony_fixtures` in libid-rs.
    function test_verifiesTheRecordsLibidRsProduces() public {
        string memory json = vm.readFile(RUST_SESSION);
        assertEq(vm.parseJsonBytes32(json, ".authorization_digest"), digest, "derived from this suite's digest");
        assertEq(vm.parseJsonBytes32(json, ".authorization_nonce"), AUTH_NONCE);
        assertEq(vm.parseJsonAddress(json, ".notary"), vm.addr(NOTARY_KEY), "signed by the key this suite trusts");
        assertEq(uint64(vm.parseJsonUint(json, ".created_at")), T0);
        // The identity response keeps GitHub's pretty-printing for the pinned media type.
        assertTrue(
            AttestationBuilder.contains(vm.parseJsonBytes(json, ".identity.received"), bytes('"login": "OctoCat"')),
            "the fixture carries GitHub's pretty-printed response"
        );

        TlsNotaryVerifierBase.TlsNotaryProof memory s = _payload();
        s.tokenSession = AttestationBuilder.fixtureSession(json, ".token");
        s.identitySession = AttestationBuilder.fixtureSession(json, ".identity");
        ICeremony.VerifiedClaim memory f = this.run{value: quote}(s);
        assertEq(f.idNode, ID_NODE);
        assertEq(f.handleNode, HANDLE_NODE);
        assertEq(string(f.clientIdentifier), "Iv1.8a61f9b3a7aba766");
        assertEq(f.sessionId, digest);
    }

    /// @dev The record reveals the anchors and the id's terminator, and
    ///      neither value in any case.
    function test_theIdentityRecordRevealsNeitherTheIdNorTheLogin() public view {
        bytes memory attested = vm.parseJsonBytes(vm.readFile(RUST_SESSION), ".identity.attested_data");
        assertFalse(AttestationBuilder.contains(attested, "583231"), "the id");
        assertFalse(AttestationBuilder.contains(attested, "OctoCat"), "the login");
        assertFalse(AttestationBuilder.contains(attested, "octocat"), "the folded login");
        assertTrue(AttestationBuilder.contains(attested, '"login": "'), "the login's anchor");
        assertTrue(AttestationBuilder.contains(attested, '"id": '), "the id's anchor");
    }

    /// @dev The fixture opening, SHA-256(value || blinder), matches the signed
    ///      commitments, and the framing finds exactly those two.
    function test_theWitnessOpensTheCommitmentsTheFramingFinds() public view {
        string memory json = vm.readFile(RUST_SESSION);
        assertEq(vm.parseJsonString(json, ".identity_link_witness.id.value"), "583231");
        assertEq(vm.parseJsonString(json, ".identity_link_witness.handle.value"), "OctoCat");

        bytes32 id = vm.parseJsonBytes32(json, ".identity_link_witness.id.commitment");
        bytes32 handle = vm.parseJsonBytes32(json, ".identity_link_witness.handle.commitment");
        assertEq(sha256(bytes.concat("583231", _blinder(json, ".identity_link_witness.id.blinder"))), id);
        assertEq(sha256(bytes.concat("OctoCat", _blinder(json, ".identity_link_witness.handle.blinder"))), handle);

        CeremonyAttestation.AttestedData memory data = this.decode(vm.parseJsonBytes(json, ".identity.attested_data"));
        assertEq(
            CeremonyAttestation.requireFramedInteger(CeremonyAttestation.framing(data.received), '"id":').commitment, id
        );
        assertEq(CeremonyAttestation.requireFramedCommitment(data.received, '"login":"', '"').commitment, handle);
    }

    function decode(bytes calldata attested) external pure returns (CeremonyAttestation.AttestedData memory) {
        return CeremonyAttestation.decode(attested);
    }

    string constant RUST_SESSION_PROOF = "contracts/ceremony/test/fixtures/github-ceremony-session-proof.json";

    function _platformVerifier() internal view override returns (PlatformVerifierBase) {
        return verifier;
    }

    function _notary() internal view override returns (INotaryService) {
        return INotaryService(address(notary));
    }

    function _session() internal pure override returns (string memory) {
        return RUST_SESSION;
    }

    function _proofFile() internal pure override returns (string memory) {
        return RUST_SESSION_PROOF;
    }

    function _otherSession() internal pure override returns (string memory) {
        return "contracts/ceremony/test/fixtures/x-ceremony-session.json";
    }

    /// @dev A real proof outputs the hashlib nodes for `583231` and `octocat`.
    function test_verifiesARealProofOfTheRecordsLibidRsProduces() public {
        (TlsNotaryVerifierBase.TlsNotaryProof memory s, address circuit, bytes32[] memory proved) = _realProofPayload();
        assertEq(proved.length, 16);
        vm.expectCall(circuit, abi.encodeCall(IHonkVerifier.verify, (s.proof, proved)));
        ICeremony.VerifiedClaim memory f = this.run{value: quote}(s);
        assertEq(f.idNode, 0x475902b27989feb395b9b0cd3156aa573a9676c13155b8e7e3ddaf3e77181847, "hashlib idNode");
        assertEq(f.handleNode, 0x381fb9d7d3b01214e58b94202ea10f78e169adef68bcc20d40c130deca6dfe74, "hashlib handleNode");
        assertEq(string(f.clientIdentifier), "Iv1.8a61f9b3a7aba766");
        assertEq(f.sessionId, digest);
        assertEq(f.operationDomain, DOMAIN);
        assertEq(f.transactionData, _txData());
        assertEq(f.ceremonyVersion, 1);
        assertEq(f.metadataObservedAt, T0 - ALLOWANCE);
    }

    /// @dev This suite's GitHub sessions and proof are refused by an X verifier.
    function test_anXVerifierRefusesAGitHubCeremony() public {
        (TlsNotaryVerifierBase.TlsNotaryProof memory s,,) = _realProofPayload();
        address circuit = vm.deployCode(HonkStub.BEARER_LINK);
        XPlatformVerifier x = XPlatformVerifier(
            address(
                new ERC1967Proxy(
                    address(new XPlatformVerifier()),
                    abi.encodeCall(
                        XPlatformVerifier.initialize, (OWNER, INotaryService(address(notary)), IHonkVerifier(circuit))
                    )
                )
            )
        );
        uint256 value = x.quote();
        vm.expectPartialRevert(PlatformVerifierBase.WrongAuthority.selector);
        x.verify{value: value}(abi.encode(s));
    }

    /// @dev Anchors match the pretty-printed `/user` with JSON whitespace
    ///      removed.
    function test_framesTheIdentityGitHubPrettyPrints() public {
        AttestationBuilder.Direction memory received;
        received.commit("HTTP/1.1 200 OK\r\n\r\n{\n  ", OTHER)
            .reveal('"login" :  "')
            .commit("OctoCat", HANDLE_COMMITMENT)
            .reveal('"')
            .commit(",\n  ", OTHER)
            .reveal('"id"\t:\n ')
            .commit("583231", ID_COMMITMENT)
            .reveal("\n,")
            .commit('"name": "The Octocat"\n}', OTHER);
        ICeremony.VerifiedClaim memory f = _accepted(received);
        assertEq(f.idNode, ID_NODE);
        assertEq(f.handleNode, HANDLE_NODE);
    }

    string constant REAL_SESSION = "contracts/ceremony/test/fixtures/github-ceremony-real.json";

    /// @dev A captured ceremony (libid-rs `examples/capture_ceremony.rs`):
    ///      its token session and identity request pass every transcript check.
    function test_theRealTokenSessionAndIdentityRequestVerify() public {
        string memory json = vm.readFile(REAL_SESSION);
        ICeremony.Attestation memory token = AttestationBuilder.fixtureSession(json, ".token");
        ICeremony.Attestation memory identity = AttestationBuilder.fixtureSession(json, ".identity");
        CeremonyAttestation.AttestedData memory tokenData = notary.verify{value: FEE}(token.attestedData, token.proof);
        CeremonyAttestation.AttestedData memory identityData =
            notary.verify{value: FEE}(identity.attestedData, identity.proof);
        assertEq(tokenData.authorityId, CeremonyProfile.AUTHORITY_GITHUB);
        assertEq(identityData.authorityId, CeremonyProfile.AUTHORITY_GITHUB_API);

        GitHubTranscripts transcripts = new GitHubTranscripts();
        (bytes memory clientId, bytes32 tokenCommitment) = transcripts.tokenTranscript(
            tokenData,
            vm.parseJsonBytes32(json, ".authorization_digest"),
            vm.parseJsonBytes32(json, ".authorization_nonce")
        );
        assertEq(string(clientId), "Iv23lioEM9NAR9vO8CmT");
        assertTrue(tokenCommitment != bytes32(0));
        assertEq(transcripts.identityRequest(identityData), identityData.sent.commitments[0].commitment);
    }

    /// @dev The whole captured record: its response reveals the anchors and
    ///      commits the login and the id.
    function test_verifiesTheRecordsACeremonyProduced() public {
        string memory json = vm.readFile(REAL_SESSION);
        assertEq(vm.parseJsonBytes32(json, ".authorization_digest"), digest, "bound to this suite's digest");
        vm.warp(vm.parseJsonUint(json, ".identity.created_at") + 60);

        TlsNotaryVerifierBase.TlsNotaryProof memory s = _payload();
        s.tokenSession = AttestationBuilder.fixtureSession(json, ".token");
        s.identitySession = AttestationBuilder.fixtureSession(json, ".identity");
        ICeremony.VerifiedClaim memory f = this.run{value: quote}(s);
        assertEq(string(f.clientIdentifier), "Iv23lioEM9NAR9vO8CmT");
        assertEq(f.sessionId, digest);
    }

    /// @dev The wrong authority is still refused before any field is read.
    function test_rejectsAnIdentityReadFromTheWrongAuthority() public {
        TlsNotaryVerifierBase.TlsNotaryProof memory s = _payload();
        bytes memory attested = s.identitySession.attestedData;
        attested[0] = bytes1(uint8(attested[0]) ^ 0x01);
        s.identitySession =
            ICeremony.Attestation({attestedData: attested, proof: AttestationBuilder.sign(NOTARY_KEY, attested)});
        vm.expectPartialRevert(PlatformVerifierBase.WrongAuthority.selector);
        this.run{value: quote}(s);
    }

    /// The honest identity read, with extra revealed header lines after the
    /// request line.
    function _identityWithHeadPrefix(string memory extraHeaders) private pure returns (ICeremony.Attestation memory) {
        bytes memory head = abi.encodePacked(
            "GET /user HTTP/1.1\r\n",
            extraHeaders,
            "accept: application/vnd.github+json\r\nhost: api.github.com\r\nauthorization: Bearer "
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
        bytes memory attested =
            AttestationBuilder.encode(CeremonyProfile.AUTHORITY_GITHUB_API, T0, sent, _identityResponse());
        return ICeremony.Attestation({attestedData: attested, proof: AttestationBuilder.sign(NOTARY_KEY, attested)});
    }

    /// A committed request line passes coverage and fails the origin rule.
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
        s.tokenSession = ICeremony.Attestation({attestedData: a, proof: AttestationBuilder.sign(NOTARY_KEY, a)});
        vm.expectRevert(abi.encodeWithSelector(TlsNotaryVerifierBase.RequestLineNotAtOrigin.selector, uint32(40)));
        this.run{value: quote}(s);
    }

    /// @dev A request hiding a body suffix behind a commitment is refused.
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
        s.tokenSession = ICeremony.Attestation({attestedData: a, proof: AttestationBuilder.sign(NOTARY_KEY, a)});
        vm.expectRevert(abi.encodeWithSelector(TlsNotaryVerifierBase.WrongTokenRequestLayout.selector, 1, 1));
        this.run{value: quote}(s);
    }

    /// @dev REQ-COMMON-21B: `github/v1` pins its exchange head; the media type
    ///      decides whether GitHub parses the body as a form.
    function test_rejectsAnotherMediaTypeOnTheExchange() public {
        bytes memory body = _exchangeBody();
        bytes memory head = _exchangeHead(
            "host: github.com\r\ncontent-type: application/json\r\naccept: application/json\r\nconnection: close\r\n",
            body.length
        );
        AttestationBuilder.Direction memory sent = _wholeSent(abi.encodePacked(head, body));
        bytes memory a = AttestationBuilder.encode(CeremonyProfile.AUTHORITY_GITHUB, T0, sent, _exchangeResponse());
        TlsNotaryVerifierBase.TlsNotaryProof memory s = _payload();
        s.tokenSession = ICeremony.Attestation({attestedData: a, proof: AttestationBuilder.sign(NOTARY_KEY, a)});
        vm.expectRevert(TlsNotaryVerifierBase.WrongTokenRequestHead.selector);
        this.run{value: quote}(s);
    }

    /// @dev A header the profile does not name or forbid is accepted.
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
        s.tokenSession = ICeremony.Attestation({attestedData: a, proof: AttestationBuilder.sign(NOTARY_KEY, a)});
        ICeremony.VerifiedClaim memory f = this.run{value: quote}(s);
        assertEq(f.handleNode, HANDLE_NODE);
    }

    /// @dev The suite's composed head carries the headers the profile requires.
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
        s.tokenSession = ICeremony.Attestation({attestedData: a, proof: AttestationBuilder.sign(NOTARY_KEY, a)});
        vm.expectRevert(CeremonyAttestation.NoFramedCommitment.selector);
        this.run{value: quote}(s);
    }

    function test_rejectsAPayloadForAnotherCeremonyVersion() public {
        TlsNotaryVerifierBase.TlsNotaryProof memory s = _payload();
        s.ceremonyVersion = 2;
        vm.expectRevert(abi.encodeWithSelector(PlatformVerifierBase.WrongCeremonyVersion.selector, 1, 2));
        this.run{value: quote}(s);
    }

    /// @dev REQ-PLAT-52B: the 16 public inputs, built here independently of
    ///      the verifier; each tag is int.from_bytes(tag.ljust(31, b"\0"), "big").
    function test_provesAgainstTheCommitmentsTheNotarySigned() public {
        bytes32[] memory expected = new bytes32[](16);
        bytes32[6] memory wide =
            [TOKEN_COMMITMENT, IDENTITY_COMMITMENT, ID_COMMITMENT, HANDLE_COMMITMENT, ID_NODE, HANDLE_NODE];
        for (uint256 k = 0; k < 6; ++k) {
            expected[2 * k] = bytes32(uint256(wide[k]) / 2 ** 128);
            expected[2 * k + 1] = bytes32(uint256(wide[k]) % 2 ** 128);
        }
        expected[12] = 0x006c696269642e6769746875622e757365722d69640000000000000000000000; // libid.github.user-id
        expected[13] = bytes32(uint256(20));
        expected[14] = 0x006c696269642e6769746875622e68616e646c65000000000000000000000000; // libid.github.handle
        expected[15] = bytes32(uint256(19));
        TlsNotaryVerifierBase.TlsNotaryProof memory s = _payload();
        vm.expectCall(address(honk), abi.encodeCall(IHonkVerifier.verify, (s.proof, expected)));
        this.run{value: quote}(s);
    }
}
