// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {XTranscripts} from "./TranscriptEquivalence.t.sol";
import {CircuitCodehashes} from "../../circuits/CircuitCodehashes.sol";
import {HonkStub} from "./HonkStub.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

import {AttestationBuilder} from "./AttestationBuilder.sol";
import {CeremonyAttestation} from "../CeremonyAttestation.sol";
import {CeremonyAuthorization} from "../CeremonyAuthorization.sol";
import {CeremonyFields} from "../CeremonyFields.sol";
import {CeremonyProfile} from "../CeremonyProfile.sol";
import {ICeremony} from "../ICeremony.sol";
import {INotaryService} from "../INotaryService.sol";
import {RealTlsNotaryProofTest} from "./RealTlsNotaryProof.sol";
import {NotaryService} from "../NotaryService.sol";
import {IHonkVerifier, PlatformVerifierBase} from "../PlatformVerifierBase.sol";
import {TlsNotaryVerifierBase} from "../TlsNotaryVerifierBase.sol";
import {XPlatformVerifier} from "../XPlatformVerifier.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";

/// @notice A profile whose allowance sits below its skew.
contract SkewPastAllowance is PlatformVerifierBase {
    uint64 public constant SKEW = 300;

    function requireFresh(uint64 createdAt) external view returns (uint64) {
        return _requireFresh(createdAt);
    }

    function _platform() internal pure override returns (bytes32) {
        return CeremonyProfile.PLATFORM_X;
    }

    function _ceremonyVersion() internal pure override returns (uint16) {
        return CeremonyProfile.LAUNCH_VERSION;
    }

    function _circuitCodehash() internal pure override returns (bytes32) {
        return bytes32(0);
    }

    function _proofLifetime() internal pure override returns (uint64) {
        return 3600;
    }

    function _maxFutureAttestationSkew() internal pure override returns (uint64) {
        return SKEW;
    }

    function _futureObservationAllowance() internal pure override returns (uint64) {
        return 0;
    }
}

/// @notice An X verifier that pins the Google circuit's code hash.
contract XPinningGooglesCircuit is XPlatformVerifier {
    function _circuitCodehash() internal pure override returns (bytes32) {
        return CircuitCodehashes.OIDC_GOOGLE;
    }
}

/// @notice The `x/v1` path end to end: two notary-signed attestations and
///         every check the profile assigns to the verifier.
contract XPlatformVerifierTest is RealTlsNotaryProofTest {
    using AttestationBuilder for AttestationBuilder.Range;
    using AttestationBuilder for AttestationBuilder.Direction;

    XPlatformVerifier verifier;
    NotaryService notary;
    address honk;
    /// Read once in `setUp`: an external call in a `{value:}` argument would consume `expectRevert`.
    uint256 quote;

    uint256 constant FEE = 0.001 ether;
    uint64 constant LIFETIME = CeremonyProfile.PROOF_LIFETIME_SECONDS_X;
    uint64 constant SKEW = CeremonyProfile.MAX_FUTURE_ATTESTATION_SKEW_SECONDS_X;
    uint64 constant ALLOWANCE = CeremonyProfile.FUTURE_OBSERVATION_ALLOWANCE_SECONDS_X;
    uint64 constant T0 = 1_770_000_000;

    bytes32 constant DOMAIN = keccak256(bytes("libid.bind-identity"));
    bytes32 constant AUTH_NONCE = bytes32(uint256(0x5555555555555555555555555555555555555555555555555555555555555555));
    /// The digest the verifier rebuilds from the payload; set in `setUp`.
    bytes32 digest;

    bytes32 constant TOKEN_COMMITMENT = bytes32(uint256(0x1111));
    bytes32 constant IDENTITY_COMMITMENT = bytes32(uint256(0x2222));
    bytes32 constant ID_COMMITMENT = bytes32(uint256(0x3333));
    bytes32 constant HANDLE_COMMITMENT = bytes32(uint256(0x4444));
    /// Whatever else the response hides: the status, the other members.
    bytes32 constant OTHER = bytes32(uint256(0x5555));

    /// The fixture account's nodes, from Python's hashlib:
    ///   hashlib.sha256(b"libid.x.user-id2244994945")
    ///   hashlib.sha256(b"libid.x.handlealice_1")  (`Alice_1`, folded)
    bytes32 constant ID_NODE = 0x68291869976ffad2abf3e933ec9ab2623395ff8b3b9242e655e1da3ef43d4f94;
    bytes32 constant HANDLE_NODE = 0xe09c4f5bfbbc723bc35701ea9d718a1c5edb29b1ed5bb0cb0fabb3c43d8136af;

    function setUp() public {
        vm.warp(T0 + 10);
        digest = CeremonyAuthorization.digest(DOMAIN, 1, AUTH_NONCE, _txData());

        NotaryService nImpl = new NotaryService();
        notary = NotaryService(
            address(
                new ERC1967Proxy(
                    address(nImpl), abi.encodeCall(NotaryService.initialize, (OWNER, vm.addr(NOTARY_KEY), FEE))
                )
            )
        );
        honk = HonkStub.deploy(HonkStub.BEARER_LINK);

        XPlatformVerifier vImpl = new XPlatformVerifier();
        verifier = XPlatformVerifier(
            address(
                new ERC1967Proxy(
                    address(vImpl),
                    abi.encodeCall(
                        XPlatformVerifier.initialize,
                        (OWNER, INotaryService(address(notary)), IHonkVerifier(address(honk)))
                    )
                )
            )
        );
        quote = verifier.quote();
        vm.deal(address(this), 100 ether);
    }

    // ─── Building a session ─────────────────────────────────────────

    /// The head the browser sends: the two headers the profile requires, and
    /// two it does not compare.
    bytes constant TOKEN_HEADERS =
        "host: api.x.com\r\ncontent-type: application/x-www-form-urlencoded\r\naccept: application/json\r\nconnection: close\r\n";

    /// A token request head: the request line, `headers`, and the declared body length.
    function _tokenHead(bytes memory headers, uint256 bodyLength) private pure returns (bytes memory) {
        return abi.encodePacked(
            "POST /2/oauth2/token HTTP/1.1\r\n", headers, "content-length: ", vm.toString(bodyLength), "\r\n\r\n"
        );
    }

    /// The token request: request line at offset 0, then the whole form body.
    function _tokenAttestation(string memory grantType, string memory clientId, string memory verifierValue)
        private
        pure
        returns (ICeremony.Attestation memory)
    {
        return _tokenAttestation(grantType, clientId, verifierValue, true);
    }

    /// @dev `bearerFraming` false commits the bearer with no revealed anchors (REQ-PLAT-57).
    function _tokenAttestation(
        string memory grantType,
        string memory clientId,
        string memory verifierValue,
        bool bearerFraming
    ) private pure returns (ICeremony.Attestation memory) {
        AttestationBuilder.Direction memory received;
        // The whole request in one revealed run; the body is located by its HTTP framing.
        bytes memory body = abi.encodePacked(
            "grant_type=",
            grantType,
            "&client_id=",
            clientId,
            "&code=abc&redirect_uri=https%3A%2F%2Fapp.example%2Fcb&code_verifier=",
            verifierValue
        );
        bytes memory whole = abi.encodePacked(_tokenHead(TOKEN_HEADERS, body.length), body);
        uint32 wholeEnd = uint32(whole.length);

        AttestationBuilder.Direction memory sent = AttestationBuilder.Direction({
            revealed: AttestationBuilder.one(AttestationBuilder.Range({start: 0, value: whole})),
            commitments: AttestationBuilder.none(),
            length: wholeEnd
        });
        received = _tokenResponse(bearerFraming);

        bytes memory attested = AttestationBuilder.encode(CeremonyProfile.AUTHORITY_X_API, T0, sent, received);
        return ICeremony.Attestation({attestedData: attested, proof: AttestationBuilder.sign(NOTARY_KEY, attested)});
    }

    /// A token response shaped like the real one:
    ///   [0,15)  revealed `HTTP/1.1 200 OK`
    ///   [15,17) the CRLF closing it, committed
    ///   [17,33) revealed `"access_token":"`
    ///   [33,45) the committed bearer
    ///   [45,46) revealed closing quote
    ///   [46,70) the rest of the JSON, behind another commitment
    function _tokenResponse(bool framed) private pure returns (AttestationBuilder.Direction memory received) {
        bytes memory status = "HTTP/1.1 200 OK";
        bytes memory prefix = '"access_token":"';
        uint32 statusEnd = uint32(status.length);
        uint32 headEnd = 17;
        uint32 prefixEnd = headEnd + uint32(prefix.length);
        uint32 bearerEnd = prefixEnd + 12;
        uint32 quoteEnd = bearerEnd + 1;
        uint32 total = quoteEnd + 24;

        if (framed) {
            return AttestationBuilder.Direction({
                revealed: AttestationBuilder.three(
                    AttestationBuilder.Range({start: 0, value: status}),
                    AttestationBuilder.Range({start: headEnd, value: prefix}),
                    AttestationBuilder.Range({start: bearerEnd, value: '"'})
                ),
                commitments: AttestationBuilder.three(
                    AttestationBuilder.Commitment({start: statusEnd, end: headEnd, value: bytes32(uint256(0x8888))}),
                    AttestationBuilder.Commitment({start: prefixEnd, end: bearerEnd, value: TOKEN_COMMITMENT}),
                    AttestationBuilder.Commitment({start: quoteEnd, end: total, value: bytes32(uint256(0x9999))})
                ),
                length: total
            });
        }

        // Only the status line revealed: an unanchored bearer could be a
        // `refresh_token` value (REQ-PLAT-57).
        return AttestationBuilder.Direction({
            revealed: AttestationBuilder.one(AttestationBuilder.Range({start: 0, value: status})),
            commitments: AttestationBuilder.three(
                AttestationBuilder.Commitment({start: statusEnd, end: prefixEnd, value: bytes32(uint256(0x8888))}),
                AttestationBuilder.Commitment({start: prefixEnd, end: bearerEnd, value: TOKEN_COMMITMENT}),
                AttestationBuilder.Commitment({start: bearerEnd, end: total, value: bytes32(uint256(0x9999))})
            ),
            length: total
        });
    }

    /// The identity request: bearer committed, every other byte revealed.
    function _identityAttestation(string memory idValue, string memory username, string memory extraHeader)
        private
        pure
        returns (ICeremony.Attestation memory)
    {
        return _signedIdentity(_identitySent(extraHeader), _identityResponse(bytes(idValue), bytes(username)));
    }

    /// The identity request with `extraHeader` among its headers, the bearer
    /// committed and every other byte revealed.
    function _identitySent(string memory extraHeader) private pure returns (AttestationBuilder.Direction memory sent) {
        sent.reveal(
                abi.encodePacked(
                    "GET /2/users/me HTTP/1.1\r\naccept: application/json\r\nhost: api.x.com\r\n",
                    extraHeader,
                    "authorization: Bearer "
                )
            )
            .commit("TOKENTOKENTOKEN", IDENTITY_COMMITMENT)
            .reveal("\r\nconnection: close\r\n\r\n");
    }

    /// The identity response: anchors revealed, id and handle each committed,
    /// every other byte committed.
    function _identityResponse(bytes memory id, bytes memory handle)
        private
        pure
        returns (AttestationBuilder.Direction memory received)
    {
        received.commit('HTTP/1.1 200 OK\r\ncontent-type: application/json\r\n\r\n{"data":{', OTHER)
            .reveal('"id":"')
            .commit(id, ID_COMMITMENT)
            .reveal('"')
            .commit(',"name":"Alice",', OTHER)
            .reveal('"username":"')
            .commit(handle, HANDLE_COMMITMENT)
            .reveal('"')
            .commit("}}", OTHER);
    }

    /// An identity attestation over these two directions, signed by the
    /// notary this suite trusts.
    function _signedIdentity(AttestationBuilder.Direction memory sent, AttestationBuilder.Direction memory received)
        private
        pure
        returns (ICeremony.Attestation memory)
    {
        bytes memory attested = AttestationBuilder.encode(CeremonyProfile.AUTHORITY_X_API, T0, sent, received);
        return ICeremony.Attestation({attestedData: attested, proof: AttestationBuilder.sign(NOTARY_KEY, attested)});
    }

    /// The honest identity request around a response of the test's choosing.
    function _identityReceiving(AttestationBuilder.Direction memory received)
        private
        pure
        returns (ICeremony.Attestation memory)
    {
        return _signedIdentity(_identitySent(""), received);
    }

    function _txData() private pure returns (bytes memory) {
        return abi.encode(address(0xBEEF));
    }

    /// The `x/v1` payload the fixtures are made for; the verifier derives the public inputs.
    function _payload() internal view override returns (TlsNotaryVerifierBase.TlsNotaryProof memory s) {
        string memory verifierValue = string(CeremonyAuthorization.codeVerifier(digest, AUTH_NONCE));
        s.ceremonyVersion = 1;
        s.operationDomain = DOMAIN;
        s.authorizationNonce = AUTH_NONCE;
        s.transactionData = _txData();
        s.proof = hex"00";
        s.tokenSession = _tokenAttestation("authorization_code", "myClient-1", verifierValue);
        s.identitySession = _identityAttestation("2244994945", "Alice_1", "");
        s.idNode = ID_NODE;
        s.handleNode = HANDLE_NODE;
    }

    /// The payload as the bytes the Proof Verifier would forward.
    function run(TlsNotaryVerifierBase.TlsNotaryProof memory s)
        external
        payable
        returns (ICeremony.VerifiedClaim memory)
    {
        return verifier.verify{value: msg.value}(abi.encode(s));
    }

    // ─── The happy path ─────────────────────────────────────────────

    function test_verifiesAWholeXCeremony() public {
        ICeremony.VerifiedClaim memory f = this.run{value: quote}(_payload());
        // Passed through from the payload; the stubbed proof accepts any nodes.
        assertEq(f.idNode, ID_NODE);
        assertEq(f.handleNode, HANDLE_NODE);
        assertEq(string(f.clientIdentifier), "myClient-1");
        assertEq(f.sessionId, digest);
        assertEq(f.operationDomain, DOMAIN);
        assertEq(f.transactionData, _txData());
        assertEq(f.ceremonyVersion, 1);
        // On the shared scale: each verifier subtracts its own allowance so
        // claims from different profiles compare.
        assertEq(f.metadataObservedAt, T0 - ALLOWANCE);
    }

    function test_quotesTwoNotaryFees() public view {
        assertEq(verifier.quote(), 2 * notary.fee());
    }

    function test_bothFeesReachTheNotary() public {
        this.run{value: quote}(_payload());
        assertEq(address(notary).balance, 2 * FEE);
    }

    function test_rejectsAnyValueOtherThanTheQuote() public {
        TlsNotaryVerifierBase.TlsNotaryProof memory s = _payload();
        vm.expectRevert(abi.encodeWithSelector(PlatformVerifierBase.WrongValue.selector, quote, quote - 1));
        this.run{value: quote - 1}(s);
    }

    // ─── The digest binding ─────────────────────────────────────────

    /// @dev REQ-COMMON-15A: the verifier rebuilds the digest from the payload, so
    ///      another nonce derives another code verifier.
    function test_rejectsAnAttestationRetargetedToAnotherDigest() public {
        TlsNotaryVerifierBase.TlsNotaryProof memory s = _payload();
        s.authorizationNonce = bytes32(uint256(AUTH_NONCE) ^ 1);
        vm.expectRevert(TlsNotaryVerifierBase.CodeVerifierMismatch.selector);
        this.run{value: quote}(s);
    }

    /// @dev The transaction data is in the digest, so another target fails.
    function test_rejectsAnAttestationRetargetedToAnotherWallet() public {
        TlsNotaryVerifierBase.TlsNotaryProof memory s = _payload();
        s.transactionData = abi.encode(address(0xDEAD));
        vm.expectRevert(TlsNotaryVerifierBase.CodeVerifierMismatch.selector);
        this.run{value: quote}(s);
    }

    /// @dev REQ-COMMON-12: a code verifier derived under another nonce fails, even
    ///      when the payload names the right one.
    function test_rejectsAVerifierDerivedUnderAnotherNonce() public {
        TlsNotaryVerifierBase.TlsNotaryProof memory s = _payload();
        string memory foreign = string(CeremonyAuthorization.codeVerifier(digest, bytes32(uint256(1))));
        s.tokenSession = _tokenAttestation("authorization_code", "myClient-1", foreign);
        vm.expectRevert(TlsNotaryVerifierBase.CodeVerifierMismatch.selector);
        this.run{value: quote}(s);
    }

    /// @dev Another ceremony version is refused by name before any fee moves.
    function test_rejectsAPayloadForAnotherCeremonyVersion() public {
        TlsNotaryVerifierBase.TlsNotaryProof memory s = _payload();
        s.ceremonyVersion = 2;
        vm.expectRevert(abi.encodeWithSelector(PlatformVerifierBase.WrongCeremonyVersion.selector, 1, 2));
        this.run{value: quote}(s);
    }

    // ─── grant_type ─────────────────────────────────────────────────

    /// @dev REQ-PLAT-56: a refresh grant passes every other check, so the grant
    ///      type itself is checked.
    function test_rejectsARefreshGrant() public {
        TlsNotaryVerifierBase.TlsNotaryProof memory s = _payload();
        string memory v = string(CeremonyAuthorization.codeVerifier(digest, AUTH_NONCE));
        s.tokenSession = _tokenAttestation("refresh_token", "myClient-1", v);
        vm.expectPartialRevert(XPlatformVerifier.WrongGrantType.selector);
        this.run{value: quote}(s);
    }

    // ─── The token body's form ──────────────────────────────────────

    /// @dev Fields out of order fail where the second pair begins.
    function test_rejectsATokenBodyWithItsFieldsReordered() public {
        bytes memory first = "grant_type=authorization_code&";
        bytes memory body = abi.encodePacked(
            first,
            "code=abc&redirect_uri=https%3A%2F%2Fapp.example%2Fcb&code_verifier=",
            CeremonyAuthorization.codeVerifier(digest, AUTH_NONCE),
            "&client_id=myClient-1"
        );
        TlsNotaryVerifierBase.TlsNotaryProof memory s = _payloadWithBody(body);
        vm.expectRevert(abi.encodeWithSelector(CeremonyFields.MalformedForm.selector, first.length));
        this.run{value: quote}(s);
    }

    /// @dev X is a public client: a `client_secret` is a sixth pair, refused at its `&`.
    function test_rejectsATokenBodyCarryingAClientSecret() public {
        bytes memory honest = _honestTokenBody();
        TlsNotaryVerifierBase.TlsNotaryProof memory s =
            _payloadWithBody(abi.encodePacked(honest, "&client_secret=0123456789abcdef0123456789abcdef"));
        vm.expectRevert(abi.encodeWithSelector(CeremonyFields.MalformedForm.selector, honest.length));
        this.run{value: quote}(s);
    }

    /// @dev REQ-PLAT-63, TEST-PLAT-09C: `code%5Fverifier` decodes to `code_verifier`
    ///      and is refused as a sixth pair.
    function test_rejectsATokenBodyWithAnEncodedDuplicateName() public {
        bytes memory honest = _honestTokenBody();
        TlsNotaryVerifierBase.TlsNotaryProof memory s =
            _payloadWithBody(abi.encodePacked(honest, "&code%5Fverifier=EVILEVILEVILEVILEVILEVILEVILEVILEVILEVIL0"));
        vm.expectRevert(abi.encodeWithSelector(CeremonyFields.MalformedForm.selector, honest.length));
        this.run{value: quote}(s);
    }

    /// @dev Four pairs fail where `redirect_uri=` should stand.
    function test_rejectsATokenBodyMissingTheRedirect() public {
        bytes memory first = "grant_type=authorization_code&client_id=myClient-1&code=abc&";
        bytes memory body =
            abi.encodePacked(first, "code_verifier=", CeremonyAuthorization.codeVerifier(digest, AUTH_NONCE));
        TlsNotaryVerifierBase.TlsNotaryProof memory s = _payloadWithBody(body);
        vm.expectRevert(abi.encodeWithSelector(CeremonyFields.MalformedForm.selector, first.length));
        this.run{value: quote}(s);
    }

    /// @dev Some form parsers split pairs on `;`, and the serializer never emits
    ///      it raw, so a raw `;` is refused.
    function test_rejectsATokenBodyWithARawSemicolonInTheRedirect() public {
        bytes memory body = _honestTokenBody(
            "abc", "https%3A%2F%2Fapp.example%2Fcb;code_verifier=EVILEVILEVILEVILEVILEVILEVILEVILEVILEVIL0"
        );
        TlsNotaryVerifierBase.TlsNotaryProof memory s = _payloadWithBody(body);
        vm.expectRevert(
            abi.encodeWithSelector(CeremonyFields.MalformedForm.selector, AttestationBuilder.indexOf(body, ";"))
        );
        this.run{value: quote}(s);
    }

    /// @dev `%3a` is a noncanonical spelling of `%3A`.
    function test_rejectsATokenBodyWithALowercaseEscape() public {
        bytes memory body = _honestTokenBody("abc", "https%3a%2F%2Fapp.example%2Fcb");
        TlsNotaryVerifierBase.TlsNotaryProof memory s = _payloadWithBody(body);
        vm.expectRevert(
            abi.encodeWithSelector(CeremonyFields.MalformedForm.selector, AttestationBuilder.indexOf(body, "%3a"))
        );
        this.run{value: quote}(s);
    }

    /// @dev Nothing may follow the last value.
    function test_rejectsATokenBodyWithATrailingAmpersand() public {
        bytes memory honest = _honestTokenBody();
        TlsNotaryVerifierBase.TlsNotaryProof memory s = _payloadWithBody(abi.encodePacked(honest, "&"));
        vm.expectRevert(abi.encodeWithSelector(CeremonyFields.MalformedForm.selector, honest.length));
        this.run{value: quote}(s);
    }

    // ─── The client identifier ──────────────────────────────────────

    function test_rejectsAPercentEncodedClientIdentifier() public {
        TlsNotaryVerifierBase.TlsNotaryProof memory s = _payload();
        string memory v = string(CeremonyAuthorization.codeVerifier(digest, AUTH_NONCE));
        s.tokenSession = _tokenAttestation("authorization_code", "my%2Bapp", v);
        vm.expectPartialRevert(TlsNotaryVerifierBase.ClientIdentifierNotSerializerSafe.selector);
        this.run{value: quote}(s);
    }

    // ─── The attestations themselves ────────────────────────────────

    function test_rejectsAnUntrustedNotary() public {
        TlsNotaryVerifierBase.TlsNotaryProof memory s = _payload();
        bytes memory attested = s.identitySession.attestedData;
        s.identitySession.proof = AttestationBuilder.sign(0xB0B, attested);
        vm.expectPartialRevert(NotaryService.UntrustedNotary.selector);
        this.run{value: quote}(s);
    }

    /// @dev X serves both sessions from one host, so the notarized request line
    ///      tells them apart.
    function test_rejectsTheTwoSessionsSwapped() public {
        TlsNotaryVerifierBase.TlsNotaryProof memory s = _payload();
        (s.tokenSession, s.identitySession) = (s.identitySession, s.tokenSession);
        vm.expectPartialRevert(TlsNotaryVerifierBase.WrongRequestLine.selector);
        this.run{value: quote}(s);
    }

    // ─── The circuit link ───────────────────────────────────────────

    /// @dev REQ-PLAT-32C: the verifier builds the public inputs from the two attestations.
    function test_provesAgainstTheCommitmentsTheNotarySigned() public {
        TlsNotaryVerifierBase.TlsNotaryProof memory s = _payload();
        vm.expectCall(
            address(honk),
            abi.encodeCall(
                IHonkVerifier.verify,
                (s.proof, _expectedInputs(TOKEN_COMMITMENT, IDENTITY_COMMITMENT, ID_COMMITMENT, HANDLE_COMMITMENT))
            )
        );
        this.run{value: quote}(s);
    }

    /// @dev The id and handle are found by their anchors, so a response naming the
    ///      handle first yields the same public inputs.
    function test_findsTheIdAndHandleByTheirAnchorsNotTheirOrder() public {
        TlsNotaryVerifierBase.TlsNotaryProof memory s = _payload();
        AttestationBuilder.Direction memory received;
        received.commit('HTTP/1.1 200 OK\r\n\r\n{"data":{', OTHER)
            .reveal('"username":"')
            .commit("Alice_1", HANDLE_COMMITMENT)
            .reveal('"')
            .commit(",", OTHER)
            .reveal('"id":"')
            .commit("2244994945", ID_COMMITMENT)
            .reveal('"')
            .commit("}}", OTHER);
        s.identitySession = _identityReceiving(received);
        vm.expectCall(
            address(honk),
            abi.encodeCall(
                IHonkVerifier.verify,
                (s.proof, _expectedInputs(TOKEN_COMMITMENT, IDENTITY_COMMITMENT, ID_COMMITMENT, HANDLE_COMMITMENT))
            )
        );
        this.run{value: quote}(s);
    }

    /// The 16 public inputs, written out independently of the verifier: each
    /// tag is int.from_bytes(tag.ljust(31, b"\0"), "big") and its length.
    function _expectedInputs(bytes32 token, bytes32 identity, bytes32 id, bytes32 handle)
        private
        pure
        returns (bytes32[] memory expected)
    {
        expected = new bytes32[](16);
        bytes32[6] memory wide = [token, identity, id, handle, ID_NODE, HANDLE_NODE];
        for (uint256 k = 0; k < 6; ++k) {
            expected[2 * k] = bytes32(uint256(wide[k]) / 2 ** 128);
            expected[2 * k + 1] = bytes32(uint256(wide[k]) % 2 ** 128);
        }
        expected[12] = 0x006c696269642e782e757365722d696400000000000000000000000000000000; // libid.x.user-id
        expected[13] = bytes32(uint256(15));
        expected[14] = 0x006c696269642e782e68616e646c650000000000000000000000000000000000; // libid.x.handle
        expected[15] = bytes32(uint256(14));
    }

    function test_rejectsAProofThatDoesNotVerify() public {
        HonkStub.answer(honk, false);
        TlsNotaryVerifierBase.TlsNotaryProof memory s = _payload();
        vm.expectRevert(PlatformVerifierBase.BadProof.selector);
        this.run{value: quote}(s);
    }

    /// An upgrade that changes the pinned circuit leaves the wired verifier
    /// unusable until `setTrustRoots` wires that circuit's.
    function test_rejectsAProofAfterAnUpgradeRepinsTheCircuit() public {
        address repinned = address(new XPinningGooglesCircuit());
        vm.prank(OWNER);
        verifier.upgradeToAndCall(repinned, "");
        TlsNotaryVerifierBase.TlsNotaryProof memory s = _payload();
        vm.expectRevert(
            abi.encodeWithSelector(
                PlatformVerifierBase.WrongCircuit.selector, CircuitCodehashes.OIDC_GOOGLE, honk.codehash
            )
        );
        this.run{value: quote}(s);
    }

    // ─── The requests the runtime sends ─────────────────────────────

    /// @dev The token request as the browser composes it: five lowercased headers,
    ///      `content-length` third.
    function test_verifiesTheTokenRequestTheBrowserSends() public {
        bytes memory body = _honestTokenBody();
        TlsNotaryVerifierBase.TlsNotaryProof memory s = _payloadWithHead(
            abi.encodePacked(
                "POST /2/oauth2/token HTTP/1.1\r\nhost: api.x.com\r\ncontent-type: application/x-www-form-urlencoded\r\ncontent-length: ",
                vm.toString(body.length),
                "\r\naccept: application/json\r\nconnection: close\r\n\r\n"
            )
        );
        this.run{value: quote}(s);
    }

    /// @dev The identity request as the browser composes it: `authorization`, then
    ///      `accept`, `host`, `connection`.
    function test_verifiesTheIdentityRequestTheBrowserSends() public {
        TlsNotaryVerifierBase.TlsNotaryProof memory s = _payload();
        s.identitySession = _identityAttestationWithHead(
            "GET /2/users/me HTTP/1.1\r\nauthorization: Bearer ",
            "\r\naccept: application/json\r\nhost: api.x.com\r\nconnection: close\r\n\r\n"
        );
        this.run{value: quote}(s);
    }

    /// The honest identity attestation for a request given as the bytes
    /// before the committed bearer and the bytes after it.
    function _identityAttestationWithHead(bytes memory head, bytes memory tail)
        private
        pure
        returns (ICeremony.Attestation memory)
    {
        bytes memory bearer = "TOKENTOKENTOKEN";
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
        return _signedIdentity(sent, _identityResponse("2244994945", "Alice_1"));
    }

    // ─── The records libid-rs produces ──────────────────────────────

    string constant RUST_SESSION = "contracts/ceremony/test/fixtures/x-ceremony-session.json";

    /// @dev Verifies the session libid-rs's Rust pipeline produces, signatures unedited.
    ///      Generated by `cargo run -p libid-tlsn --example ceremony_fixtures` in libid-rs.
    function test_verifiesTheRecordsLibidRsProduces() public {
        string memory json = vm.readFile(RUST_SESSION);
        assertEq(vm.parseJsonBytes32(json, ".authorization_digest"), digest, "derived from this suite's digest");
        assertEq(vm.parseJsonBytes32(json, ".authorization_nonce"), AUTH_NONCE);
        assertEq(vm.parseJsonAddress(json, ".notary"), vm.addr(NOTARY_KEY), "signed by the key this suite trusts");
        assertEq(uint64(vm.parseJsonUint(json, ".created_at")), T0);

        TlsNotaryVerifierBase.TlsNotaryProof memory s = _payload();
        s.tokenSession = AttestationBuilder.fixtureSession(json, ".token");
        s.identitySession = AttestationBuilder.fixtureSession(json, ".identity");
        ICeremony.VerifiedClaim memory f = this.run{value: quote}(s);
        assertEq(f.idNode, ID_NODE);
        assertEq(f.handleNode, HANDLE_NODE);
        assertEq(string(f.clientIdentifier), "myClient-1");
        assertEq(f.sessionId, digest);
    }

    /// @dev The record carries neither the id nor the handle, in any case.
    function test_theIdentityRecordRevealsNeitherTheIdNorTheHandle() public view {
        bytes memory attested = vm.parseJsonBytes(vm.readFile(RUST_SESSION), ".identity.attested_data");
        assertFalse(AttestationBuilder.contains(attested, "2244994945"), "the id");
        assertFalse(AttestationBuilder.contains(attested, "Alice_1"), "the handle");
        assertFalse(AttestationBuilder.contains(attested, "alice_1"), "the folded handle");
        assertTrue(AttestationBuilder.contains(attested, '"id":"'), "the id's anchor");
        assertTrue(AttestationBuilder.contains(attested, '"username":"'), "the handle's anchor");
    }

    /// @dev The fixture opening, SHA-256(value || blinder), matches the signed
    ///      commitments, and the framing finds exactly those two.
    function test_theWitnessOpensTheCommitmentsTheFramingFinds() public view {
        string memory json = vm.readFile(RUST_SESSION);
        assertEq(vm.parseJsonString(json, ".identity_link_witness.id.value"), "2244994945");
        assertEq(vm.parseJsonString(json, ".identity_link_witness.handle.value"), "Alice_1");

        bytes32 id = vm.parseJsonBytes32(json, ".identity_link_witness.id.commitment");
        bytes32 handle = vm.parseJsonBytes32(json, ".identity_link_witness.handle.commitment");
        assertEq(sha256(bytes.concat("2244994945", _blinder(json, ".identity_link_witness.id.blinder"))), id);
        assertEq(sha256(bytes.concat("Alice_1", _blinder(json, ".identity_link_witness.handle.blinder"))), handle);

        CeremonyAttestation.AttestedData memory data = this.decode(vm.parseJsonBytes(json, ".identity.attested_data"));
        assertEq(CeremonyAttestation.requireFramedCommitment(data.received, '"id":"', '"').commitment, id);
        assertEq(CeremonyAttestation.requireFramedCommitment(data.received, '"username":"', '"').commitment, handle);
    }

    function decode(bytes calldata attested) external pure returns (CeremonyAttestation.AttestedData memory) {
        return CeremonyAttestation.decode(attested);
    }

    string constant RUST_SESSION_PROOF = "contracts/ceremony/test/fixtures/x-ceremony-session-proof.json";

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
        return "contracts/ceremony/test/fixtures/github-ceremony-session.json";
    }

    /// @dev A real proof outputs the hashlib nodes for `2244994945` and `alice_1`.
    function test_verifiesARealProofOfTheRecordsLibidRsProduces() public {
        (TlsNotaryVerifierBase.TlsNotaryProof memory s, address circuit, bytes32[] memory proved) = _realProofPayload();
        assertEq(proved.length, 16);
        vm.expectCall(circuit, abi.encodeCall(IHonkVerifier.verify, (s.proof, proved)));
        ICeremony.VerifiedClaim memory f = this.run{value: quote}(s);
        assertEq(f.idNode, 0x68291869976ffad2abf3e933ec9ab2623395ff8b3b9242e655e1da3ef43d4f94, "hashlib idNode");
        assertEq(f.handleNode, 0xe09c4f5bfbbc723bc35701ea9d718a1c5edb29b1ed5bb0cb0fabb3c43d8136af, "hashlib handleNode");
        assertEq(string(f.clientIdentifier), "myClient-1");
        assertEq(f.sessionId, digest);
        assertEq(f.operationDomain, DOMAIN);
        assertEq(f.transactionData, _txData());
        assertEq(f.ceremonyVersion, 1);
        assertEq(f.metadataObservedAt, T0 - ALLOWANCE);
    }

    string constant REAL_SESSION = "contracts/ceremony/test/fixtures/x-ceremony-real.json";

    /// @dev A captured ceremony (libid-rs `examples/capture_ceremony.rs`):
    ///      its token session and identity request pass every transcript check.
    function test_theRealTokenSessionAndIdentityRequestVerify() public {
        string memory json = vm.readFile(REAL_SESSION);
        ICeremony.Attestation memory token = AttestationBuilder.fixtureSession(json, ".token");
        ICeremony.Attestation memory identity = AttestationBuilder.fixtureSession(json, ".identity");
        CeremonyAttestation.AttestedData memory tokenData = notary.verify{value: FEE}(token.attestedData, token.proof);
        CeremonyAttestation.AttestedData memory identityData =
            notary.verify{value: FEE}(identity.attestedData, identity.proof);
        assertEq(tokenData.authorityId, CeremonyProfile.AUTHORITY_X_API);
        assertEq(identityData.authorityId, CeremonyProfile.AUTHORITY_X_API);

        XTranscripts transcripts = new XTranscripts();
        (bytes memory clientId, bytes32 tokenCommitment) = transcripts.tokenTranscript(
            tokenData,
            vm.parseJsonBytes32(json, ".authorization_digest"),
            vm.parseJsonBytes32(json, ".authorization_nonce")
        );
        assertEq(string(clientId), "MnY0bnJ6VzFGY2hVNmF2N2RFWkg6MTpjaQ");
        assertTrue(tokenCommitment != bytes32(0));
        assertEq(transcripts.identityRequest(identityData), identityData.sent.commitments[0].commitment);
    }

    /// @dev The whole captured record: its response reveals the anchors and
    ///      commits the id and the handle.
    function test_verifiesTheRecordsACeremonyProduced() public {
        string memory json = vm.readFile(REAL_SESSION);
        assertEq(vm.parseJsonBytes32(json, ".authorization_digest"), digest, "bound to this suite's digest");
        vm.warp(vm.parseJsonUint(json, ".identity.created_at") + 60);

        TlsNotaryVerifierBase.TlsNotaryProof memory s = _payload();
        s.tokenSession = AttestationBuilder.fixtureSession(json, ".token");
        s.identitySession = AttestationBuilder.fixtureSession(json, ".identity");
        ICeremony.VerifiedClaim memory f = this.run{value: quote}(s);
        assertEq(string(f.clientIdentifier), "MnY0bnJ6VzFGY2hVNmF2N2RFWkg6MTpjaQ");
        assertEq(f.sessionId, digest);
    }

    // ─── The identity request ───────────────────────────────────────

    /// @dev A second HTTP request in the identity session is refused, with
    ///      or without a credential.
    function test_rejectsASecondRequestOnTheIdentitySession() public {
        TlsNotaryVerifierBase.TlsNotaryProof memory s = _payload();
        s.identitySession = _identityAttestationWithHead(
            "GET /2/users/me HTTP/1.1\r\nhost: api.x.com\r\nauthorization: Bearer ",
            "\r\n\r\nGET /2/users/me HTTP/1.1\r\nhost: api.x.com\r\nauthorization: Bearer OTHERTOKENOTHER\r\n\r\n"
        );
        vm.expectRevert(abi.encodeWithSelector(CeremonyAttestation.NotOneRequest.selector, 2));
        this.run{value: quote}(s);

        s.identitySession = _identityAttestationWithHead(
            "GET /2/users/me HTTP/1.1\r\nhost: api.x.com\r\nauthorization: Bearer ",
            "\r\n\r\nGET /2/users/me HTTP/1.1\r\nhost: api.x.com\r\n\r\n"
        );
        vm.expectRevert(abi.encodeWithSelector(CeremonyAttestation.NotOneRequest.selector, 2));
        this.run{value: quote}(s);
    }

    /// @dev `host` names the identity authority exactly once.
    function test_rejectsAnIdentityRequestWithoutItsHost() public {
        TlsNotaryVerifierBase.TlsNotaryProof memory s = _payload();
        s.identitySession =
            _identityAttestationWithHead("GET /2/users/me HTTP/1.1\r\nauthorization: Bearer ", "\r\n\r\n");
        vm.expectRevert(TlsNotaryVerifierBase.WrongIdentityRequestHead.selector);
        this.run{value: quote}(s);

        s.identitySession = _identityAttestationWithHead(
            "GET /2/users/me HTTP/1.1\r\nhost: api.github.com\r\nauthorization: Bearer ", "\r\n\r\n"
        );
        vm.expectRevert(TlsNotaryVerifierBase.WrongIdentityRequestHead.selector);
        this.run{value: quote}(s);

        s.identitySession = _identityAttestation("2244994945", "Alice_1", "host: api.x.com\r\n");
        vm.expectRevert(TlsNotaryVerifierBase.WrongIdentityRequestHead.selector);
        this.run{value: quote}(s);
    }

    /// @dev The name is compared as X reads it, the value trimmed.
    function test_acceptsTheIdentityHostInAnotherSpelling() public {
        TlsNotaryVerifierBase.TlsNotaryProof memory s = _payload();
        s.identitySession = _identityAttestationWithHead(
            "GET /2/users/me HTTP/1.1\r\nHost:  api.x.com \r\nauthorization: Bearer ", "\r\n\r\n"
        );
        this.run{value: quote}(s);
    }

    /// @dev A GET has no body: bytes after the head are refused.
    function test_rejectsBytesAfterTheIdentityRequest() public {
        TlsNotaryVerifierBase.TlsNotaryProof memory s = _payload();
        s.identitySession = _identityAttestationWithHead(
            "GET /2/users/me HTTP/1.1\r\nhost: api.x.com\r\nauthorization: Bearer ", "\r\n\r\nGET"
        );
        vm.expectRevert(abi.encodeWithSelector(CeremonyAttestation.BytesAfterRequest.selector, 3));
        this.run{value: quote}(s);
    }

    function test_rejectsASecondAuthorizationHeader() public {
        TlsNotaryVerifierBase.TlsNotaryProof memory s = _payload();
        s.identitySession = _identityAttestation("2244994945", "Alice_1", "authorization: Bearer stolen\r\n");
        vm.expectPartialRevert(CeremonyAttestation.NotOneAuthorizationHeader.selector);
        this.run{value: quote}(s);
    }

    /// @dev A second `authorization` counts whatever its scheme.
    function test_rejectsASecondAuthorizationHeaderOfAnotherScheme() public {
        TlsNotaryVerifierBase.TlsNotaryProof memory s = _payload();
        s.identitySession =
            _identityAttestation("2244994945", "Alice_1", "Authorization: Basic dmljdGltOnN0b2xlbg==\r\n");
        vm.expectPartialRevert(CeremonyAttestation.NotOneAuthorizationHeader.selector);
        this.run{value: quote}(s);
    }

    /// @dev A `cookie` could stand in for the bearer, so it is forbidden on the identity request.
    function test_rejectsACookieOnTheIdentityRequest() public {
        TlsNotaryVerifierBase.TlsNotaryProof memory s = _payload();
        s.identitySession = _identityAttestation("2244994945", "Alice_1", "Cookie: auth_token=stolen\r\n");
        vm.expectRevert(abi.encodeWithSelector(TlsNotaryVerifierBase.ForbiddenRequestHeader.selector, bytes("cookie")));
        this.run{value: quote}(s);
    }

    /// @dev A space or a tab inside the name does not hide it: names are
    ///      compared with every space and tab removed (REQ-COMMON-39B).
    function test_rejectsACookieWithWhitespaceInsideItsName() public {
        TlsNotaryVerifierBase.TlsNotaryProof memory s = _payload();
        s.identitySession = _identityAttestation("2244994945", "Alice_1", "Coo kie: auth_token=stolen\r\n");
        vm.expectRevert(abi.encodeWithSelector(TlsNotaryVerifierBase.ForbiddenRequestHeader.selector, bytes("cookie")));
        this.run{value: quote}(s);

        s.identitySession = _identityAttestation("2244994945", "Alice_1", "Co\tokie: auth_token=stolen\r\n");
        vm.expectRevert(abi.encodeWithSelector(TlsNotaryVerifierBase.ForbiddenRequestHeader.selector, bytes("cookie")));
        this.run{value: quote}(s);
    }

    /// @dev Any other header on the identity request is the runtime's own.
    function test_acceptsAnUnlistedHeaderOnTheIdentityRequest() public {
        TlsNotaryVerifierBase.TlsNotaryProof memory s = _payload();
        s.identitySession = _identityAttestation("2244994945", "Alice_1", "user-agent: libid-ceremony\r\n");
        this.run{value: quote}(s);
    }

    /// @dev A bare carriage return is refused before anything is counted.
    function test_rejectsABareCarriageReturnOnTheIdentityRequest() public {
        TlsNotaryVerifierBase.TlsNotaryProof memory s = _payload();
        s.identitySession = _identityAttestation("2244994945", "Alice_1", "user-agent: a\rcookie: b\r\n");
        vm.expectPartialRevert(CeremonyAttestation.BareCarriageReturn.selector);
        this.run{value: quote}(s);
    }

    function test_rejectsAnObsoleteLineFold() public {
        TlsNotaryVerifierBase.TlsNotaryProof memory s = _payload();
        s.identitySession = _identityAttestation("2244994945", "Alice_1", "authorization:\r\n Bearer stolen\r\n");
        vm.expectPartialRevert(CeremonyAttestation.ObsoleteLineFold.selector);
        this.run{value: quote}(s);
    }

    // ─── Evidence time ──────────────────────────────────────────────

    function test_rejectsAnExpiredProof() public {
        vm.warp(T0 + LIFETIME);
        // Built before `expectPartialRevert`: `vm.sign` would consume it.
        TlsNotaryVerifierBase.TlsNotaryProof memory s = _payload();
        vm.expectPartialRevert(PlatformVerifierBase.ProofExpired.selector);
        this.run{value: quote}(s);
    }

    function test_acceptsRightUpToExpiry() public {
        vm.warp(T0 + LIFETIME - 1);
        this.run{value: quote}(_payload());
    }

    function test_rejectsAnAttestationTooFarAhead() public {
        vm.warp(T0 - SKEW - 1);
        TlsNotaryVerifierBase.TlsNotaryProof memory s = _payload();
        vm.expectPartialRevert(PlatformVerifierBase.AttestationAhead.selector);
        this.run{value: quote}(s);
    }

    /// @dev The window is the profile's, read as constants (REQ-PARAM-01).
    function test_theValidityIsTheProfiles() public view {
        (uint64 lifetime, uint64 skew, uint64 allowance) = verifier.protocolParameters();
        assertEq(lifetime, CeremonyProfile.PROOF_LIFETIME_SECONDS_X);
        assertEq(skew, CeremonyProfile.MAX_FUTURE_ATTESTATION_SKEW_SECONDS_X);
        assertEq(allowance, CeremonyProfile.FUTURE_OBSERVATION_ALLOWANCE_SECONDS_X);
    }

    /// @dev No one can move the window, so a proof stays good until the expiry its version fixes.
    function test_theOwnerCannotShortenAnOutstandingProof() public {
        vm.warp(T0 + 100);
        vm.prank(OWNER);
        (bool moved,) = address(verifier)
            .call(abi.encodeWithSignature("setProtocolParameters(uint64,uint64,uint64)", uint64(50), SKEW, ALLOWANCE));
        assertFalse(moved, "the owner moved the window");
        this.run{value: quote}(_payload());
    }

    /// @dev An attestation inside `maxFutureAttestationSkew` but past
    ///      `futureObservationAllowance` is refused.
    function test_rejectsAnAttestationPastTheObservationAllowanceButInsideTheSkew() public {
        SkewPastAllowance window = new SkewPastAllowance();
        vm.warp(T0 - window.SKEW());
        vm.expectPartialRevert(PlatformVerifierBase.ObservedInTheFuture.selector);
        window.requireFresh(T0);
    }

    // ─── The proof artifact (REQ-COMMON-45) ─────────────────────────

    /// @dev bb's verifiers embed their key as code, so the code hash names the
    ///      circuit: an account with no code is refused like another circuit's.
    function test_rejectsAnAddressHoldingNoCode() public {
        address eoa = address(0xB0B);
        vm.prank(OWNER);
        vm.expectRevert(
            abi.encodeWithSelector(PlatformVerifierBase.WrongCircuit.selector, CircuitCodehashes.BEARER_LINK, 0)
        );
        verifier.setTrustRoots(INotaryService(address(notary)), IHonkVerifier(eoa));
    }

    /// @dev Only bearer-link's verifier: Google's is refused by its code hash.
    function test_rejectsAnotherCircuitsVerifier() public {
        address google = vm.deployCode(HonkStub.GOOGLE);
        vm.prank(OWNER);
        vm.expectRevert(
            abi.encodeWithSelector(
                PlatformVerifierBase.WrongCircuit.selector, CircuitCodehashes.BEARER_LINK, google.codehash
            )
        );
        verifier.setTrustRoots(INotaryService(address(notary)), IHonkVerifier(google));
        assertEq(verifier.circuitCodehash(), CircuitCodehashes.BEARER_LINK);
    }

    function test_recordsTheArtifactItWired() public {
        address other = HonkStub.deploy(HonkStub.BEARER_LINK);
        vm.prank(OWNER);
        verifier.setTrustRoots(INotaryService(address(notary)), IHonkVerifier(other));
        assertEq(verifier.honkVerifier(), other);
    }

    // ─── The identity fields ────────────────────────────────────────

    function _refusedFraming(AttestationBuilder.Direction memory received, bytes4 error_) private {
        TlsNotaryVerifierBase.TlsNotaryProof memory s = _payload();
        s.identitySession = _identityReceiving(received);
        vm.expectPartialRevert(error_);
        this.run{value: quote}(s);
    }

    /// The response up to the handle's anchor, honest: the id framed.
    function _upToTheHandle() private pure returns (AttestationBuilder.Direction memory received) {
        received.commit('HTTP/1.1 200 OK\r\n\r\n{"data":{', OTHER)
            .reveal('"id":"')
            .commit("2244994945", ID_COMMITMENT)
            .reveal('"')
            .commit(",", OTHER);
    }

    /// @dev The key revealed in two pieces around a commitment is no anchor.
    function test_refusesAHandleAnchorSplitAroundACommittedGap() public {
        AttestationBuilder.Direction memory received = _upToTheHandle();
        received.reveal('"user')
            .commit("name", OTHER)
            .reveal('":"')
            .commit("Alice_1", HANDLE_COMMITMENT)
            .reveal('"')
            .commit("}}", OTHER);
        _refusedFraming(received, CeremonyAttestation.NoFramedCommitment.selector);
    }

    /// @dev A key split across two adjacent revealed ranges is no anchor.
    function test_refusesAHandleAnchorSplitAcrossTwoRevealedRanges() public {
        AttestationBuilder.Direction memory received = _upToTheHandle();
        received.reveal('"user').reveal('name":"').commit("Alice_1", HANDLE_COMMITMENT).reveal('"').commit("}}", OTHER);
        _refusedFraming(received, CeremonyAttestation.NoFramedCommitment.selector);
    }

    /// @dev X's id is a JSON string, so its value must end at a quote.
    function test_refusesAnIdWithNoClosingQuote() public {
        AttestationBuilder.Direction memory received;
        received.commit('HTTP/1.1 200 OK\r\n\r\n{"data":{', OTHER)
            .reveal('"id":"')
            .commit("2244994945", ID_COMMITMENT)
            .reveal("',")
            .reveal('"username":"')
            .commit("Alice_1", HANDLE_COMMITMENT)
            .reveal('"')
            .commit("}}", OTHER);
        _refusedFraming(received, CeremonyAttestation.NoFramedCommitment.selector);
    }

    /// @dev A closing quote committed with the value leaves the commitment unframed.
    function test_refusesAHandleCommittedWithItsClosingQuote() public {
        AttestationBuilder.Direction memory received = _upToTheHandle();
        received.reveal('"username":"').commit('Alice_1"', HANDLE_COMMITMENT).reveal("}}");
        _refusedFraming(received, CeremonyAttestation.NoFramedCommitment.selector);
    }

    /// @dev An id anchor escaped inside a revealed string is no anchor: with
    ///      the real member hidden, nothing frames the id.
    function test_refusesAnEscapedIdAnchorInARevealedString() public {
        bytes[2] memory decoys = [bytes('"name":"x\\"id\\":\\"999\\"y",'), bytes('"bio":"\\"id\\":999,",')];
        for (uint256 i = 0; i < decoys.length; ++i) {
            AttestationBuilder.Direction memory received;
            received.commit('HTTP/1.1 200 OK\r\n\r\n{"data":{', OTHER)
                .reveal(decoys[i])
                .commit('"id":"2244994945",', OTHER)
                .reveal('"username":"')
                .commit("Alice_1", HANDLE_COMMITMENT)
                .reveal('"')
                .commit("}}", OTHER);
            _refusedFraming(received, CeremonyAttestation.NoFramedCommitment.selector);
        }
    }

    /// @dev A value revealed between its anchors is refused, not read.
    function test_refusesARevealedHandle() public {
        AttestationBuilder.Direction memory received = _upToTheHandle();
        received.reveal('"username":"Alice_1"').commit("}}", OTHER);
        _refusedFraming(received, CeremonyAttestation.NoFramedCommitment.selector);
    }

    /// @dev Two revealed handle anchors, each framing a commitment, are ambiguous.
    function test_refusesTwoHandleAnchorsInTheRevealedBytes() public {
        AttestationBuilder.Direction memory received = _upToTheHandle();
        received.reveal('"username":"')
            .commit("Alice_1", HANDLE_COMMITMENT)
            .reveal('"')
            .commit(",", OTHER)
            .reveal('"username":"')
            .commit("mallory", OTHER)
            .reveal('"')
            .commit("}}", OTHER);
        _refusedFraming(received, CeremonyAttestation.AmbiguousFraming.selector);
    }

    /// @dev The anchor count covers every revealed byte, so a second anchor framing
    ///      nothing is still ambiguous.
    function test_refusesASecondRevealedHandleAnchorFramingNothing() public {
        AttestationBuilder.Direction memory received = _upToTheHandle();
        received.reveal('"username":"').commit("Alice_1", HANDLE_COMMITMENT).reveal('","username":"mallory"}}');
        _refusedFraming(received, CeremonyAttestation.AmbiguousFraming.selector);
    }

    /// @dev Two id anchors, each framing a commitment, are ambiguous.
    function test_refusesTwoFramedIdCommitments() public {
        AttestationBuilder.Direction memory received;
        received.commit('HTTP/1.1 200 OK\r\n\r\n{"data":{', OTHER)
            .reveal('"id":"')
            .commit("2244994945", ID_COMMITMENT)
            .reveal('"')
            .commit(",", OTHER)
            .reveal('"id":"')
            .commit("1", OTHER)
            .reveal('"')
            .commit(",", OTHER)
            .reveal('"username":"')
            .commit("Alice_1", HANDLE_COMMITMENT)
            .reveal('"')
            .commit("}}", OTHER);
        _refusedFraming(received, CeremonyAttestation.AmbiguousFraming.selector);
    }

    /// @dev A second id anchor cut by a range boundary: neither half holds the
    ///      whole anchor, but the count reads the revealed bytes joined.
    function test_refusesADuplicateAnchorHiddenUnderARangeBoundary() public {
        AttestationBuilder.Direction memory received = _upToTheHandle();
        received.reveal('"username":"').commit("Alice_1", HANDLE_COMMITMENT).reveal('","i').reveal('d":"1"}}');
        _refusedFraming(received, CeremonyAttestation.AmbiguousFraming.selector);
    }

    /// @dev `"user name"` is another member: only whitespace beside a structural byte is ignored.
    function test_refusesWhitespaceInsideTheKey() public {
        AttestationBuilder.Direction memory received = _upToTheHandle();
        received.reveal('"user name":"').commit("Alice_1", HANDLE_COMMITMENT).reveal('"').commit("}}", OTHER);
        _refusedFraming(received, CeremonyAttestation.NoFramedCommitment.selector);
    }

    /// @dev Whitespace around the colon is accepted.
    function test_acceptsJsonWhitespaceAroundTheColon() public {
        AttestationBuilder.Direction memory received = _upToTheHandle();
        received.reveal('"username" :\n "').commit("Alice_1", HANDLE_COMMITMENT).reveal('"').commit("}}", OTHER);
        TlsNotaryVerifierBase.TlsNotaryProof memory s = _payload();
        s.identitySession = _identityReceiving(received);
        assertEq(this.run{value: quote}(s).handleNode, HANDLE_NODE);
    }

    function test_refusesAResponseWithNoHandleAnchor() public {
        AttestationBuilder.Direction memory received = _upToTheHandle();
        received.commit('"username":"Alice_1"}}', OTHER);
        _refusedFraming(received, CeremonyAttestation.NoFramedCommitment.selector);
    }

    /// @dev Every response byte must be revealed or committed.
    function test_refusesAnIdentityResponseWithAnUncoveredByte() public {
        AttestationBuilder.Direction memory received = _identityResponse("2244994945", "Alice_1");
        received.length += 1;
        _refusedFraming(received, CeremonyAttestation.CoverageGap.selector);
    }

    /// @dev ASM-PROV-06: a duplicate member hidden in a commitment is accepted.
    function test_acceptsAnIdentityResponseHidingADuplicateMember() public {
        AttestationBuilder.Direction memory received = _upToTheHandle();
        received.commit('"username":"victim",', OTHER)
            .reveal('"username":"')
            .commit("Alice_1", HANDLE_COMMITMENT)
            .reveal('"')
            .commit("}}", OTHER);
        TlsNotaryVerifierBase.TlsNotaryProof memory s = _payload();
        s.identitySession = _identityReceiving(received);
        assertEq(this.run{value: quote}(s).handleNode, HANDLE_NODE);
    }

    /// @dev ASM-PROV-06: the object a framed member belongs to is not checked.
    function test_acceptsAnAnchorInAnotherObject() public {
        AttestationBuilder.Direction memory received;
        received.commit('HTTP/1.1 200 OK\r\n\r\n{"data":{', OTHER)
            .reveal('"id":"')
            .commit("2244994945", ID_COMMITMENT)
            .reveal('"')
            .commit('},"includes":{', OTHER)
            .reveal('"username":"')
            .commit("Alice_1", HANDLE_COMMITMENT)
            .reveal('"')
            .commit("}}", OTHER);
        TlsNotaryVerifierBase.TlsNotaryProof memory s = _payload();
        s.identitySession = _identityReceiving(received);
        assertEq(this.run{value: quote}(s).handleNode, HANDLE_NODE);
    }

    // ─── The token response covers every byte ───────────────────────

    /// @dev Every token response byte outside the anchors must be committed.
    function test_rejectsATokenResponseWithAnUncoveredByte() public {
        TlsNotaryVerifierBase.TlsNotaryProof memory s = _payload();
        s.tokenSession = _tokenAttestationWithGap();
        vm.expectPartialRevert(CeremonyAttestation.CoverageGap.selector);
        this.run{value: quote}(s);
    }

    /// @dev A token response whose status-line CRLF is neither revealed nor committed.
    function _tokenAttestationWithGap() private view returns (ICeremony.Attestation memory) {
        // An honest request, so the coverage gap is what fails.
        bytes memory whole = _honestXRequest();
        AttestationBuilder.Direction memory sent = AttestationBuilder.Direction({
            revealed: AttestationBuilder.one(AttestationBuilder.Range({start: 0, value: whole})),
            commitments: AttestationBuilder.none(),
            length: uint32(whole.length)
        });

        bytes memory status = "HTTP/1.1 200 OK";
        bytes memory prefix = '"access_token":"';
        uint32 headEnd = 17;
        uint32 prefixEnd = headEnd + uint32(prefix.length);
        uint32 bearerEnd = prefixEnd + 12;
        uint32 quoteEnd = bearerEnd + 1;
        uint32 total = quoteEnd + 24;

        AttestationBuilder.Direction memory received = AttestationBuilder.Direction({
            revealed: AttestationBuilder.three(
                AttestationBuilder.Range({start: 0, value: status}),
                AttestationBuilder.Range({start: headEnd, value: prefix}),
                AttestationBuilder.Range({start: bearerEnd, value: '"'})
            ),
            // The CRLF at [15,17) is covered by nothing.
            commitments: AttestationBuilder.two(
                AttestationBuilder.Commitment({start: prefixEnd, end: bearerEnd, value: TOKEN_COMMITMENT}),
                AttestationBuilder.Commitment({start: quoteEnd, end: total, value: bytes32(uint256(0x9999))})
            ),
            length: total
        });

        bytes memory attested = AttestationBuilder.encode(CeremonyProfile.AUTHORITY_X_API, T0, sent, received);
        return ICeremony.Attestation({attestedData: attested, proof: AttestationBuilder.sign(NOTARY_KEY, attested)});
    }

    // ─── The token response anchors (REQ-PLAT-57, TEST-PLAT-22) ─────

    /// @dev The bearer is identified by its revealed anchors; without them it could
    ///      be a `refresh_token` value.
    function test_rejectsATokenResponseWithNoRevealedAnchors() public {
        string memory v = string(CeremonyAuthorization.codeVerifier(digest, AUTH_NONCE));
        TlsNotaryVerifierBase.TlsNotaryProof memory s = _payload();
        s.tokenSession = _tokenAttestation("authorization_code", "myClient-1", v, false);
        vm.expectRevert(CeremonyAttestation.NoFramedCommitment.selector);
        this.run{value: quote}(s);
    }

    // ─── The identity request line (REQ-COMMON-21A) ─────────────────

    /// @dev The path must be `/2/users/me`; a lookup by username answers for another account.
    function test_rejectsAForeignIdentityPath() public {
        TlsNotaryVerifierBase.TlsNotaryProof memory s = _payload();
        s.identitySession = _identityAttestationOnPath("GET /2/users/by/username/victim ");
        vm.expectRevert(TlsNotaryVerifierBase.WrongRequestLine.selector);
        this.run{value: quote}(s);
    }

    function _identityAttestationOnPath(string memory requestLine) private pure returns (ICeremony.Attestation memory) {
        bytes memory head = abi.encodePacked(
            requestLine, "HTTP/1.1\r\naccept: application/json\r\nhost: api.x.com", "\r\nauthorization: Bearer "
        );
        bytes memory bearer = "TOKENTOKENTOKEN";
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
        return _signedIdentity(sent, _identityResponse("2244994945", "Alice_1"));
    }

    /// @dev The authority is the server the notary authenticated, not a revealed `Host` header.
    function test_rejectsAForeignAuthority() public {
        TlsNotaryVerifierBase.TlsNotaryProof memory s = _payload();
        bytes memory attested = s.identitySession.attestedData;
        // authorityId is the first 32 bytes.
        bytes32 evil = keccak256(bytes("evil.example"));
        for (uint256 i = 0; i < 32; ++i) {
            attested[i] = evil[i];
        }
        s.identitySession =
            ICeremony.Attestation({attestedData: attested, proof: AttestationBuilder.sign(NOTARY_KEY, attested)});
        vm.expectPartialRevert(PlatformVerifierBase.WrongAuthority.selector);
        this.run{value: quote}(s);
    }

    /// @dev The digest commits no chain, so the same submission verifies on
    ///      another chain and names the same session.
    function test_verifiesTheSameSubmissionOnAnotherChain() public {
        TlsNotaryVerifierBase.TlsNotaryProof memory s = _payload();
        vm.chainId(block.chainid + 1);
        ICeremony.VerifiedClaim memory f = this.run{value: quote}(s);
        assertEq(f.sessionId, digest);
    }

    function test_refusesTheWrongCeremonyVersionBeforeAnyNotaryCall() public {
        TlsNotaryVerifierBase.TlsNotaryProof memory s = _payload();
        s.ceremonyVersion = 2;
        vm.expectCall(address(notary), abi.encodeWithSelector(INotaryService.verify.selector), 0);
        vm.expectRevert(abi.encodeWithSelector(PlatformVerifierBase.WrongCeremonyVersion.selector, 1, 2));
        this.run{value: quote}(s);
        assertEq(address(notary).balance, 0);
    }

    function test_aTlsProfileRefusesAZeroNotary() public {
        XPlatformVerifier impl = new XPlatformVerifier();
        vm.expectPartialRevert(PlatformVerifierBase.WrongNotaryForProfile.selector);
        new ERC1967Proxy(
            address(impl),
            abi.encodeCall(
                XPlatformVerifier.initialize, (OWNER, INotaryService(address(0)), IHonkVerifier(address(honk)))
            )
        );
    }

    function test_onlyTheOwnerRotatesRoots() public {
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, address(this)));
        verifier.setTrustRoots(INotaryService(address(notary)), IHonkVerifier(address(honk)));
    }

    function test_zeroHonkVerifierIsRefused() public {
        vm.prank(OWNER);
        vm.expectRevert(PlatformVerifierBase.ZeroAddress.selector);
        verifier.setTrustRoots(INotaryService(address(notary)), IHonkVerifier(address(0)));
    }

    function test_aRejectionAtTheSecondSessionLeavesNoFee() public {
        TlsNotaryVerifierBase.TlsNotaryProof memory s = _payload();
        s.identitySession.proof = AttestationBuilder.sign(0xB0B, s.identitySession.attestedData);
        vm.expectPartialRevert(NotaryService.UntrustedNotary.selector);
        this.run{value: quote}(s);
        assertEq(address(notary).balance, 0, "the first fee stayed delivered");
    }

    function test_rejectsOneWeiMoreThanTheQuote() public {
        TlsNotaryVerifierBase.TlsNotaryProof memory s = _payload();
        vm.expectRevert(abi.encodeWithSelector(PlatformVerifierBase.WrongValue.selector, quote, quote + 1));
        this.run{value: quote + 1}(s);
    }

    /// @dev REQ-COMMON-16B: an empty identifier fails the form check.
    function test_rejectsAnEmptyClientIdentifier() public {
        TlsNotaryVerifierBase.TlsNotaryProof memory s = _payload();
        string memory v = string(CeremonyAuthorization.codeVerifier(digest, AUTH_NONCE));
        s.tokenSession = _tokenAttestation("authorization_code", "", v);
        vm.expectRevert(abi.encodeWithSelector(CeremonyFields.EmptyFormValue.selector, "client_id"));
        this.run{value: quote}(s);
    }

    /// @dev A head with one CRLF where the blank line belongs has no body to read.
    function test_rejectsATokenRequestWithNoHeadBoundary() public {
        bytes memory body = _honestTokenBody();
        bytes memory whole = abi.encodePacked(
            "POST /2/oauth2/token HTTP/1.1\r\n",
            TOKEN_HEADERS,
            "content-length: ",
            vm.toString(body.length),
            "\r\n",
            body
        );
        AttestationBuilder.Direction memory sent = AttestationBuilder.Direction({
            revealed: AttestationBuilder.one(AttestationBuilder.Range({start: 0, value: whole})),
            commitments: AttestationBuilder.none(),
            length: uint32(whole.length)
        });
        bytes memory a = AttestationBuilder.encode(CeremonyProfile.AUTHORITY_X_API, T0, sent, _tokenResponse(true));
        TlsNotaryVerifierBase.TlsNotaryProof memory s = _payload();
        s.tokenSession = ICeremony.Attestation({attestedData: a, proof: AttestationBuilder.sign(NOTARY_KEY, a)});
        vm.expectRevert(abi.encodeWithSelector(TlsNotaryVerifierBase.NoHeadBoundary.selector, 0));
        this.run{value: quote}(s);
    }

    /// @dev REQ-COMMON-21A: the method is part of the pinned request line.
    function test_rejectsTheWrongMethodOnTheTokenRequest() public {
        bytes memory body = _honestTokenBody();
        bytes memory whole = abi.encodePacked(
            "GET /2/oauth2/token HTTP/1.1\r\n",
            TOKEN_HEADERS,
            "content-length: ",
            vm.toString(body.length),
            "\r\n\r\n",
            body
        );
        AttestationBuilder.Direction memory sent = AttestationBuilder.Direction({
            revealed: AttestationBuilder.one(AttestationBuilder.Range({start: 0, value: whole})),
            commitments: AttestationBuilder.none(),
            length: uint32(whole.length)
        });
        bytes memory a = AttestationBuilder.encode(CeremonyProfile.AUTHORITY_X_API, T0, sent, _tokenResponse(true));
        TlsNotaryVerifierBase.TlsNotaryProof memory s = _payload();
        s.tokenSession = ICeremony.Attestation({attestedData: a, proof: AttestationBuilder.sign(NOTARY_KEY, a)});
        vm.expectRevert(TlsNotaryVerifierBase.WrongRequestLine.selector);
        this.run{value: quote}(s);
    }

    /// The honest token request, byte for byte as `_tokenAttestation` sends it.
    function _honestXRequest() private view returns (bytes memory) {
        bytes memory body = _honestTokenBody();
        return abi.encodePacked(_tokenHead(TOKEN_HEADERS, body.length), body);
    }

    /// The body of that request.
    function _honestTokenBody() private view returns (bytes memory) {
        return _honestTokenBody("abc", "https%3A%2F%2Fapp.example%2Fcb");
    }

    /// The token body with `code` and `redirect_uri` given.
    function _honestTokenBody(string memory code, string memory redirectUri) private view returns (bytes memory) {
        return abi.encodePacked(
            "grant_type=authorization_code&client_id=myClient-1&code=",
            code,
            "&redirect_uri=",
            redirectUri,
            "&code_verifier=",
            CeremonyAuthorization.codeVerifier(digest, AUTH_NONCE)
        );
    }

    // ─── The token request's headers (REQ-COMMON-21B) ───────────────

    /// An honest token session under `head`.
    function _tokenSessionWithHead(bytes memory head) private view returns (ICeremony.Attestation memory) {
        return _tokenSessionWith(head, _honestTokenBody());
    }

    /// The payload with an honest token session over `body`, its length declared.
    function _payloadWithBody(bytes memory body) private view returns (TlsNotaryVerifierBase.TlsNotaryProof memory s) {
        s = _payload();
        s.tokenSession = _tokenSessionWith(_tokenHead(TOKEN_HEADERS, body.length), body);
    }

    function _tokenSessionWith(bytes memory head, bytes memory body)
        private
        pure
        returns (ICeremony.Attestation memory)
    {
        bytes memory whole = abi.encodePacked(head, body);
        AttestationBuilder.Direction memory sent = AttestationBuilder.Direction({
            revealed: AttestationBuilder.one(AttestationBuilder.Range({start: 0, value: whole})),
            commitments: AttestationBuilder.none(),
            length: uint32(whole.length)
        });
        bytes memory a = AttestationBuilder.encode(CeremonyProfile.AUTHORITY_X_API, T0, sent, _tokenResponse(true));
        return ICeremony.Attestation({attestedData: a, proof: AttestationBuilder.sign(NOTARY_KEY, a)});
    }

    /// The payload with an honest token session under `headers`.
    function _payloadWithHeaders(bytes memory headers)
        private
        view
        returns (TlsNotaryVerifierBase.TlsNotaryProof memory s)
    {
        s = _payload();
        s.tokenSession = _tokenSessionWithHead(_tokenHead(headers, _honestTokenBody().length));
    }

    /// The payload with an honest token session under a whole `head`.
    function _payloadWithHead(bytes memory head) private view returns (TlsNotaryVerifierBase.TlsNotaryProof memory s) {
        s = _payload();
        s.tokenSession = _tokenSessionWithHead(head);
    }

    /// @dev The suite's composed head carries the headers `profiles.json` requires.
    function test_theFixtureHeadCarriesTheProfilesRequiredHeaders() public pure {
        assertTrue(
            AttestationBuilder.contains(
                _tokenHead(TOKEN_HEADERS, 0), abi.encodePacked(CeremonyProfile.X_TOKEN_REQUIRED_HEADERS, "\r\n")
            )
        );
    }

    /// @dev REQ-COMMON-21B: the media type selects X's body parser, and the verifier
    ///      reads the body as a form.
    function test_rejectsAnotherMediaTypeOnTheTokenRequest() public {
        TlsNotaryVerifierBase.TlsNotaryProof memory s = _payloadWithHeaders(
            "host: api.x.com\r\ncontent-type: application/json\r\naccept: application/json\r\nconnection: close\r\n"
        );
        vm.expectRevert(TlsNotaryVerifierBase.WrongTokenRequestHead.selector);
        this.run{value: quote}(s);
    }

    /// @dev With `authorization: Basic`, X authenticates the client from it rather
    ///      than from the revealed `client_id`.
    function test_rejectsAForbiddenHeaderOnTheTokenRequest() public {
        TlsNotaryVerifierBase.TlsNotaryProof memory s = _payloadWithHeaders(
            "host: api.x.com\r\ncontent-type: application/x-www-form-urlencoded\r\naccept: application/json\r\n"
            "authorization: Basic bXlDbGllbnQtMTpzM2NyZXQ=\r\nconnection: close\r\n"
        );
        vm.expectRevert(
            abi.encodeWithSelector(TlsNotaryVerifierBase.ForbiddenRequestHeader.selector, bytes("authorization"))
        );
        this.run{value: quote}(s);
    }

    /// @dev A forbidden name with a space or a tab inside it is still the
    ///      forbidden name (REQ-PLAT-56A).
    function test_rejectsAForbiddenHeaderWithWhitespaceInsideItsName() public {
        TlsNotaryVerifierBase.TlsNotaryProof memory s = _payloadWithHeaders(
            "host: api.x.com\r\ncontent-type: application/x-www-form-urlencoded\r\naccept: application/json\r\n"
            "author ization: Basic bXlDbGllbnQtMTpzM2NyZXQ=\r\nconnection: close\r\n"
        );
        vm.expectRevert(
            abi.encodeWithSelector(TlsNotaryVerifierBase.ForbiddenRequestHeader.selector, bytes("authorization"))
        );
        this.run{value: quote}(s);

        s = _payloadWithHeaders(
            "host: api.x.com\r\ncontent-type: application/x-www-form-urlencoded\r\naccept: application/json\r\n"
            "Transfer\t-Encoding: chunked\r\nconnection: close\r\n"
        );
        vm.expectRevert(
            abi.encodeWithSelector(TlsNotaryVerifierBase.ForbiddenRequestHeader.selector, bytes("transfer-encoding"))
        );
        this.run{value: quote}(s);
    }

    /// @dev Every forbidden name, in spellings the platform reads alike: case, colon
    ///      spacing, `_` for `-`. The error names it normalized.
    function test_rejectsEachForbiddenHeaderOnTheTokenRequest() public {
        string[9] memory lines = [
            "Transfer-Encoding: chunked",
            "content-encoding:gzip",
            "Content_Encoding: gzip",
            "Cookie: session=abc",
            "X-HTTP-Method-Override: GET",
            "x-http-method: DELETE",
            "X-Method-Override: PUT",
            "AUTHORIZATION: Basic bXlDbGllbnQtMTpzM2NyZXQ=",
            "authorization : Basic bXlDbGllbnQtMTpzM2NyZXQ="
        ];
        string[9] memory names = [
            "transfer-encoding",
            "content-encoding",
            "content-encoding",
            "cookie",
            "x-http-method-override",
            "x-http-method",
            "x-method-override",
            "authorization",
            "authorization"
        ];
        for (uint256 i = 0; i < lines.length; ++i) {
            TlsNotaryVerifierBase.TlsNotaryProof memory s = _payloadWithHeaders(
                abi.encodePacked(
                    "host: api.x.com\r\ncontent-type: application/x-www-form-urlencoded\r\n",
                    lines[i],
                    "\r\naccept: application/json\r\nconnection: close\r\n"
                )
            );
            vm.expectRevert(
                abi.encodeWithSelector(TlsNotaryVerifierBase.ForbiddenRequestHeader.selector, bytes(names[i]))
            );
            this.run{value: quote}(s);
        }
    }

    /// @dev The media type and `host` are required.
    function test_rejectsATokenRequestMissingARequiredHeader() public {
        TlsNotaryVerifierBase.TlsNotaryProof memory s =
            _payloadWithHeaders("host: api.x.com\r\naccept: application/json\r\nconnection: close\r\n");
        vm.expectRevert(TlsNotaryVerifierBase.WrongTokenRequestHead.selector);
        this.run{value: quote}(s);

        s = _payloadWithHeaders(
            "content-type: application/x-www-form-urlencoded\r\naccept: application/json\r\nconnection: close\r\n"
        );
        vm.expectRevert(TlsNotaryVerifierBase.WrongTokenRequestHead.selector);
        this.run{value: quote}(s);
    }

    /// @dev A required header must appear exactly once.
    function test_rejectsARequiredHeaderTwice() public {
        TlsNotaryVerifierBase.TlsNotaryProof memory s = _payloadWithHeaders(
            "host: api.x.com\r\ncontent-type: application/x-www-form-urlencoded\r\n"
            "content-type: application/x-www-form-urlencoded\r\naccept: application/json\r\nconnection: close\r\n"
        );
        vm.expectRevert(TlsNotaryVerifierBase.WrongTokenRequestHead.selector);
        this.run{value: quote}(s);
    }

    /// @dev A header the profile sends but does not compare, such as `accept`, may be missing.
    function test_acceptsATokenRequestWithoutAnUncomparedHeader() public {
        TlsNotaryVerifierBase.TlsNotaryProof memory s = _payloadWithHeaders(
            "host: api.x.com\r\ncontent-type: application/x-www-form-urlencoded\r\nconnection: close\r\n"
        );
        this.run{value: quote}(s);
    }

    /// @dev Headers the profile does not name or forbid are accepted.
    function test_acceptsUnlistedHeadersOnTheTokenRequest() public {
        TlsNotaryVerifierBase.TlsNotaryProof memory s = _payloadWithHeaders(
            "host: api.x.com\r\nuser-agent: libid-ceremony\r\ncontent-type: application/x-www-form-urlencoded\r\n"
            "accept: application/json\r\naccept-encoding: identity\r\nconnection: close\r\nx-request-id: 7\r\n"
        );
        this.run{value: quote}(s);
    }

    /// @dev A required header in spellings HTTP reads alike: case, colon spacing,
    ///      a tab before the value.
    function test_acceptsARequiredHeaderInAnotherSpelling() public {
        TlsNotaryVerifierBase.TlsNotaryProof memory s = _payloadWithHeaders(
            "Host:\tapi.x.com \r\nContent-Type :application/x-www-form-urlencoded\r\naccept: application/json\r\nconnection: close\r\n"
        );
        this.run{value: quote}(s);
    }

    /// @dev A carriage return without a line feed is refused, even inside an ignored header's value.
    function test_rejectsABareCarriageReturnInTheTokenHead() public {
        TlsNotaryVerifierBase.TlsNotaryProof memory s = _payloadWithHeaders(
            "host: api.x.com\r\ncontent-type: application/x-www-form-urlencoded\r\naccept: application/json\rauthorization: Basic x\r\nconnection: close\r\n"
        );
        vm.expectPartialRevert(CeremonyAttestation.BareCarriageReturn.selector);
        this.run{value: quote}(s);
    }

    /// @dev A header line without a colon is refused.
    function test_rejectsAHeaderLineWithoutAColon() public {
        TlsNotaryVerifierBase.TlsNotaryProof memory s = _payloadWithHeaders(
            "host: api.x.com\r\ncontent-type: application/x-www-form-urlencoded\r\nnot a header\r\nconnection: close\r\n"
        );
        vm.expectRevert(TlsNotaryVerifierBase.WrongTokenRequestHead.selector);
        this.run{value: quote}(s);
    }

    /// @dev Header order is not pinned.
    function test_acceptsTheSameHeadersInAnotherOrder() public {
        TlsNotaryVerifierBase.TlsNotaryProof memory s = _payloadWithHeaders(
            "host: api.x.com\r\naccept: application/json\r\ncontent-type: application/x-www-form-urlencoded\r\nconnection: close\r\n"
        );
        this.run{value: quote}(s);
    }

    /// @dev The length header may sit anywhere in the head.
    function test_acceptsTheLengthHeaderAnywhereInTheHead() public {
        uint256 length = _honestTokenBody().length;
        TlsNotaryVerifierBase.TlsNotaryProof memory s = _payloadWithHead(
            abi.encodePacked(
                "POST /2/oauth2/token HTTP/1.1\r\ncontent-length: ",
                vm.toString(length),
                "\r\nhost: api.x.com\r\ncontent-type: application/x-www-form-urlencoded\r\naccept: application/json\r\nconnection: close\r\n\r\n"
            )
        );
        this.run{value: quote}(s);
    }

    /// @dev X frames the body by the declared length, so it must cover the whole revealed body.
    function test_rejectsATokenRequestUnderdeclaringItsBody() public {
        uint256 length = _honestTokenBody().length;
        TlsNotaryVerifierBase.TlsNotaryProof memory s = _payload();
        s.tokenSession = _tokenSessionWithHead(_tokenHead(TOKEN_HEADERS, length - 10));
        vm.expectRevert(
            abi.encodeWithSelector(TlsNotaryVerifierBase.WrongDeclaredBodyLength.selector, length - 10, length)
        );
        this.run{value: quote}(s);
    }

    /// @dev The `content-length` value must be digits only.
    function test_rejectsADeclaredBodyLengthThatIsNotDigits() public {
        TlsNotaryVerifierBase.TlsNotaryProof memory s = _payload();
        s.tokenSession = _tokenSessionWithHead(
            abi.encodePacked("POST /2/oauth2/token HTTP/1.1\r\n", TOKEN_HEADERS, "content-length: 72, 8\r\n\r\n")
        );
        vm.expectRevert(TlsNotaryVerifierBase.WrongTokenRequestHead.selector);
        this.run{value: quote}(s);
    }

    /// @dev A leading zero is a second spelling of the same length and is refused.
    function test_rejectsANoncanonicalDeclaredBodyLength() public {
        TlsNotaryVerifierBase.TlsNotaryProof memory s = _payload();
        s.tokenSession = _tokenSessionWithHead(
            abi.encodePacked(
                "POST /2/oauth2/token HTTP/1.1\r\n",
                TOKEN_HEADERS,
                "content-length: 0",
                vm.toString(_honestTokenBody().length),
                "\r\n\r\n"
            )
        );
        vm.expectRevert(TlsNotaryVerifierBase.WrongTokenRequestHead.selector);
        this.run{value: quote}(s);
    }

    /// That request as the one revealed run the profile fixes.
    function _honestTokenSent() private view returns (AttestationBuilder.Direction memory) {
        bytes memory whole = _honestXRequest();
        return AttestationBuilder.Direction({
            revealed: AttestationBuilder.one(AttestationBuilder.Range({start: 0, value: whole})),
            commitments: AttestationBuilder.none(),
            length: uint32(whole.length)
        });
    }

    /// A request line hidden under a commitment over [0,10).
    function test_rejectsATokenRequestLineNotAtOrigin() public {
        bytes memory whole = _honestXRequest();
        bytes memory rest = new bytes(whole.length - 10);
        for (uint256 i = 0; i < rest.length; ++i) {
            rest[i] = whole[10 + i];
        }
        AttestationBuilder.Direction memory sent = AttestationBuilder.Direction({
            revealed: AttestationBuilder.one(AttestationBuilder.Range({start: 10, value: rest})),
            commitments: AttestationBuilder.one(
                AttestationBuilder.Commitment({start: 0, end: 10, value: bytes32(uint256(0xAB))})
            ),
            length: uint32(whole.length)
        });
        bytes memory a = AttestationBuilder.encode(CeremonyProfile.AUTHORITY_X_API, T0, sent, _tokenResponse(true));
        TlsNotaryVerifierBase.TlsNotaryProof memory s = _payload();
        s.tokenSession = ICeremony.Attestation({attestedData: a, proof: AttestationBuilder.sign(NOTARY_KEY, a)});
        vm.expectRevert(abi.encodeWithSelector(TlsNotaryVerifierBase.RequestLineNotAtOrigin.selector, uint32(10)));
        this.run{value: quote}(s);
    }

    /// No revealed range in the sent direction.
    function test_rejectsATokenRequestWithNoRevealedRange() public {
        AttestationBuilder.Direction memory sent = AttestationBuilder.Direction({
            revealed: new AttestationBuilder.Range[](0), commitments: AttestationBuilder.none(), length: 0
        });
        bytes memory a = AttestationBuilder.encode(CeremonyProfile.AUTHORITY_X_API, T0, sent, _tokenResponse(true));
        TlsNotaryVerifierBase.TlsNotaryProof memory s = _payload();
        s.tokenSession = ICeremony.Attestation({attestedData: a, proof: AttestationBuilder.sign(NOTARY_KEY, a)});
        vm.expectRevert(abi.encodeWithSelector(TlsNotaryVerifierBase.RequestLineNotAtOrigin.selector, type(uint32).max));
        this.run{value: quote}(s);
    }

    function test_rejectsATokenResponseFramingTwoBearers() public {
        bytes memory p = '"access_token":"';
        AttestationBuilder.Direction memory recv = AttestationBuilder.Direction({
            revealed: AttestationBuilder.three(
                AttestationBuilder.Range({start: 0, value: p}),
                AttestationBuilder.Range({start: 28, value: abi.encodePacked('"', p)}),
                AttestationBuilder.Range({start: 57, value: '"'})
            ),
            commitments: AttestationBuilder.two(
                AttestationBuilder.Commitment({start: 16, end: 28, value: TOKEN_COMMITMENT}),
                AttestationBuilder.Commitment({start: 45, end: 57, value: bytes32(uint256(0x3333))})
            ),
            length: 58
        });
        bytes memory a = AttestationBuilder.encode(CeremonyProfile.AUTHORITY_X_API, T0, _honestTokenSent(), recv);
        TlsNotaryVerifierBase.TlsNotaryProof memory s = _payload();
        s.tokenSession = ICeremony.Attestation({attestedData: a, proof: AttestationBuilder.sign(NOTARY_KEY, a)});
        vm.expectRevert(CeremonyAttestation.AmbiguousFraming.selector);
        this.run{value: quote}(s);
    }

    function test_aForeignOperationDomainFailsTheBinding() public {
        TlsNotaryVerifierBase.TlsNotaryProof memory s = _payload();
        s.operationDomain = keccak256("someone.else");
        vm.expectRevert(TlsNotaryVerifierBase.CodeVerifierMismatch.selector);
        this.run{value: quote}(s);
    }

    function test_aNeedleInsideAHeaderValueIsNotAHeaderLine() public {
        TlsNotaryVerifierBase.TlsNotaryProof memory s = _payload();
        s.identitySession = _identityAttestation("2244994945", "Alice_1", "x-note: authorization: Bearer decoy\r\n");
        assertEq(this.run{value: quote}(s).handleNode, HANDLE_NODE);
    }

    function test_rejectsABareLineFeedInTheIdentityRequest() public {
        TlsNotaryVerifierBase.TlsNotaryProof memory s = _payload();
        s.identitySession = _identityAttestation("2244994945", "Alice_1", "x-pad: a\nauthorization: Bearer STOLEN\r\n");
        vm.expectPartialRevert(CeremonyAttestation.BareLineFeed.selector);
        this.run{value: quote}(s);
    }

    function test_theIdentityAttestationsOwnTimeIsNotEvidenceTime() public {
        TlsNotaryVerifierBase.TlsNotaryProof memory s = _payload();
        bytes memory a = s.identitySession.attestedData;
        // createdAt := 1, the eight bytes after the authority id.
        for (uint256 i = 32; i < 40; ++i) {
            a[i] = 0;
        }
        a[39] = 0x01;
        s.identitySession = ICeremony.Attestation({attestedData: a, proof: AttestationBuilder.sign(NOTARY_KEY, a)});
        assertEq(this.run{value: quote}(s).metadataObservedAt, T0 - ALLOWANCE);
    }

    function test_aMalformedPayloadRevertsWithNoData() public {
        (bool ok, bytes memory ret) = address(verifier).call{value: quote}(abi.encodeCall(verifier.verify, (hex"")));
        assertFalse(ok);
        assertEq(ret.length, 0);
    }
}
