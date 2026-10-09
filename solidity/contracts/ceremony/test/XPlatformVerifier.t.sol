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

/// @notice A profile no launch profile is: its allowance sits below its skew.
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

/// @notice An upgrade that pins another circuit, wired to nothing new.
contract XPinningGitHubsCircuit is XPlatformVerifier {
    function _circuitCodehash() internal pure override returns (bytes32) {
        return CircuitCodehashes.BEARER_LINK_GITHUB;
    }
}

/// @notice The `x/v1` path end to end: two attestations, a real notary
///         signature over each, and every check the profile assigns here.
contract XPlatformVerifierTest is RealTlsNotaryProofTest {
    using AttestationBuilder for AttestationBuilder.Range;
    using AttestationBuilder for AttestationBuilder.Direction;

    XPlatformVerifier verifier;
    NotaryService notary;
    address honk;
    /// Hoisted: an external call inside a `{value:}` argument would consume the
    /// `expectRevert` before the call under test ever runs.
    uint256 quote;

    uint256 constant FEE = 0.001 ether;
    uint64 constant LIFETIME = CeremonyProfile.PROOF_LIFETIME_SECONDS_X;
    uint64 constant SKEW = CeremonyProfile.MAX_FUTURE_ATTESTATION_SKEW_SECONDS_X;
    uint64 constant ALLOWANCE = CeremonyProfile.FUTURE_OBSERVATION_ALLOWANCE_SECONDS_X;
    uint64 constant T0 = 1_770_000_000;

    bytes32 constant DOMAIN = keccak256(bytes("libid.claim-identity"));
    bytes32 constant AUTH_NONCE = bytes32(uint256(0x5555555555555555555555555555555555555555555555555555555555555555));
    /// The digest the fixtures are made for: what the verifier rebuilds from
    /// the payload below, on this chain. Derived in `setUp`, because it
    /// depends on the chain id.
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
        digest = CeremonyAuthorization.digestFor(DOMAIN, 1, AUTH_NONCE, _txData());

        NotaryService nImpl = new NotaryService();
        notary = NotaryService(
            address(
                new ERC1967Proxy(
                    address(nImpl), abi.encodeCall(NotaryService.initialize, (OWNER, vm.addr(NOTARY_KEY), FEE))
                )
            )
        );
        honk = HonkStub.deploy(HonkStub.X);

        XPlatformVerifier vImpl = new XPlatformVerifier();
        verifier = XPlatformVerifier(
            address(
                new ERC1967Proxy(
                    address(vImpl),
                    abi.encodeCall(
                        XPlatformVerifier.initialize,
                        (OWNER, INotaryService(address(notary)), IHonkVerifier(address(honk)), address(honk).codehash)
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

    /// A token request head: the request line, a header block, and the length
    /// the platform frames the body by. Assembled from its parts so a test can
    /// change one header and watch the verifier refuse it.
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

    /// @dev `bearerFraming` false commits the bearer with no revealed anchors,
    ///      which is the shape REQ-PLAT-57 exists to refuse.
    function _tokenAttestation(
        string memory grantType,
        string memory clientId,
        string memory verifierValue,
        bool bearerFraming
    ) private pure returns (ICeremony.Attestation memory) {
        AttestationBuilder.Direction memory received;
        // The whole request in one revealed run: X uses a public client and
        // hides no body field, so the head boundary is visible and the body is
        // located by the framing the server itself parsed.
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
        // A real token response: the bearer committed and framed by the
        // revealed `"access_token":"` delimiter and its closing quote, with
        // every other byte hidden behind a commitment of its own.
        received = _tokenResponse(bearerFraming);

        bytes memory attested = AttestationBuilder.encode(CeremonyProfile.AUTHORITY_X_API, T0, sent, received);
        return ICeremony.Attestation({attestedData: attested, proof: AttestationBuilder.sign(NOTARY_KEY, attested)});
    }

    /// A token response shaped like the real one:
    ///   [0,15)  revealed `HTTP/1.1 200 OK` -- the server's agreement
    ///   [15,17) the CRLF closing it, committed
    ///   [17,33) revealed `"access_token":"`
    ///   [33,45) the committed bearer
    ///   [45,46) revealed closing quote
    ///   [46,70) the rest of the JSON, behind another commitment
    ///
    /// Every byte accounted for: the direction tiles, like the other three.
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

        // The status line and nothing else: the bearer commitment has no
        // revealed anchors around it, which is the shape REQ-PLAT-57 refuses,
        // because it could equally be a `refresh_token` value.
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
            ).commit("TOKENTOKENTOKEN", IDENTITY_COMMITMENT).reveal("\r\nconnection: close\r\n\r\n");
    }

    /// The identity response: anchors revealed, id and handle each committed,
    /// every other byte committed.
    function _identityResponse(bytes memory id, bytes memory handle)
        private
        pure
        returns (AttestationBuilder.Direction memory received)
    {
        received.commit('HTTP/1.1 200 OK\r\ncontent-type: application/json\r\n\r\n{"data":{', OTHER).reveal('"id":"')
            .commit(id, ID_COMMITMENT).reveal('"').commit(',"name":"Alice",', OTHER).reveal('"username":"')
            .commit(handle, HANDLE_COMMITMENT).reveal('"').commit("}}", OTHER);
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
        return abi.encode(address(0xBEEF), uint256(0), address(0));
    }

    /// The `x/v1` payload the fixtures are made for. Public inputs are not in
    /// it: the verifier derives them from the two attestations.
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
        // The nodes the payload claims, passed through: the proof is what
        // binds them, and the stub here accepts any.
        assertEq(f.idNode, ID_NODE);
        assertEq(f.handleNode, HANDLE_NODE);
        assertEq(string(f.clientIdentifier), "myClient-1");
        // What entered the digest comes back, with the session id and the
        // ceremony version this verifier implements.
        assertEq(f.sessionId, digest);
        assertEq(f.operationDomain, DOMAIN);
        assertEq(f.transactionData, _txData());
        assertEq(f.ceremonyVersion, 1);
        // On the shared scale, not raw. Profiles disagree about "now" -- this
        // one's evidence time is an attestation creation time, Google's is a
        // signed expiry an hour ahead -- so each verifier subtracts its own
        // allowance and a Consumer can compare the two.
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

    /// @dev REQ-COMMON-15A, and the whole binding between evidence and
    ///      transaction. The verifier rebuilds the digest from the payload, so
    ///      changing any digest input -- here the nonce -- derives a different
    ///      verifier, and the revealed one no longer matches.
    function test_rejectsAnAttestationRetargetedToAnotherDigest() public {
        TlsNotaryVerifierBase.TlsNotaryProof memory s = _payload();
        s.authorizationNonce = bytes32(uint256(AUTH_NONCE) ^ 1);
        vm.expectRevert(TlsNotaryVerifierBase.CodeVerifierMismatch.selector);
        this.run{value: quote}(s);
    }

    /// @dev The same for the transaction data: it is in the digest, so a
    ///      payload naming another target opens against nothing.
    function test_rejectsAnAttestationRetargetedToAnotherWallet() public {
        TlsNotaryVerifierBase.TlsNotaryProof memory s = _payload();
        s.transactionData = abi.encode(address(0xDEAD));
        vm.expectRevert(TlsNotaryVerifierBase.CodeVerifierMismatch.selector);
        this.run{value: quote}(s);
    }

    /// @dev REQ-COMMON-12: the verifier is derived under the same nonce the
    ///      digest commits, and the payload carries no second one. Evidence
    ///      built under any other nonce opens against nothing, even where the
    ///      payload itself still names the nonce the digest was made for.
    function test_rejectsAVerifierDerivedUnderAnotherNonce() public {
        TlsNotaryVerifierBase.TlsNotaryProof memory s = _payload();
        string memory foreign = string(CeremonyAuthorization.codeVerifier(digest, bytes32(uint256(1))));
        s.tokenSession = _tokenAttestation("authorization_code", "myClient-1", foreign);
        vm.expectRevert(TlsNotaryVerifierBase.CodeVerifierMismatch.selector);
        this.run{value: quote}(s);
    }

    /// @dev The verifier implements one ceremony version and the digest binds
    ///      it. A payload claiming another is refused by name, before any fee
    ///      moves, rather than as a verifier mismatch after both sessions were
    ///      paid for.
    function test_rejectsAPayloadForAnotherCeremonyVersion() public {
        TlsNotaryVerifierBase.TlsNotaryProof memory s = _payload();
        s.ceremonyVersion = 2;
        vm.expectRevert(abi.encodeWithSelector(PlatformVerifierBase.WrongCeremonyVersion.selector, 1, 2));
        this.run{value: quote}(s);
    }

    // ─── grant_type ─────────────────────────────────────────────────

    /// @dev REQ-PLAT-56. A refresh grant still carries a code, a redirect_uri
    ///      and a digest-derived verifier, so every other check passes while X
    ///      mints a fresh bearer — letting an app with a refresh token mint
    ///      identity proofs at arbitrary addresses from one consent.
    function test_rejectsARefreshGrant() public {
        TlsNotaryVerifierBase.TlsNotaryProof memory s = _payload();
        string memory v = string(CeremonyAuthorization.codeVerifier(digest, AUTH_NONCE));
        s.tokenSession = _tokenAttestation("refresh_token", "myClient-1", v);
        vm.expectPartialRevert(XPlatformVerifier.WrongGrantType.selector);
        this.run{value: quote}(s);
    }

    // ─── The token body's form ──────────────────────────────────────

    /// @dev The five fields in another order -- `client_id` last, as the
    ///      legacy claim worker serializes them -- are not the profile's
    ///      serialization, whatever X makes of them. The first pair is the
    ///      right one, so the body fails where the second begins.
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

    /// @dev A sixth pair is refused at the `&` that begins it. X is a public
    ///      client and its profile lists no `client_secret`.
    function test_rejectsATokenBodyCarryingAClientSecret() public {
        bytes memory honest = _honestTokenBody();
        TlsNotaryVerifierBase.TlsNotaryProof memory s =
            _payloadWithBody(abi.encodePacked(honest, "&client_secret=0123456789abcdef0123456789abcdef"));
        vm.expectRevert(abi.encodeWithSelector(CeremonyFields.MalformedForm.selector, honest.length));
        this.run{value: quote}(s);
    }

    /// @dev REQ-PLAT-63, TEST-PLAT-09C: a duplicate in an ENCODED spelling.
    ///      `code%5Fverifier` is `code_verifier` to a form parser but no
    ///      literal match for it. It is a sixth pair here, refused like any
    ///      other.
    function test_rejectsATokenBodyWithAnEncodedDuplicateName() public {
        bytes memory honest = _honestTokenBody();
        TlsNotaryVerifierBase.TlsNotaryProof memory s =
            _payloadWithBody(abi.encodePacked(honest, "&code%5Fverifier=EVILEVILEVILEVILEVILEVILEVILEVILEVILEVIL0"));
        vm.expectRevert(abi.encodeWithSelector(CeremonyFields.MalformedForm.selector, honest.length));
        this.run{value: quote}(s);
    }

    /// @dev Four pairs are not five. The fourth is `code_verifier=` where
    ///      `redirect_uri=` should stand, so the body fails where it begins.
    function test_rejectsATokenBodyMissingTheRedirect() public {
        bytes memory first = "grant_type=authorization_code&client_id=myClient-1&code=abc&";
        bytes memory body =
            abi.encodePacked(first, "code_verifier=", CeremonyAuthorization.codeVerifier(digest, AUTH_NONCE));
        TlsNotaryVerifierBase.TlsNotaryProof memory s = _payloadWithBody(body);
        vm.expectRevert(abi.encodeWithSelector(CeremonyFields.MalformedForm.selector, first.length));
        this.run{value: quote}(s);
    }

    /// @dev A raw `;` inside the redirect. Some form parsers split pairs on
    ///      it, so to them this body carries a second `code_verifier`, while
    ///      a reader splitting only on `&` counts one. The serializer never
    ///      emits a raw `;`, so the byte
    ///      itself is refused.
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

    /// @dev `%3a` decodes as `%3A` does and is not what the serializer
    ///      writes, so it is a second spelling of the same redirect and
    ///      refused as noncanonical.
    function test_rejectsATokenBodyWithALowercaseEscape() public {
        bytes memory body = _honestTokenBody("abc", "https%3a%2F%2Fapp.example%2Fcb");
        TlsNotaryVerifierBase.TlsNotaryProof memory s = _payloadWithBody(body);
        vm.expectRevert(
            abi.encodeWithSelector(CeremonyFields.MalformedForm.selector, AttestationBuilder.indexOf(body, "%3a"))
        );
        this.run{value: quote}(s);
    }

    /// @dev Nothing after the last value, not even the delimiter that would
    ///      begin a sixth pair.
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

    /// @dev Nothing in an attestation says which session of a ceremony it
    ///      covers, and nothing needs to. X serves both sessions from one host,
    ///      so the authority cannot separate them either -- what separates them
    ///      is the request line, which the notary recorded as a revealed range
    ///      and did not choose. Swapping the two therefore fails on bytes that
    ///      came off the wire rather than on a label the prover handed over.
    function test_rejectsTheTwoSessionsSwapped() public {
        TlsNotaryVerifierBase.TlsNotaryProof memory s = _payload();
        (s.tokenSession, s.identitySession) = (s.identitySession, s.tokenSession);
        vm.expectPartialRevert(TlsNotaryVerifierBase.WrongRequestLine.selector);
        this.run{value: quote}(s);
    }

    // ─── The circuit link ───────────────────────────────────────────

    /// @dev The inputs the proof is checked against are BUILT from the two
    ///      attestations, so "the circuit proved a link between other
    ///      attestations" (REQ-PLAT-32C) is not a case to reject -- it is a
    ///      case that cannot be stated. This asserts what the verifier derived.
    function test_provesAgainstTheCommitmentsTheNotarySigned() public {
        TlsNotaryVerifierBase.TlsNotaryProof memory s = _payload();
        // Exact arguments: the proof as submitted, and inputs the caller never
        // supplied.
        vm.expectCall(
            address(honk),
            abi.encodeCall(
                IHonkVerifier.verify,
                (s.proof, _expectedInputs(TOKEN_COMMITMENT, IDENTITY_COMMITMENT, ID_COMMITMENT, HANDLE_COMMITMENT))
            )
        );
        this.run{value: quote}(s);
    }

    /// @dev The id and handle are found by their anchors, not by where they
    ///      sit. A response naming the handle first still puts the id
    ///      commitment at fields 64-65, which is where the circuit opens it.
    function test_findsTheIdAndHandleByTheirAnchorsNotTheirOrder() public {
        TlsNotaryVerifierBase.TlsNotaryProof memory s = _payload();
        AttestationBuilder.Direction memory received;
        received.commit('HTTP/1.1 200 OK\r\n\r\n{"data":{', OTHER).reveal('"username":"')
            .commit("Alice_1", HANDLE_COMMITMENT).reveal('"').commit(",", OTHER).reveal('"id":"')
            .commit("2244994945", ID_COMMITMENT).reveal('"').commit("}}", OTHER);
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

    /// The 12 public inputs, written out independently of the verifier.
    function _expectedInputs(bytes32 token, bytes32 identity, bytes32 id, bytes32 handle)
        private
        pure
        returns (bytes32[] memory expected)
    {
        expected = new bytes32[](12);
        bytes32[6] memory wide = [token, identity, id, handle, ID_NODE, HANDLE_NODE];
        for (uint256 k = 0; k < 6; ++k) {
            expected[2 * k] = bytes32(uint256(wide[k]) / 2 ** 128);
            expected[2 * k + 1] = bytes32(uint256(wide[k]) % 2 ** 128);
        }
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
        address repinned = address(new XPinningGitHubsCircuit());
        vm.prank(OWNER);
        verifier.upgradeToAndCall(repinned, "");
        TlsNotaryVerifierBase.TlsNotaryProof memory s = _payload();
        vm.expectRevert(
            abi.encodeWithSelector(
                PlatformVerifierBase.WrongCircuit.selector, CircuitCodehashes.BEARER_LINK_GITHUB, honk.codehash
            )
        );
        this.run{value: quote}(s);
    }

    // ─── The requests the runtime sends ─────────────────────────────

    /// @dev The token request as the browser composes it (`buildTokenRequest`
    ///      on libid `feat/ceremony-rebuild-plan`): five headers in its order,
    ///      `content-length` set by the builder itself and third, every name
    ///      lowercased by hyper on the way to the wire. The rule was written
    ///      for this head, and this is what says the rule admits it.
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

    /// @dev And the identity request as `buildIdentityRequest` composes it:
    ///      `authorization` first and inside the head, then `accept`, `host`,
    ///      `connection`. The fixtures elsewhere in this file put the bearer
    ///      line after a blank line, which the verifier tolerates; this one is
    ///      the head a real session carries.
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

    /// @dev Two records the Rust pipeline produced the way a ceremony produces
    ///      them minus the MPC: the requests composed as the browser composes
    ///      them and encoded by hyper, the layouts `libid_transcript::ceremony`'s,
    ///      the commitments tlsn's SHA-256 plaintext hashes, the record
    ///      `AttestedData::from_observed`, which is the notary's own path,
    ///      signed by the key this suite trusts. Nothing in the file was
    ///      written by hand, and it verifies with those signatures unedited:
    ///      the verifier inside was derived from the digest this suite derives,
    ///      which the first assertion checks. Generated by
    ///      `cargo run -p libid-tlsn --example ceremony_fixtures` in libid-rs.
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

    function _circuitArtifact() internal pure override returns (string memory) {
        return "BearerLinkXHonkVerifier.sol:BearerLinkXHonkVerifier";
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

    /// @dev A real proof through the circuit's verifier outputs the hashlib
    ///      nodes for `2244994945` and `alice_1` (folded from `Alice_1`).
    function test_verifiesARealProofOfTheRecordsLibidRsProduces() public {
        (TlsNotaryVerifierBase.TlsNotaryProof memory s, address circuit, bytes32[] memory proved) = _realProofPayload();
        assertEq(proved.length, 12);
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

    /// @dev The whole captured record: its response reveals the id and handle,
    ///      which the anchor-only framing refuses.
    function test_verifiesTheRecordsACeremonyProduced() public {
        vm.skip(
            true,
            "x-ceremony-real.json's identity response predates the hashed identities: it reveals the id and handle; recapture with libid-rs capture_ceremony under the anchor-only reveal"
        );
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

    /// @dev And a second one under another scheme. The count sees
    ///      `authorization:` whatever follows it; counting only `bearer` left
    ///      a Basic line uncounted, and X answering for whichever credential
    ///      it honoured -- the one the exchange is bound to, or the other.
    function test_rejectsASecondAuthorizationHeaderOfAnotherScheme() public {
        TlsNotaryVerifierBase.TlsNotaryProof memory s = _payload();
        s.identitySession =
            _identityAttestation("2244994945", "Alice_1", "Authorization: Basic dmljdGltOnN0b2xlbg==\r\n");
        vm.expectPartialRevert(CeremonyAttestation.NotOneAuthorizationHeader.selector);
        this.run{value: quote}(s);
    }

    /// @dev `cookie` is the other credential a platform might honour over the
    ///      bearer, and the bearer is the one thing the cross-bind ties to the
    ///      exchange. Forbidden on the identity request as on the token one.
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

    /// @dev A bare carriage return on the identity request is refused the
    ///      same way, before anything is counted.
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
        // Built first: `vm.sign` inside is an external call, and it would
        // consume the cheatcode before the call under test.
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

    /// @dev Nothing moves the window, the owner included. A browser derives a
    ///      proof's expiry from the version it ran, so an outstanding proof
    ///      stays good until the expiry that version fixes.
    function test_theOwnerCannotShortenAnOutstandingProof() public {
        vm.warp(T0 + 100);
        vm.prank(OWNER);
        (bool moved,) = address(verifier)
            .call(abi.encodeWithSignature("setProtocolParameters(uint64,uint64,uint64)", uint64(50), SKEW, ALLOWANCE));
        assertFalse(moved, "the owner moved the window");
        this.run{value: quote}(_payload());
    }

    /// @dev An attestation inside `maxFutureAttestationSkew` but past
    ///      `futureObservationAllowance` is refused; a test profile sets allowance < skew.
    function test_rejectsAnAttestationPastTheObservationAllowanceButInsideTheSkew() public {
        SkewPastAllowance window = new SkewPastAllowance();
        vm.warp(T0 - window.SKEW());
        vm.expectPartialRevert(PlatformVerifierBase.ObservedInTheFuture.selector);
        window.requireFresh(T0);
    }

    // ─── The proof artifact (REQ-COMMON-45) ─────────────────────────

    /// @dev An address alone does not say WHICH circuit answers behind it.
    ///      bb-generated Honk verifiers embed their verification key as code
    ///      constants and expose no getter, so the code hash is the only handle
    ///      governance has on the artifact it selected. Naming it makes a
    ///      mis-wiring fail here, at the governance call, rather than at the
    ///      first user's proof.
    function test_rejectsAVerifierThatIsNotTheNamedArtifact() public {
        address other = HonkStub.deploy(HonkStub.X);
        vm.prank(OWNER);
        vm.expectPartialRevert(PlatformVerifierBase.WrongVerifierArtifact.selector);
        verifier.setTrustRoots(INotaryService(address(notary)), IHonkVerifier(other), keccak256("some other artifact"));
    }

    /// @dev An account with no code hashes to the empty-code hash, which no
    ///      real artifact matches, so a plain address cannot be wired either.
    /// @dev A non-existent account hashes to zero (EIP-1052) and an empty one
    ///      to `keccak256("")`, so either as the EXPECTED value is a hash any
    ///      such address satisfies -- and the mis-wiring surfaces at the first
    ///      user's proof, which is what this check exists to prevent.
    function test_refusesAnExpectedCodehashAnEmptyAccountWouldSatisfy() public {
        address untouched = address(0xDEAD0001);
        vm.startPrank(OWNER);
        vm.expectPartialRevert(PlatformVerifierBase.WrongVerifierArtifact.selector);
        verifier.setTrustRoots(INotaryService(address(notary)), IHonkVerifier(untouched), bytes32(0));
        vm.expectPartialRevert(PlatformVerifierBase.WrongVerifierArtifact.selector);
        verifier.setTrustRoots(INotaryService(address(notary)), IHonkVerifier(untouched), keccak256(""));
        vm.stopPrank();
    }

    function test_rejectsAnAddressHoldingNoCode() public {
        address eoa = address(0xB0B);
        vm.prank(OWNER);
        vm.expectPartialRevert(PlatformVerifierBase.WrongVerifierArtifact.selector);
        verifier.setTrustRoots(INotaryService(address(notary)), IHonkVerifier(eoa), keccak256("anything"));
    }

    /// @dev Only this platform's circuit's verifier: GitHub's has the same
    ///      public-input layout, and is refused by its code hash.
    function test_rejectsAnotherCircuitsVerifier() public {
        address github = vm.deployCode(HonkStub.GITHUB);
        vm.prank(OWNER);
        vm.expectRevert(
            abi.encodeWithSelector(
                PlatformVerifierBase.WrongCircuit.selector, CircuitCodehashes.BEARER_LINK_X, github.codehash
            )
        );
        verifier.setTrustRoots(INotaryService(address(notary)), IHonkVerifier(github), github.codehash);
        assertEq(verifier.circuitCodehash(), CircuitCodehashes.BEARER_LINK_X);
    }

    function test_recordsTheArtifactItWired() public {
        address other = HonkStub.deploy(HonkStub.X);
        vm.prank(OWNER);
        verifier.setTrustRoots(INotaryService(address(notary)), IHonkVerifier(other), other.codehash);
        assertEq(verifier.honkVerifier(), other);
        assertEq(verifier.honkVerifierCodehash(), other.codehash);
    }

    // ─── The identity fields ────────────────────────────────────────

    /// @dev Signed responses laid out by the prover: the framing names the one
    ///      commitment behind each anchor, or refuses.

    function _refusedFraming(AttestationBuilder.Direction memory received, bytes4 error_) private {
        TlsNotaryVerifierBase.TlsNotaryProof memory s = _payload();
        s.identitySession = _identityReceiving(received);
        vm.expectPartialRevert(error_);
        this.run{value: quote}(s);
    }

    /// The response up to the handle's anchor, honest: the id framed.
    function _upToTheHandle() private pure returns (AttestationBuilder.Direction memory received) {
        received.commit('HTTP/1.1 200 OK\r\n\r\n{"data":{', OTHER).reveal('"id":"').commit("2244994945", ID_COMMITMENT)
            .reveal('"').commit(",", OTHER);
    }

    /// @dev The key revealed in two pieces around a commitment is no anchor.
    function test_refusesAHandleAnchorSplitAroundACommittedGap() public {
        AttestationBuilder.Direction memory received = _upToTheHandle();
        received.reveal('"user').commit("name", OTHER).reveal('":"').commit("Alice_1", HANDLE_COMMITMENT).reveal('"')
            .commit("}}", OTHER);
        _refusedFraming(received, CeremonyAttestation.NoFramedCommitment.selector);
    }

    /// @dev The same key in two ADJACENT revealed ranges, nothing hidden
    ///      between them. Still not one run.
    function test_refusesAHandleAnchorSplitAcrossTwoRevealedRanges() public {
        AttestationBuilder.Direction memory received = _upToTheHandle();
        received.reveal('"user').reveal('name":"').commit("Alice_1", HANDLE_COMMITMENT).reveal('"').commit("}}", OTHER);
        _refusedFraming(received, CeremonyAttestation.NoFramedCommitment.selector);
    }

    /// @dev X's id is a JSON string, so its value ends at a quote. A
    ///      commitment followed by anything else is not the whole value.
    function test_refusesAnIdWithNoClosingQuote() public {
        AttestationBuilder.Direction memory received;
        received.commit('HTTP/1.1 200 OK\r\n\r\n{"data":{', OTHER).reveal('"id":"').commit("2244994945", ID_COMMITMENT)
            .reveal("',").reveal('"username":"').commit("Alice_1", HANDLE_COMMITMENT).reveal('"').commit("}}", OTHER);
        _refusedFraming(received, CeremonyAttestation.NoFramedCommitment.selector);
    }

    /// @dev The closing quote committed with the value: the byte after the
    ///      commitment is the comma, so the commitment frames nothing, and
    ///      the circuit is never asked to open a value with a quote in it.
    function test_refusesAHandleCommittedWithItsClosingQuote() public {
        AttestationBuilder.Direction memory received = _upToTheHandle();
        received.reveal('"username":"').commit('Alice_1"', HANDLE_COMMITMENT).reveal("}}");
        _refusedFraming(received, CeremonyAttestation.NoFramedCommitment.selector);
    }

    /// @dev A value revealed between its anchors is refused, not read.
    function test_refusesARevealedHandle() public {
        AttestationBuilder.Direction memory received = _upToTheHandle();
        received.reveal('"username":"Alice_1"').commit("}}", OTHER);
        _refusedFraming(received, CeremonyAttestation.NoFramedCommitment.selector);
    }

    /// @dev A second handle anchor in the revealed bytes, framing a second
    ///      commitment. Two places the anchor could point, so it names none.
    function test_refusesTwoHandleAnchorsInTheRevealedBytes() public {
        AttestationBuilder.Direction memory received = _upToTheHandle();
        received.reveal('"username":"').commit("Alice_1", HANDLE_COMMITMENT).reveal('"').commit(",", OTHER)
            .reveal('"username":"').commit("mallory", OTHER).reveal('"').commit("}}", OTHER);
        _refusedFraming(received, CeremonyAttestation.AmbiguousFraming.selector);
    }

    /// @dev The same with the second anchor framing nothing -- the value
    ///      after it revealed. The count is over everything revealed, not
    ///      only the anchors that frame a commitment.
    function test_refusesASecondRevealedHandleAnchorFramingNothing() public {
        AttestationBuilder.Direction memory received = _upToTheHandle();
        received.reveal('"username":"').commit("Alice_1", HANDLE_COMMITMENT).reveal('","username":"mallory"}}');
        _refusedFraming(received, CeremonyAttestation.AmbiguousFraming.selector);
    }

    /// @dev Two id anchors, each in its own range and each framing a
    ///      commitment: two commitments both framed.
    function test_refusesTwoFramedIdCommitments() public {
        AttestationBuilder.Direction memory received;
        received.commit('HTTP/1.1 200 OK\r\n\r\n{"data":{', OTHER).reveal('"id":"').commit("2244994945", ID_COMMITMENT)
            .reveal('"').commit(",", OTHER).reveal('"id":"').commit("1", OTHER).reveal('"').commit(",", OTHER)
            .reveal('"username":"').commit("Alice_1", HANDLE_COMMITMENT).reveal('"').commit("}}", OTHER);
        _refusedFraming(received, CeremonyAttestation.AmbiguousFraming.selector);
    }

    /// @dev A second id anchor cut by a range boundary: neither half holds the
    ///      whole anchor, but the count reads the revealed bytes joined.
    function test_refusesADuplicateAnchorHiddenUnderARangeBoundary() public {
        AttestationBuilder.Direction memory received = _upToTheHandle();
        received.reveal('"username":"').commit("Alice_1", HANDLE_COMMITMENT).reveal('","i').reveal('d":"1"}}');
        _refusedFraming(received, CeremonyAttestation.AmbiguousFraming.selector);
    }

    /// @dev Whitespace inside the key is part of the key: `"user name"` is
    ///      another member, and the JSON whitespace the comparison ignores is
    ///      only the whitespace beside a structural byte.
    function test_refusesWhitespaceInsideTheKey() public {
        AttestationBuilder.Direction memory received = _upToTheHandle();
        received.reveal('"user name":"').commit("Alice_1", HANDLE_COMMITMENT).reveal('"').commit("}}", OTHER);
        _refusedFraming(received, CeremonyAttestation.NoFramedCommitment.selector);
    }

    /// @dev Whitespace around the colon is JSON's, and X's parser and this
    ///      one read the member alike.
    function test_acceptsJsonWhitespaceAroundTheColon() public {
        AttestationBuilder.Direction memory received = _upToTheHandle();
        received.reveal('"username" :\n "').commit("Alice_1", HANDLE_COMMITMENT).reveal('"').commit("}}", OTHER);
        TlsNotaryVerifierBase.TlsNotaryProof memory s = _payload();
        s.identitySession = _identityReceiving(received);
        assertEq(this.run{value: quote}(s).handleNode, HANDLE_NODE);
    }

    /// @dev No handle anchor at all.
    function test_refusesAResponseWithNoHandleAnchor() public {
        AttestationBuilder.Direction memory received = _upToTheHandle();
        received.commit('"username":"Alice_1"}}', OTHER);
        _refusedFraming(received, CeremonyAttestation.NoFramedCommitment.selector);
    }

    /// @dev The response must still tile: a byte neither revealed nor
    ///      committed is a byte the notary signed no position for.
    function test_refusesAnIdentityResponseWithAnUncoveredByte() public {
        AttestationBuilder.Direction memory received = _identityResponse("2244994945", "Alice_1");
        received.length += 1;
        _refusedFraming(received, CeremonyAttestation.CoverageGap.selector);
    }

    /// @dev Not caught: a duplicate member hidden in a commitment (ASM-PROV-06
    ///      assumes the platform never emits one).
    function test_acceptsAnIdentityResponseHidingADuplicateMember() public {
        AttestationBuilder.Direction memory received = _upToTheHandle();
        // `"username":"victim",` sits behind a commitment; the prover frames
        // the member after it.
        received.commit('"username":"victim",', OTHER).reveal('"username":"').commit("Alice_1", HANDLE_COMMITMENT)
            .reveal('"').commit("}}", OTHER);
        TlsNotaryVerifierBase.TlsNotaryProof memory s = _payload();
        s.identitySession = _identityReceiving(received);
        assertEq(this.run{value: quote}(s).handleNode, HANDLE_NODE);
    }

    /// @dev Not caught: which object a framed member belongs to (ASM-PROV-06).
    function test_acceptsAnAnchorInAnotherObject() public {
        AttestationBuilder.Direction memory received;
        received.commit('HTTP/1.1 200 OK\r\n\r\n{"data":{', OTHER).reveal('"id":"').commit("2244994945", ID_COMMITMENT)
            .reveal('"').commit('},"includes":{', OTHER).reveal('"username":"').commit("Alice_1", HANDLE_COMMITMENT)
            .reveal('"').commit("}}", OTHER);
        TlsNotaryVerifierBase.TlsNotaryProof memory s = _payload();
        s.identitySession = _identityReceiving(received);
        assertEq(this.run{value: quote}(s).handleNode, HANDLE_NODE);
    }

    // ─── The token response covers every byte ───────────────────────

    /// @dev The profile says every byte outside the anchors is committed. Until
    ///      the token response was tiled that was stated and not enforced, so a
    ///      prover could leave bytes neither revealed nor committed -- bytes the
    ///      notary signed no position for at all.
    function test_rejectsATokenResponseWithAnUncoveredByte() public {
        TlsNotaryVerifierBase.TlsNotaryProof memory s = _payload();
        s.tokenSession = _tokenAttestationWithGap();
        vm.expectPartialRevert(CeremonyAttestation.CoverageGap.selector);
        this.run{value: quote}(s);
    }

    /// @dev A token response with one byte belonging to neither list: the
    ///      status line's CRLF is left out of both.
    function _tokenAttestationWithGap() private view returns (ICeremony.Attestation memory) {
        // The verifier is derived from the digest the payload rebuilds to, so
        // the request passes the PKCE check and the coverage gap below is what
        // the verifier trips on.
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

    /// @dev The bearer is identified by its framing, not by being the only
    ///      commitment: the response hides every other byte behind a commitment
    ///      of its own. With no revealed anchors the committed range is
    ///      indistinguishable from a `refresh_token` value, or any other
    ///      substring the prover chose to commit.
    function test_rejectsATokenResponseWithNoRevealedAnchors() public {
        string memory v = string(CeremonyAuthorization.codeVerifier(digest, AUTH_NONCE));
        TlsNotaryVerifierBase.TlsNotaryProof memory s = _payload();
        s.tokenSession = _tokenAttestation("authorization_code", "myClient-1", v, false);
        vm.expectRevert(CeremonyAttestation.NoFramedCommitment.selector);
        this.run{value: quote}(s);
    }

    // ─── The identity request line (REQ-COMMON-21A) ─────────────────

    /// @dev The path separates operations on the same server, so
    ///      `/2/users/me` must be what was asked. A lookup-by-username endpoint
    ///      would answer for an account the prover never held.
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

    /// @dev The authority is what the notary authenticated, not a revealed
    ///      `Host` header, so a transcript from an attacker's server cannot
    ///      substitute for the platform's.
    function test_rejectsAForeignAuthority() public {
        TlsNotaryVerifierBase.TlsNotaryProof memory s = _payload();
        bytes memory attested = s.identitySession.attestedData;
        // authorityId is the first 32 bytes: it is the whole header identity
        // now that the stamped tags are gone.
        bytes32 evil = keccak256(bytes("evil.example"));
        for (uint256 i = 0; i < 32; ++i) {
            attested[i] = evil[i];
        }
        s.identitySession =
            ICeremony.Attestation({attestedData: attested, proof: AttestationBuilder.sign(NOTARY_KEY, attested)});
        vm.expectPartialRevert(PlatformVerifierBase.WrongAuthority.selector);
        this.run{value: quote}(s);
    }

    function test_rejectsTheSameSubmissionOnAnotherChain() public {
        TlsNotaryVerifierBase.TlsNotaryProof memory s = _payload();
        vm.chainId(block.chainid + 1);
        vm.expectRevert(TlsNotaryVerifierBase.CodeVerifierMismatch.selector);
        this.run{value: quote}(s);
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
                XPlatformVerifier.initialize,
                (OWNER, INotaryService(address(0)), IHonkVerifier(address(honk)), address(honk).codehash)
            )
        );
    }

    function test_onlyTheOwnerRotatesRoots() public {
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, address(this)));
        verifier.setTrustRoots(INotaryService(address(notary)), IHonkVerifier(address(honk)), address(honk).codehash);
    }

    function test_zeroHonkVerifierIsRefused() public {
        vm.prank(OWNER);
        vm.expectRevert(PlatformVerifierBase.ZeroAddress.selector);
        verifier.setTrustRoots(INotaryService(address(notary)), IHonkVerifier(address(0)), address(honk).codehash);
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

    /// @dev REQ-COMMON-16B: an empty identifier is refused by the form
    ///      itself, before the charset is asked.
    function test_rejectsAnEmptyClientIdentifier() public {
        TlsNotaryVerifierBase.TlsNotaryProof memory s = _payload();
        string memory v = string(CeremonyAuthorization.codeVerifier(digest, AUTH_NONCE));
        s.tokenSession = _tokenAttestation("authorization_code", "", v);
        vm.expectRevert(abi.encodeWithSelector(CeremonyFields.EmptyFormValue.selector, "client_id"));
        this.run{value: quote}(s);
    }

    /// @dev The head is the profile's right up to its last header, and then
    ///      never ends: one CRLF where the blank line belongs. Nothing says
    ///      which bytes are the body, so nothing may read one.
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

    /// @dev REQ-COMMON-21A: the method is part of the pinned request line, so
    ///      a GET with an otherwise honest body is refused before any field
    ///      is read.
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

    /// The body of that request, for a test that varies only the head.
    function _honestTokenBody() private view returns (bytes memory) {
        return _honestTokenBody("abc", "https%3A%2F%2Fapp.example%2Fcb");
    }

    /// The same with `code` and `redirect_uri` given, for the spellings of
    /// them the form refuses.
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

    /// A token session honest in every respect but the head it is handed: the
    /// layout, the digest binding, the response anchors and the coverage all
    /// check out, so the head is the only thing left to decide it.
    function _tokenSessionWithHead(bytes memory head) private view returns (ICeremony.Attestation memory) {
        return _tokenSessionWith(head, _honestTokenBody());
    }

    /// A token session honest in every respect but the body it is handed,
    /// under a head declaring that body's length: the form is the only thing
    /// left to decide it.
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

    /// That session under a header block of the test's choosing, declaring the
    /// body it really carries.
    function _payloadWithHeaders(bytes memory headers)
        private
        view
        returns (TlsNotaryVerifierBase.TlsNotaryProof memory s)
    {
        s = _payload();
        s.tokenSession = _tokenSessionWithHead(_tokenHead(headers, _honestTokenBody().length));
    }

    /// That session under a whole head of the test's choosing, for the cases
    /// where the length header's own position is what is under test.
    function _payloadWithHead(bytes memory head) private view returns (TlsNotaryVerifierBase.TlsNotaryProof memory s) {
        s = _payload();
        s.tokenSession = _tokenSessionWithHead(head);
    }

    /// @dev The fixtures compose their head from parts; this says the two
    ///      lines the profile requires are among them. Without it an edit to
    ///      `profiles.json` that the fixtures did not follow would fail every
    ///      test in this file at once and name none of them as the reason.
    function test_theFixtureHeadCarriesTheProfilesRequiredHeaders() public pure {
        assertTrue(
            AttestationBuilder.contains(
                _tokenHead(TOKEN_HEADERS, 0), abi.encodePacked(CeremonyProfile.X_TOKEN_REQUIRED_HEADERS, "\r\n")
            )
        );
    }

    /// @dev REQ-COMMON-21B: the media type selects the platform's request
    ///      parser, and `_tokenBody` reads those same bytes under a form
    ///      encoding. Announcing JSON leaves X parsing one document while this
    ///      verifier reads another, with every other check still passing --
    ///      which is what a pinned media type nothing compared was worth.
    function test_rejectsAnotherMediaTypeOnTheTokenRequest() public {
        TlsNotaryVerifierBase.TlsNotaryProof memory s = _payloadWithHeaders(
            "host: api.x.com\r\ncontent-type: application/json\r\naccept: application/json\r\nconnection: close\r\n"
        );
        vm.expectRevert(TlsNotaryVerifierBase.WrongTokenRequestHead.selector);
        this.run{value: quote}(s);
    }

    /// @dev `authorization: Basic` is the header the forbidden list exists
    ///      for: X authenticates the client from it instead, so the revealed
    ///      `client_id` this verifier returns stops being the credential the
    ///      exchange was made under, and no revealed byte says so.
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

    /// @dev Every forbidden name, each in a spelling the platform would read
    ///      as the same header: another case, no space after the colon, a
    ///      space before it, an underscore where a CGI-style stack folds it
    ///      into the dash. The name comes back normalized, which is how the
    ///      list is compared.
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

    /// @dev A required header has to be there. Without the media type nothing
    ///      says X read the bytes the verifier reads as a form at all; without
    ///      `host` nothing says which server the prover meant.
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

    /// @dev And twice is not once: two media types leave X to pick one and
    ///      this verifier with no way to know which.
    function test_rejectsARequiredHeaderTwice() public {
        TlsNotaryVerifierBase.TlsNotaryProof memory s = _payloadWithHeaders(
            "host: api.x.com\r\ncontent-type: application/x-www-form-urlencoded\r\n"
            "content-type: application/x-www-form-urlencoded\r\naccept: application/json\r\nconnection: close\r\n"
        );
        vm.expectRevert(TlsNotaryVerifierBase.WrongTokenRequestHead.selector);
        this.run{value: quote}(s);
    }

    /// @dev A header the profile sends but nothing verifies may be missing.
    ///      Without `accept`, X may answer in another representation, and that
    ///      is a response this verifier cannot read rather than one it can be
    ///      fooled by.
    function test_acceptsATokenRequestWithoutAnUncomparedHeader() public {
        TlsNotaryVerifierBase.TlsNotaryProof memory s = _payloadWithHeaders(
            "host: api.x.com\r\ncontent-type: application/x-www-form-urlencoded\r\nconnection: close\r\n"
        );
        this.run{value: quote}(s);
    }

    /// @dev And headers the profile never mentions may be present: what a
    ///      prover's HTTP library adds is its own business, as long as it is
    ///      not on the forbidden list.
    function test_acceptsUnlistedHeadersOnTheTokenRequest() public {
        TlsNotaryVerifierBase.TlsNotaryProof memory s = _payloadWithHeaders(
            "host: api.x.com\r\nuser-agent: libid-ceremony\r\ncontent-type: application/x-www-form-urlencoded\r\n"
            "accept: application/json\r\naccept-encoding: identity\r\nconnection: close\r\nx-request-id: 7\r\n"
        );
        this.run{value: quote}(s);
    }

    /// @dev A required header in another spelling the platform reads the
    ///      same: the name in another case, no space after the colon, a space
    ///      before it, a tab before the value. HTTP reads all of them as one
    ///      header, and so does this.
    function test_acceptsARequiredHeaderInAnotherSpelling() public {
        TlsNotaryVerifierBase.TlsNotaryProof memory s = _payloadWithHeaders(
            "Host:\tapi.x.com \r\nContent-Type :application/x-www-form-urlencoded\r\naccept: application/json\r\nconnection: close\r\n"
        );
        this.run{value: quote}(s);
    }

    /// @dev A carriage return no line feed follows. A compliant parser never
    ///      ends a line on one, so it is refused rather than left to every
    ///      platform's handling of it. Tucked inside an ignored header's value,
    ///      where a parser that did split on it would find a second header.
    function test_rejectsABareCarriageReturnInTheTokenHead() public {
        TlsNotaryVerifierBase.TlsNotaryProof memory s = _payloadWithHeaders(
            "host: api.x.com\r\ncontent-type: application/x-www-form-urlencoded\r\naccept: application/json\rauthorization: Basic x\r\nconnection: close\r\n"
        );
        vm.expectPartialRevert(CeremonyAttestation.BareCarriageReturn.selector);
        this.run{value: quote}(s);
    }

    /// @dev A line no colon splits is not a header, and a head carrying one is
    ///      a head some parser somewhere reads differently.
    function test_rejectsAHeaderLineWithoutAColon() public {
        TlsNotaryVerifierBase.TlsNotaryProof memory s = _payloadWithHeaders(
            "host: api.x.com\r\ncontent-type: application/x-www-form-urlencoded\r\nnot a header\r\nconnection: close\r\n"
        );
        vm.expectRevert(TlsNotaryVerifierBase.WrongTokenRequestHead.selector);
        this.run{value: quote}(s);
    }

    /// @dev Nothing is pinned by position. The same headers in another order
    ///      are the same request: field order is insignificant in HTTP except
    ///      for repeated names, so a reordering changes nothing X does with the
    ///      request, and pinning it would bind every prover to the order its
    ///      HTTP library emits.
    function test_acceptsTheSameHeadersInAnotherOrder() public {
        TlsNotaryVerifierBase.TlsNotaryProof memory s = _payloadWithHeaders(
            "host: api.x.com\r\naccept: application/json\r\ncontent-type: application/x-www-form-urlencoded\r\nconnection: close\r\n"
        );
        this.run{value: quote}(s);
    }

    /// @dev And the length header may sit anywhere among them, because where a
    ///      client appends it is that client's business. hyper puts it last;
    ///      nothing promises the next one will.
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

    /// @dev The declared length is what the PLATFORM framed the body by. A
    ///      short one leaves X parsing a form that stops early while every
    ///      field this verifier reads comes from the bytes after it -- a
    ///      `grant_type` X never saw, over a grant it did.
    function test_rejectsATokenRequestUnderdeclaringItsBody() public {
        uint256 length = _honestTokenBody().length;
        TlsNotaryVerifierBase.TlsNotaryProof memory s = _payload();
        s.tokenSession = _tokenSessionWithHead(_tokenHead(TOKEN_HEADERS, length - 10));
        vm.expectRevert(
            abi.encodeWithSelector(TlsNotaryVerifierBase.WrongDeclaredBodyLength.selector, length - 10, length)
        );
        this.run{value: quote}(s);
    }

    /// @dev The bytes between the pinned head and the blank line are the
    ///      declared length and nothing else. Were anything else allowed there,
    ///      it would be a header after the last one the profile names.
    function test_rejectsADeclaredBodyLengthThatIsNotDigits() public {
        TlsNotaryVerifierBase.TlsNotaryProof memory s = _payload();
        s.tokenSession = _tokenSessionWithHead(
            abi.encodePacked("POST /2/oauth2/token HTTP/1.1\r\n", TOKEN_HEADERS, "content-length: 72, 8\r\n\r\n")
        );
        vm.expectRevert(TlsNotaryVerifierBase.WrongTokenRequestHead.selector);
        this.run{value: quote}(s);
    }

    /// @dev A leading zero is a second spelling of a head this exists to fix
    ///      one spelling of, and it declares the same length, so nothing below
    ///      would notice.
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

    /// TlsNotaryVerifierBase.sol:294-295: request line hidden under a commitment tiling [0,10).
    function test_rejectsATokenRequestLineNotAtOrigin() public {
        bytes memory whole = _honestXRequest(); // the whole honest token request of _tokenAttestation
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

    /// TlsNotaryVerifierBase.sol:293: no revealed range in the sent direction at all.
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
