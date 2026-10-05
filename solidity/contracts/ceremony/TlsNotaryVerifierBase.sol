// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {CeremonyAttestation} from "./CeremonyAttestation.sol";
import {CeremonyProfile} from "./CeremonyProfile.sol";
import {CeremonyAuthorization} from "./CeremonyAuthorization.sol";
import {CeremonyFields} from "./CeremonyFields.sol";
import {IPlatformVerifier} from "./IPlatformVerifier.sol";
import {PlatformVerifierBase} from "./PlatformVerifierBase.sol";

/// @title TlsNotaryVerifierBase
/// @notice The shape both TLSNotary profiles share: two notarized sessions, one
///         hidden bearer linking them, one proof binding that link.
///
/// @dev `x/v1` and `github/v1` state the same relation and differ only in
///      constants and two reads, so the flow lives here once. What a subclass
///      supplies is exactly what genuinely differs:
///
///        the platform id and its two authorities — GitHub's exchange is served
///        by one host and its identity read by another, so an authority is per
///        SESSION rather than per profile;
///        the two request lines;
///        the token body's field list, which the base holds the whole body to;
///        any value check on the token body beyond the base's — X compares
///        `grant_type`, GitHub adds none;
///        how the identity fields are read — X's `id` is a JSON string, GitHub's
///        a bare integer.
///
///      Order matters in one place. The proof is verified LAST, once the
///      commitments it links are known to be the ones the attestations carried;
///      verifying it earlier would prove a relation between numbers nobody had
///      tied to a session yet.
abstract contract TlsNotaryVerifierBase is IPlatformVerifier, PlatformVerifierBase {
    /// @dev Two 32-byte commitments as 64 public inputs, one byte each.
    uint256 internal constant PUBLIC_INPUTS = 64;
    uint256 internal constant OFF_TOKEN_COMMITMENT = 0;
    uint256 internal constant OFF_IDENTITY_COMMITMENT = 32;

    /// @dev What frames the committed bearer in the token response. Every other
    ///      response byte is hidden, so without these the committed range is
    ///      indistinguishable from a `refresh_token` value (REQ-PLAT-57,
    ///      REQ-PLAT-58).
    /// @dev HTTP framing owns this one, not the profile: the client appends
    ///      it and its value is the body's own count, so the head carries it
    ///      and no profile lists it.
    bytes32 private constant LENGTH_HEADER = keccak256("content-length");
    bytes32 private constant AUTHORIZATION = keccak256("authorization");

    bytes internal constant ACCESS_TOKEN_PREFIX = '"access_token":"';
    bytes internal constant ACCESS_TOKEN_SUFFIX = '"';

    /// @notice What a TLSNotary profile decodes from its payload.
    ///
    /// @dev `abi.encode` of this struct is the payload for `x/v1` and
    ///      `github/v1`. The two profiles share one shape because they state
    ///      the same relation; platform separation is the route that reached
    ///      this contract plus the authorities each subclass pins, not the
    ///      struct's name, which the encoding does not carry.
    ///
    ///      It carries no platform id and no chain id: this verifier knows the
    ///      first and reads the second. It carries no public inputs and no
    ///      client identifier: both are DERIVED from the attestations, so a
    ///      caller's copy would be a second representation of a fact this
    ///      verifier already holds. The two sessions are named rather than
    ///      listed, because they are not interchangeable.
    ///
    /// @param ceremonyVersion    What the payload was built for. Checked against
    ///                           this verifier's own before anything is paid.
    /// @param operationDomain    Into the digest, and returned for the Consumer
    ///                           to judge (REQ-COMMON-06A).
    /// @param authorizationNonce Into the digest, making it unique and therefore
    ///                           its own replay nullifier, and into the PKCE
    ///                           verifier the digest is carried under. There is
    ///                           no second salt beside it (REQ-COMMON-12).
    /// @param transactionData    Into the digest, and returned opaque
    ///                           (REQ-COMMON-06B).
    /// @param tokenSession       The token exchange, notarized.
    /// @param identitySession    The identity read, notarized.
    /// @param proof              Verified under the artifact governance
    ///                           selected, never one the caller names.
    struct TlsNotaryProof {
        uint16 ceremonyVersion;
        bytes32 operationDomain;
        bytes32 authorizationNonce;
        bytes transactionData;
        Attestation tokenSession;
        Attestation identitySession;
        bytes proof;
    }

    error WrongRequestLine();
    error CodeVerifierMismatch();
    error ClientIdentifierNotSerializerSafe(bytes found);
    /// @dev A field was found in no revealed range, or in more than one.
    error FieldNotUnique(string name, uint256 rangesMatching);
    /// @dev The first revealed range does not begin the transcript, so nothing
    ///      says the bytes read as a request line ARE the request line.
    error RequestLineNotAtOrigin(uint32 start);
    /// @dev The token request is not one revealed run with no commitment.
    error WrongTokenRequestLayout(uint256 revealedRanges, uint256 commitments);
    /// @dev The head/body separator is missing or ambiguous, so the body cannot
    ///      be located by the framing the server itself parsed.
    error NoHeadBoundary(uint256 occurrences);
    /// @dev The token request's head lacks a required header, repeats one,
    ///      gives one another value, carries a line no colon splits, or
    ///      declares a body length that is not plain decimal digits.
    error WrongTokenRequestHead();
    /// @dev A request carries a header the profile forbids: one that changes
    ///      what the platform does with the request in a way no revealed byte
    ///      shows. The name, normalized.
    error ForbiddenRequestHeader(bytes name);
    /// @dev The request declared a body of one length and the notary signed
    ///      another, so the bytes the platform parsed as the form are not the
    ///      bytes read below.
    error WrongDeclaredBodyLength(uint256 declared, uint256 signed);

    // ─── What a profile supplies ────────────────────────────────────

    function _tokenAuthority() internal pure virtual returns (bytes32);
    function _identityAuthority() internal pure virtual returns (bytes32);
    function _tokenRequestLine() internal pure virtual returns (bytes memory);
    function _identityRequestLine() internal pure virtual returns (bytes memory);

    /// @dev The header lines the token request must carry, CRLF-joined: `host`
    ///      naming the pinned authority, and the media type that selects the
    ///      platform's parser. `_checkTokenHead` requires each once with its
    ///      value, refuses the names `CeremonyProfile.FORBIDDEN_REQUEST_HEADERS`
    ///      lists, reads `content-length`, and ignores every other header.
    ///
    ///      Only the token request has one. The identity request carries the
    ///      bearer in a header, so its headers are not fixed and are held to
    ///      `requireBearerHeaderRequest` instead: coverage, one line-anchored
    ///      `authorization`, and the framing around the committed value.
    function _tokenRequiredHeaders() internal pure virtual returns (bytes memory);

    /// @dev The form fields the token request's body carries, `&`-joined in
    ///      the order the prover serializes them. `_tokenTranscript` holds the
    ///      WHOLE body to this list (`requireExactForm`): exactly these names
    ///      in this order, each once with a nonempty value in the serializer's
    ///      one spelling, and nothing after the last. Every profile is held
    ///      this way, so the reads below see a body already known to carry
    ///      each name once, and acceptance never rests on the platform
    ///      refusing a form it did not count. GitHub's list is REQ-PLAT-61's
    ///      and X's is REQ-PLAT-63's.
    function _tokenFields() internal pure virtual returns (bytes memory);

    /// @dev Any VALUE constraint the profile places on a token-body field
    ///      beyond the base's own. Default: nothing. Runs after the form is
    ///      known exact and before `code_verifier` and `client_id` are read.
    ///      X compares `grant_type`; GitHub adds none.
    function _checkTokenBody(CeremonyFields.Form memory form) internal pure virtual {}

    /// @dev Which shape a platform's immutable identifier takes in its identity
    ///      response. X quotes it; GitHub sends a bare integer, whose
    ///      terminator is what proves the revealed digits are the whole number
    ///      rather than a prefix of a longer one.
    enum IdShape {
        JsonString,
        JsonInteger
    }

    /// @dev The two identity members this profile reads, as DATA rather than as
    ///      a reading routine.
    ///
    ///      A hook handed the direction block could concatenate its revealed
    ///      ranges, index them positionally, or read `revealed[0]` -- and each
    ///      of those has broken this verifier before. Concatenation discards
    ///      every offset, so a prover revealing disjoint fragments gets them
    ///      joined into a document that never crossed the wire. Positional
    ///      reads take whichever range the prover put first.
    ///
    ///      Declaring the field names and leaving the reading to the base makes
    ///      all three unwritable rather than forbidden by a comment. A new
    ///      profile supplies two strings and a shape; it never touches an
    ///      attestation.
    function _identityFields()
        internal
        pure
        virtual
        returns (string memory idField, IdShape idShape, string memory handleField);

    /// @dev Find a JSON string field in exactly one revealed range.
    ///
    ///      Reading from a concatenation of the revealed ranges is what this
    ///      exists to prevent. Concatenation discards every offset, so a prover
    ///      revealing disjoint fragments -- the opening of one member, the
    ///      middle of a display name, the tail of another member -- gets them
    ///      joined into a document that never existed on the wire, and the
    ///      duplicate-delimiter check of REQ-COMMON-19A has nothing to fire on
    ///      because the genuine member is simply not in the buffer.
    ///
    ///      Requiring the whole match to sit inside one authenticated range
    ///      means every byte of it came from one contiguous run the notary
    ///      signed, at the offsets it signed them at.
    ///
    ///      `ranges` holds each revealed range and `joined` their concatenation,
    ///      each normalized whole by `normalizeJsonBytes`. The count over
    ///      `joined` can only over-count at a seam, which fails closed.
    function _uniqueJsonString(bytes[] memory ranges, bytes memory joined, string memory name)
        private
        pure
        returns (bytes memory value)
    {
        uint256 matches;
        for (uint256 i = 0; i < ranges.length; ++i) {
            (CeremonyFields.Found found, bytes memory v) = CeremonyFields.tryNormalizedJsonString(ranges[i], name);
            if (found == CeremonyFields.Found.Several) revert FieldNotUnique(name, 2);
            if (found == CeremonyFields.Found.One) {
                ++matches;
                value = v;
            }
        }
        if (matches != 1) revert FieldNotUnique(name, matches);
        // And the delimiter appears once across the whole revealed set, so a
        // second copy cannot hide under a range boundary.
        uint256 seen = CeremonyFields.occurrences(joined, abi.encodePacked('"', name, '":"'));
        if (seen != 1) revert FieldNotUnique(name, seen);
    }

    /// @dev The same, for a bare JSON integer.
    function _uniqueJsonInteger(bytes[] memory ranges, bytes memory joined, string memory name)
        private
        pure
        returns (bytes memory digits)
    {
        uint256 matches;
        for (uint256 i = 0; i < ranges.length; ++i) {
            (CeremonyFields.Found found, bytes memory v) = CeremonyFields.tryNormalizedJsonInteger(ranges[i], name);
            if (found == CeremonyFields.Found.Several) revert FieldNotUnique(name, 2);
            if (found == CeremonyFields.Found.One) {
                ++matches;
                digits = v;
            }
        }
        if (matches != 1) revert FieldNotUnique(name, matches);
        uint256 seen = CeremonyFields.occurrences(joined, abi.encodePacked('"', name, '":'));
        if (seen != 1) revert FieldNotUnique(name, seen);
    }

    // ─── The flow ───────────────────────────────────────────────────

    /// @inheritdoc IPlatformVerifier
    function platformId() external pure returns (bytes32) {
        return _platform();
    }

    /// @inheritdoc IPlatformVerifier
    function quote() public view returns (uint256) {
        // Two attestations, so two Notary Fees.
        return 2 * _base().notary.fee();
    }

    /// @inheritdoc IPlatformVerifier
    function verify(bytes calldata payload) external payable returns (VerifiedClaim memory claimed) {
        uint256 fee = _base().notary.fee();
        // Exact value at every hop needs no refund path, so no partial-failure
        // or reentrancy rule is required and no value can be captured in
        // transit (REQ-COMMON-06D).
        if (msg.value != 2 * fee) revert WrongValue(2 * fee, msg.value);

        // Decoded here and nowhere above. `abi.decode` refuses a payload that
        // does not have exactly this shape, so there is no separate count or
        // presence check for any field.
        TlsNotaryProof memory p = abi.decode(payload, (TlsNotaryProof));
        _requireCeremonyVersion(p.ceremonyVersion);

        // The digest, rebuilt from what was decoded, this verifier's own
        // version, and the chain it runs on. Never trusted for its content:
        // it is a commitment the token session's revealed `code_verifier` has
        // to match, so any input a caller changes yields a digest no proof
        // opens against.
        bytes32 digest = CeremonyAuthorization.digestFor(
            p.operationDomain, _ceremonyVersion(), p.authorizationNonce, p.transactionData
        );

        (uint64 observedAt, bytes32 tokenCommitment) = _tokenSession(digest, p, fee, claimed);
        bytes32 identityCommitment = _identitySession(p, fee, claimed);

        // Built, not compared. The proof verifies against the commitments the
        // notary signed and nothing else can be substituted for them.
        _requireProof(p.proof, _publicInputs(tokenCommitment, identityCommitment));

        // The same locals that entered the digest, returned. The Consumer acts
        // on these and records that digest; they are one submission's worth of
        // facts, and this is the one function that holds all of them.
        claimed.sessionId = digest;
        claimed.operationDomain = p.operationDomain;
        claimed.transactionData = p.transactionData;
        claimed.ceremonyVersion = _ceremonyVersion();
        claimed.metadataObservedAt = observedAt;
    }

    function _tokenSession(
        bytes32 authorizationDigest,
        TlsNotaryProof memory p,
        uint256 fee,
        VerifiedClaim memory fields
    ) private returns (uint64 observedAt, bytes32 tokenCommitment) {
        CeremonyAttestation.AttestedData memory data = _authenticate(p.tokenSession, _tokenAuthority(), fee);
        (fields.clientIdentifier, tokenCommitment) = _tokenTranscript(data, authorizationDigest, p.authorizationNonce);

        // The token attestation is the one-time PKCE and digest binding, so it
        // alone supplies evidence time (section 2.2).
        observedAt = _requireFresh(data.createdAt);
    }

    /// @dev Every transcript check of the token session, request then
    ///      response; `data` must come from `_authenticate`. Returns the client
    ///      identifier and the committed bearer.
    function _tokenTranscript(
        CeremonyAttestation.AttestedData memory data,
        bytes32 authorizationDigest,
        bytes32 authorizationNonce
    ) internal pure returns (bytes memory clientId, bytes32 tokenCommitment) {
        // REQ-COMMON-18A applies to THIS direction too. Without tiling, a
        // prover reveals two header values it composed itself and this verifier
        // reads them as the request line and the body -- every field below then
        // comes from bytes the prover typed rather than from the request the
        // platform answered.
        CeremonyAttestation.requireExactCoverage(data.sent, data.sentTranscriptLength);

        // Range 0 must BEGIN the transcript. Indexing the list is not enough:
        // the lowest-offset revealed range is wherever the prover put it. An
        // empty list passes coverage against a zero signed length, so it is
        // named here rather than left to an out-of-bounds panic that tells an
        // operator nothing.
        if (data.sent.revealed.length == 0) revert RequestLineNotAtOrigin(type(uint32).max);
        if (data.sent.revealed[0].start != 0) {
            revert RequestLineNotAtOrigin(data.sent.revealed[0].start);
        }
        // The one comparison of the method and path (REQ-COMMON-21A): the head
        // check below starts past the request line.
        if (!_startsWith(data.sent.revealed[0].value, _tokenRequestLine())) revert WrongRequestLine();

        bytes memory body = _tokenBody(data.sent);

        // The shape first, then the values a verifier compares: a read below
        // answers what a field IS, and only an exact body says nothing else
        // is there. A value nobody reads is held to the alphabet and to
        // nothing more -- in that alphabet it cannot become another field,
        // and no contract acts on what it decodes to.
        CeremonyFields.Form memory form = CeremonyFields.requireExactForm(body, _tokenFields());
        _checkTokenBody(form);

        // REQ-COMMON-15A. This is the whole binding between the evidence and
        // the transaction: retargeting an attestation to another digest would
        // take a second preimage of the revealed verifier.
        bytes memory revealedVerifier = CeremonyFields.valueOf(form, "code_verifier");
        // Under the same nonce the digest commits, so a caller has no second
        // value to move: changing it moves the digest too (REQ-COMMON-12).
        bytes memory expected = CeremonyAuthorization.codeVerifier(authorizationDigest, authorizationNonce);
        if (keccak256(revealedVerifier) != keccak256(expected)) revert CodeVerifierMismatch();

        clientId = CeremonyFields.valueOf(form, "client_id");
        if (!CeremonyFields.isSerializerSafe(clientId)) {
            revert ClientIdentifierNotSerializerSafe(clientId);
        }

        // Tiled, like every other direction. The profile says every byte
        // outside the anchors is committed; this is what makes that true rather
        // than stated, and it is what leaves the framing below nothing to work
        // around -- a byte that is neither revealed nor committed is a byte the
        // notary never signed a position for.
        CeremonyAttestation.requireExactCoverage(data.received, data.recvTranscriptLength);

        // The bearer is identified by its framing, not by being the only
        // commitment: the response hides every other byte behind one of its own.
        CeremonyAttestation.RangeCommitment memory bearer =
            CeremonyAttestation.requireFramedCommitment(data.received, ACCESS_TOKEN_PREFIX, ACCESS_TOKEN_SUFFIX);
        tokenCommitment = bearer.commitment;
    }

    function _identitySession(TlsNotaryProof memory p, uint256 fee, VerifiedClaim memory fields)
        private
        returns (bytes32 identityCommitment)
    {
        CeremonyAttestation.AttestedData memory data = _authenticate(p.identitySession, _identityAuthority(), fee);
        (identityCommitment, fields.userId, fields.handle) = _identityTranscript(data);
    }

    /// @dev Every transcript check of the identity session, request then
    ///      response; `data` must come from `_authenticate`. Returns the
    ///      committed bearer, the user id and the raw handle.
    function _identityTranscript(CeremonyAttestation.AttestedData memory data)
        internal
        pure
        returns (bytes32 identityCommitment, string memory userId, string memory handle)
    {
        // REQ-COMMON-21A: the path separates operations on the same server.
        // Anchored at the origin for the same reason as the token request --
        // the lowest-offset revealed range is wherever the prover put it.
        if (data.sent.revealed.length == 0 || data.sent.revealed[0].start != 0) {
            revert RequestLineNotAtOrigin(data.sent.revealed.length == 0
                    ? type(uint32).max
                    : data.sent.revealed[0].start);
        }
        if (!_startsWith(data.sent.revealed[0].value, _identityRequestLine())) {
            revert WrongRequestLine();
        }

        // Coverage, the line-anchored uniqueness scan and the framing bytes,
        // together. They are one property: the scan reads only revealed bytes,
        // so without coverage a prover hides a second authorization header in a
        // gap and the count still says one.
        (CeremonyAttestation.RangeCommitment memory bearer, bytes memory revealed) =
            CeremonyAttestation.requireBearerHeaderRequest(data.sent, data.sentTranscriptLength);
        identityCommitment = bearer.commitment;
        _checkIdentityHead(revealed);

        // Tiled, not revealed whole. The response may hide bytes, which is
        // what keeps a platform's account metadata off chain when the profile's
        // client returns more than the two members this reads.
        //
        // The cost is stated rather than hidden. Every reader below scans
        // revealed bytes, so a commitment is invisible to all of them: a
        // response that genuinely names an authoritative field TWICE lets a
        // prover commit the real member and reveal the one it chose, and both
        // the per-range read and the cross-range count then see exactly one.
        // Uniqueness is a property of the document, and this establishes it
        // over a part.
        //
        // What stands in for it is ASM-PROV-06 -- the platform emits each
        // authoritative field exactly once -- plus the platform's own JSON
        // escaping, which keeps a delimiter out of any value the account
        // controls. Neither is checked here, and neither can be. A duplicate
        // that reaches the REVEALED bytes is still caught, in either range
        // layout; only one hidden behind a commitment is not.
        CeremonyAttestation.requireExactCoverage(data.received, data.recvTranscriptLength);
        // The join is normalized whole, not assembled from the normalized
        // ranges: whitespace at a seam goes or stays by the bytes on both sides.
        bytes[] memory ranges = new bytes[](data.received.revealed.length);
        for (uint256 i = 0; i < ranges.length; ++i) {
            ranges[i] = CeremonyFields.normalizeJsonBytes(data.received.revealed[i].value);
        }
        bytes memory joined = CeremonyFields.normalizeJsonBytes(CeremonyAttestation.concatRevealed(data.received));
        (string memory idField, IdShape idShape, string memory handleField) = _identityFields();
        userId = string(
            idShape == IdShape.JsonString
                ? _uniqueJsonString(ranges, joined, idField)
                : _uniqueJsonInteger(ranges, joined, idField)
        );
        handle = string(_uniqueJsonString(ranges, joined, handleField));
    }

    // ─── Helpers ────────────────────────────────────────────────────

    /// @dev Match a proved commitment against the one the attestation carried.
    ///      Without this the circuit could prove a link between two
    ///      attestations other than the ones submitted (REQ-PLAT-32C,
    ///      REQ-PLAT-52B).
    /// @dev The circuit's public inputs, as this verifier derives them.
    ///
    ///      Two 32-byte commitments as 64 field elements of one byte each,
    ///      token first. The circuit fixes that order; this contract fixes
    ///      where the bytes come from -- the attestations it just
    ///      authenticated, never the caller.
    ///
    ///      There used to be a comparison here instead, against inputs the
    ///      caller supplied. It cost 64 words of calldata to say something the
    ///      verifier already knew, and it could be got wrong: reconstructing a
    ///      byte with `uint8(...)` accepted a field element of 0x0101 as 0x01,
    ///      so the binding rested on the circuit range-constraining outputs
    ///      this contract cannot see. Derived, there is nothing to constrain
    ///      and nothing to disagree with.
    function _publicInputs(bytes32 tokenCommitment, bytes32 identityCommitment)
        private
        pure
        returns (bytes32[] memory inputs)
    {
        inputs = new bytes32[](PUBLIC_INPUTS);
        for (uint256 i = 0; i < 32; ++i) {
            inputs[OFF_TOKEN_COMMITMENT + i] = bytes32(uint256(uint8(tokenCommitment[i])));
            inputs[OFF_IDENTITY_COMMITMENT + i] = bytes32(uint256(uint8(identityCommitment[i])));
        }
    }

    /// @dev The head's header lines: each required one exactly once with its
    ///      value, none of the forbidden names, one `content-length`, and
    ///      anything else ignored. Returns the declared length.
    ///
    ///      Required and forbidden rather than a fixed set. A header outside
    ///      both lists changes only what the platform ANSWERS, and a wrong
    ///      answer is a response this verifier cannot read, not one it can be
    ///      fooled by. The forbidden names change what the platform does with
    ///      the request in ways no revealed byte shows: which client it
    ///      authenticates, which bytes it parses, which method it runs. Between
    ///      the two, what a prover's HTTP library adds is its own business.
    ///
    ///      Names are compared lowercased, because the platform reads them
    ///      case-insensitively and a forbidden name in another case is the same
    ///      header to it. Values are compared exactly, with the optional
    ///      whitespace HTTP allows around them removed.
    ///
    ///      Reading lines is where the leniencies live, so `requireCrlfLineEndings`
    ///      goes first: the same guard REQ-COMMON-39 puts on the identity
    ///      request, without which a bare line feed ends the head somewhere the
    ///      platform's parser does and this one does not.
    // `1 << i` is the mask for line i. The lint's heuristic reads a literal on
    // the left of a shift as swapped operands, which is what building a mask
    // looks like.
    // forge-lint: disable-next-item(incorrect-shift)
    function _checkTokenHead(bytes memory head) private pure returns (uint256 declared) {
        CeremonyAttestation.requireCrlfLineEndings(head);

        TokenHead memory state;
        (state.requiredNames, state.requiredValues) = _requiredHeaders();

        // Past the request line, which `_tokenTranscript` has already compared.
        uint256 from = _lineEnd(head, 0) + 2;
        while (from < head.length) {
            uint256 to = _lineEnd(head, from);
            _tokenHeaderLine(head, from, to, state);
            from = to + 2;
        }

        if (!state.lengths) revert WrongTokenRequestHead();
        // Every required line seen: the low bits all set.
        if (state.found != (1 << state.requiredNames.length) - 1) revert WrongTokenRequestHead();
        return state.declared;
    }

    /// @dev `_checkTokenHead`'s state. `found` holds a bit per required line,
    ///      capping a profile at 255 of them (the generator allows two).
    ///      `lengths` records a `content-length` line, `declared` its value.
    struct TokenHead {
        bytes32[] requiredNames;
        bytes32[] requiredValues;
        uint256 found;
        bool lengths;
        uint256 declared;
    }

    /// @dev Checks token-head line `head[from:to]` and records it in `state`.
    // forge-lint: disable-next-item(incorrect-shift)
    function _tokenHeaderLine(bytes memory head, uint256 from, uint256 to, TokenHead memory state) private pure {
        (bool isHeader, bytes memory name, uint256 valueStart, uint256 valueEnd) = _field(head, from, to);
        if (!isHeader) revert WrongTokenRequestHead();

        bytes32 nameHash = keccak256(name);
        if (CeremonyProfile.isForbiddenRequestHeader(nameHash)) revert ForbiddenRequestHeader(name);
        if (nameHash == LENGTH_HEADER) {
            if (state.lengths) revert WrongTokenRequestHead();
            state.lengths = true;
            state.declared = _decimal(head, valueStart, valueEnd);
            return;
        }
        uint256 i = _indexOf(state.requiredNames, nameHash);
        if (i == type(uint256).max) return;
        if (_hash(head, valueStart, valueEnd) != state.requiredValues[i]) revert WrongTokenRequestHead();
        if (state.found & (1 << i) != 0) revert WrongTokenRequestHead();
        state.found |= 1 << i;
    }

    /// @dev The name and value hashes of each `_tokenRequiredHeaders()` line.
    ///      A line `_field` rejects hashes as the empty name, which no header
    ///      line has, so no head satisfies it.
    function _requiredHeaders() private pure returns (bytes32[] memory names, bytes32[] memory values) {
        bytes memory block_ = _tokenRequiredHeaders();
        names = new bytes32[](_countLines(block_));
        values = new bytes32[](names.length);
        uint256 from;
        for (uint256 i = 0; i < names.length; ++i) {
            uint256 to = _lineEnd(block_, from);
            (, bytes memory name, uint256 valueStart, uint256 valueEnd) = _field(block_, from, to);
            names[i] = keccak256(name);
            values[i] = _hash(block_, valueStart, valueEnd);
            from = to + 2;
        }
    }

    /// @dev The first index of `hash` in `hashes`, or `max`.
    function _indexOf(bytes32[] memory hashes, bytes32 hash) private pure returns (uint256) {
        for (uint256 i = 0; i < hashes.length; ++i) {
            if (hashes[i] == hash) return i;
        }
        return type(uint256).max;
    }

    /// @dev Header line `data[from:to]` as the platform reads it: the name
    ///      before the first colon, lowercased, whitespace before the colon
    ///      dropped (REQ-COMMON-39), `_` read as `-` since a CGI-style stack
    ///      maps both to one key; the value as offsets, optional whitespace
    ///      trimmed. No colon or an empty name returns `isHeader` false: the
    ///      token head refuses it; the identity head leaves it to the platform.
    function _field(bytes memory data, uint256 from, uint256 to)
        private
        pure
        returns (bool isHeader, bytes memory name, uint256 valueStart, uint256 valueEnd)
    {
        // The line lies inside `data`, so every read below does.
        assert(from <= to && to <= data.length);
        uint256 colon = CeremonyFields.indexOfByte(data, from, to, ":");
        if (colon == to) return (false, name, 0, 0);
        name = _slice(data, from, colon);
        // The name lowercased, `_` read as `-`, every space and tab dropped
        // (REQ-PLAT-56A, REQ-COMMON-39B). In place: the write index never
        // passes the read index, which stays below `name.length`.
        assembly ("memory-safe") {
            let p := add(name, 0x20)
            let len := mload(name)
            let kept := 0
            for { let i := 0 } lt(i, len) { i := add(i, 1) } {
                let c := byte(0, mload(add(p, i)))
                if iszero(or(eq(c, 0x20), eq(c, 0x09))) {
                    if and(gt(c, 0x40), lt(c, 0x5b)) { c := add(c, 0x20) }
                    if eq(c, 0x5f) { c := 0x2d }
                    mstore8(add(p, kept), c)
                    kept := add(kept, 1)
                }
            }
            mstore(name, kept)
        }
        if (name.length == 0) return (false, name, 0, 0);
        isHeader = true;
        valueStart = colon + 1;
        // Skips the value's leading spaces and tabs, reading only below `to`.
        assembly ("memory-safe") {
            let p := add(data, 0x20)
            for {} lt(valueStart, to) { valueStart := add(valueStart, 1) } {
                let c := byte(0, mload(add(p, valueStart)))
                if iszero(or(eq(c, 0x20), eq(c, 0x09))) { break }
            }
        }
        valueEnd = _trimEnd(data, valueStart, to);
    }

    /// @dev `to`, moved back over the spaces and tabs ending `data[from:to]`.
    function _trimEnd(bytes memory data, uint256 from, uint256 to) private pure returns (uint256 end) {
        end = to;
        // Reads `data[end - 1]` only for `from < end <= to`, and every caller
        // keeps `to <= data.length`.
        assembly ("memory-safe") {
            let p := add(data, 0x20)
            for {} gt(end, from) { end := sub(end, 1) } {
                let c := byte(0, mload(add(p, sub(end, 1))))
                if iszero(or(eq(c, 0x20), eq(c, 0x09))) { break }
            }
        }
    }

    /// @dev Every revealed line of the identity request carries none of the
    ///      forbidden names but `authorization`, whose one line
    ///      `requireBearerHeaderRequest` has counted under any scheme. `cookie`
    ///      is the case: another credential the platform might honour over the
    ///      bearer the exchange is bound to, which is the one thing the
    ///      cross-bind exists to fix. Read over the whole concatenation, as the
    ///      count is, so a header after a blank line is refused too; a line
    ///      that is not a header is the platform's to refuse.
    function _checkIdentityHead(bytes memory revealed) private pure {
        uint256 from = _lineEnd(revealed, 0) + 2;
        while (from < revealed.length) {
            uint256 to = _lineEnd(revealed, from);
            if (to > from) {
                (bool isHeader, bytes memory name,,) = _field(revealed, from, to);
                if (isHeader) {
                    bytes32 nameHash = keccak256(name);
                    if (nameHash != AUTHORIZATION && CeremonyProfile.isForbiddenRequestHeader(nameHash)) {
                        revert ForbiddenRequestHeader(name);
                    }
                }
            }
            from = to + 2;
        }
    }

    /// @dev The offset of the CRLF that ends the line beginning at `from`, or
    ///      the end of `data` for the last line -- the head is sliced at the
    ///      blank line, so its final header carries no CRLF of its own.
    function _lineEnd(bytes memory data, uint256 from) private pure returns (uint256) {
        for (
            uint256 cr = CeremonyFields.indexOfByte(data, from, 0x0d);
            cr + 1 < data.length;
            cr = CeremonyFields.indexOfByte(data, cr + 1, 0x0d)
        ) {
            if (data[cr + 1] == 0x0a) return cr;
        }
        return data.length;
    }

    function _countLines(bytes memory block_) private pure returns (uint256 count) {
        count = 1;
        for (uint256 end = _lineEnd(block_, 0); end < block_.length; end = _lineEnd(block_, end + 2)) {
            ++count;
        }
    }

    /// @dev `data[from:to]` as canonical decimal, at most `uint32`'s ten
    ///      digits. A leading zero is a second spelling of a length this
    ///      compares one spelling of.
    function _decimal(bytes memory data, uint256 from, uint256 to) private pure returns (uint256 value) {
        uint256 width = to - from;
        if (width == 0 || width > 10) revert WrongTokenRequestHead();
        if (width > 1 && data[from] == "0") revert WrongTokenRequestHead();
        for (uint256 i = from; i < to; ++i) {
            if (data[i] < "0" || data[i] > "9") revert WrongTokenRequestHead();
            value = value * 10 + (uint8(data[i]) - 0x30);
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

    /// @dev The token request's body: the bytes after its one `\r\n\r\n`. The
    ///      request must be one revealed range with no commitment, which the
    ///      caller's exact coverage makes the whole request: the body is the one
    ///      the platform framed, not a decoy beside a committed original. Its
    ///      `content-length` must equal the signed body length, or the platform
    ///      could parse a shorter form than the one read here.
    function _tokenBody(CeremonyAttestation.DirectionBlock memory block_) internal pure returns (bytes memory body) {
        if (block_.revealed.length != 1 || block_.commitments.length != 0) {
            revert WrongTokenRequestLayout(block_.revealed.length, block_.commitments.length);
        }
        bytes memory whole = block_.revealed[0].value;

        // Exactly one head boundary. A well-formed request has one; requiring
        // it removes any question of which run of bytes the body is.
        uint256 at = type(uint256).max;
        uint256 seen;
        // Every boundary begins with a CR, so only those offsets are tried.
        for (
            uint256 cr = CeremonyFields.indexOfByte(whole, 0, 0x0d);
            cr + 4 <= whole.length;
            cr = CeremonyFields.indexOfByte(whole, cr + 1, 0x0d)
        ) {
            uint256 four;
            // The four bytes at `cr`, inside `whole` by the loop condition;
            // the shift drops what the word holds past them.
            assembly ("memory-safe") {
                four := shr(224, mload(add(add(whole, 0x20), cr)))
            }
            if (four == 0x0d0a0d0a) {
                ++seen;
                if (at == type(uint256).max) at = cr;
            }
        }
        if (seen != 1) revert NoHeadBoundary(seen);

        uint256 declared = _checkTokenHead(_slice(whole, 0, at));

        at += 4;
        // The run is the request whole and the head is revealed, so the
        // remainder is the body the platform parsed.
        if (declared != whole.length - at) revert WrongDeclaredBodyLength(declared, whole.length - at);

        body = _slice(whole, at, whole.length);
    }

    function _startsWith(bytes memory data, bytes memory prefix) internal pure returns (bool) {
        if (data.length < prefix.length) return false;
        return _hash(data, 0, prefix.length) == keccak256(prefix);
    }
}
