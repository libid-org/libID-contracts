// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {CircuitCodehashes} from "../circuits/CircuitCodehashes.sol";
import {CeremonyAttestation} from "./CeremonyAttestation.sol";
import {CeremonyProfile} from "./CeremonyProfile.sol";
import {CeremonyAuthorization} from "./CeremonyAuthorization.sol";
import {CeremonyFields} from "./CeremonyFields.sol";
import {IPlatformVerifier} from "./IPlatformVerifier.sol";
import {PlatformVerifierBase} from "./PlatformVerifierBase.sol";

/// @title TlsNotaryVerifierBase
/// @notice The flow both TLSNotary profiles share: two notarized sessions, one
///         hidden bearer linking them, and one bearer-link proof binding that
///         link and the committed id and handle to the two nodes the payload
///         claims, under the platform's tags.
/// @dev Subclasses supply the platform and any token-body checks; the rest
///      is the platform's `CeremonyProfile`. The proof is verified last, once
///      its commitments are tied to the attestations.
abstract contract TlsNotaryVerifierBase is IPlatformVerifier, PlatformVerifierBase {
    /// @dev The bearer-link circuit's public inputs: two bearer commitments, id and
    ///      handle commitments, then the two nodes, each as `[high, low]` halves;
    ///      then each tag as one Field and its length.
    uint256 internal constant PUBLIC_INPUTS = 16;
    uint256 internal constant OFF_TOKEN_COMMITMENT = 0;
    uint256 internal constant OFF_IDENTITY_COMMITMENT = 2;
    uint256 internal constant OFF_ID_COMMITMENT = 4;
    uint256 internal constant OFF_HANDLE_COMMITMENT = 6;
    uint256 internal constant OFF_ID_NODE = 8;
    uint256 internal constant OFF_HANDLE_NODE = 10;
    uint256 internal constant OFF_ID_TAG = 12;
    uint256 internal constant OFF_HANDLE_TAG = 14;

    /// @dev Read from every token head and matched to the signed body length;
    ///      no profile lists it.
    bytes32 private constant LENGTH_HEADER = keccak256("content-length");
    bytes32 private constant AUTHORIZATION = keccak256("authorization");

    /// @dev What frames the committed bearer in the token response, telling it
    ///      apart from other hidden values such as `refresh_token`
    ///      (REQ-PLAT-57, REQ-PLAT-58).
    bytes internal constant ACCESS_TOKEN_PREFIX = '"access_token":"';
    bytes internal constant ACCESS_TOKEN_SUFFIX = '"';

    /// @notice The `x/v1` and `github/v1` payload, as `abi.encode` of this struct.
    /// @dev The client identifier and public inputs are derived from the
    ///      attestations, so the payload does not carry them.
    /// @param ceremonyVersion    Checked against the verifier's own first.
    /// @param operationDomain    Into the digest; returned (REQ-COMMON-06A).
    /// @param authorizationNonce Into the digest and the PKCE verifier; the replay nullifier.
    /// @param transactionData    Into the digest; returned opaque (REQ-COMMON-06B).
    /// @param tokenSession       The notarized token exchange.
    /// @param identitySession    The notarized identity read.
    /// @param idNode             `SHA256(user-id tag || id)`, bound by the proof.
    /// @param handleNode         `SHA256(handle tag || fold(handle))`, bound by the proof.
    /// @param proof              The Honk proof.
    struct TlsNotaryProof {
        uint16 ceremonyVersion;
        bytes32 operationDomain;
        bytes32 authorizationNonce;
        bytes transactionData;
        Attestation tokenSession;
        Attestation identitySession;
        bytes32 idNode;
        bytes32 handleNode;
        bytes proof;
    }

    error WrongRequestLine();
    error CodeVerifierMismatch();
    error ClientIdentifierNotSerializerSafe(bytes found);
    /// @dev The first revealed range does not begin the transcript, or none exists.
    error RequestLineNotAtOrigin(uint32 start);
    /// @dev The token request is not one revealed run with no commitment.
    error WrongTokenRequestLayout(uint256 revealedRanges, uint256 commitments);
    /// @dev The token request holds `occurrences` head/body separators, not one.
    error NoHeadBoundary(uint256 occurrences);
    /// @dev The token request's head lacks a required header, repeats one,
    ///      gives one another value, carries a line no colon splits, or
    ///      declares a body length that is not plain decimal digits.
    error WrongTokenRequestHead();
    /// @dev The identity request's head lacks a required header, repeats one,
    ///      or gives one another value.
    error WrongIdentityRequestHead();
    /// @dev A request carries a header the profile forbids; `name` is normalized.
    error ForbiddenRequestHeader(bytes name);
    /// @dev The declared `content-length` differs from the signed body length.
    error WrongDeclaredBodyLength(uint256 declared, uint256 signed);

    // ─── What a profile supplies ────────────────────────────────────

    // Authorities, request lines, headers, token fields and identity members
    // come from `CeremonyProfile` through `_platform()`.

    /// @dev A profile's value checks on token-body fields, empty by default.
    ///      Runs after the form is known exact and before `code_verifier` and
    ///      `client_id` are read.
    function _checkTokenBody(CeremonyFields.Form memory form) internal pure virtual {}

    // ─── The flow ───────────────────────────────────────────────────

    /// @dev The `bearer-link` circuit's verifier.
    function _circuitCodehash() internal pure virtual override returns (bytes32) {
        return CircuitCodehashes.BEARER_LINK;
    }

    /// @inheritdoc IPlatformVerifier
    function platformId() external pure returns (bytes32) {
        return _platform();
    }

    /// @inheritdoc IPlatformVerifier
    function quote() public view returns (uint256) {
        // One Notary Fee per attestation.
        return 2 * _base().notary.fee();
    }

    /// @inheritdoc IPlatformVerifier
    function verify(bytes calldata payload) external payable returns (VerifiedClaim memory claimed) {
        uint256 fee = _base().notary.fee();
        // Exact value at every hop, so no refund path (REQ-COMMON-06D).
        if (msg.value != 2 * fee) revert WrongValue(2 * fee, msg.value);

        // `abi.decode` reverts on a malformed payload.
        TlsNotaryProof memory p = abi.decode(payload, (TlsNotaryProof));
        uint16 version = _requireCeremonyVersion(p.ceremonyVersion);
        // The token session's revealed `code_verifier` must match this digest,
        // so any changed input yields a digest no attestation matches.
        bytes32 digest =
            CeremonyAuthorization.digest(p.operationDomain, version, p.authorizationNonce, p.transactionData);

        (uint64 observedAt, bytes32 tokenCommitment) = _tokenSession(digest, p, fee, claimed);
        Commitments memory identity = _identitySession(p, fee);

        // Inputs built from the notary-signed commitments and the claimed nodes.
        _requireProof(p.proof, _publicInputs(tokenCommitment, identity, p.idNode, p.handleNode));
        claimed.idNode = p.idNode;
        claimed.handleNode = p.handleNode;

        // The same values that entered the digest.
        claimed.sessionId = digest;
        claimed.operationDomain = p.operationDomain;
        claimed.transactionData = p.transactionData;
        claimed.ceremonyVersion = version;
        claimed.metadataObservedAt = observedAt;
    }

    function _tokenSession(
        bytes32 authorizationDigest,
        TlsNotaryProof memory p,
        uint256 fee,
        VerifiedClaim memory fields
    ) private returns (uint64 observedAt, bytes32 tokenCommitment) {
        CeremonyAttestation.AttestedData memory data =
            _authenticate(p.tokenSession, CeremonyProfile.tokenAuthority(_platform()), fee);
        (fields.clientIdentifier, tokenCommitment) = _tokenTranscript(data, authorizationDigest, p.authorizationNonce);

        // The token attestation alone supplies evidence time (section 2.2).
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
        // REQ-COMMON-18A: tiling ties the request line and body read below to
        // the request the platform answered.
        CeremonyAttestation.requireExactCoverage(data.sent, data.sentTranscriptLength);

        // The one comparison of the method and path (REQ-COMMON-21A): the head
        // check below starts past the request line.
        _requireRequestLine(data.sent, CeremonyProfile.tokenRequestLine(_platform()));

        bytes memory body = _tokenBody(data.sent);

        // The exact shape first, then the values this verifier compares.
        CeremonyFields.Form memory form =
            CeremonyFields.requireExactForm(body, CeremonyProfile.tokenFields(_platform()));
        _checkTokenBody(form);

        // REQ-COMMON-15A: the binding between the evidence and the transaction.
        bytes memory revealedVerifier = CeremonyFields.valueOf(form, "code_verifier");
        // Derived under the nonce the digest commits (REQ-COMMON-12).
        bytes memory expected = CeremonyAuthorization.codeVerifier(authorizationDigest, authorizationNonce);
        if (keccak256(revealedVerifier) != keccak256(expected)) revert CodeVerifierMismatch();

        clientId = CeremonyFields.valueOf(form, "client_id");
        if (!CeremonyFields.isSerializerSafe(clientId)) {
            revert ClientIdentifierNotSerializerSafe(clientId);
        }

        // Tiled, so every byte outside the anchors is committed.
        CeremonyAttestation.requireExactCoverage(data.received, data.recvTranscriptLength);

        // The response commits other bytes too, so the framing identifies the bearer.
        CeremonyAttestation.RangeCommitment memory bearer =
            CeremonyAttestation.requireFramedCommitment(data.received, ACCESS_TOKEN_PREFIX, ACCESS_TOKEN_SUFFIX);
        tokenCommitment = bearer.commitment;
    }

    /// @dev The identity session's three commitments the circuit opens.
    struct Commitments {
        bytes32 bearer;
        bytes32 id;
        bytes32 handle;
    }

    function _identitySession(TlsNotaryProof memory p, uint256 fee) private returns (Commitments memory) {
        CeremonyAttestation.AttestedData memory data =
            _authenticate(p.identitySession, CeremonyProfile.identityAuthority(_platform()), fee);
        return _identityTranscript(data);
    }

    /// @dev Every transcript check of the identity session; `data` must come
    ///      from `_authenticate`. Returns the committed bearer, id and handle.
    function _identityTranscript(CeremonyAttestation.AttestedData memory data)
        internal
        pure
        returns (Commitments memory committed)
    {
        committed.bearer = _identityRequest(data);
        (committed.id, committed.handle) = _identityResponse(data);
    }

    /// @dev The identity session's sent direction: the request line, one
    ///      bodiless request, its one authorization header framing the
    ///      committed bearer, and no forbidden header. Returns that bearer.
    function _identityRequest(CeremonyAttestation.AttestedData memory data) internal pure returns (bytes32) {
        // REQ-COMMON-21A: the path separates operations on the same server.
        _requireRequestLine(data.sent, CeremonyProfile.identityRequestLine(_platform()));

        // Coverage, one request, the header scan and the framing, together:
        // the scan reads only revealed bytes.
        (CeremonyAttestation.RangeCommitment memory bearer, bytes memory revealed) =
            CeremonyAttestation.requireBearerHeaderRequest(data.sent, data.sentTranscriptLength);
        _checkIdentityHead(revealed);
        return bearer.commitment;
    }

    /// @dev The identity session's received direction: tiled, with the id and
    ///      the handle each one commitment between revealed anchors.
    function _identityResponse(CeremonyAttestation.AttestedData memory data)
        internal
        pure
        returns (bytes32 id, bytes32 handle)
    {
        // Each anchor is revealed once and frames one commitment. A second
        // anchor inside a commitment is excluded by ASM-PROV-06: the pinned
        // request line returns one member per anchor.
        CeremonyAttestation.requireExactCoverage(data.received, data.recvTranscriptLength);
        (string memory idField, bool idIsInteger, string memory handleField) =
            CeremonyProfile.identityFields(_platform());
        // Joined and normalized once; both reads count their prefix in it.
        CeremonyAttestation.Framing memory f = CeremonyAttestation.framing(data.received);
        id = idIsInteger
            ? CeremonyAttestation.requireFramedInteger(f, abi.encodePacked('"', idField, '":')).commitment
            : CeremonyAttestation.requireFramedCommitment(f, abi.encodePacked('"', idField, '":"'), '"').commitment;
        handle =
        CeremonyAttestation.requireFramedCommitment(f, abi.encodePacked('"', handleField, '":"'), '"').commitment;
    }

    // ─── Helpers ────────────────────────────────────────────────────

    /// @dev The circuit's public inputs, from the authenticated commitments, the
    ///      returned nodes and this platform's tags (REQ-PLAT-32C, REQ-PLAT-52B).
    function _publicInputs(bytes32 tokenCommitment, Commitments memory identity, bytes32 idNode, bytes32 handleNode)
        private
        pure
        returns (bytes32[] memory inputs)
    {
        inputs = new bytes32[](PUBLIC_INPUTS);
        _halves(inputs, OFF_TOKEN_COMMITMENT, tokenCommitment);
        _halves(inputs, OFF_IDENTITY_COMMITMENT, identity.bearer);
        _halves(inputs, OFF_ID_COMMITMENT, identity.id);
        _halves(inputs, OFF_HANDLE_COMMITMENT, identity.handle);
        _halves(inputs, OFF_ID_NODE, idNode);
        _halves(inputs, OFF_HANDLE_NODE, handleNode);
        _tag(inputs, OFF_ID_TAG, CeremonyProfile.userIdTag(_platform()));
        _tag(inputs, OFF_HANDLE_TAG, CeremonyProfile.handleTag(_platform()));
    }

    /// @dev A tag as one Field, its bytes from the top of the low 31 bytes, then
    ///      its length. Every tag is shorter than 32 bytes.
    function _tag(bytes32[] memory inputs, uint256 at, bytes memory tag) private pure {
        // Every tag is shorter than 32 bytes, so the cast drops none of it.
        // forge-lint: disable-next-line(unsafe-typecast)
        inputs[at] = bytes32(tag) >> 8;
        inputs[at + 1] = bytes32(tag.length);
    }

    /// @dev The head's header lines: each required one exactly once with its
    ///      value, none of the forbidden names, one `content-length`, and
    ///      anything else ignored. Returns the declared length.
    ///
    ///      Forbidden names change what the platform does with the request:
    ///      which client it authenticates, which bytes it parses, which method
    ///      it runs. Other headers change only the answer. Names compare
    ///      lowercased; values exactly, optional whitespace trimmed.
    ///      `requireCrlfLineEndings` runs first, as REQ-COMMON-39 requires
    ///      for the identity request.
    function _checkTokenHead(bytes memory head) private pure returns (uint256 declared) {
        CeremonyAttestation.requireCrlfLineEndings(head);

        Head memory state;
        (state.requiredNames, state.requiredValues) = CeremonyProfile.tokenRequiredHeaderHashes(_platform());
        state.strict = true;
        // Past the request line, which `_tokenTranscript` has already compared.
        _checkHead(head, state);
        if (!state.lengths) revert WrongTokenRequestHead();
        return state.declared;
    }

    /// @dev `_checkHead`'s state. `found` holds a bit per required line, so
    ///      a profile has at most 255; the generator allows two. `strict` is
    ///      the token head's reading; `lengths` records its `content-length`
    ///      line, `declared` that line's value.
    struct Head {
        bytes32[] requiredNames;
        bytes32[] requiredValues;
        bool strict;
        uint256 found;
        bool lengths;
        uint256 declared;
    }

    /// @dev Every line of `head` past the first: each required header once,
    ///      with its value, and no forbidden name. Strict, every line is a
    ///      header and `content-length` is read once; lenient, a line that is
    ///      not a header is skipped and `authorization` is allowed.
    // `1 << i` is the mask for line i; the lint misreads it as swapped operands.
    // forge-lint: disable-next-item(incorrect-shift)
    function _checkHead(bytes memory head, Head memory state) private pure {
        uint256 from = _lineEnd(head, 0) + 2;
        while (from < head.length) {
            uint256 to = _lineEnd(head, from);
            _headerLine(head, from, to, state);
            from = to + 2;
        }
        // Every required line seen: the low bits all set.
        if (state.found != (1 << state.requiredNames.length) - 1) _wrongHead(state.strict);
    }

    /// @dev Checks header line `head[from:to]` and records it in `state`.
    // forge-lint: disable-next-item(incorrect-shift)
    function _headerLine(bytes memory head, uint256 from, uint256 to, Head memory state) private pure {
        (bool isHeader, bytes memory name, uint256 valueStart, uint256 valueEnd) = _field(head, from, to);
        if (!isHeader) {
            if (state.strict) revert WrongTokenRequestHead();
            return;
        }

        bytes32 nameHash = keccak256(name);
        if (CeremonyProfile.isForbiddenRequestHeader(nameHash) && (state.strict || nameHash != AUTHORIZATION)) {
            revert ForbiddenRequestHeader(name);
        }
        if (state.strict && nameHash == LENGTH_HEADER) {
            if (state.lengths) revert WrongTokenRequestHead();
            state.lengths = true;
            state.declared = _decimal(head, valueStart, valueEnd);
            return;
        }
        uint256 i = _indexOf(state.requiredNames, nameHash);
        if (i == type(uint256).max) return;
        if (_hash(head, valueStart, valueEnd) != state.requiredValues[i] || state.found & (1 << i) != 0) {
            _wrongHead(state.strict);
        }
        state.found |= 1 << i;
    }

    /// @dev Reverts the error of the head `strict` names.
    function _wrongHead(bool strict) private pure {
        if (strict) revert WrongTokenRequestHead();
        revert WrongIdentityRequestHead();
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
    ///      dropped (REQ-COMMON-39), `_` read as `-` as CGI-style stacks do;
    ///      the value as offsets, optional whitespace
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

    /// @dev Every revealed line of the identity request carries no forbidden
    ///      name except `authorization`, already counted once by
    ///      `requireBearerHeaderRequest`. Each required identity line appears
    ///      once with its value. Reads the whole concatenation, as the count
    ///      does, and skips lines that are not headers.
    function _checkIdentityHead(bytes memory revealed) private pure {
        Head memory state;
        (state.requiredNames, state.requiredValues) = CeremonyProfile.identityRequiredHeaderHashes(_platform());
        _checkHead(revealed, state);
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

    /// @dev The token request's body: the bytes after its one `\r\n\r\n`.
    ///      The request must be one revealed range with no commitment, which
    ///      exact coverage makes the whole request. Its `content-length` must
    ///      equal the signed body length.
    function _tokenBody(CeremonyAttestation.DirectionBlock memory block_) internal pure returns (bytes memory body) {
        if (block_.revealed.length != 1 || block_.commitments.length != 0) {
            revert WrongTokenRequestLayout(block_.revealed.length, block_.commitments.length);
        }
        bytes memory whole = block_.revealed[0].value;

        // Exactly one head boundary, so the body is unambiguous.
        (uint256 seen, uint256 at) = CeremonyAttestation.headBoundaries(whole);
        if (seen != 1) revert NoHeadBoundary(seen);

        uint256 declared = _checkTokenHead(_slice(whole, 0, at));

        at += 4;
        // The run is the request whole and the head is revealed, so the
        // remainder is the body the platform parsed.
        if (declared != whole.length - at) revert WrongDeclaredBodyLength(declared, whole.length - at);

        body = _slice(whole, at, whole.length);
    }

    /// @dev Range 0 begins the transcript and starts with `line`.
    function _requireRequestLine(CeremonyAttestation.DirectionBlock memory sent, bytes memory line) private pure {
        if (sent.revealed.length == 0) revert RequestLineNotAtOrigin(type(uint32).max);
        if (sent.revealed[0].start != 0) revert RequestLineNotAtOrigin(sent.revealed[0].start);
        if (!_startsWith(sent.revealed[0].value, line)) revert WrongRequestLine();
    }

    function _startsWith(bytes memory data, bytes memory prefix) internal pure returns (bool) {
        if (data.length < prefix.length) return false;
        return _hash(data, 0, prefix.length) == keccak256(prefix);
    }
}
