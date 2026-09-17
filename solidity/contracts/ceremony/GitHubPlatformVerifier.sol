// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {CeremonyProfile} from "./CeremonyProfile.sol";
import {INotaryService} from "./INotaryService.sol";
import {IHonkVerifier} from "./PlatformVerifierBase.sol";
import {TlsNotaryVerifierBase} from "./TlsNotaryVerifierBase.sol";

/// @title GitHubPlatformVerifier — the `github/v1` profile.
///
/// @notice The same relation X states, for a second platform.
///
/// @dev This verifier sees two attestations and one proof, exactly as X does.
///      It differs in four constants and two reads.
///
///      TWO AUTHORITIES, NOT ONE. `github.com` serves the exchange and
///      `api.github.com` serves the identity read, so an authority is per
///      SESSION here. A profile pinning one authority would accept an identity
///      attestation from the exchange host, or the reverse.
///
///      NO `grant_type` TO COMPARE. Section 6.2 lists five fields and that is
///      not among them, so REQ-PLAT-56 has no GitHub counterpart and this
///      profile adds no extra token-body check.
///
///      THE REVEALED LAYOUT IS A PROFILE DECISION, as it is for X:
///
///        token exchange — ONE revealed sent range covering the request whole,
///                         and NO commitment; `_tokenBody` refuses any other
///                         count. The credential GitHub calls `client_secret`
///                         is sent in the body and revealed with everything
///                         around it, so every field a verifier reads lies in
///                         the open and the request has no hidden suffix.
///
///                         What the revealed bytes do not settle is the
///                         decoded form. `formField` refuses a name it finds
///                         at two `&`-anchored positions, but a value carrying
///                         a raw `&` or `=` would decode as fields nobody
///                         counted. That is ASM-PROV-07 -- the platform
///                         rejects a body carrying a profile field twice --
///                         backed by the recurring probes REQ-COMMON-32
///                         requires, exactly as it is for X.
///        token response — the `"access_token":"` delimiter and closing quote
///                         revealed; the bearer and everything else committed.
///        identity request — the bearer committed, every other byte revealed
///                         and tiled exactly.
///        identity response — `id` and `login` with their full delimiters.
///
///      An attestation of this exchange carries the application credential in
///      plaintext: to the notary that observed the session, and to every
///      reader of the chain that verifies it. That follows from the layout
///      above rather than from any choice a prover makes.
contract GitHubPlatformVerifier is TlsNotaryVerifierBase {
    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    function initialize(
        address owner_,
        INotaryService notary_,
        IHonkVerifier honkVerifier_,
        bytes32 honkVerifierCodehash_,
        uint64 proofLifetime_,
        uint64 maxFutureAttestationSkew_,
        uint64 futureObservationAllowance_
    ) external initializer {
        __PlatformVerifierBase_init(
            owner_,
            notary_,
            honkVerifier_,
            honkVerifierCodehash_,
            proofLifetime_,
            maxFutureAttestationSkew_,
            futureObservationAllowance_
        );
    }

    function _platform() internal pure override returns (bytes32) {
        return CeremonyProfile.PLATFORM_GITHUB;
    }

    /// @dev The ceremony version this contract implements. The digest binds it;
    ///      a payload claiming another is refused before any fee moves.
    function _ceremonyVersion() internal pure override returns (uint16) {
        return CeremonyProfile.LAUNCH_VERSION;
    }

    /// @dev The exchange host.
    function _tokenAuthority() internal pure override returns (bytes32) {
        return CeremonyProfile.AUTHORITY_GITHUB;
    }

    /// @dev The API host. Deliberately not the same as above.
    function _identityAuthority() internal pure override returns (bytes32) {
        return CeremonyProfile.AUTHORITY_GITHUB_API;
    }

    /// @dev GitHub's exchange hides no body field, so its request is revealed
    ///      whole and this direction carries no commitment at all.
    function _tokenSentCommitments() internal pure override returns (uint256) {
        return CeremonyProfile.GITHUB_TOKEN_SENT_COMMITMENTS;
    }

    function _tokenRequestLine() internal pure override returns (bytes memory) {
        return CeremonyProfile.GITHUB_TOKEN_REQUEST_LINE;
    }

    /// @dev REQ-COMMON-21B: `host` and section 6.2's media type. What else
    ///      the sender puts in the head is not compared: it changes what
    ///      GitHub answers, never how GitHub parses the body.
    function _tokenRequiredHeaders() internal pure override returns (bytes memory) {
        return CeremonyProfile.GITHUB_TOKEN_REQUIRED_HEADERS;
    }

    function _identityRequestLine() internal pure override returns (bytes memory) {
        return CeremonyProfile.GITHUB_IDENTITY_REQUEST_LINE;
    }

    /// @dev REQ-PLAT-51. GitHub's `id` is a BARE integer, so it is read by the
    ///      integer template with its terminator pinned to `,` or `}` and no
    ///      other byte: the terminator is what proves the revealed digits are
    ///      the whole number rather than a prefix of a longer one, and JSON
    ///      member order does not say which of the two closes it.
    ///
    ///      The handle field is `login`, not `username`.
    function _identityFields()
        internal
        pure
        override
        returns (string memory idField, IdShape idShape, string memory handleField)
    {
        return (CeremonyProfile.GITHUB_ID_FIELD, IdShape.JsonInteger, CeremonyProfile.GITHUB_HANDLE_FIELD);
    }
}
