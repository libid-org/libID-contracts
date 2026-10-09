// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {CircuitCodehashes} from "../circuits/CircuitCodehashes.sol";
import {CeremonyProfile} from "./CeremonyProfile.sol";
import {INotaryService} from "./INotaryService.sol";
import {IHonkVerifier} from "./PlatformVerifierBase.sol";
import {TlsNotaryVerifierBase} from "./TlsNotaryVerifierBase.sol";

/// @title GitHubPlatformVerifier — the `github/v1` profile.
///
/// @notice The X relation for GitHub, proved under `bearer-link-github`.
///
/// @dev Two authorities: `github.com` for the exchange, `api.github.com` for
///      the identity read. The token body is exactly `GITHUB_TOKEN_FIELDS`
///      (REQ-PLAT-61), revealed whole, so the application credential is public.
///      The identity response reveals the `"id":` and `"login":"` anchors and
///      their terminators; id and handle are committed for the circuit.
contract GitHubPlatformVerifier is TlsNotaryVerifierBase {
    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    function initialize(
        address owner_,
        INotaryService notary_,
        IHonkVerifier honkVerifier_,
        bytes32 honkVerifierCodehash_
    ) external initializer {
        __PlatformVerifierBase_init(owner_, notary_, honkVerifier_, honkVerifierCodehash_);
    }

    /// @dev `bearer-link-github`'s verifier, and no other.
    function _circuitCodehash() internal pure override returns (bytes32) {
        return CircuitCodehashes.BEARER_LINK_GITHUB;
    }

    function _platform() internal pure override returns (bytes32) {
        return CeremonyProfile.PLATFORM_GITHUB;
    }

    /// @dev The ceremony version this contract implements. The digest binds it;
    ///      a payload claiming another is refused before any fee moves.
    function _ceremonyVersion() internal pure override returns (uint16) {
        return CeremonyProfile.LAUNCH_VERSION;
    }

    function _proofLifetime() internal pure override returns (uint64) {
        return CeremonyProfile.PROOF_LIFETIME_SECONDS_GITHUB;
    }

    function _maxFutureAttestationSkew() internal pure override returns (uint64) {
        return CeremonyProfile.MAX_FUTURE_ATTESTATION_SKEW_SECONDS_GITHUB;
    }

    function _futureObservationAllowance() internal pure override returns (uint64) {
        return CeremonyProfile.FUTURE_OBSERVATION_ALLOWANCE_SECONDS_GITHUB;
    }

    /// @dev The exchange host.
    function _tokenAuthority() internal pure override returns (bytes32) {
        return CeremonyProfile.AUTHORITY_GITHUB;
    }

    /// @dev The API host. Deliberately not the same as above.
    function _identityAuthority() internal pure override returns (bytes32) {
        return CeremonyProfile.AUTHORITY_GITHUB_API;
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

    /// @dev REQ-PLAT-61's field list: the body is the serialization of exactly
    ///      these five, in this order, each once with a nonempty value in the
    ///      serializer's one spelling, and nothing after the last. Of the
    ///      values, the base reads two: `code_verifier`, recomputed and
    ///      compared, which holds it to section 7's canonical encoding, and
    ///      `client_id`, held to REQ-COMMON-16B. `code`, `redirect_uri` and
    ///      `client_secret` are held to the alphabet and read by nothing.
    function _tokenFields() internal pure override returns (bytes memory) {
        return CeremonyProfile.GITHUB_TOKEN_FIELDS;
    }

    /// @dev REQ-PLAT-51. GitHub's `id` is a bare integer, terminated by `,` or
    ///      `}` so the committed digits are the whole number. Handle: `login`.
    function _identityFields()
        internal
        pure
        override
        returns (string memory idField, IdShape idShape, string memory handleField)
    {
        return (CeremonyProfile.GITHUB_ID_FIELD, IdShape.JsonInteger, CeremonyProfile.GITHUB_HANDLE_FIELD);
    }
}
