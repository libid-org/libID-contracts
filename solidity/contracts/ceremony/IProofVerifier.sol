// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {ICeremony} from "./ICeremony.sol";

/// @title IProofVerifier
/// @notice The one component every Consumer calls to verify a libID proof.
///
/// @dev Third of the four roles of ceremony-common section 5.1, counting down
///      from the Consumer. It is dispatch: it selects the
///      Platform Verifier registered for the pair a Consumer names, forwards
///      the payload and the value to it, and forwards what comes back. It
///      remembers the last payload it verified in the transaction and that
///      payload's claim (see `verify`). It does not decode the payload, holds
///      no platform constant, and applies no transaction. Only the Platform
///      Verifier knows what the bytes are, only the Consumer knows what a
///      claim means, and only the Notary Service knows whether the notary
///      signed.
interface IProofVerifier {
    /// @notice What one verification of this pair costs, over the whole path:
    ///         the price before a payload exists.
    ///
    /// @dev A Consumer cannot attach a correct fee if quoting requires knowing
    ///      the path's topology, so this covers all of it: one Notary Fee per
    ///      attestation the profile requires, and zero where it requires none
    ///      (REQ-COMMON-06E).
    function quote(bytes32 platformId, uint16 verifierVersion) external view returns (uint256);

    /// @notice What `verify` takes for this payload under this pair: zero when
    ///         this payload, under this pair's Platform Verifier, is the last
    ///         one the transaction verified through any Platform Verifier,
    ///         else the full price.
    function quoteFor(bytes32 platformId, uint16 verifierVersion, bytes calldata payload)
        external
        view
        returns (uint256);

    /// @notice Whether any version of this platform can be verified here.
    ///
    /// @dev So a Consumer can tell "no holder" from "not wired yet" without
    ///      holding a copy of the Supported Version Set.
    function verifiesPlatform(bytes32 platformId) external view returns (bool);

    /// @notice Route one payload to the Platform Verifier for this pair and
    ///         return what it authenticated.
    ///
    /// @dev `verifierVersion` selects which registered verifier answers; it is
    ///      this chain's slot number, chosen by governance here, and unrelated
    ///      to the ceremony version the verifier itself supports. `payload` is
    ///      opaque at this hop.
    ///
    ///      The value is exactly `quoteFor(platformId, verifierVersion,
    ///      payload)`, else `WrongValue(quote, value)` (REQ-COMMON-06F). This
    ///      payload, under this pair's Platform Verifier, returns its claim
    ///      and calls nothing when it is the last one the transaction verified
    ///      through any Platform Verifier; otherwise it verifies and becomes
    ///      the last one. A value fixed before the transaction
    ///      reverts if another call verified the same payload earlier in it. A
    ///      caller whose paying call may be rejected pays in a call that
    ///      cannot be, such as a standalone `verify`: a rejected call keeps no
    ///      claim.
    function verify(bytes32 platformId, uint16 verifierVersion, bytes calldata payload)
        external
        payable
        returns (ICeremony.VerifiedClaim memory);
}
