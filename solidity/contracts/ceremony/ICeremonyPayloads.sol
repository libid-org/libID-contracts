// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {GooglePlatformVerifier} from "./GooglePlatformVerifier.sol";
import {TlsNotaryVerifierBase} from "./TlsNotaryVerifierBase.sol";

/// @title ICeremonyPayloads
/// @notice The payloads the Platform Verifiers decode, as an ABI a client can
///         encode against.
///
/// @dev Nothing implements or calls this. `bind` carries a payload as opaque
///      bytes, so no contract's ABI names the structs a verifier decodes; these
///      two functions take them, which puts each struct's exact tuple type into
///      this interface's artifact. The TypeScript package's encoders are
///      generated from that artifact and the Rust crate's structs are held to
///      it, so a field added, removed or reordered in a struct changes what
///      both encode or fails their check.
///
///      A payload is `abi.encode(p)` of one struct, the way each verifier
///      `abi.decode`s it -- the encoding of the function's arguments, without a
///      selector -- never a call to either function.
interface ICeremonyPayloads {
    /// @notice The `x/v1` and `github/v1` payload.
    function tlsNotaryProof(TlsNotaryVerifierBase.TlsNotaryProof calldata payload) external pure;

    /// @notice The `google/v1` payload.
    function googleProof(GooglePlatformVerifier.GoogleProof calldata payload) external pure;
}
