// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {GoogleProof, TlsNotaryProof} from "./CeremonyPayloads.sol";

/// @title ICeremonyPayloads
/// @notice The payloads the Platform Verifiers decode, as an ABI clients encode
///         against. A payload is `abi.encode(p)`, never a call.
/// @dev Nothing implements or calls this; it puts each struct's tuple type in
///      an artifact the TypeScript and Rust encoders are checked against.
interface ICeremonyPayloads {
    /// @notice The `x/v1` and `github/v1` payload.
    function tlsNotaryProof(TlsNotaryProof calldata payload) external pure;

    /// @notice The `google/v1` payload.
    function googleProof(GoogleProof calldata payload) external pure;
}
