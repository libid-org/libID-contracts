// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {ICeremony} from "./ICeremony.sol";

// The payloads the Platform Verifiers decode, shared with `ICeremonyPayloads`.

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
/// @param handle             Empty, or the handle to disclose; must hash to `handleNode`.
/// @param proof              The Honk proof.
struct TlsNotaryProof {
    uint16 ceremonyVersion;
    bytes32 operationDomain;
    bytes32 authorizationNonce;
    bytes transactionData;
    ICeremony.Attestation tokenSession;
    ICeremony.Attestation identitySession;
    bytes32 idNode;
    bytes32 handleNode;
    string handle;
    bytes proof;
}

/// @notice The `google/v1` payload, as `abi.encode` of this struct.
/// @dev Public inputs are carried, and authentic only once the proof verifies.
/// @param ceremonyVersion    Checked against the verifier's own first.
/// @param operationDomain    Into the digest; returned.
/// @param authorizationNonce Into the digest.
/// @param transactionData    Into the digest; returned opaque.
/// @param clientIdentifier   The `aud` bytes, checked against their public-input hash (REQ-PLAT-19A).
/// @param publicInputs       The circuit's 57 public inputs (REQ-PLAT-16B order).
/// @param handle             Empty, or the address to disclose; must hash to the handle node.
/// @param proof              The Honk proof.
struct GoogleProof {
    uint16 ceremonyVersion;
    bytes32 operationDomain;
    bytes32 authorizationNonce;
    bytes transactionData;
    bytes clientIdentifier;
    bytes32[] publicInputs;
    string handle;
    bytes proof;
}
