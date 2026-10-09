// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {ICeremony} from "./ICeremony.sol";

// The payloads the Platform Verifiers decode, apart from the verifiers. The
// payload ABI (`ICeremonyPayloads`) and the verifiers that decode it both read
// these, so a client encoding a payload depends on its shape and not on a
// verifier's implementation.

/// @notice What a TLSNotary profile decodes from its payload.
///
/// @dev `abi.encode` of this struct is the payload for `x/v1` and
///      `github/v1`. The two profiles share one shape because they state
///      the same relation; platform separation is the route that reached
///      the verifier, the authorities each subclass pins, and the circuit
///      its Honk verifier answers for, not the struct's name, which the
///      encoding does not carry.
///
///      It carries no platform id and no chain id: the verifier knows the
///      first and reads the second. It carries no public inputs and no
///      client identifier: both are DERIVED from the attestations, so a
///      caller's copy would be a second representation of a fact the
///      verifier already holds. The two sessions are named rather than
///      listed, because they are not interchangeable.
///
/// @param ceremonyVersion    What the payload was built for. Checked against
///                           the verifier's own before anything is paid.
/// @param operationDomain    Into the digest, and returned for the Consumer
///                           to judge (REQ-COMMON-06A).
/// @param authorizationNonce Into the digest, making it unique and therefore
///                           its own replay nullifier, and into the PKCE
///                           verifier the digest is carried under. There is
///                           no second salt beside it (REQ-COMMON-12).
/// @param transactionData    Into the digest, and returned opaque
///                           (REQ-COMMON-06B).
/// @param tokenSession       The token exchange, notarized.
/// @param identitySession    The identity read, notarized. Its response
///                           reveals only the anchors around the id and
///                           the handle; both values are committed.
/// @param idNode             `SHA256(user-id tag || id)`, as the prover
///                           claims it. The proof binds it to the committed
///                           id; nothing else vouches for it.
/// @param handleNode         `SHA256(handle tag || fold(handle))`, bound to
///                           the committed handle the same way.
/// @param handle             Empty for a private submission. Otherwise the
///                           handle to disclose as the holder's name; it
///                           must hash to `handleNode` (`_disclosed`).
/// @param proof              Verified under the artifact governance
///                           selected, never one the caller names.
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

/// @notice What the `google/v1` profile decodes from its payload.
///
/// @dev `abi.encode` of this struct is the payload for `google/v1`. No
///      attestations: the evidence is a signed ID Token verified inside the
///      circuit, and the contract sees only its public inputs -- which are
///      therefore carried, unlike the TLSNotary profiles' where they are
///      derived, and become authentic only once the proof verifies.
///
/// @param ceremonyVersion    What the payload was built for. Checked against
///                           the verifier's own first.
/// @param operationDomain    Into the digest, and returned for the Consumer
///                           to judge.
/// @param authorizationNonce Into the digest.
/// @param transactionData    Into the digest, and returned opaque.
/// @param clientIdentifier   The `aud` bytes. Authenticated by hashing them
///                           against a public input (REQ-PLAT-19A), because
///                           the circuit publishes the audience as a hash
///                           rather than packing a variable-length string;
///                           the bytes cannot be recovered from the proof,
///                           so they are carried and checked instead.
/// @param publicInputs       The circuit's 57 public inputs, in the order
///                           REQ-PLAT-16B fixes.
/// @param handle             Empty for a private submission. Otherwise the
///                           address to disclose as the holder's name; it
///                           must hash to the proof's handle node.
/// @param proof              Verified under the artifact governance
///                           selected, never one the caller names.
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
