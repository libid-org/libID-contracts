// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title ICeremony
/// @notice The shapes that travel the verification path of ceremony-common
///         section 5.1: Consumer to Proof Verifier to Platform Verifier to
///         Notary Service.
///
/// @dev A Consumer submits opaque bytes. The Proof Verifier routes on
///      platform and verifier version, and each Platform Verifier declares
///      and decodes its own payload struct (see `ICeremonyPayloads`).
interface ICeremony {
    /// @notice One attestation and the notary's proof that it stood behind it.
    /// @dev The Notary Service authenticates the pair itself, taking no
    ///      caller-supplied digest or key, so it authenticates the bytes the
    ///      Platform Verifier reads (REQ-COMMON-33). Both fields are opaque
    ///      above the Notary Service: `attestedData` is the notary's
    ///      chain-agnostic format, `proof` whatever that service accepts.
    struct Attestation {
        bytes attestedData;
        bytes proof;
    }

    /// @notice What a Platform Verifier returns on acceptance (REQ-COMMON-06);
    ///         the Proof Verifier forwards it unchanged.
    /// @param sessionId           The Authorization Digest; the ceremony's replay nullifier (REQ-COMMON-03).
    /// @param operationDomain     The Consumer rejects one it does not own (REQ-COMMON-06A).
    /// @param transactionData     Opaque bytes; the Consumer decodes them.
    /// @param ceremonyVersion     The ceremony version the digest binds, not the routing version.
    /// @param clientIdentifier    The exact authenticated bytes, never a digest (REQ-COMMON-16).
    /// @param idNode              `SHA256(user-id tag || id)`.
    /// @param handleNode          `SHA256(handle tag || fold(handle))`.
    /// @param metadataObservedAt  When the platform stated the identity.
    struct VerifiedClaim {
        bytes32 sessionId;
        bytes32 operationDomain;
        bytes transactionData;
        uint16 ceremonyVersion;
        bytes clientIdentifier;
        bytes32 idNode;
        bytes32 handleNode;
        uint64 metadataObservedAt;
    }
}
