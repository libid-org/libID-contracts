// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title ICeremony
/// @notice The shapes that travel the verification path of ceremony-common
///         section 5.1: Consumer to Proof Verifier to Platform Verifier to
///         Notary Service.
///
/// @dev What a Consumer submits is NOT declared here. It is opaque bytes: the
///      Consumer names a platform and a verifier version, the Proof Verifier
///      routes on that pair, and only the Platform Verifier at the end of the
///      route knows the shape of what it decodes. Each verifier declares its
///      own payload struct, because the shapes genuinely differ -- two notarized
///      sessions and a PKCE nonce for X and GitHub, a signed token's public
///      inputs for Google -- and nothing above the verifier needs to read them.
interface ICeremony {
    /// @notice One attestation and the notary's proof that it stood behind it.
    /// @dev The Notary Service authenticates this pair by itself and accepts
    ///      no caller-supplied digest, preimage hash, or verifying key: a
    ///      caller-computed digest authenticates whatever the caller hashed,
    ///      not the bytes the Platform Verifier goes on to read
    ///      (REQ-COMMON-33).
    ///
    ///      Both halves are opaque above the Notary Service. The attested
    ///      bytes are the notary's format, not this chain's -- one notary
    ///      serves every chain, so what it attests is chain-agnostic and is
    ///      decoded by the Notary Service alone. The proof is whatever that
    ///      service accepts: a signature today, and nothing here would change
    ///      if it became a threshold of them or a zero-knowledge argument. The
    ///      envelope around the pair is what each chain encodes its own way.
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
    /// @param handle              The disclosed handle, normalized, or empty; hashes to `handleNode`.
    /// @param metadataObservedAt  When the platform stated the identity.
    struct VerifiedClaim {
        bytes32 sessionId;
        bytes32 operationDomain;
        bytes transactionData;
        uint16 ceremonyVersion;
        bytes clientIdentifier;
        bytes32 idNode;
        bytes32 handleNode;
        string handle;
        uint64 metadataObservedAt;
    }
}
