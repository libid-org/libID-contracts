//! Bindings for the ceremony verification path (`solidity/contracts/ceremony/`),
//! read from the compiled artifacts: the Notary Service, the Proof Verifier,
//! the three launch Platform Verifiers and the Google JWT root list.
//! [`platform_verifier`](crate::platform_verifier) builds a Platform Verifier
//! initializer and checks its rules.

#[allow(
    clippy::too_many_arguments,
    missing_docs,
    non_camel_case_types,
    unused_attributes
)]
mod notary_service {
    alloy::sol!(
        #[sol(rpc, all_derives)]
        NotaryService,
        "abi/NotaryService.json"
    );
}

/// `ceremony/NotaryService.sol`: authenticates one attestation for one fee.
pub use notary_service::NotaryService;

#[allow(
    clippy::too_many_arguments,
    missing_docs,
    non_camel_case_types,
    unused_attributes
)]
mod proof_verifier {
    alloy::sol!(
        #[sol(rpc, all_derives)]
        CeremonyProofVerifier,
        "abi/CeremonyProofVerifier.json"
    );
}

/// `ceremony/CeremonyProofVerifier.sol`: the Supported Version Set, which
/// Platform Verifier answers for a `(platformId, verifierVersion)` pair.
pub use proof_verifier::CeremonyProofVerifier;

#[allow(
    clippy::too_many_arguments,
    missing_docs,
    non_camel_case_types,
    unused_attributes
)]
mod google_jwt_roots {
    alloy::sol!(
        #[sol(rpc, all_derives)]
        GoogleJwtRoots,
        "abi/GoogleJwtRoots.json"
    );
}

/// `ceremony/GoogleJwtRoots.sol`: the Google signing keys the `google/v1`
/// verifier trusts, two generations of a notarized JWKS reading.
pub use google_jwt_roots::GoogleJwtRoots;

#[allow(
    clippy::too_many_arguments,
    missing_docs,
    non_camel_case_types,
    unused_attributes
)]
mod i_platform_verifier {
    alloy::sol!(
        #[sol(rpc, all_derives)]
        IPlatformVerifier,
        "abi/IPlatformVerifier.json"
    );
}

/// `ceremony/IPlatformVerifier.sol`: what the Proof Verifier calls on every
/// Platform Verifier, `platformId()` among it.
pub use i_platform_verifier::IPlatformVerifier;

#[allow(
    clippy::too_many_arguments,
    missing_docs,
    non_camel_case_types,
    unused_attributes
)]
mod platform_verifier_base {
    alloy::sol!(
        #[sol(rpc, all_derives)]
        PlatformVerifierBase,
        "abi/PlatformVerifierBase.json"
    );
}

/// `ceremony/PlatformVerifierBase.sol`: the trust roots every Platform
/// Verifier holds, `circuitCodehash()` among them.
pub use platform_verifier_base::PlatformVerifierBase;

#[allow(
    clippy::too_many_arguments,
    missing_docs,
    non_camel_case_types,
    unused_attributes
)]
mod x_platform_verifier {
    alloy::sol!(
        #[sol(rpc, all_derives)]
        XPlatformVerifier,
        "abi/XPlatformVerifier.json"
    );
}

/// `ceremony/XPlatformVerifier.sol`: the `x/v1` profile.
pub use x_platform_verifier::XPlatformVerifier;

#[allow(
    clippy::too_many_arguments,
    missing_docs,
    non_camel_case_types,
    unused_attributes
)]
mod github_platform_verifier {
    alloy::sol!(
        #[sol(rpc, all_derives)]
        GitHubPlatformVerifier,
        "abi/GitHubPlatformVerifier.json"
    );
}

/// `ceremony/GitHubPlatformVerifier.sol`: the `github/v1` profile.
pub use github_platform_verifier::GitHubPlatformVerifier;

#[allow(
    clippy::too_many_arguments,
    missing_docs,
    non_camel_case_types,
    unused_attributes
)]
mod google_platform_verifier {
    alloy::sol!(
        #[sol(rpc, all_derives)]
        GooglePlatformVerifier,
        "abi/GooglePlatformVerifier.json"
    );
}

/// `ceremony/GooglePlatformVerifier.sol`: the `google/v1` profile.
pub use google_platform_verifier::GooglePlatformVerifier;

#[allow(
    clippy::too_many_arguments,
    missing_docs,
    non_camel_case_types,
    unused_attributes
)]
mod payloads {
    alloy::sol!(
        #[sol(all_derives)]
        ICeremonyPayloads,
        "abi/ICeremonyPayloads.json"
    );
}

/// `ceremony/ICeremonyPayloads.sol`: the payloads `IdentityRegistry.bind`
/// carries to a Platform Verifier. A payload is the struct's
/// [`SolValue::abi_encode`](alloy::sol_types::SolValue::abi_encode), never a
/// call to either function.
pub use payloads::{
    GooglePlatformVerifier::GoogleProof,
    ICeremony::Attestation,
    ICeremonyPayloads,
    TlsNotaryVerifierBase::TlsNotaryProof,
};

#[cfg(test)]
mod tests {
    use std::fs;

    use alloy::{
        primitives::{
            keccak256,
            Bytes,
            B256,
        },
        sol_types::SolValue,
    };
    use serde::{
        de::DeserializeOwned,
        Deserialize,
    };

    use super::*;

    /// The notarized sessions in `x-ceremony-session.json`, read for the
    /// payload fields.
    #[derive(Deserialize)]
    struct SessionFixture {
        ceremony_version: u16,
        operation_domain: B256,
        authorization_nonce: B256,
        transaction_data: Bytes,
        token: AttestationFixture,
        identity: AttestationFixture,
    }

    /// One session's notarized bytes and the notary's signature over them.
    #[derive(Deserialize)]
    struct AttestationFixture {
        attested_data: Bytes,
        notary_signature: Bytes,
    }

    impl From<AttestationFixture> for Attestation {
        fn from(fixture: AttestationFixture) -> Self {
            Self {
                attestedData: fixture.attested_data,
                proof: fixture.notary_signature,
            }
        }
    }

    /// `x-ceremony-session-proof.json`, read for the proof.
    #[derive(Deserialize)]
    struct ProofFixture {
        proof: Bytes,
    }

    /// `x-ceremony-payload.json`: the nodes and the encoding solc pins.
    #[derive(Deserialize)]
    struct PayloadFixture {
        id_node: B256,
        handle_node: B256,
        keccak256: B256,
        length: usize,
    }

    /// A Solidity suite fixture.
    fn fixture<T: DeserializeOwned>(name: &str) -> T {
        let path = format!(
            "{}/../../solidity/contracts/ceremony/test/fixtures/{name}",
            env!("CARGO_MANIFEST_DIR")
        );
        let text = fs::read_to_string(&path).expect(&path);
        serde_json::from_str(&text).expect(&path)
    }

    /// The X fixture encodes to the hash `x-ceremony-payload.json` pins.
    #[test]
    fn the_x_fixture_payload_encodes_to_the_pinned_bytes() {
        let session: SessionFixture = fixture("x-ceremony-session.json");
        let proof: ProofFixture = fixture("x-ceremony-session-proof.json");
        let pinned: PayloadFixture = fixture("x-ceremony-payload.json");

        let payload = TlsNotaryProof {
            ceremonyVersion: session.ceremony_version,
            operationDomain: session.operation_domain,
            authorizationNonce: session.authorization_nonce,
            transactionData: session.transaction_data,
            tokenSession: session.token.into(),
            identitySession: session.identity.into(),
            idNode: pinned.id_node,
            handleNode: pinned.handle_node,
            proof: proof.proof,
        };

        let encoded = payload.abi_encode();
        assert_eq!(encoded.len(), pinned.length);
        assert_eq!(keccak256(&encoded), pinned.keccak256);
        assert_eq!(TlsNotaryProof::abi_decode(&encoded).unwrap(), payload);
    }

    #[test]
    fn a_google_payload_round_trips() {
        let payload = GoogleProof {
            ceremonyVersion: 1,
            operationDomain: B256::repeat_byte(0x11),
            authorizationNonce: B256::repeat_byte(0x22),
            transactionData: vec![1, 2].into(),
            clientIdentifier: b"aud".to_vec().into(),
            idNode: B256::repeat_byte(0x33),
            handleNode: B256::repeat_byte(0x44),
            exp: 1_800_000_000,
            modulus: [B256::repeat_byte(0x55); 18],
            proof: vec![0xde, 0xad].into(),
        };
        assert_eq!(
            GoogleProof::abi_decode(&payload.abi_encode()).unwrap(),
            payload
        );
    }
}
