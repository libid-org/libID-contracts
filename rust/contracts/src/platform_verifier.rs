//! Deploying a launch Platform Verifier: which contract serves which
//! platform, and its `initialize` rules checked off chain first.
//!
//! [`Initializer::call`] builds the `initialize` call; [`deploy_platform_verifier`]
//! requires the Honk verifier to be the platform's own circuit
//! ([`PlatformVerifier::circuit`]) and puts the implementation behind a fresh
//! ERC1967 proxy with it.

use alloy::{
    contract::Error as ContractError,
    primitives::{
        keccak256,
        Address,
        B256,
    },
    providers::Provider,
    sol_types::SolCall,
};

use crate::{
    artifacts::Artifacts,
    bindings::ceremony::{
        GitHubPlatformVerifier,
        GooglePlatformVerifier,
        IPlatformVerifier,
        PlatformVerifierBase,
        XPlatformVerifier,
    },
    circuits::Circuit,
    deploy::deploy_behind_proxy,
    error::{
        Error,
        Result,
    },
};

/// One of the three launch Platform Verifiers.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum PlatformVerifier {
    /// `x/v1`: `XPlatformVerifier`, a TLSNotary profile.
    X,
    /// `github/v1`: `GitHubPlatformVerifier`, a TLSNotary profile.
    GitHub,
    /// `google/v1`: `GooglePlatformVerifier`, a signed-token profile that
    /// notarizes nothing.
    Google,
}

impl PlatformVerifier {
    /// Every launch verifier.
    pub const ALL: [Self; 3] = [Self::X, Self::GitHub, Self::Google];

    /// The contract, which is also its `.sol` file and its entry in
    /// [`COVERED`](crate::artifacts::COVERED).
    pub const fn contract(self) -> &'static str {
        match self {
            Self::X => "XPlatformVerifier",
            Self::GitHub => "GitHubPlatformVerifier",
            Self::Google => "GooglePlatformVerifier",
        }
    }

    /// The platform's bare name, as `CeremonyProfile` spells it. libID
    /// namespaces only its own strings.
    pub const fn platform(self) -> &'static str {
        match self {
            Self::X => "x",
            Self::GitHub => "github",
            Self::Google => "google",
        }
    }

    /// What the deployed contract answers to `platformId()`: `keccak256`
    /// of the bare name.
    pub fn platform_id(self) -> B256 {
        keccak256(self.platform().as_bytes())
    }

    /// The ceremony circuit this platform's proofs are made under, and so
    /// which vendored Honk verifier its `honk_verifier` should be.
    pub const fn circuit(self) -> Circuit {
        match self {
            Self::X | Self::GitHub => Circuit::BearerLink,
            Self::Google => Circuit::OidcGoogle,
        }
    }

    /// Whether the profile notarizes any session, and so whether its
    /// verifier holds a Notary Service. Mirrors
    /// `CeremonyProfile.attestationCount`; a test pins it to `libid-profiles`.
    pub const fn notarizes(self) -> bool {
        match self {
            Self::X | Self::GitHub => true,
            Self::Google => false,
        }
    }
}

impl PlatformVerifier {
    /// The code hash at `address`, required to be this platform's
    /// [`circuit`](Self::circuit) verifier's ([`Error::WrongCircuit`]
    /// otherwise, [`Error::Rpc`] when there is no code).
    pub async fn circuit_codehash_at<P: Provider>(
        self,
        provider: &P,
        artifacts: &Artifacts,
        address: Address,
    ) -> Result<B256> {
        let pinned = self.circuit().runtime_codehash(artifacts)?;
        self.pinned_codehash_at(provider, artifacts, address, pinned)
            .await
    }

    /// The code hash at `address`, required to be the `circuitCodehash()` the
    /// Platform Verifier at `proxy` pins, for `setTrustRoots` on a deployed
    /// proxy. The proxy must serve this platform ([`Error::WrongPlatform`]).
    pub async fn rotation_codehash_at<P: Provider>(
        self,
        provider: &P,
        artifacts: &Artifacts,
        proxy: Address,
        address: Address,
    ) -> Result<B256> {
        let read = |what: &str, e: ContractError| Error::Rpc {
            detail: format!("failed to read {what} at {proxy}: {e}"),
        };
        let found = IPlatformVerifier::new(proxy, provider)
            .platformId()
            .call()
            .await
            .map_err(|e| read("platformId()", e))?;
        if found != self.platform_id() {
            return Err(Error::WrongPlatform {
                proxy,
                expected: self.platform_id(),
                found,
            });
        }
        let pinned = PlatformVerifierBase::new(proxy, provider)
            .circuitCodehash()
            .call()
            .await
            .map_err(|e| read("circuitCodehash()", e))?;
        self.pinned_codehash_at(provider, artifacts, address, pinned)
            .await
    }

    async fn pinned_codehash_at<P: Provider>(
        self,
        provider: &P,
        artifacts: &Artifacts,
        address: Address,
        pinned: B256,
    ) -> Result<B256> {
        let codehash = codehash_at(provider, address).await?;
        if codehash != pinned {
            let known = Circuit::runtime_codehashes(artifacts)?;
            return Err(Error::WrongCircuit {
                contract: self.contract(),
                address,
                expected_codehash: pinned,
                expected: Circuit::with_runtime_codehash(&known, pinned),
                found: Circuit::with_runtime_codehash(&known, codehash),
                codehash,
            });
        }
        Ok(codehash)
    }
}

/// What a TLSNotary Platform Verifier (`x/v1`, `github/v1`) initializes
/// with: its owner and trust roots.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TlsNotaryRoots {
    /// Governance. Rotates the roots, upgrades.
    pub owner: Address,
    /// The Notary Service both attestations are authenticated through.
    /// Required: the profile pins one (REQ-COMMON-18).
    pub notary_service: Address,
    /// The bb-generated UltraHonk verifier for this platform's circuit.
    pub honk_verifier: Address,
}

/// What the Google Platform Verifier initializes with. The base refuses a
/// Notary Service for this profile.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GoogleRoots {
    /// Governance.
    pub owner: Address,
    /// The bb-generated UltraHonk verifier for the Google OIDC circuit.
    pub honk_verifier: Address,
    /// The `GoogleJwtRoots` proxy the trusted moduli are read through.
    pub jwt_roots: Address,
}

/// What one Platform Verifier is initialized with.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Initializer {
    /// `XPlatformVerifier`.
    X(TlsNotaryRoots),
    /// `GitHubPlatformVerifier`.
    GitHub(TlsNotaryRoots),
    /// `GooglePlatformVerifier`.
    Google(GoogleRoots),
}

/// A built `initialize` call. Its [`abi_encode`](Self::abi_encode) is an
/// ERC1967 proxy's init data, for [`deploy_platform_verifier`],
/// [`deploy_proxy`](crate::deploy::deploy_proxy) or a [factory](crate::factory) deploy.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum InitializeCall {
    /// `XPlatformVerifier.initialize`.
    X(XPlatformVerifier::initializeCall),
    /// `GitHubPlatformVerifier.initialize`.
    GitHub(GitHubPlatformVerifier::initializeCall),
    /// `GooglePlatformVerifier.initialize`.
    Google(GooglePlatformVerifier::initializeCall),
}

impl InitializeCall {
    /// The ABI-encoded call.
    pub fn abi_encode(&self) -> Vec<u8> {
        match self {
            Self::X(call) => call.abi_encode(),
            Self::GitHub(call) => call.abi_encode(),
            Self::Google(call) => call.abi_encode(),
        }
    }
}

impl Initializer {
    /// Which verifier this initializes.
    pub const fn verifier(&self) -> PlatformVerifier {
        match self {
            Self::X(_) => PlatformVerifier::X,
            Self::GitHub(_) => PlatformVerifier::GitHub,
            Self::Google(_) => PlatformVerifier::Google,
        }
    }

    /// The Honk verifier it pins.
    pub const fn honk_verifier(&self) -> Address {
        match self {
            Self::X(roots) | Self::GitHub(roots) => roots.honk_verifier,
            Self::Google(roots) => roots.honk_verifier,
        }
    }

    /// The rules `initialize` enforces that need no chain: a nonzero owner
    /// and Honk verifier, a Notary Service for a TLSNotary profile, and a
    /// root list for Google. [`deploy_platform_verifier`] checks the code hash.
    pub fn check(&self) -> Result<()> {
        let contract = self.verifier().contract();
        let refuse = |detail: String| Error::Initializer {
            detail: format!("{contract}: {detail}"),
        };
        let nonzero = |what: &str, address: Address| {
            if address == Address::ZERO {
                return Err(refuse(format!("{what} is the zero address")));
            }
            Ok(())
        };
        match self {
            Self::X(roots) | Self::GitHub(roots) => {
                nonzero("owner", roots.owner)?;
                nonzero("honk verifier", roots.honk_verifier)?;
                if roots.notary_service == Address::ZERO {
                    return Err(refuse(
                        "notary service is the zero address, but the profile \
                         notarizes two sessions and must pin the Notary Service \
                         they are authenticated through"
                            .into(),
                    ));
                }
                Ok(())
            }
            Self::Google(roots) => {
                nonzero("owner", roots.owner)?;
                nonzero("honk verifier", roots.honk_verifier)?;
                nonzero("jwt roots", roots.jwt_roots)
            }
        }
    }

    /// Build the `initialize` call, after [`check`](Self::check).
    pub fn call(&self) -> Result<InitializeCall> {
        self.check()?;
        Ok(match self {
            Self::X(roots) => InitializeCall::X(XPlatformVerifier::initializeCall {
                owner_: roots.owner,
                notary_: roots.notary_service,
                honkVerifier_: roots.honk_verifier,
            }),
            Self::GitHub(roots) => {
                InitializeCall::GitHub(GitHubPlatformVerifier::initializeCall {
                    owner_: roots.owner,
                    notary_: roots.notary_service,
                    honkVerifier_: roots.honk_verifier,
                })
            }
            Self::Google(roots) => {
                InitializeCall::Google(GooglePlatformVerifier::initializeCall {
                    owner_: roots.owner,
                    // Attestation Count zero: no Notary Service (REQ-COMMON-05D).
                    notary_: Address::ZERO,
                    honkVerifier_: roots.honk_verifier,
                    jwtRoots_: roots.jwt_roots,
                })
            }
        })
    }
}

/// The code hash of the account at `address`: `keccak256` of its runtime
/// bytecode. An account without code is an error, since `setTrustRoots`
/// refuses both `keccak256("")` and zero.
pub async fn codehash_at<P: Provider>(provider: &P, address: Address) -> Result<B256> {
    let code = provider
        .get_code_at(address)
        .await
        .map_err(|e| Error::Rpc {
            detail: format!("failed to read code at {address}: {e}"),
        })?;
    if code.is_empty() {
        return Err(Error::Rpc {
            detail: format!("no code at {address}"),
        });
    }
    Ok(keccak256(&code))
}

/// Deploy the verifier's implementation behind a fresh ERC1967 proxy
/// initialized with `init`, and return the proxy address. The Honk verifier
/// must be the platform's circuit's
/// ([`circuit_codehash_at`](PlatformVerifier::circuit_codehash_at)), checked
/// before anything is sent. `sender` opts into explicit nonces
/// ([`deploy_contract_from`](crate::deploy::deploy_contract_from)).
pub async fn deploy_platform_verifier<P: Provider>(
    provider: &P,
    artifacts: &Artifacts,
    init: &Initializer,
    sender: Option<Address>,
) -> Result<Address> {
    let contract = init.verifier().contract();
    let call = init.call()?;
    init.verifier()
        .circuit_codehash_at(provider, artifacts, init.honk_verifier())
        .await
        .map_err(|e| match e {
            Error::Rpc { .. } => Error::Initializer {
                detail: format!("{contract}: honk verifier: {e}"),
            },
            other => other,
        })?;
    match call {
        InitializeCall::X(call) => {
            deploy_behind_proxy(provider, artifacts, contract, &call, sender).await
        }
        InitializeCall::GitHub(call) => {
            deploy_behind_proxy(provider, artifacts, contract, &call, sender).await
        }
        InitializeCall::Google(call) => {
            deploy_behind_proxy(provider, artifacts, contract, &call, sender).await
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::artifacts::COVERED;

    fn tls() -> TlsNotaryRoots {
        TlsNotaryRoots {
            owner: Address::repeat_byte(0x01),
            notary_service: Address::repeat_byte(0x02),
            honk_verifier: Address::repeat_byte(0x03),
        }
    }

    fn google() -> GoogleRoots {
        GoogleRoots {
            owner: Address::repeat_byte(0x01),
            honk_verifier: Address::repeat_byte(0x03),
            jwt_roots: Address::repeat_byte(0x04),
        }
    }

    /// Whether a verifier holds a Notary Service is derived from the
    /// generated profile table, as the contract derives it from
    /// `CeremonyProfile.attestationCount`.
    #[test]
    fn notarizes_follows_the_profile_table() {
        for verifier in PlatformVerifier::ALL {
            let profile = libid_profiles::LAUNCH
                .iter()
                .find(|p| p.platform == verifier.platform())
                .unwrap_or_else(|| panic!("{verifier:?} has no launch profile"));
            assert_eq!(
                verifier.notarizes(),
                profile.attestation_count() != 0,
                "{verifier:?}"
            );
            assert_eq!(verifier.platform_id(), keccak256(profile.platform));
        }
        assert_eq!(PlatformVerifier::ALL.len(), libid_profiles::LAUNCH.len());
    }

    /// Every vendored circuit has a platform proving under it.
    #[test]
    fn every_circuit_serves_a_platform() {
        for circuit in Circuit::ALL {
            assert!(
                PlatformVerifier::ALL.iter().any(|v| v.circuit() == circuit),
                "{circuit:?} serves no platform"
            );
        }
    }

    /// Every verifier's contract is one the crate vendors.
    #[test]
    fn every_verifier_is_covered() {
        for verifier in PlatformVerifier::ALL {
            let contract = verifier.contract();
            assert!(
                COVERED.contains(&(contract, contract)),
                "{contract} is not in COVERED"
            );
        }
    }

    #[test]
    fn well_formed_initializers_pass() {
        Initializer::X(tls()).check().unwrap();
        Initializer::GitHub(tls()).check().unwrap();
        Initializer::Google(google()).check().unwrap();
    }

    #[test]
    fn a_tls_notary_profile_must_pin_a_notary_service() {
        let err = Initializer::GitHub(TlsNotaryRoots {
            notary_service: Address::ZERO,
            ..tls()
        })
        .check()
        .unwrap_err();
        assert!(matches!(err, Error::Initializer { .. }), "{err}");
        assert!(err.to_string().contains("notary service"), "{err}");
        assert!(err.to_string().contains("GitHubPlatformVerifier"), "{err}");
    }

    #[test]
    fn zero_addresses_are_refused() {
        let cases: [(Initializer, &str); 5] = [
            (
                Initializer::X(TlsNotaryRoots {
                    owner: Address::ZERO,
                    ..tls()
                }),
                "owner",
            ),
            (
                Initializer::X(TlsNotaryRoots {
                    honk_verifier: Address::ZERO,
                    ..tls()
                }),
                "honk verifier",
            ),
            (
                Initializer::Google(GoogleRoots {
                    owner: Address::ZERO,
                    ..google()
                }),
                "owner",
            ),
            (
                Initializer::Google(GoogleRoots {
                    honk_verifier: Address::ZERO,
                    ..google()
                }),
                "honk verifier",
            ),
            (
                Initializer::Google(GoogleRoots {
                    jwt_roots: Address::ZERO,
                    ..google()
                }),
                "jwt roots",
            ),
        ];
        for (init, what) in cases {
            let err = init.check().unwrap_err();
            assert!(err.to_string().contains(what), "{what}: {err}");
        }
    }
}
