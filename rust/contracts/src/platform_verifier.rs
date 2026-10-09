//! Deploying a launch Platform Verifier: which contract serves which
//! platform, what it initializes with, and the rules its `initialize`
//! enforces — checked here, off chain, before a transaction is built.
//!
//! `PlatformVerifierBase.__PlatformVerifierBase_init` refuses three things a
//! deployer would otherwise rediscover at the proxy's constructor revert:
//! a Notary Service that does not match what the profile notarizes (a
//! TLSNotary profile must hold one, Google must hold none), a code hash
//! that is zero, `keccak256("")` or not the hash of the code at the Honk
//! verifier's address, and a zero owner or root list. The validity window is
//! not among them: each verifier reads its profile's from `CeremonyProfile`,
//! so a deployment supplies none. [`Initializer::call`] reads the code hash off the chain,
//! requires it to be the platform's own circuit's verifier — the contract
//! pins that runtime code hash too, and reverts `WrongCircuit` otherwise —
//! checks the rest, and builds the exact `initialize` call;
//! [`deploy_platform_verifier`] puts the implementation behind a fresh
//! ERC1967 proxy with it.
//!
//! The Honk verifier a Platform Verifier pins is vendored here too
//! ([`circuits`](crate::circuits)): bb-generated in `libid-circuits` from
//! the circuit's verification key, deployed by
//! [`deploy_honk_verifier`](crate::circuits::deploy_honk_verifier). Which
//! circuit a platform proves under is [`PlatformVerifier::circuit`]; the
//! contract pins whichever address governance names, by address AND by
//! code hash, and [`Initializer::call`] refuses an address holding any
//! other circuit's verifier.

use alloy::{
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
        GooglePlatformVerifier,
        TlsNotaryPlatformVerifier,
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
            Self::X => Circuit::BearerLinkX,
            Self::GitHub => Circuit::BearerLinkGithub,
            Self::Google => Circuit::OidcGoogle,
        }
    }

    /// Whether the profile notarizes any session, and so whether its
    /// verifier holds a Notary Service. `CeremonyProfile.attestationCount`
    /// is two for the TLSNotary profiles and zero for Google; the
    /// `libid-profiles` table says the same, and a test pins the two
    /// together.
    pub const fn notarizes(self) -> bool {
        match self {
            Self::X | Self::GitHub => true,
            Self::Google => false,
        }
    }
}

impl PlatformVerifier {
    /// The code hash at `address`, required to be the hash of `artifacts`'
    /// runtime code for this platform's [`circuit`](Self::circuit): what
    /// `initialize` takes beside a Honk verifier.
    ///
    /// [`Error::WrongCircuit`] when the address holds another circuit's
    /// verifier, or code that is no vendored verifier at all — which the
    /// contract refuses too, since X's and GitHub's circuits share one
    /// public-input layout. [`Error::Rpc`] when it holds no code.
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

    /// The code hash at `address`, required to be the `circuitCodehash()`
    /// the Platform Verifier at `proxy` pins: what `setTrustRoots` takes
    /// beside a Honk verifier on a deployed proxy, including one upgraded
    /// to a circuit release these `artifacts` predate. `artifacts` only name
    /// the circuit found in an [`Error::WrongCircuit`].
    pub async fn rotation_codehash_at<P: Provider>(
        self,
        provider: &P,
        artifacts: &Artifacts,
        proxy: Address,
        address: Address,
    ) -> Result<B256> {
        let pinned = TlsNotaryPlatformVerifier::new(proxy, provider)
            .circuitCodehash()
            .call()
            .await
            .map_err(|e| Error::Rpc {
                detail: format!("failed to read circuitCodehash() at {proxy}: {e}"),
            })?;
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
            return Err(Error::WrongCircuit {
                contract: self.contract(),
                address,
                expected: self.circuit(),
                found: Circuit::with_runtime_codehash(artifacts, codehash)?,
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
    /// The bb-generated UltraHonk verifier for this platform's circuit. Its
    /// code hash is read off chain and pinned beside it.
    pub honk_verifier: Address,
}

/// What the Google Platform Verifier initializes with. No Notary Service:
/// the profile notarizes nothing, and the base refuses one.
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
    X(TlsNotaryRoots),
    GitHub(TlsNotaryRoots),
    Google(GoogleRoots),
}

/// A built `initialize` call, typed by shape. Feed
/// [`abi_encode`](Self::abi_encode) to an ERC1967 proxy as its init data —
/// through [`deploy_platform_verifier`], [`deploy_proxy`](crate::deploy::deploy_proxy),
/// or as part of the creation code a [factory](crate::factory) deploy takes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum InitializeCall {
    /// `XPlatformVerifier.initialize` or `GitHubPlatformVerifier.initialize`
    /// (one signature).
    TlsNotary(TlsNotaryPlatformVerifier::initializeCall),
    /// `GooglePlatformVerifier.initialize`.
    Google(GooglePlatformVerifier::initializeCall),
}

impl InitializeCall {
    /// The ABI-encoded call.
    pub fn abi_encode(&self) -> Vec<u8> {
        match self {
            Self::TlsNotary(call) => call.abi_encode(),
            Self::Google(call) => call.abi_encode(),
        }
    }

    /// The code hash the call pins.
    pub fn honk_verifier_codehash(&self) -> B256 {
        match self {
            Self::TlsNotary(call) => call.honkVerifierCodehash_,
            Self::Google(call) => call.honkVerifierCodehash_,
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

    /// The rules `initialize` enforces that need no chain: a nonzero owner,
    /// a nonzero Honk verifier, a Notary Service where the profile notarizes
    /// (the Google shape cannot carry one at all), and a nonzero root list
    /// for Google. The code hash is the one rule left to
    /// [`call`](Self::call).
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

    /// Build the `initialize` call: [`check`](Self::check), then read the
    /// code hash of the Honk verifier through `provider`, require it to be
    /// the hash of `artifacts`' runtime code for this platform's
    /// [`circuit`](PlatformVerifier::circuit), and pin it.
    ///
    /// Fails when the address holds no code — the contract would refuse the
    /// resulting hash, and a verifier that is not deployed yet is the
    /// mis-wiring the check exists to catch — and with
    /// [`Error::WrongCircuit`] when it holds another circuit's verifier, or
    /// code that is no vendored verifier at all. The contract refuses the
    /// same (`WrongCircuit`): X's and GitHub's circuits share one
    /// public-input layout, and the wrong one would key bindings under the
    /// other platform's tags.
    pub async fn call<P: Provider>(
        &self,
        provider: &P,
        artifacts: &Artifacts,
    ) -> Result<InitializeCall> {
        self.check()?;
        let contract = self.verifier().contract();
        let codehash = self
            .verifier()
            .circuit_codehash_at(provider, artifacts, self.honk_verifier())
            .await
            .map_err(|e| match e {
                Error::Rpc { .. } => Error::Initializer {
                    detail: format!("{contract}: honk verifier: {e}"),
                },
                other => other,
            })?;
        Ok(match self {
            Self::X(roots) | Self::GitHub(roots) => {
                InitializeCall::TlsNotary(TlsNotaryPlatformVerifier::initializeCall {
                    owner_: roots.owner,
                    notary_: roots.notary_service,
                    honkVerifier_: roots.honk_verifier,
                    honkVerifierCodehash_: codehash,
                })
            }
            Self::Google(roots) => {
                InitializeCall::Google(GooglePlatformVerifier::initializeCall {
                    owner_: roots.owner,
                    // A profile whose Attestation Count is zero must not
                    // reach a Notary Service (REQ-COMMON-05D); the base
                    // refuses one.
                    notary_: Address::ZERO,
                    honkVerifier_: roots.honk_verifier,
                    honkVerifierCodehash_: codehash,
                    jwtRoots_: roots.jwt_roots,
                })
            }
        })
    }
}

/// The code hash of the account at `address`, as `EXTCODEHASH` reports it
/// for an account with code: `keccak256` of its runtime bytecode. An
/// account without code is an error rather than `keccak256("")` or zero,
/// because `setTrustRoots` refuses both and a caller comparing against the
/// hash of nothing has nothing to pin.
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

/// Deploy the verifier's implementation from `artifacts` and put it behind
/// a fresh ERC1967 proxy initialized with `init` — the code hash read off
/// the chain and checked against the circuit's verifier in `artifacts`, the
/// rules checked first. Returns the proxy address, which is
/// the Platform Verifier a Proof Verifier registers with `setVerifier`.
///
/// `sender` opts into explicit nonce management (see
/// [`deploy_contract_from`](crate::deploy::deploy_contract_from)).
pub async fn deploy_platform_verifier<P: Provider>(
    provider: &P,
    artifacts: &Artifacts,
    init: &Initializer,
    sender: Option<Address>,
) -> Result<Address> {
    let contract = init.verifier().contract();
    match init.call(provider, artifacts).await? {
        InitializeCall::TlsNotary(call) => {
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

    /// Every circuit has a platform proving under it: a vendored verifier
    /// no platform pins would be dead weight in every consumer's binary.
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
