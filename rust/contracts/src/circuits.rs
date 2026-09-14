//! The ceremony circuits' UltraHonk verifiers: which circuit each platform
//! proves under, and a deploy that links the libraries a bb verifier needs.
//!
//! A Honk verifier is not written in this repository. bb derives it from a
//! circuit's verification key, `libid-circuits` runs bb and ships the
//! Solidity in its release tarballs, and `scripts/vendor-circuit-verifiers.sh`
//! downloads the pinned release — checked against digests committed in
//! `solidity/contracts/circuits/circuits.json` — formats it and writes it
//! under `solidity/contracts/circuits`, gitignored and vendored again before
//! every build. From there it is a contract like any other: `forge build`
//! compiles it and `scripts/vendor-artifacts.sh` embeds it, so a consumer
//! deploys it from [`Artifacts::embedded`] with no `bb`.
//!
//! bb emits `RelationsLib` and `ZKTranscriptLib` as external libraries, so a
//! verifier's creation code carries a placeholder per call site until each
//! library is deployed and its address linked in. bb writes a copy of both
//! into every verifier it generates, and forge links a verifier only
//! against the copies of its own file; the copies compile to the same
//! bytecode, and [`Libraries`] deploys each distinct bytecode once, at an
//! address derived from it, so every verifier links against the one
//! deployment. [`deploy_honk_verifiers`] does that for a set of circuits
//! and [`deploy_honk_verifier`] for one; either returns the address a
//! [`platform_verifier::Initializer`](crate::platform_verifier::Initializer)
//! pins — by address and by the code hash it reads off the chain, which
//! covers the library addresses linked into the verifier's code.

use std::collections::BTreeMap;

use alloy::{
    primitives::Address,
    providers::Provider,
};

use crate::{
    artifacts::Artifacts,
    deploy::{
        deploy_contract_from,
        Libraries,
    },
    error::{
        Error,
        Result,
    },
};

/// One ceremony circuit, and so one vendored Honk verifier.
///
/// Two, not three: `oidc-google` proves the Google ID Token, and
/// `bearer-link` ties a token exchange to an identity for X and GitHub
/// alike, because their statements are the same.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Circuit {
    /// The token-exchange circuit, shared by the `x/v1` and `github/v1`
    /// profiles.
    BearerLink,
    /// The Google OIDC circuit, for `google/v1`.
    OidcGoogle,
}

impl Circuit {
    /// Every circuit the launch platforms verify under.
    pub const ALL: [Self; 2] = [Self::BearerLink, Self::OidcGoogle];

    /// The circuit's directory in the `libid-circuits` release, which is
    /// also its tarball's name and its key in `circuits.json`.
    pub const fn name(self) -> &'static str {
        match self {
            Self::BearerLink => "bearer-link",
            Self::OidcGoogle => "oidc-google",
        }
    }

    /// The vendored contract, which is also its `.sol` file and its entry
    /// in [`COVERED`](crate::artifacts::COVERED). bb names every verifier
    /// `HonkVerifier`; `libid-circuits` renames each so two can share a
    /// project and one artifact path names one circuit.
    pub const fn contract(self) -> &'static str {
        match self {
            Self::BearerLink => "BearerLinkHonkVerifier",
            Self::OidcGoogle => "OidcGoogleHonkVerifier",
        }
    }
}

/// The external libraries every bb verifier links, vendored beside it under
/// its own `.sol` file (the shape `linkReferences` names them in). Which
/// verifiers share a deployment of one is decided by its bytecode at deploy
/// time, not here.
pub const LIBRARIES: [&str; 2] = ["RelationsLib", "ZKTranscriptLib"];

/// The `libid-circuits` release the vendored verifiers came from, read from
/// the pin `scripts/vendor-artifacts.sh` copies in as `circuits.json`.
///
/// A Honk verifier IS its verification key, so a consumer that names a
/// deployment after its artifact — a CREATE3 name, say — wants this in the
/// name: a new circuits release is a different contract and must land at a
/// different address rather than silently replace the old one.
///
/// Errors for an [`Artifacts::from_dir`] over a raw forge `out/`, which
/// carries no pin.
pub fn version(artifacts: &Artifacts) -> Result<String> {
    let pin: serde_json::Value = artifacts.read_json("circuits.json")?;
    pin["version"]
        .as_str()
        .map(str::to_owned)
        .ok_or_else(|| Error::Artifact {
            detail: "circuits.json has no version".into(),
        })
}

/// What [`deploy_honk_verifiers`] put on the chain.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct HonkVerifiers {
    /// Each circuit's verifier, its libraries linked.
    pub verifiers: BTreeMap<Circuit, Address>,
    /// The libraries they link: one deployment per distinct bytecode, and
    /// which address each verifier's file links against.
    pub libraries: Libraries,
}

/// Deploy the Honk verifiers of `circuits`, sharing every library whose
/// bytecode they have in common, and return their addresses.
///
/// The libraries first, through [`Libraries::deploy`]: one deployment per
/// distinct creation code, however many circuits carry a copy, and none for
/// a bytecode already at its address. Then each verifier, its placeholders
/// substituted with the addresses its own file resolves to; deploying the
/// placeholder would produce a contract that reverts on every proof. For
/// the two launch circuits that is two libraries and two verifiers — four
/// transactions on a bare chain, not six.
///
/// A library is shared by bytecode alone. Circuits whose libraries differ
/// get separate deployments, and no circuit is ever linked against bytes
/// it was not compiled against.
///
/// Each address is what a Platform Verifier initializer takes as
/// `honk_verifier`; the code hash it pins beside it is read off the chain by
/// [`Initializer::call`](crate::platform_verifier::Initializer::call), and
/// carries the library addresses linked in.
///
/// `sender` opts into explicit nonce management (see
/// [`deploy_contract_from`]).
pub async fn deploy_honk_verifiers<P: Provider>(
    provider: &P,
    artifacts: &Artifacts,
    circuits: &[Circuit],
    sender: Option<Address>,
) -> Result<HonkVerifiers> {
    let contracts: Vec<(&str, &str)> = circuits
        .iter()
        .map(|circuit| (circuit.contract(), circuit.contract()))
        .collect();
    let libraries = Libraries::deploy(provider, artifacts, &contracts, sender).await?;
    let mut verifiers = BTreeMap::new();
    for circuit in circuits {
        if verifiers.contains_key(circuit) {
            continue;
        }
        let contract = circuit.contract();
        let bytecode = libraries.link(artifacts, contract, contract)?;
        let address = deploy_contract_from(
            provider,
            bytecode,
            &format!("{contract} ({} circuit)", circuit.name()),
            sender,
        )
        .await?;
        verifiers.insert(*circuit, address);
    }
    Ok(HonkVerifiers {
        verifiers,
        libraries,
    })
}

/// Deploy `circuit`'s Honk verifier with its libraries linked, and return
/// its address: [`deploy_honk_verifiers`] over the one circuit.
///
/// Called alone it still shares: a library's address is a function of its
/// bytecode, so a copy another circuit's deploy already put on the chain is
/// found there and linked, not deployed again. Three transactions on a bare
/// chain, one when both libraries are in place.
///
/// `sender` opts into explicit nonce management (see
/// [`deploy_contract_from`]).
pub async fn deploy_honk_verifier<P: Provider>(
    provider: &P,
    artifacts: &Artifacts,
    circuit: Circuit,
    sender: Option<Address>,
) -> Result<Address> {
    let honk = deploy_honk_verifiers(provider, artifacts, &[circuit], sender).await?;
    honk.verifiers
        .get(&circuit)
        .copied()
        .ok_or_else(|| Error::Rpc {
            detail: format!("{} verifier deploy recorded no address", circuit.name()),
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::artifacts::COVERED;

    /// Every verifier and every library it links is one the crate vendors,
    /// under the verifier's own file — a library missing from the artifacts
    /// could only deploy with its placeholder left in.
    #[test]
    fn every_verifier_and_its_libraries_are_covered() {
        let artifacts = Artifacts::embedded();
        for circuit in Circuit::ALL {
            let contract = circuit.contract();
            assert!(
                COVERED.contains(&(contract, contract)),
                "{contract} is not in COVERED"
            );
            for library in LIBRARIES {
                assert!(
                    COVERED.contains(&(contract, library)),
                    "{contract}.sol:{library} is not in COVERED"
                );
            }

            // The artifact links exactly LIBRARIES, and nothing under another
            // file: a verifier that linked a library the list does not name
            // would deploy with a placeholder left in.
            let refs = artifacts.link_references(contract, contract).unwrap();
            let mut linked: Vec<(String, String)> = refs
                .iter()
                .flat_map(|(path, libs)| {
                    let stem = std::path::Path::new(path)
                        .file_stem()
                        .and_then(|s| s.to_str())
                        .unwrap_or_else(|| panic!("{contract}: bad library path {path}"))
                        .to_owned();
                    libs.as_object()
                        .into_iter()
                        .flatten()
                        .map(move |(name, _)| (stem.clone(), name.clone()))
                })
                .collect();
            linked.sort();
            let mut expected: Vec<(String, String)> = LIBRARIES
                .iter()
                .map(|lib| (contract.to_owned(), (*lib).to_owned()))
                .collect();
            expected.sort();
            assert_eq!(linked, expected, "{contract} links something else");
        }
    }

    /// The two circuits are distinct artifacts: a shared one would wire
    /// both platforms to one verification key.
    #[test]
    fn the_two_circuits_are_different_artifacts() {
        let artifacts = Artifacts::embedded();
        let [bearer, oidc] = Circuit::ALL;
        assert_ne!(bearer.contract(), oidc.contract());
        assert_ne!(
            artifacts
                .bytecode_hex(bearer.contract(), bearer.contract())
                .unwrap(),
            artifacts
                .bytecode_hex(oidc.contract(), oidc.contract())
                .unwrap()
        );
    }

    /// The enum and the pin name the same circuits under the same
    /// contracts; the pin is what the vendor script follows, the enum what
    /// a consumer deploys by.
    #[test]
    fn the_enum_matches_the_pin() {
        let artifacts = Artifacts::embedded();
        let pin: serde_json::Value = artifacts.read_json("circuits.json").unwrap();
        let circuits = pin["circuits"].as_object().expect("circuits object");
        assert_eq!(circuits.len(), Circuit::ALL.len());
        for circuit in Circuit::ALL {
            let entry = &circuits[circuit.name()];
            assert_eq!(entry["contract"].as_str(), Some(circuit.contract()));
            let digest = entry["sha256"].as_str().expect("sha256 string");
            assert_eq!(digest.len(), 64, "{}: not a sha256", circuit.name());
        }
        let version = version(&artifacts).unwrap();
        assert!(
            version.split('.').count() == 3,
            "circuits.json version '{version}' is not major.minor.patch"
        );
    }
}
