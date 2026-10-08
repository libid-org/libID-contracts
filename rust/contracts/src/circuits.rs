//! The ceremony circuits' UltraHonk verifiers: which circuit each platform
//! proves under, and the deploy of a circuit's verifier.
//!
//! A Honk verifier is not written in this repository. bb derives it from a
//! circuit's verification key, `libid-circuits` runs bb and ships the
//! Solidity in its release tarballs, and `scripts/vendor-circuit-verifiers.sh`
//! downloads the pinned release — checked against digests committed in
//! `solidity/contracts/circuits/circuits.json` — formats it and writes it
//! under `solidity/contracts/circuits`, gitignored and vendored again before
//! every build. From there `forge build` compiles it, on the legacy
//! pipeline `solidity/foundry.toml` sets for these files, and
//! `scripts/vendor-artifacts.sh` embeds it, so a consumer deploys it from
//! [`Artifacts::embedded`] with no `bb`.
//!
//! The verifier is bb's optimized template: one contract, deployed in one
//! transaction by [`deploy_honk_verifier`]. Its address is what a
//! [`platform_verifier::Initializer`](crate::platform_verifier::Initializer)
//! pins, beside the code hash it reads off the chain.

use alloy::{
    primitives::{
        keccak256,
        Address,
        B256,
    },
    providers::Provider,
};

use crate::{
    artifacts::Artifacts,
    deploy::deploy_contract_from,
    error::{
        Error,
        Result,
    },
};

/// One ceremony circuit, and so one vendored Honk verifier.
///
/// One per platform: each circuit carries its platform's handle rules and
/// node tags, so an X proof cannot key a GitHub binding.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Circuit {
    /// X's token exchange, identity read and account keys, for `x/v1`.
    BearerLinkX,
    /// GitHub's, for `github/v1`.
    BearerLinkGithub,
    /// The Google OIDC circuit, for `google/v1`.
    OidcGoogle,
}

impl Circuit {
    /// Every circuit the launch platforms verify under.
    pub const ALL: [Self; 3] =
        [Self::BearerLinkX, Self::BearerLinkGithub, Self::OidcGoogle];

    /// The circuit's directory in the `libid-circuits` release, which is
    /// also its tarball's name and its key in `circuits.json`.
    pub const fn name(self) -> &'static str {
        match self {
            Self::BearerLinkX => "bearer-link-x",
            Self::BearerLinkGithub => "bearer-link-github",
            Self::OidcGoogle => "oidc-google",
        }
    }

    /// The vendored contract, which is also its `.sol` file and its entry
    /// in [`COVERED`](crate::artifacts::COVERED). bb names every verifier
    /// `HonkVerifier`; `libid-circuits` renames each so two can share a
    /// project and one artifact path names one circuit.
    pub const fn contract(self) -> &'static str {
        match self {
            Self::BearerLinkX => "BearerLinkXHonkVerifier",
            Self::BearerLinkGithub => "BearerLinkGithubHonkVerifier",
            Self::OidcGoogle => "OidcGoogleHonkVerifier",
        }
    }
}

impl Circuit {
    /// The code hash a deployed copy of this circuit's verifier has:
    /// `keccak256` of the vendored runtime code, which is what `EXTCODEHASH`
    /// reports at its address. bb's verifier has no immutables, so every
    /// copy deployed from the vendored creation code holds exactly these
    /// bytes.
    pub fn runtime_codehash(self, artifacts: &Artifacts) -> Result<B256> {
        Ok(keccak256(artifacts.deployed_bytecode_named(
            self.contract(),
            self.contract(),
        )?))
    }

    /// The circuit whose vendored verifier has this code hash, if any.
    pub fn with_runtime_codehash(
        artifacts: &Artifacts,
        codehash: B256,
    ) -> Result<Option<Self>> {
        for circuit in Self::ALL {
            if circuit.runtime_codehash(artifacts)? == codehash {
                return Ok(Some(circuit));
            }
        }
        Ok(None)
    }
}

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

/// Deploy `circuit`'s Honk verifier and return its address, which a
/// Platform Verifier initializer takes as `honk_verifier`.
///
/// `sender` opts into explicit nonce management (see
/// [`deploy_contract_from`]).
pub async fn deploy_honk_verifier<P: Provider>(
    provider: &P,
    artifacts: &Artifacts,
    circuit: Circuit,
    sender: Option<Address>,
) -> Result<Address> {
    deploy_contract_from(
        provider,
        artifacts.bytecode(circuit.contract())?,
        &format!("{} ({} circuit)", circuit.contract(), circuit.name()),
        sender,
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::artifacts::COVERED;

    /// Every circuit's verifier is one the crate vendors.
    #[test]
    fn every_verifier_is_covered() {
        for circuit in Circuit::ALL {
            let contract = circuit.contract();
            assert!(
                COVERED.contains(&(contract, contract)),
                "{contract} is not in COVERED"
            );
        }
    }

    /// The circuits are distinct artifacts: a shared one would wire two
    /// platforms to one verification key, and one platform's proof would key
    /// the other's bindings.
    #[test]
    fn the_circuits_are_different_artifacts() {
        let artifacts = Artifacts::embedded();
        for (i, a) in Circuit::ALL.iter().enumerate() {
            for b in &Circuit::ALL[i + 1..] {
                assert_ne!(a.contract(), b.contract());
                assert_ne!(
                    artifacts.bytecode_hex(a.contract(), a.contract()).unwrap(),
                    artifacts.bytecode_hex(b.contract(), b.contract()).unwrap(),
                    "{a:?} and {b:?}"
                );
            }
        }
    }

    /// Each circuit's runtime code hash names it back, and no other.
    #[test]
    fn a_runtime_codehash_names_its_circuit() {
        let artifacts = Artifacts::embedded();
        for circuit in Circuit::ALL {
            let codehash = circuit.runtime_codehash(&artifacts).unwrap();
            assert_eq!(
                Circuit::with_runtime_codehash(&artifacts, codehash).unwrap(),
                Some(circuit)
            );
        }
        assert_eq!(
            Circuit::with_runtime_codehash(&artifacts, B256::ZERO).unwrap(),
            None
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
