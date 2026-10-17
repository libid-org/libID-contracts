//! Access to the compiled forge artifacts the crate ships.
//!
//! The default source is [`Artifacts::embedded`]: the pruned artifact JSONs
//! vendored by `scripts/vendor-artifacts.sh` into `artifacts/` are compiled
//! into the binary, so deployment has zero filesystem dependencies at runtime.
//! [`Artifacts::from_dir`] reads the same `<File>.sol/<Name>.json` layout from
//! disk instead — it accepts a raw forge `out/` directory too, since the crate
//! only reads fields forge emits.

use std::{
    fs,
    path::PathBuf,
};

use alloy::{
    hex,
    primitives::Bytes,
};
use include_dir::{
    include_dir,
    Dir,
};
use serde::{
    de::DeserializeOwned,
    Deserialize,
};

use crate::error::{
    Error,
    Result,
};

/// The vendored artifacts, embedded at compile time.
static EMBEDDED: Dir<'static> = include_dir!("$CARGO_MANIFEST_DIR/artifacts");

/// Every deployable contract the crate covers, as `(file, contract)` — the
/// artifact lives at `<file>.sol/<contract>.json`. Keep in sync with
/// `scripts/vendor-artifacts.sh`.
pub const COVERED: &[(&str, &str)] = &[
    // ceremony
    ("NotaryService", "NotaryService"),
    ("CeremonyProofVerifier", "CeremonyProofVerifier"),
    ("ERC1967Proxy", "ERC1967Proxy"),
    ("GoogleJwtRoots", "GoogleJwtRoots"),
    // ceremony: the launch Platform Verifiers (one per profile)
    ("XPlatformVerifier", "XPlatformVerifier"),
    ("GitHubPlatformVerifier", "GitHubPlatformVerifier"),
    ("GooglePlatformVerifier", "GooglePlatformVerifier"),
    // circuits: the UltraHonk verifiers the Platform Verifiers pin, vendored
    // from the libid-circuits release
    ("BearerLinkHonkVerifier", "BearerLinkHonkVerifier"),
    ("OidcGoogleHonkVerifier", "OidcGoogleHonkVerifier"),
    // identity
    ("IdentityRegistry", "IdentityRegistry"),
    // ens (deployed once per network, not CREATE3-canonical)
    ("HandleResolver", "HandleResolver"),
    // escrow: value held against a handle nobody holds yet
    ("HandleEscrow", "HandleEscrow"),
    // factory
    ("LibidFactory", "LibidFactory"),
    ("WTIA9", "WTIA9"),
];

enum Source {
    Embedded,
    Dir(PathBuf),
}

/// A source of compiled contract artifacts.
pub struct Artifacts {
    source: Source,
}

impl Artifacts {
    /// The artifacts vendored into the crate. The default, filesystem-free
    /// path.
    pub const fn embedded() -> Self {
        Self {
            source: Source::Embedded,
        }
    }

    /// Artifacts read from a directory laid out as `<File>.sol/<Name>.json`
    /// (a forge `out/` directory qualifies).
    pub fn from_dir(dir: impl Into<PathBuf>) -> Self {
        Self {
            source: Source::Dir(dir.into()),
        }
    }

    /// The JSON document at `rel` inside the source: an artifact, or the
    /// `circuits.json` pin the vendor script copies in beside them.
    pub(crate) fn read<T: DeserializeOwned>(&self, rel: &str) -> Result<T> {
        let contents = match &self.source {
            Source::Embedded => EMBEDDED
                .get_file(rel)
                .and_then(|f| f.contents_utf8())
                .map(str::to_owned)
                .ok_or_else(|| Error::Artifact {
                    detail: format!("no embedded artifact {rel}"),
                })?,
            Source::Dir(dir) => {
                let path = dir.join(rel);
                fs::read_to_string(&path).map_err(|e| Error::Artifact {
                    detail: format!("failed to read artifact {}: {e}", path.display()),
                })?
            }
        };
        serde_json::from_str(&contents).map_err(|e| Error::Artifact {
            detail: format!("failed to parse artifact {rel}: {e}"),
        })
    }

    /// The artifact at `<file>.sol/<contract>.json`.
    fn artifact(&self, file: &str, contract: &str) -> Result<Artifact> {
        self.read(&format!("{file}.sol/{contract}.json"))
    }

    /// Creation bytecode of a contract whose `.sol` file name matches the
    /// contract name.
    pub fn bytecode(&self, contract: &str) -> Result<Bytes> {
        self.bytecode_named(contract, contract)
    }

    /// Creation bytecode where the source file and contract names differ
    /// (a bb-generated `Verifier.sol` holding `HonkVerifier`, say).
    pub fn bytecode_named(&self, file: &str, contract: &str) -> Result<Bytes> {
        self.code(file, contract, CodeKind::Creation)
    }

    /// Runtime bytecode where the source file and contract names differ.
    /// Matches deployed code only for contracts without immutables.
    pub(crate) fn deployed_bytecode_named(
        &self,
        file: &str,
        contract: &str,
    ) -> Result<Bytes> {
        self.code(file, contract, CodeKind::Runtime)
    }

    /// The `kind` code of `<file>.sol/<contract>.json`, decoded.
    fn code(&self, file: &str, contract: &str, kind: CodeKind) -> Result<Bytes> {
        let member = kind.member();
        let code =
            kind.of(self.artifact(file, contract)?)
                .ok_or_else(|| Error::Artifact {
                    detail: format!("no {member}.object in {file}.sol/{contract}.json"),
                })?;
        let bytes = hex::decode(code.hex()).map_err(|e| Error::Artifact {
            detail: format!("invalid {member} hex for {file}.sol:{contract}: {e}"),
        })?;
        Ok(Bytes::from(bytes))
    }
}

/// A forge artifact, read for the members the crate uses; a raw forge
/// artifact's other members are skipped.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Artifact {
    bytecode: Option<Code>,
    deployed_bytecode: Option<Code>,
}

/// An artifact's `bytecode` or `deployedBytecode` member.
#[derive(Deserialize)]
struct Code {
    /// Hex, with or without `0x`.
    object: String,
}

impl Code {
    /// The hex without `0x`.
    fn hex(&self) -> &str {
        self.object.strip_prefix("0x").unwrap_or(&self.object)
    }
}

/// Which code of an artifact: what a deploy sends, or what an account holds.
#[derive(Clone, Copy)]
enum CodeKind {
    Creation,
    Runtime,
}

impl CodeKind {
    /// The artifact member holding it.
    const fn member(self) -> &'static str {
        match self {
            Self::Creation => "bytecode",
            Self::Runtime => "deployedBytecode",
        }
    }

    /// This code of `artifact`, if it carries it.
    fn of(self, artifact: Artifact) -> Option<Code> {
        match self {
            Self::Creation => artifact.bytecode,
            Self::Runtime => artifact.deployed_bytecode,
        }
    }
}

impl Default for Artifacts {
    fn default() -> Self {
        Self::embedded()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every covered contract's creation bytecode decodes as it is embedded
    /// and is not empty: the crate links no libraries, so a contract that
    /// needed one would carry a placeholder here and fail to decode.
    #[test]
    fn every_covered_contract_has_deployable_bytecode() {
        let artifacts = Artifacts::embedded();
        for &(file, contract) in COVERED {
            let bytecode = artifacts
                .bytecode_named(file, contract)
                .unwrap_or_else(|e| panic!("{file}.sol:{contract}: {e}"));
            assert!(
                !bytecode.is_empty(),
                "{file}.sol:{contract} has empty bytecode"
            );
        }
    }
}
