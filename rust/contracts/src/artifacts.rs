//! Access to the compiled forge artifacts the crate ships.
//!
//! The default source is [`Artifacts::embedded`]: the pruned artifact JSONs
//! vendored by `scripts/vendor-artifacts.sh` into `artifacts/` are compiled
//! into the binary, so deployment has zero filesystem dependencies at runtime.
//! [`Artifacts::from_dir`] reads the same `<File>.sol/<Name>.json` layout from
//! disk instead — it accepts a raw forge `out/` directory too, since the crate
//! only reads fields forge emits.

use std::{
    collections::BTreeMap,
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
    ("BearerLinkXHonkVerifier", "BearerLinkXHonkVerifier"),
    (
        "BearerLinkGithubHonkVerifier",
        "BearerLinkGithubHonkVerifier",
    ),
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

    /// The raw artifact JSON for `out/<file>.sol/<contract>.json`.
    pub fn raw(&self, file: &str, contract: &str) -> Result<serde_json::Value> {
        self.read_json(&format!("{file}.sol/{contract}.json"))
    }

    /// Any JSON file at `rel` inside the source: an artifact, or the
    /// `circuits.json` pin the vendor script copies in beside them.
    pub(crate) fn read_json(&self, rel: &str) -> Result<serde_json::Value> {
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
                std::fs::read_to_string(&path).map_err(|e| Error::Artifact {
                    detail: format!("failed to read artifact {}: {e}", path.display()),
                })?
            }
        };
        serde_json::from_str(&contents).map_err(|e| Error::Artifact {
            detail: format!("failed to parse artifact {rel}: {e}"),
        })
    }

    /// Creation bytecode of a contract whose `.sol` file name matches the
    /// contract name.
    pub fn bytecode(&self, contract: &str) -> Result<Bytes> {
        self.bytecode_named(contract, contract)
    }

    /// Creation bytecode where the source file and contract names differ
    /// (a bb-generated `Verifier.sol` holding `HonkVerifier`, say).
    pub fn bytecode_named(&self, file: &str, contract: &str) -> Result<Bytes> {
        let hex_str = self.bytecode_hex(file, contract)?;
        let bytes = hex::decode(&hex_str).map_err(|e| Error::Artifact {
            detail: format!("invalid bytecode hex for {file}.sol:{contract}: {e}"),
        })?;
        Ok(Bytes::from(bytes))
    }

    /// The artifact's `methodIdentifiers`: `"sig(args)" -> 4-byte selector`
    /// (8 hex chars, no `0x`).
    pub fn method_identifiers(&self, contract: &str) -> Result<BTreeMap<String, String>> {
        let json = self.raw(contract, contract)?;
        let methods =
            json["methodIdentifiers"]
                .as_object()
                .ok_or_else(|| Error::Artifact {
                    detail: format!(
                        "no methodIdentifiers in {contract}.sol/{contract}.json"
                    ),
                })?;
        methods
            .iter()
            .map(|(sig, value)| {
                let sel = value.as_str().ok_or_else(|| Error::Artifact {
                    detail: format!("non-string selector for {sig} in {contract}"),
                })?;
                Ok((sig.clone(), sel.to_owned()))
            })
            .collect()
    }

    /// Runtime bytecode where the source file and contract names differ.
    /// Matches deployed code only for contracts without immutables.
    pub fn deployed_bytecode_named(&self, file: &str, contract: &str) -> Result<Bytes> {
        let hex_str = self.object_hex(file, contract, "deployedBytecode")?;
        let bytes = hex::decode(&hex_str).map_err(|e| Error::Artifact {
            detail: format!(
                "invalid deployedBytecode hex for {file}.sol:{contract}: {e}"
            ),
        })?;
        Ok(Bytes::from(bytes))
    }

    /// The raw `bytecode.object` hex, without `0x`.
    pub(crate) fn bytecode_hex(&self, file: &str, contract: &str) -> Result<String> {
        self.object_hex(file, contract, "bytecode")
    }

    /// The raw `<field>.object` hex, without `0x`.
    fn object_hex(&self, file: &str, contract: &str, field: &str) -> Result<String> {
        let json = self.raw(file, contract)?;
        let raw = json[field]["object"]
            .as_str()
            .ok_or_else(|| Error::Artifact {
                detail: format!("no {field}.object in {file}.sol/{contract}.json"),
            })?;
        Ok(raw.strip_prefix("0x").unwrap_or(raw).to_owned())
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
