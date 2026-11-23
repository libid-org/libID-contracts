//! What a simulation of an `AUTHORIZED_MODE` batch with dummy signatures
//! leaves out, from `solidity/snapshots/wallet-verify.json`, which
//! `WalletVerifyGas.t.sol` measures and `scripts/vendor-artifacts.sh` vendors.

use std::collections::HashMap;

use crate::error::{
    Error,
    Result,
};

/// `CALL_OVERHEAD` of `wallet/IWebWallet.sol`: the gas the wallet requires
/// beyond `callGas` before each call of a batch.
pub const CALL_OVERHEAD: u64 = 20_000;

/// The snapshot, vendored into the crate.
const VENDORED: &str = include_str!("../artifacts/wallet-verify.json");

/// A session key's kind, which decides what checking its signature costs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyKind {
    /// A 20-byte key, recovered with ECDSA.
    Ecdsa,
    /// A passkey behind OpenZeppelin's `ERC7913WebAuthnVerifier`.
    WebAuthn,
    /// A P-256 key behind OpenZeppelin's `ERC7913P256Verifier`, under
    /// EIP-7951's precompile.
    P256,
}

/// The snapshot's entries.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WalletGas {
    ecdsa: u64,
    web_authn: u64,
    p256: u64,
    rules_refund: u64,
    rules_per_call: u64,
}

impl WalletGas {
    /// The snapshot this crate was built with.
    pub fn vendored() -> Self {
        Self::from_json(VENDORED).expect("the vendored wallet-verify.json")
    }

    /// A `wallet-verify.json` snapshot; every entry is required.
    pub fn from_json(json: &str) -> Result<Self> {
        let entries: HashMap<String, String> =
            serde_json::from_str(json).map_err(|e| Error::Artifact {
                detail: format!("wallet-verify.json: {e}"),
            })?;
        let entry = |name: &str| {
            entries
                .get(name)
                .and_then(|gas| gas.parse().ok())
                .ok_or_else(|| Error::Artifact {
                    detail: format!("wallet-verify.json has no gas for `{name}`"),
                })
        };
        Ok(Self {
            ecdsa: entry("verify(ECDSA)")?,
            web_authn: entry("verify(WebAuthn)")?,
            p256: entry("verify(P-256)")?,
            rules_refund: entry("rules(refund)")?,
            rules_per_call: entry("rules(per call)")?,
        })
    }

    /// One valid signature's check by a key of `kind`.
    pub fn verify(&self, kind: KeyKind) -> u64 {
        match kind {
            KeyKind::Ecdsa => self.ecdsa,
            KeyKind::WebAuthn => self.web_authn,
            KeyKind::P256 => self.p256,
        }
    }

    /// The rules check of a batch of `n_calls` below quorum in its costly
    /// case: a native refund's first spend, and an ERC-20 `transfer`'s first
    /// spend with its depth-2 proof for each further call.
    pub fn rules(&self, n_calls: u64) -> u64 {
        let more = self
            .rules_per_call
            .saturating_mul(n_calls.saturating_sub(1));
        self.rules_refund.saturating_add(more)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn call_overhead_is_the_wallets() {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../solidity/contracts/wallet/IWebWallet.sol"
        );
        let source = std::fs::read_to_string(path).expect(path);
        let declared = source
            .split_once("uint256 constant CALL_OVERHEAD = ")
            .and_then(|(_, rest)| rest.split_once(';'))
            .map(|(value, _)| value.replace('_', ""))
            .expect("IWebWallet.sol declares CALL_OVERHEAD");
        assert_eq!(declared.parse::<u64>().unwrap(), CALL_OVERHEAD);
    }
}
