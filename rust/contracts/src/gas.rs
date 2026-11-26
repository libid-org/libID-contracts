//! What a simulation of an `AUTHORIZED_MODE` batch with dummy signatures
//! leaves out, and the wallet's `CALL_OVERHEAD`, from `solidity/snapshots/wallet-verify.json`, which
//! `WalletVerifyGas.t.sol` measures and `scripts/vendor-artifacts.sh` vendors.

use serde::Deserialize;
use serde_with::{
    serde_as,
    DisplayFromStr,
};

use crate::error::{
    Error,
    Result,
};

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
#[serde_as]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
pub struct WalletGas {
    #[serde(rename = "verify(ECDSA)")]
    #[serde_as(as = "DisplayFromStr")]
    ecdsa: u64,
    #[serde(rename = "verify(WebAuthn)")]
    #[serde_as(as = "DisplayFromStr")]
    web_authn: u64,
    #[serde(rename = "verify(P-256)")]
    #[serde_as(as = "DisplayFromStr")]
    p256: u64,
    #[serde(rename = "verify(tail)")]
    #[serde_as(as = "DisplayFromStr")]
    tail: u64,
    #[serde(rename = "rules(refund)")]
    #[serde_as(as = "DisplayFromStr")]
    rules_refund: u64,
    #[serde(rename = "rules(per call)")]
    #[serde_as(as = "DisplayFromStr")]
    rules_per_call: u64,
    #[serde(rename = "CALL_OVERHEAD")]
    #[serde_as(as = "DisplayFromStr")]
    call_overhead: u64,
}

impl WalletGas {
    /// The snapshot this crate was built with.
    pub fn vendored() -> Self {
        Self::from_json(VENDORED)
            .expect("the vendored snapshot parses, as a unit test checks")
    }

    /// A `wallet-verify.json` snapshot; every entry is required.
    pub fn from_json(json: &str) -> Result<Self> {
        serde_json::from_str(json).map_err(|e| Error::Artifact {
            detail: format!("wallet-verify.json: {e}"),
        })
    }

    /// One more valid signature by a key of `kind`, its verifier cold:
    /// its iteration of `_verify`'s signature loop.
    pub fn verify(&self, kind: KeyKind) -> u64 {
        match kind {
            KeyKind::Ecdsa => self.ecdsa,
            KeyKind::WebAuthn => self.web_authn,
            KeyKind::P256 => self.p256,
        }
    }

    /// The run after a valid `_verify`, at quorum, less a dummy run's after a
    /// failing signature: from the last `_signedBy`'s return to `execute`'s,
    /// less from it to the `ExecutionNotSigned` revert.
    pub fn verify_tail(&self) -> u64 {
        self.tail
    }

    /// The rules check of a batch of `n_calls` below quorum, as measured: a
    /// native refund's first spend, and for each further call a 68-byte
    /// ERC-20 `transfer`'s first spend with its depth-4 scope proof.
    pub fn rules(&self, n_calls: u64) -> u64 {
        let more = self
            .rules_per_call
            .saturating_mul(n_calls.saturating_sub(1));
        self.rules_refund.saturating_add(more)
    }

    /// `CALL_OVERHEAD` of `wallet/IWebWallet.sol`: the gas the wallet requires
    /// beyond call `i`'s signed `callGas[i]` before it. A transaction gives
    /// call `i` its floor when its gas is at least
    /// `before × (64/63)^(d−1) + (callGas[i] + call_overhead) × (64/63)^d`:
    /// `before` the gas of a run of the calls before `i`, `d` the frames to the
    /// wallet's check, 2 for `execute`, 4 for `createAndExecute`.
    pub fn call_overhead(&self) -> u64 {
        self.call_overhead
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_vendored_snapshot_parses_and_a_renamed_entry_is_refused() {
        WalletGas::vendored();
        for name in [
            "verify(ECDSA)",
            "verify(WebAuthn)",
            "verify(P-256)",
            "verify(tail)",
            "rules(refund)",
            "rules(per call)",
            "CALL_OVERHEAD",
        ] {
            let renamed = VENDORED.replace(&format!("\"{name}\""), "\"renamed\"");
            assert_ne!(renamed, VENDORED);
            assert!(WalletGas::from_json(&renamed).is_err(), "{name}");
        }
        let hex = VENDORED.replace("\"CALL_OVERHEAD\": \"", "\"CALL_OVERHEAD\": \"0x");
        assert_ne!(hex, VENDORED);
        assert!(WalletGas::from_json(&hex).is_err());
    }

    /// Each accessor reads its own row.
    #[test]
    fn each_accessor_reads_its_row() {
        let rows = [
            "verify(ECDSA)",
            "verify(WebAuthn)",
            "verify(P-256)",
            "verify(tail)",
            "rules(refund)",
            "rules(per call)",
            "CALL_OVERHEAD",
        ];
        let snapshot: std::collections::BTreeMap<_, _> = rows
            .iter()
            .zip(1u64..)
            .map(|(row, gas)| (*row, gas.to_string()))
            .collect();
        let gas =
            WalletGas::from_json(&serde_json::to_string(&snapshot).unwrap()).unwrap();
        let read = [
            gas.verify(KeyKind::Ecdsa),
            gas.verify(KeyKind::WebAuthn),
            gas.verify(KeyKind::P256),
            gas.verify_tail(),
            gas.rules(1),
            gas.rules(2) - gas.rules(1),
            gas.call_overhead(),
        ];
        assert_eq!(read, [1, 2, 3, 4, 5, 6, 7]);
    }

    /// By hand: 100 + 11 (n - 1), never below 1 call's, saturating.
    #[test]
    fn rules_adds_each_further_call_and_saturates() {
        let gas = WalletGas {
            rules_refund: 100,
            rules_per_call: 11,
            ..WalletGas::vendored()
        };
        assert_eq!(
            [0, 1, 2, 3, 4].map(|n| gas.rules(n)),
            [100, 100, 111, 122, 133]
        );
        assert_eq!(gas.rules(u64::MAX), u64::MAX);
    }
}
