use alloy::primitives::{
    Address,
    B256,
};

use crate::circuits::Circuit;

/// Crate error type.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// A vendored artifact is missing, unparsable, or malformed.
    #[error("artifact error: {detail}")]
    Artifact {
        /// What went wrong.
        detail: String,
    },
    /// An RPC send, receipt wait, or read failed.
    #[error("rpc error: {detail}")]
    Rpc {
        /// What went wrong.
        detail: String,
    },
    /// ABI data that does not decode, or does not re-encode to itself.
    #[error("abi error: {detail}")]
    Abi {
        /// What went wrong.
        detail: String,
    },
    /// A transaction that was mined and reverted: it spent gas and changed
    /// nothing.
    #[error("reverted: {label} in transaction {tx_hash}")]
    Reverted {
        /// What was sent.
        label: String,
        /// The mined transaction.
        tx_hash: B256,
    },
    /// An upgrade the proxy did not take: after it, the proxy's EIP-1967
    /// implementation slot names another contract than the one deployed for
    /// it.
    #[error(
        "upgrade error: {contract}: the proxy at {proxy} runs {found} after its \
         upgrade, not the new implementation {wanted}"
    )]
    NotUpgraded {
        /// The contract upgraded.
        contract: String,
        /// The proxy upgraded.
        proxy: Address,
        /// The implementation deployed for it.
        wanted: Address,
        /// The implementation its slot names.
        found: Address,
    },
    /// A Platform Verifier initializer the contract would refuse, caught
    /// before any transaction is sent.
    #[error("initializer error: {detail}")]
    Initializer {
        /// Which rule, and which contract.
        detail: String,
    },
    /// A proxy that serves another platform than the one asked about.
    #[error(
        "platform error: the Platform Verifier at {proxy} serves platform {found}, \
         not {expected}; ask with the platform it serves"
    )]
    WrongPlatform {
        /// The proxy asked.
        proxy: Address,
        /// The platform id the caller named.
        expected: B256,
        /// The platform id the proxy answers.
        found: B256,
    },
    /// A Honk verifier whose code hash is not the one wanted: the platform's
    /// vendored circuit's for an initializer, the proxy's `circuitCodehash()`
    /// for a rotation. The off-chain form of the contract's `WrongCircuit`.
    #[error(
        "trust root error: {contract}: the Honk verifier at {address} (code hash {codehash}) \
         is {}; wanted code hash {expected_codehash}, {}",
        .found.map_or("no vendored circuit's verifier", |c| c.name()),
        .expected.map_or(
            "a circuit release not vendored here: vendor the circuits.json release that \
             built it, or upgrade the proxy",
            |c| c.name()
        )
    )]
    WrongCircuit {
        /// The Platform Verifier being initialized or rotated.
        contract: &'static str,
        /// The address it was handed.
        address: Address,
        /// The code hash wanted.
        expected_codehash: B256,
        /// The vendored circuit whose verifier has `expected_codehash`, if any.
        expected: Option<Circuit>,
        /// The circuit whose verifier is at `address`, if any.
        found: Option<Circuit>,
        /// The code hash at `address`.
        codehash: B256,
    },
}

impl Error {
    /// ABI data that does not decode.
    pub(crate) fn abi(e: alloy::sol_types::Error) -> Self {
        Self::Abi {
            detail: e.to_string(),
        }
    }
}

/// Crate result alias.
pub type Result<T> = std::result::Result<T, Error>;
