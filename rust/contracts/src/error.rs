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
    /// A Platform Verifier initializer the contract would refuse, caught
    /// before any transaction is sent.
    #[error("initializer error: {detail}")]
    Initializer {
        /// Which rule, and which contract.
        detail: String,
    },
    /// A Platform Verifier initializer pins a Honk verifier that is not its
    /// platform's circuit (the contract's `WrongCircuit`, caught off chain).
    #[error(
        "initializer error: {contract}: the Honk verifier at {address} (code hash {codehash}) \
         is {}, not the {} circuit's",
        .found.map_or("no vendored circuit's verifier", |c| c.name()),
        .expected.name()
    )]
    WrongCircuit {
        /// The Platform Verifier being initialized.
        contract: &'static str,
        /// The address it was handed.
        address: alloy::primitives::Address,
        /// The circuit its platform proves under.
        expected: crate::circuits::Circuit,
        /// The circuit whose verifier is at `address`, if any.
        found: Option<crate::circuits::Circuit>,
        /// The code hash at `address`.
        codehash: alloy::primitives::B256,
    },
}

/// Crate result alias.
pub type Result<T> = std::result::Result<T, Error>;
