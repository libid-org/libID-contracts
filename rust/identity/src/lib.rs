//! The off-chain half of the identity keys: handle normalization, the id
//! rules and, with the `node` feature, the nodes a binding is stored under.
//!
//! `handle` and `id` are hand written and mirror the circuits' `lib/identity`
//! and `contracts/identity/HandleNormalizer.sol` byte for byte; `handle_vectors` is generated from
//! `contracts/identity/handles.json` by `scripts/regen-identity-handles.py`.
//! Solidity, Rust and TypeScript each run the same vector table, so a
//! difference between the languages fails a test instead of writing a node
//! the chain never wrote.

#![deny(warnings)]
#![deny(missing_docs)]

pub mod handle;
pub mod id;
#[cfg(feature = "node")]
pub mod node;

#[rustfmt::skip]
pub mod handle_vectors;

pub use handle::{
    normalize,
    rules_for,
    HandleError,
    Rules,
};
pub use id::{
    check_id,
    id_rules_for,
    IdRules,
};
#[cfg(feature = "node")]
pub use node::{
    handle_node,
    id_node,
    tags_for,
};
