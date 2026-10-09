//! The off-chain half of the identity keys: handle normalization, the id
//! rules and, with the `node` feature, the nodes a binding is stored under.
//!
//! `handle_vectors` is generated from `contracts/handles/handles.json` by
//! `scripts/regen-identity-handles.py`; every language runs its vectors.

#![deny(warnings)]
#![deny(missing_docs)]

pub mod handle;
pub mod id;
#[cfg(feature = "node")]
pub mod node;

#[rustfmt::skip]
pub mod handle_vectors;

/// The README's examples, run as doctests (the node one needs the feature).
#[cfg(all(doctest, feature = "node"))]
#[doc = include_str!("../README.md")]
struct ReadmeDoctests;

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
