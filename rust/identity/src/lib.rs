//! The off-chain half of the identity keys: handle normalization, the id
//! rules and, with the `node` feature, the nodes a binding is stored under.
//!
//! `platforms` (the platform table and the refusals) and, for tests and the
//! `test-helpers` feature, `vectors` are generated from the pinned
//! libID-circuits release's `platforms.json` and `handles.json`, vendored into
//! `contracts/circuits/`, by `scripts/regen-identity-handles.py`; every
//! language runs the vectors.

#![deny(warnings)]
#![deny(missing_docs)]

pub mod handle;
pub mod id;
#[cfg(feature = "node")]
pub mod node;

#[rustfmt::skip]
pub mod platforms;
#[cfg(any(test, feature = "test-helpers"))]
#[rustfmt::skip]
pub mod vectors;

/// The README's examples, run as doctests (the node one needs the feature).
#[cfg(all(doctest, feature = "node"))]
#[doc = include_str!("../README.md")]
struct ReadmeDoctests;

pub use handle::{
    normalize,
    rules_for,
    Rules,
};
pub use id::{
    check_id,
    IdRules,
};
pub use platforms::{
    HandleError,
    IdError,
};
