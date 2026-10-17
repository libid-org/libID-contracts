//! The libid identity keys off chain: handle normalization, the id rules
//! and, with the `node` feature, the nodes a binding is stored under.
//!
//! `scripts/regen-identity-handles.py` generates `platforms` and `vectors`
//! from the pinned libID-circuits release's `platforms.json` and
//! `handles.json`. The README covers the rules and examples.

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

/// The README's examples, run as doctests; they need the `node` feature.
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
