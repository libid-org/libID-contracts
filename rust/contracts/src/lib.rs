//! Typed bindings, embedded forge artifacts, and deploy/upgrade helpers for
//! the libid identity stack. Every helper takes a provider already wired with
//! a wallet.
//!
//! - [`bindings`] — hand-written `alloy::sol!` interfaces for every contract a
//!   consumer talks to, kept in lockstep with `solidity/contracts`.
//! - [`artifacts`] — creation bytecode and method identifiers of every
//!   deployable contract, embedded at compile time ([`Artifacts::embedded`])
//!   or read from a forge `out/` tree ([`Artifacts::from_dir`]).
//! - [`deploy`] — deploy and upgrade over any alloy
//!   [`Provider`](alloy::providers::Provider): plain deploys, constructor
//!   args, ERC1967 proxies and UUPS upgrades.
//! - [`factory`] — install the canonical cross-network factory and its
//!   keyless CREATE2 deployer where missing, and deploy protocol proxies
//!   through it at name-derived CREATE3 addresses.
//! - [`platform_verifier`] — the Platform Verifier initializer, checked
//!   against its platform's circuit and `PlatformVerifierBase`'s rules.
//! - [`bind_error`] — a refused `bind`, decoded by name.
//! - [`circuits`] — the ceremony circuits' vendored UltraHonk verifiers:
//!   which circuit a platform proves under, and the deploy of its verifier.

#![deny(dead_code)]
#![deny(missing_docs)]

pub mod artifacts;
pub mod bind_error;
pub mod bindings;
pub mod circuits;
pub mod deploy;
mod error;
pub mod factory;
pub mod platform_verifier;

pub use artifacts::Artifacts;
pub use bind_error::BindError;
pub use error::{
    Error,
    Result,
};
