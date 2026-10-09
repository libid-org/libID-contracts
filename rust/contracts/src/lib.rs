//! Typed bindings, embedded forge artifacts, and deploy/upgrade helpers for
//! the libid identity stack.
//!
//! The crate has four layers:
//!
//! - [`bindings`] — hand-written `alloy::sol!` interfaces for every contract a
//!   consumer talks to: the ceremony verification path (`NotaryService`,
//!   `CeremonyProofVerifier`, the three launch Platform Verifiers it routes
//!   to, and `GoogleJwtRoots`, the Google signing keys the `google/v1`
//!   verifier trusts), the identity registry (`IdentityRegistry`), the
//!   deterministic factory, and the UltraHonk verifiers the Platform
//!   Verifiers pin. Kept in lockstep with the Solidity sources in
//!   `solidity/contracts`.
//! - [`artifacts`] — the compiled creation bytecode and method identifiers
//!   of every deployable contract, embedded at compile time
//!   ([`Artifacts::embedded`]) so deployment needs no filesystem at runtime. A
//!   directory-backed variant ([`Artifacts::from_dir`]) reads a forge `out/`
//!   tree instead.
//! - [`deploy`] — generic deploy and upgrade primitives over any alloy
//!   [`Provider`](alloy::providers::Provider): plain deploys, constructor
//!   args, ERC1967 proxies, and UUPS upgrades.
//! - [`factory`] — the deterministic-factory bootstrap: predict the canonical
//!   cross-network factory address, install it (and the keyless CREATE2
//!   deployer it hangs off) where missing, and deploy protocol proxies
//!   through it at name-derived CREATE3 addresses.
//! - [`platform_verifier`] — the Platform Verifier initializer, checked
//!   against its platform's circuit and `PlatformVerifierBase`'s rules.
//! - [`bind_error`] — a refused `bind`, decoded by name.
//! - [`circuits`] — the ceremony circuits' UltraHonk verifiers, vendored
//!   from the pinned `libid-circuits` release: which circuit a platform
//!   proves under, and the deploy of its verifier.
//!
//! Signing is the consumer's concern: every helper takes a provider you have
//! already wired with a wallet.

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
