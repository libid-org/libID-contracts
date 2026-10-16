//! The off-chain half of the identity keys: handle normalization, the id
//! rules and, with the `node` feature, the nodes a binding is stored under.
//!
//! `handle_vectors` is generated from the pinned libID-circuits release's
//! `platforms.json` and `handles.json`, vendored into `contracts/circuits/`,
//! by `scripts/regen-identity-handles.py`; every language runs its vectors.

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
    IdError,
    IdRules,
};
#[cfg(feature = "node")]
pub use node::{
    folded_handle_node,
    handle_node,
    id_node,
    tags_for,
};

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;
    use crate::handle_vectors as v;

    /// `(kind, message)` of each `new <class>(ERROR_…, '…')` in a TypeScript source.
    fn typescript(file: &str, class: &str) -> BTreeSet<(u8, String)> {
        let path = format!(
            "{}/../../ts/packages/contracts/src/identity/{file}",
            env!("CARGO_MANIFEST_DIR")
        );
        let source = std::fs::read_to_string(&path).expect(&path);
        let opening = format!("new {class}(");
        source
            .split(opening.as_str())
            .skip(1)
            .map(|call| {
                let (kind, rest) = call.split_once(',').expect("kind");
                let kind = match kind.trim() {
                    "ERROR_EMPTY" => v::ERROR_EMPTY,
                    "ERROR_TOOLONG" => v::ERROR_TOOLONG,
                    "ERROR_BADCHARACTER" => v::ERROR_BADCHARACTER,
                    "ERROR_BADSHAPE" => v::ERROR_BADSHAPE,
                    other => panic!("{file}: unknown kind {other}"),
                };
                (kind, rest.split('\'').nth(1).expect("message").to_owned())
            })
            .collect()
    }

    /// TypeScript's `HandleError` and `IdError` say what Rust's do, kind for kind.
    #[test]
    fn the_typescript_errors_say_the_same() {
        let handle = [
            HandleError::Empty,
            HandleError::TooLong,
            HandleError::BadCharacter,
        ];
        let id = [
            IdError::Empty,
            IdError::TooLong,
            IdError::BadCharacter,
            IdError::BadShape,
        ];
        let rust_handle: BTreeSet<_> =
            handle.iter().map(|e| (e.kind(), e.to_string())).collect();
        let rust_id: BTreeSet<_> = id.iter().map(|e| (e.kind(), e.to_string())).collect();
        assert_eq!(typescript("handle.ts", "HandleError"), rust_handle);
        assert_eq!(typescript("node.ts", "IdError"), rust_id);
    }
}
