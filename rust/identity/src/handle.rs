//! Turns a typed handle into the form the identity circuits hash into a node.
//!
//! A-Z fold to a-z. The handle must be one JSON string as a platform sends
//! it: printable ASCII without `"` or `\\`, and no longer than the circuit's
//! buffer. Its format is the platform's. It mirrors the circuits'
//! `lib/identity`; both run the `handles.json` vector table.

use crate::platforms::{
    self as v,
    HandleError,
};

/// What one platform's circuit takes, generated from the circuits' `platforms.json`.
#[derive(Debug, Clone, Copy)]
pub struct Rules {
    /// Bytes the circuit's buffer holds.
    pub max_length: usize,
}

impl Rules {
    /// X.
    pub const X: Self = v::PLATFORM_X.rules;

    /// GitHub.
    pub const GITHUB: Self = v::PLATFORM_GITHUB.rules;

    /// Google: an address.
    pub const GOOGLE: Self = v::PLATFORM_GOOGLE.rules;
}

/// The rules for a platform key (`"x"`, `"github"`, ...) from the generated
/// table.
pub fn rules_for(platform_key: &str) -> Option<Rules> {
    v::platform(platform_key).map(|p| p.rules)
}

/// A byte of a JSON string as sent: printable ASCII, not `"` or `\\`.
pub(crate) fn is_string_byte(b: u8) -> bool {
    (0x20..=0x7e).contains(&b) && b != b'"' && b != b'\\'
}

/// The handle folded, or the reason it was refused.
pub fn normalize(raw: &str, rules: Rules) -> Result<String, HandleError> {
    let slice = raw.as_bytes();
    if slice.is_empty() {
        return Err(HandleError::Empty);
    }
    if slice.len() > rules.max_length {
        return Err(HandleError::TooLong);
    }
    if !slice.iter().all(|&b| is_string_byte(b)) {
        return Err(HandleError::BadCharacter);
    }
    // ASCII alone, so lowercasing folds A-Z and nothing else.
    Ok(raw.to_ascii_lowercase())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vectors::VECTORS;

    /// The shared table, run against this normalizer. TypeScript and the
    /// circuits run the same cases, so a language that disagrees fails here.
    #[test]
    fn every_vector_matches_the_shared_table() {
        for (i, v) in VECTORS.iter().enumerate() {
            let rules = rules_for(v.platform).expect("known platform");
            assert_eq!(
                normalize(v.input, rules),
                v.expected.map(|folded| folded.handle.to_owned()),
                "vector {i}: {:?}",
                v.input
            );
        }
    }

    /// The table must keep covering both outcomes. A regeneration that dropped
    /// every refusal would leave the test green and prove nothing.
    #[test]
    fn the_table_covers_both_outcomes() {
        let accepted = VECTORS.iter().filter(|v| v.expected.is_ok()).count();
        let refused = VECTORS.len() - accepted;
        assert!(accepted > 0, "the table accepts nothing");
        assert!(refused > 0, "the table refuses nothing");
    }

    /// Case folding is the only change to an accepted handle. Anything else
    /// could map the handles of two identities onto one node.
    #[test]
    fn folding_is_the_only_change() {
        assert_eq!(
            normalize("A.B+tag@Example.COM", Rules::GOOGLE).unwrap(),
            "a.b+tag@example.com"
        );
        assert_eq!(normalize("Alice_1", Rules::X).unwrap(), "alice_1");
        assert_eq!(
            normalize(" @Octo--Cat- ", Rules::GITHUB).unwrap(),
            " @octo--cat- "
        );
    }
}
