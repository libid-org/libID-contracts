//! Turns a typed handle into the form the identity circuits hash into a node.
//!
//! A-Z fold to a-z. The handle must be one JSON string as a platform sends
//! it: printable ASCII without `"` or `\\`, and no longer than the circuit's
//! buffer. Its format is the platform's. It mirrors the circuits'
//! `lib/identity`; both run the `handles.json` vector table.

/// Why a handle was refused. The kinds match the TypeScript ones and the
/// circuits' messages, because the vector table names which refusal it expects.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandleError {
    /// No bytes at all.
    Empty,
    /// More bytes than the circuit's buffer holds.
    TooLong,
    /// A byte outside printable ASCII, or a quote or backslash.
    BadCharacter,
}

impl HandleError {
    /// The index the vector table uses for this kind.
    pub const fn kind(self) -> u8 {
        match self {
            Self::Empty => super::handle_vectors::ERROR_EMPTY,
            Self::TooLong => super::handle_vectors::ERROR_TOOLONG,
            Self::BadCharacter => super::handle_vectors::ERROR_BADCHARACTER,
        }
    }
}

impl std::fmt::Display for HandleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Empty => "the handle is empty",
            Self::TooLong => "the handle is too long for this platform",
            Self::BadCharacter => {
                "the handle has a byte outside printable ASCII, or a quote or backslash"
            }
        })
    }
}

impl std::error::Error for HandleError {}

/// What one platform's circuit takes, generated from its profile's `keys`.
#[derive(Debug, Clone, Copy)]
pub struct Rules {
    /// Bytes the circuit's buffer holds.
    pub max_length: usize,
}

use super::handle_vectors as v;

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
    use crate::handle_vectors::VECTORS;

    /// The shared table, run against this normalizer. TypeScript and the
    /// circuits run the same cases, so a language that disagrees fails here.
    #[test]
    fn every_vector_matches_the_shared_table() {
        for (i, v) in VECTORS.iter().enumerate() {
            let rules = rules_for(v.platform)
                .unwrap_or_else(|| panic!("vector {i}: unknown platform {}", v.platform));
            match normalize(v.input, rules) {
                Ok(got) => {
                    assert!(v.accepted, "vector {i}: expected a refusal, got {got:?}");
                    assert_eq!(got, v.output, "vector {i}: wrong normalized handle");
                }
                Err(e) => {
                    assert!(
                        !v.accepted,
                        "vector {i}: expected {:?}, got {e:?}",
                        v.output
                    );
                    assert_eq!(
                        e.kind(),
                        v.error_kind,
                        "vector {i}: refused for the wrong reason ({e:?})"
                    );
                }
            }
        }
    }

    /// The generated constants carry the SHA-256 of `handles.json`.
    #[test]
    fn the_generated_constants_come_from_this_table() {
        use sha2::Digest as _;
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../solidity/contracts/handles/handles.json"
        );
        let table = std::fs::read(path).expect("handles.json beside the crate");
        let digest: String = sha2::Sha256::digest(&table)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        assert_eq!(
            digest,
            crate::handle_vectors::TABLE_SHA256,
            "handle_vectors.rs is stale: run scripts/regen-identity-handles.py"
        );
    }

    /// The table must keep covering both outcomes. A regeneration that dropped
    /// every refusal would leave the test green and prove nothing.
    #[test]
    fn the_table_covers_both_outcomes() {
        let accepted = VECTORS.iter().filter(|v| v.accepted).count();
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
