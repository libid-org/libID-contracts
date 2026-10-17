//! What a platform's user id must be before it is hashed into a node: one
//! JSON token as sent, digits for a number, otherwise a string's bytes.
//!
//! Ids are never normalized; these checks mirror the circuits' `check_id`
//! and run the same `idVectors` table.

use std::{
    error::Error,
    fmt,
};

use super::handle_vectors as v;

/// Why no circuit would hash an id. The kinds are the handle table's.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdError {
    /// No bytes at all.
    Empty,
    /// More bytes than the platform allows.
    TooLong,
    /// A byte the platform does not allow.
    BadCharacter,
}

impl IdError {
    /// The index the vector table uses for this kind.
    pub const fn kind(self) -> u8 {
        match self {
            Self::Empty => v::ERROR_EMPTY,
            Self::TooLong => v::ERROR_TOOLONG,
            Self::BadCharacter => v::ERROR_BADCHARACTER,
        }
    }
}

impl fmt::Display for IdError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Empty => "the id is empty",
            Self::TooLong => "the id is too long for this platform",
            Self::BadCharacter => "the id has a byte this platform does not allow",
        })
    }
}

impl Error for IdError {}

/// What a platform allows in an id.
#[derive(Debug, Clone, Copy)]
pub struct IdRules {
    /// Bytes the circuit's buffer holds.
    pub max_length: usize,
    /// ASCII digits; otherwise printable ASCII without `"` or `\`.
    pub decimal: bool,
}

impl IdRules {
    /// X: decimal strings.
    pub const X: Self = v::PLATFORM_X.id_rules;
    /// GitHub: JSON integers.
    pub const GITHUB: Self = v::PLATFORM_GITHUB.id_rules;
    /// Google: the OIDC `sub`.
    pub const GOOGLE: Self = v::PLATFORM_GOOGLE.id_rules;
}

/// Accept an id exactly as given, or say why no circuit would hash it.
pub fn check_id(id: &str, rules: IdRules) -> Result<(), IdError> {
    let bytes = id.as_bytes();
    if bytes.is_empty() {
        return Err(IdError::Empty);
    }
    if bytes.len() > rules.max_length {
        return Err(IdError::TooLong);
    }
    let allowed = |b: u8| {
        if rules.decimal {
            b.is_ascii_digit()
        } else {
            crate::handle::is_string_byte(b)
        }
    };
    if !bytes.iter().all(|&b| allowed(b)) {
        return Err(IdError::BadCharacter);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::handle_vectors::ID_VECTORS;

    /// TypeScript's `checkId` words its refusals the same way.
    #[test]
    fn an_id_refusal_names_the_id() {
        let refused = |id| check_id(id, IdRules::GITHUB).unwrap_err().to_string();
        assert_eq!(refused(""), "the id is empty");
        assert_eq!(
            refused("12a"),
            "the id has a byte this platform does not allow"
        );
    }

    #[test]
    fn every_id_vector_matches_the_shared_table() {
        for (i, v) in ID_VECTORS.iter().enumerate() {
            let rules = v::platform(v.platform).expect("known platform").id_rules;
            match check_id(v.input, rules) {
                Ok(()) => assert!(v.accepted, "id vector {i}: expected a refusal"),
                Err(e) => {
                    assert!(!v.accepted, "id vector {i}: refused ({e:?})");
                    assert_eq!(e.kind(), v.error_kind, "id vector {i}: wrong reason");
                }
            }
        }
    }
}
