//! The rules a platform's user id must meet before it is hashed into a node.
//!
//! Ids are never normalized; these checks mirror the circuits' `check_id`
//! and run the same `idVectors` table.

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
    /// A leading zero the platform does not allow.
    BadShape,
}

impl IdError {
    /// The index the vector table uses for this kind.
    pub const fn kind(self) -> u8 {
        match self {
            Self::Empty => v::ERROR_EMPTY,
            Self::TooLong => v::ERROR_TOOLONG,
            Self::BadCharacter => v::ERROR_BADCHARACTER,
            Self::BadShape => v::ERROR_BADSHAPE,
        }
    }
}

impl std::fmt::Display for IdError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Empty => "the id is empty",
            Self::TooLong => "the id is too long for this platform",
            Self::BadCharacter => "the id has a byte this platform does not allow",
            Self::BadShape => "the id has a leading zero",
        })
    }
}

impl std::error::Error for IdError {}

/// What a platform allows in an id.
#[derive(Debug, Clone, Copy)]
pub struct IdRules {
    /// Bytes allowed.
    pub max_length: usize,
    /// ASCII digits; otherwise printable ASCII without `"` or `\`.
    pub decimal: bool,
    /// The id may start with `0` when longer than one byte.
    pub leading_zero: bool,
}

impl IdRules {
    /// X: decimal strings.
    pub const X: Self = v::PLATFORM_X.id_rules;
    /// GitHub: JSON integers.
    pub const GITHUB: Self = v::PLATFORM_GITHUB.id_rules;
    /// Google: the OIDC `sub`.
    pub const GOOGLE: Self = v::PLATFORM_GOOGLE.id_rules;
}

/// The id rules for a platform key, from the generated table.
pub fn id_rules_for(platform_key: &str) -> Option<IdRules> {
    v::platform(platform_key).map(|p| p.id_rules)
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
            (0x20..=0x7e).contains(&b) && b != b'"' && b != b'\\'
        }
    };
    if !bytes.iter().all(|&b| allowed(b)) {
        return Err(IdError::BadCharacter);
    }
    if !rules.leading_zero && bytes.len() > 1 && bytes[0] == b'0' {
        return Err(IdError::BadShape);
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
        assert_eq!(refused("012"), "the id has a leading zero");
    }

    #[test]
    fn every_id_vector_matches_the_shared_table() {
        for (i, v) in ID_VECTORS.iter().enumerate() {
            let rules = id_rules_for(v.platform).expect("known platform");
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
