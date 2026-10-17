//! What a platform's user id must be before it is hashed into a node: one
//! JSON token as sent, digits for a number, otherwise a string's bytes.
//!
//! Ids are never normalized; these checks mirror the circuits' `check_id`
//! and run the same `idVectors` table.

use crate::platforms::{
    self as v,
    IdError,
};

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
    use crate::vectors::ID_VECTORS;

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
            assert_eq!(
                check_id(v.input, rules),
                v.expected.map(|_| ()),
                "id vector {i}: {:?}",
                v.input
            );
        }
    }
}
