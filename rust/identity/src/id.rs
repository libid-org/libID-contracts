//! What a platform's user id must be before it is hashed into a node: one
//! JSON token as sent, a number under REQ-PLAT-06's grammar, otherwise a
//! string's bytes.
//!
//! Ids are never normalized; these checks mirror the circuits' `check_id`
//! and run the same `idVectors` table.

use super::handle_vectors as v;

/// The largest decimal id, 2^64-1 (REQ-PLAT-06), as its 20 digits.
const MAX_DECIMAL_ID: &[u8] = b"18446744073709551615";

/// Why no circuit would hash an id. The kinds are the handle table's.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdError {
    /// No bytes at all.
    Empty,
    /// More bytes than the platform allows.
    TooLong,
    /// A byte the platform does not allow.
    BadCharacter,
    /// A number the platform never issues: a leading zero, or a value past
    /// 2^64-1.
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
            Self::BadShape => "the id is not a number this platform issues",
        })
    }
}

impl std::error::Error for IdError {}

/// What a platform allows in an id.
#[derive(Debug, Clone, Copy)]
pub struct IdRules {
    /// Bytes the circuit's buffer holds.
    pub max_length: usize,
    /// REQ-PLAT-06's `^[1-9][0-9]{0,19}$` with a value at most 2^64-1;
    /// otherwise printable ASCII without `"` or `\`.
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
            crate::handle::is_string_byte(b)
        }
    };
    if !bytes.iter().all(|&b| allowed(b)) {
        return Err(IdError::BadCharacter);
    }
    // A leading zero, "0" included; equal-length digit strings order as
    // their numbers do, and a shorter one is below the bound.
    if rules.decimal
        && (bytes[0] == b'0'
            || (bytes.len() == MAX_DECIMAL_ID.len() && bytes > MAX_DECIMAL_ID))
    {
        return Err(IdError::BadShape);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::handle_vectors::ID_VECTORS;

    #[test]
    fn the_bound_on_a_decimal_id_is_the_largest_u64() {
        assert_eq!(MAX_DECIMAL_ID, u64::MAX.to_string().as_bytes());
        assert_eq!(MAX_DECIMAL_ID.len(), IdRules::X.max_length);
        assert_eq!(MAX_DECIMAL_ID.len(), IdRules::GITHUB.max_length);
    }

    /// REQ-PLAT-06: `^[1-9][0-9]{0,19}$` with a value at most 2^64-1.
    #[test]
    fn a_decimal_id_follows_the_grammar() {
        for id in [
            "1",
            "2244994945",
            "9999999999999999999",
            "18446744073709551615",
        ] {
            assert_eq!(check_id(id, IdRules::X), Ok(()), "{id}");
            assert_eq!(check_id(id, IdRules::GITHUB), Ok(()), "{id}");
        }
        for id in [
            "0",
            "007",
            "0123",
            "18446744073709551616",
            "99999999999999999999",
        ] {
            assert_eq!(check_id(id, IdRules::X), Err(IdError::BadShape), "{id}");
            assert_eq!(
                check_id(id, IdRules::GITHUB),
                Err(IdError::BadShape),
                "{id}"
            );
        }
        assert_eq!(
            check_id("123456789012345678901", IdRules::X),
            Err(IdError::TooLong)
        );
        assert_eq!(check_id("", IdRules::X), Err(IdError::Empty));
        assert_eq!(check_id("12a4", IdRules::X), Err(IdError::BadCharacter));
    }

    /// The grammar is a decimal id's: a Google `sub` is opaque.
    #[test]
    fn a_string_id_keeps_its_leading_zero() {
        assert_eq!(check_id("0123", IdRules::GOOGLE), Ok(()));
        assert_eq!(check_id("0", IdRules::GOOGLE), Ok(()));
    }

    /// TypeScript's `checkId` words its refusals the same way.
    #[test]
    fn an_id_refusal_names_the_id() {
        let refused = |id| check_id(id, IdRules::GITHUB).unwrap_err().to_string();
        assert_eq!(refused(""), "the id is empty");
        assert_eq!(
            refused("12a"),
            "the id has a byte this platform does not allow"
        );
        assert_eq!(refused("0"), "the id is not a number this platform issues");
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
