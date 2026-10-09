//! The rules a platform's user id must meet before it is hashed into a node.
//!
//! Ids are never normalized: the circuit hashes the id exactly as the
//! platform sent it, so a caller computing an id node must start from those
//! bytes. These checks refuse what no circuit would have hashed, mirroring
//! the circuits' `lib/identity` `check_id`, and run the same `idVectors`
//! table.

use super::handle_vectors as v;
use crate::HandleError;

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

/// Accept an id exactly as given, or say why no circuit would hash it. The
/// refusal kinds are the handle's, in the same order.
pub fn check_id(id: &str, rules: IdRules) -> Result<(), HandleError> {
    let bytes = id.as_bytes();
    if bytes.is_empty() {
        return Err(HandleError::Empty);
    }
    if bytes.len() > rules.max_length {
        return Err(HandleError::TooLong);
    }
    let allowed = |b: u8| {
        if rules.decimal {
            b.is_ascii_digit()
        } else {
            (0x20..=0x7e).contains(&b) && b != b'"' && b != b'\\'
        }
    };
    if !bytes.iter().all(|&b| allowed(b)) {
        return Err(HandleError::BadCharacter);
    }
    if !rules.leading_zero && bytes.len() > 1 && bytes[0] == b'0' {
        return Err(HandleError::BadShape);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::handle_vectors::ID_VECTORS;

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
