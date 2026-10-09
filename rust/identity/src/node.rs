//! The keys a binding is stored under: `SHA256(tag || value)`.
//!
//! The identity circuits compute these and the registry stores what they
//! output; nothing on chain recomputes them from plaintext except a
//! disclosure check. A wallet, an indexer or an escrow payer holding what a
//! user typed computes the same key here: normalize the handle (or check the
//! id), then hash it under the platform's tag. The tags come from the
//! generated table, and the vector table pins every node, computed
//! independently with Python's hashlib.

use sha2::{
    Digest,
    Sha256,
};

use super::handle_vectors as v;
use crate::{
    check_id,
    normalize,
    HandleError,
};

/// The tags a platform's nodes are hashed under: `(user id, handle)`.
pub fn tags_for(platform_key: &str) -> Option<(&'static str, &'static str)> {
    v::platform(platform_key).map(|p| (p.user_id_tag, p.handle_tag))
}

fn tagged(tag: &str, value: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(tag.as_bytes());
    hasher.update(value.as_bytes());
    hasher.finalize().into()
}

/// The node a handle is bound under, from the handle as a user typed it, or
/// why no binding can have one. `None` for a platform this table does not
/// know.
pub fn handle_node(
    platform_key: &str,
    raw: &str,
) -> Option<Result<[u8; 32], HandleError>> {
    let p = v::platform(platform_key)?;
    Some(normalize(raw, p.rules).map(|normalized| tagged(p.handle_tag, &normalized)))
}

/// The node a user id is bound under. The id is hashed exactly as given.
pub fn id_node(platform_key: &str, id: &str) -> Option<Result<[u8; 32], HandleError>> {
    let p = v::platform(platform_key)?;
    Some(check_id(id, p.id_rules).map(|()| tagged(p.user_id_tag, id)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::handle_vectors::{
        ID_VECTORS,
        VECTORS,
    };

    fn hex(node: [u8; 32]) -> String {
        node.iter().fold(String::from("0x"), |mut s, b| {
            s.push_str(&format!("{b:02x}"));
            s
        })
    }

    #[test]
    fn every_handle_node_matches_the_table() {
        for (i, v) in VECTORS.iter().enumerate() {
            match handle_node(v.platform, v.input).expect("known platform") {
                Ok(node) => assert_eq!(hex(node), v.handle_node, "vector {i}"),
                Err(_) => assert!(!v.accepted, "vector {i}: refused"),
            }
        }
    }

    #[test]
    fn every_id_node_matches_the_table() {
        for (i, v) in ID_VECTORS.iter().enumerate() {
            match id_node(v.platform, v.input).expect("known platform") {
                Ok(node) => assert_eq!(hex(node), v.id_node, "id vector {i}"),
                Err(_) => assert!(!v.accepted, "id vector {i}: refused"),
            }
        }
    }

    #[test]
    fn a_platform_s_tag_keeps_its_keys_apart_from_another_s() {
        let x = handle_node("x", "alice").unwrap().unwrap();
        let github = handle_node("github", "alice").unwrap().unwrap();
        assert_ne!(x, github);
        let id = id_node("x", "7").unwrap().unwrap();
        let handle = handle_node("x", "7").unwrap().unwrap();
        assert_ne!(id, handle, "an id and a handle with the same text");
    }
}
