//! The keys a binding is stored under: `SHA256(tag || value)`, the same
//! nodes the identity circuits output. The vector table pins every node.

use sha2::{
    Digest,
    Sha256,
};

use super::handle_vectors as v;
use crate::{
    check_id,
    normalize,
    HandleError,
    IdError,
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

/// The node a typed handle is bound under, or why it has none. `None` for
/// an unknown platform.
pub fn handle_node(
    platform_key: &str,
    raw: &str,
) -> Option<Result<[u8; 32], HandleError>> {
    let p = v::platform(platform_key)?;
    Some(normalize(raw, p.rules).map(|normalized| tagged(p.handle_tag, &normalized)))
}

/// `text` with A-Z folded to a-z, and its node: the registry's
/// `handleNodeOf`, which applies no other rule. `None` for an unknown platform.
pub fn folded_handle_node(platform_key: &str, text: &str) -> Option<(String, [u8; 32])> {
    let p = v::platform(platform_key)?;
    let folded = text.to_ascii_lowercase();
    let node = tagged(p.handle_tag, &folded);
    Some((folded, node))
}

/// The node a user id is bound under. The id is hashed exactly as given.
pub fn id_node(platform_key: &str, id: &str) -> Option<Result<[u8; 32], IdError>> {
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
    fn folding_alone_reaches_every_accepted_node() {
        for (i, v) in VECTORS.iter().filter(|v| v.accepted).enumerate() {
            let (folded, node) = folded_handle_node(v.platform, v.input).unwrap();
            assert_eq!(
                (folded.as_str(), hex(node)),
                (v.output, v.handle_node.into()),
                "vector {i}"
            );
        }
    }

    /// Text the rules refuse still has a fold-only node, here
    /// `SHA256("libid.x.handle" || " @alice")` from `sha256sum`.
    #[test]
    fn a_refused_handle_has_a_fold_only_node() {
        assert!(handle_node("x", " @Alice").unwrap().is_err());
        let (folded, node) = folded_handle_node("x", " @Alice").unwrap();
        assert_eq!(folded, " @alice");
        assert_eq!(
            hex(node),
            "0x91f649a873eea530e1610096d7039221f1178ab2c046a8078f3b1de00d1b86fc"
        );
        assert!(folded_handle_node("myspace", "tom").is_none());
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
