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

impl v::Platform {
    /// The node a typed handle is bound under, or why it has none.
    pub fn handle_node(&self, raw: &str) -> Result<[u8; 32], HandleError> {
        normalize(raw, self.rules).map(|normalized| tagged(self.handle_tag, &normalized))
    }

    /// `text` with A-Z folded to a-z, and its node: the registry's
    /// `handleNodeOf`, which applies no other rule.
    pub fn folded_handle_node(&self, text: &str) -> (String, [u8; 32]) {
        let folded = text.to_ascii_lowercase();
        let node = tagged(self.handle_tag, &folded);
        (folded, node)
    }

    /// The node a user id is bound under. The id is hashed exactly as given.
    pub fn id_node(&self, id: &str) -> Result<[u8; 32], IdError> {
        check_id(id, self.id_rules).map(|()| tagged(self.user_id_tag, id))
    }
}

/// [`v::Platform::handle_node`] by platform key; `None` for an unknown platform.
pub fn handle_node(
    platform_key: &str,
    raw: &str,
) -> Option<Result<[u8; 32], HandleError>> {
    v::platform(platform_key).map(|p| p.handle_node(raw))
}

/// [`v::Platform::folded_handle_node`] by platform key; `None` for an unknown platform.
pub fn folded_handle_node(platform_key: &str, text: &str) -> Option<(String, [u8; 32])> {
    v::platform(platform_key).map(|p| p.folded_handle_node(text))
}

/// [`v::Platform::id_node`] by platform key; `None` for an unknown platform.
pub fn id_node(platform_key: &str, id: &str) -> Option<Result<[u8; 32], IdError>> {
    v::platform(platform_key).map(|p| p.id_node(id))
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

    /// Text the circuits refuse still has a fold-only node, here
    /// `SHA256("libid.x.handle" || "bo\"b")` from `sha256sum`.
    #[test]
    fn a_refused_handle_has_a_fold_only_node() {
        assert!(handle_node("x", "Bo\"b").unwrap().is_err());
        let (folded, node) = folded_handle_node("x", "Bo\"b").unwrap();
        assert_eq!(folded, "bo\"b");
        assert_eq!(
            hex(node),
            "0x650dc467b55054ff038aed82e055439b80903460291078585ad72e334bf0050a"
        );
        assert!(folded_handle_node("myspace", "tom").is_none());
    }

    #[test]
    fn a_platform_s_nodes_match_its_key_s() {
        assert_eq!(
            v::PLATFORM_X.handle_node("Alice_1"),
            handle_node("x", "Alice_1").unwrap()
        );
        assert_eq!(v::PLATFORM_X.id_node("7"), id_node("x", "7").unwrap());
        assert_eq!(
            v::PLATFORM_GITHUB.folded_handle_node("Bob"),
            folded_handle_node("github", "Bob").unwrap()
        );
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
