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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::handle_vectors::{
        platform,
        ID_VECTORS,
        VECTORS,
    };

    /// The table platform with this key.
    fn known(key: &str) -> &'static v::Platform {
        platform(key).expect("known platform")
    }

    fn hex(node: [u8; 32]) -> String {
        node.iter().fold(String::from("0x"), |mut s, b| {
            s.push_str(&format!("{b:02x}"));
            s
        })
    }

    #[test]
    fn every_handle_node_matches_the_table() {
        for (i, v) in VECTORS.iter().enumerate() {
            match known(v.platform).handle_node(v.input) {
                Ok(node) => assert_eq!(hex(node), v.handle_node, "vector {i}"),
                Err(_) => assert!(!v.accepted, "vector {i}: refused"),
            }
        }
    }

    #[test]
    fn every_id_node_matches_the_table() {
        for (i, v) in ID_VECTORS.iter().enumerate() {
            match known(v.platform).id_node(v.input) {
                Ok(node) => assert_eq!(hex(node), v.id_node, "id vector {i}"),
                Err(_) => assert!(!v.accepted, "id vector {i}: refused"),
            }
        }
    }

    #[test]
    fn folding_alone_reaches_every_accepted_node() {
        for (i, v) in VECTORS.iter().filter(|v| v.accepted).enumerate() {
            let (folded, node) = known(v.platform).folded_handle_node(v.input);
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
        assert!(v::PLATFORM_X.handle_node("Bo\"b").is_err());
        let (folded, node) = v::PLATFORM_X.folded_handle_node("Bo\"b");
        assert_eq!(folded, "bo\"b");
        assert_eq!(
            hex(node),
            "0x650dc467b55054ff038aed82e055439b80903460291078585ad72e334bf0050a"
        );
        assert!(platform("myspace").is_none());
    }

    #[test]
    fn a_key_finds_its_platform() {
        assert_eq!(known("x").key, v::PLATFORM_X.key);
        assert_eq!(
            known("github").folded_handle_node("Bob"),
            v::PLATFORM_GITHUB.folded_handle_node("Bob")
        );
    }

    #[test]
    fn a_platform_s_tag_keeps_its_keys_apart_from_another_s() {
        let x = v::PLATFORM_X.handle_node("alice").unwrap();
        let github = v::PLATFORM_GITHUB.handle_node("alice").unwrap();
        assert_ne!(x, github);
        let id = v::PLATFORM_X.id_node("7").unwrap();
        let handle = v::PLATFORM_X.handle_node("7").unwrap();
        assert_ne!(id, handle, "an id and a handle with the same text");
    }
}
