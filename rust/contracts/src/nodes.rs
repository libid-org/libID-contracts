//! Identity and handle nodes, as `IdentityNodes.sol` derives them: the keys
//! `IdentityNames` binds and `HandleEscrow` pays. A handle must be normalized
//! (`libid_identity::normalize`) before it is hashed.

use alloy::{
    primitives::{
        keccak256,
        B256,
    },
    sol_types::SolValue,
};

/// The version tag that leads every id-node preimage.
pub fn id_node_v1() -> B256 {
    keccak256(b"libid.identity.id-node.v1")
}

/// The version tag that leads every handle-node preimage.
pub fn handle_node_v1() -> B256 {
    keccak256(b"libid.identity.handle-node.v1")
}

/// A platform id: `keccak256` of its domain string (`"x"`, `"github"`, ...).
pub fn platform_id(domain: &str) -> B256 {
    keccak256(domain.as_bytes())
}

/// The node an account id is stored under.
pub fn id_node(platform_id: B256, user_id: &str) -> B256 {
    keccak256(
        (id_node_v1(), platform_id, keccak256(user_id.as_bytes())).abi_encode_params(),
    )
}

/// `keccak256` of a normalized handle: what `HandleEscrow.deposit` takes.
pub fn handle_hash(normalized: &str) -> B256 {
    keccak256(normalized.as_bytes())
}

/// The node of a handle given as its hash (`IdentityNames.nodeOfHash`).
pub fn handle_node_of_hash(platform_id: B256, handle_hash: B256) -> B256 {
    keccak256((handle_node_v1(), platform_id, handle_hash).abi_encode_params())
}

/// The node a normalized handle is stored under.
pub fn handle_node(platform_id: B256, normalized: &str) -> B256 {
    handle_node_of_hash(platform_id, handle_hash(normalized))
}

#[cfg(test)]
mod tests {
    use alloy::primitives::b256;
    use libid_identity::{
        handle_vectors::VECTORS,
        normalize,
        Rules,
    };

    use super::*;

    /// Literals shared with the Solidity suite and `node.test.ts`.
    #[test]
    fn matches_the_pinned_nodes() {
        let x = normalize(" Alice_1 ", Rules::for_platform("x").unwrap()).unwrap();
        assert_eq!(
            handle_node(platform_id("x"), &x),
            b256!("1c43d5d3cf3d99e9d5b6e8c74c23d14bcbb6a743712cf7fa7c15750c4fc2150d")
        );
        let github =
            normalize(" Alice-1 ", Rules::for_platform("github").unwrap()).unwrap();
        assert_eq!(
            handle_node(platform_id("github"), &github),
            b256!("2e2bee956f308d03271ce24b26e5aa20103b41841ddee3c96a94d2449902f710")
        );
    }

    /// The Solidity and TypeScript suites pin `handleHashOf` to the same rows.
    #[test]
    fn hashes_every_accepted_vector_as_its_output() {
        let mut accepted = 0;
        for v in VECTORS.iter().filter(|v| v.accepted) {
            let rules = Rules::for_platform(v.platform).unwrap();
            let normalized = normalize(v.input, rules).unwrap();
            assert_eq!(
                handle_hash(&normalized),
                keccak256(v.output.as_bytes()),
                "{}",
                v.input
            );
            accepted += 1;
        }
        assert!(accepted > 0);
    }

    #[test]
    fn id_and_handle_nodes_never_share_a_preimage() {
        let x = platform_id("x");
        assert_ne!(id_node(x, "123"), handle_node(x, "123"));
    }
}
