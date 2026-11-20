//! The Operation List of chain profiles §3.3: one ceremony's transaction data
//! carrying an entry for each of several Consumers. A bind under
//! [`OPERATIONS_DOMAIN`] is `vec![Operation::bind(target)].abi_encode()`; the
//! registry also takes the single form, `abi.encode(target)` under
//! [`BIND_DOMAIN`].

use alloy::{
    primitives::{
        b256,
        Address,
        B256,
    },
    sol_types::SolValue,
};

#[allow(missing_docs)]
mod inner {
    // `OperationList.Operation`, which no ABI carries: the vector test below
    // pins its encoding to the Solidity one.
    alloy::sol! {
        #[derive(Debug, PartialEq, Eq)]
        struct Operation {
            bytes32 domain;
            bytes data;
        }
    }
}

/// One entry: a Consumer's operation domain and the data that domain fixes.
/// A list is `Vec<Operation>`, and its `abi_encode()` is the transaction data.
pub use inner::Operation;

/// `keccak256("libid.operations")`, the operation domain of an Operation List.
pub const OPERATIONS_DOMAIN: B256 =
    b256!("0x60b329d7366897b03545eb9f63f4a707253258ee2e1cd0ba3a8973aa4959e967");

/// `keccak256("libid.bind-identity")`, the identity registry's entry domain.
pub const BIND_DOMAIN: B256 =
    b256!("0x4d59cd4487de0a5957f8c83addaac7a1238175aa5c29eeea2fbef57a8f5165ac");

impl Operation {
    /// The identity registry's entry: bind the proved identity to `target`,
    /// the account that calls `bind`.
    pub fn bind(target: Address) -> Self {
        Self {
            domain: BIND_DOMAIN,
            data: target.abi_encode().into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use alloy::primitives::keccak256;

    use super::*;

    /// chain profiles §3.3's Operation List vector, one word per line.
    #[test]
    fn an_operation_list_encodes_to_the_spec_vector() {
        let words = [
            "0000000000000000000000000000000000000000000000000000000000000020",
            "0000000000000000000000000000000000000000000000000000000000000002",
            "0000000000000000000000000000000000000000000000000000000000000040",
            "00000000000000000000000000000000000000000000000000000000000000c0",
            "4d59cd4487de0a5957f8c83addaac7a1238175aa5c29eeea2fbef57a8f5165ac",
            "0000000000000000000000000000000000000000000000000000000000000040",
            "0000000000000000000000000000000000000000000000000000000000000020",
            "0000000000000000000000001111111111111111111111111111111111111111",
            "6b8fd3a153cb2bc403041d7ca7d029d031243d8143d49a248230df9dd07fb723",
            "0000000000000000000000000000000000000000000000000000000000000040",
            "0000000000000000000000000000000000000000000000000000000000000001",
            "ff00000000000000000000000000000000000000000000000000000000000000",
        ];
        let vector = alloy::hex::decode(words.concat()).unwrap();
        let encoded = vec![
            Operation::bind(Address::repeat_byte(0x11)),
            Operation {
                domain: keccak256("libid.test.a"),
                data: vec![0xff].into(),
            },
        ]
        .abi_encode();
        assert_eq!(encoded, vector);
        assert_eq!(<Vec<Operation>>::abi_decode(&vector).unwrap().len(), 2);
    }

    #[test]
    fn the_domains_are_their_names_hashes() {
        assert_eq!(OPERATIONS_DOMAIN, keccak256("libid.operations"));
        assert_eq!(BIND_DOMAIN, keccak256("libid.bind-identity"));
    }
}
