//! The Operation List of chain profiles §3.3: one ceremony's transaction data
//! committing an entry for each of several Consumers.

use alloy::{
    primitives::{
        b256,
        keccak256,
        B256,
    },
    sol_types::SolValue,
};

/// `keccak256("libid.operations")`, the operation domain of an Operation List.
pub const OPERATIONS_DOMAIN: B256 =
    b256!("0x60b329d7366897b03545eb9f63f4a707253258ee2e1cd0ba3a8973aa4959e967");

/// The transaction data under [`OPERATIONS_DOMAIN`]: `abi.encode(Operation[])`
/// of each entry's domain and `keccak256(data)`. No `data` is in the list:
/// each Consumer's call carries its own entry's, or rebuilds it.
pub fn encode_operation_list(entries: &[(B256, &[u8])]) -> Vec<u8> {
    entries
        .iter()
        .map(|(domain, data)| (*domain, keccak256(data)))
        .collect::<Vec<_>>()
        .abi_encode()
}

#[cfg(test)]
mod tests {
    use alloy::primitives::Address;

    use super::*;

    /// chain profiles §3.3's Operation List vector, one word per line.
    #[test]
    fn an_operation_list_encodes_to_the_spec_vector() {
        let words = [
            "0000000000000000000000000000000000000000000000000000000000000020",
            "0000000000000000000000000000000000000000000000000000000000000002",
            "4d59cd4487de0a5957f8c83addaac7a1238175aa5c29eeea2fbef57a8f5165ac",
            "aafae41182fdefb0af836c3b506e127c7f229f33360c66de1139f4b0316f09d8",
            "6b8fd3a153cb2bc403041d7ca7d029d031243d8143d49a248230df9dd07fb723",
            "8b1a944cf13a9a1c08facb2c9e98623ef3254d2ddb48113885c3e8e97fec8db9",
        ];
        let vector = alloy::hex::decode(words.concat()).unwrap();
        let target = Address::repeat_byte(0x11).abi_encode();
        let encoded = encode_operation_list(&[
            (keccak256("libid.bind-identity"), &target),
            (keccak256("libid.test.a"), &[0xff]),
        ]);
        assert_eq!(encoded, vector);
        assert_eq!(OPERATIONS_DOMAIN, keccak256("libid.operations"));
    }
}
