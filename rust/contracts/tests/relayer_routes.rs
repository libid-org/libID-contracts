//! The wallet error route a relayer decodes an onboarding batch's reverts
//! with.

use alloy::{
    primitives::*,
    sol_types::SolValue,
};
use libid_contracts::WalletRegistryError;

/// The onboarding batch's claim from an empty escrow and its bind fail
/// on the wallet route, by name and contract.
#[test]
fn escrow_and_registry_refusals_decode_on_the_wallet_route() {
    for (signature, contract) in [
        ("NothingHeld(bytes32)", "HandleEscrow"),
        ("NotYourHandle(bytes32)", "IdentityRegistry"),
    ] {
        let mut data = keccak256(signature)[..4].to_vec();
        data.extend(B256::repeat_byte(0xe2).abi_encode());
        let error = WalletRegistryError::decode(&data).expect(signature);
        assert_eq!(error.signature(), signature);
        assert_eq!(error.contracts(), [contract]);
    }
}
