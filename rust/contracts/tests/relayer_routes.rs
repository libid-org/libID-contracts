//! The wallet error route a relayer decodes an onboarding batch's reverts
//! with.

use alloy::{
    primitives::*,
    sol_types::SolValue,
};
use libid_contracts::WalletRegistryError;

/// The onboarding batch's claim from an empty escrow, its bind and the
/// bind's fee fail on the wallet route, by name and contract.
#[test]
fn escrow_and_registry_refusals_decode_on_the_wallet_route() {
    let hash = B256::repeat_byte(0xe2).abi_encode();
    let fees = (U256::from(1), U256::from(2)).abi_encode_params();
    for (signature, args, contract) in [
        ("NothingHeld(bytes32)", &hash, "HandleEscrow"),
        ("NotYourHandle(bytes32)", &hash, "IdentityRegistry"),
        ("WrongBindFee(uint256,uint256)", &fees, "ReferralSplitter"),
    ] {
        let mut data = keccak256(signature)[..4].to_vec();
        data.extend(args);
        let error = WalletRegistryError::decode(&data).expect(signature);
        assert_eq!(error.signature(), signature);
        assert_eq!(error.contracts(), [contract]);
    }
}
