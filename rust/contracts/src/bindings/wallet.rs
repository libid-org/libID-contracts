//! Bindings for the web wallet (`solidity/contracts/wallet/`), read from the
//! compiled artifacts. One `sol!` per contract: the structs they share, such
//! as `IIdentityValidator.Policy`, are generated once per contract, so
//! `WalletRegistry` calls take [`RegistryPolicy`], built from
//! [`RegistryRules`] and [`RegistryAllowance`].

use alloy::{
    primitives::{
        aliases::{
            U192,
            U48,
        },
        b256,
        keccak256,
        Address,
        Bytes,
        B256,
        U256,
    },
    sol_types::{
        eip712_domain,
        SolStruct,
        SolValue,
    },
};

#[allow(
    clippy::too_many_arguments,
    missing_docs,
    non_camel_case_types,
    unused_attributes
)]
mod web_wallet {
    alloy::sol!(
        #[sol(rpc, all_derives)]
        WebWallet,
        "abi/WebWallet.json"
    );
}

/// `wallet/WebWallet.sol`: the ERC-7579 account, whose only module is the
/// IdentityValidator.
pub use web_wallet::WebWallet;
/// The ERC-4337 operation `WebWallet.validateUserOp` takes.
pub use web_wallet::WebWallet::PackedUserOperation;

#[allow(
    clippy::too_many_arguments,
    missing_docs,
    non_camel_case_types,
    unused_attributes
)]
mod identity_validator {
    alloy::sol!(
        #[sol(rpc, all_derives)]
        IdentityValidator,
        "abi/IdentityValidator.json"
    );
}

/// `wallet/IIdentityValidator.sol`'s types for `IdentityValidator` calls:
/// `Policy` and its `Rules`, `Session`, `AllowanceState`, and
/// `Authorization`, which is `abi_encode`d as a signature.
pub use identity_validator::IIdentityValidator;
/// `wallet/IdentityValidator.sol`: each wallet's identities, sessions and root
/// operations.
pub use identity_validator::IdentityValidator;

#[allow(
    clippy::too_many_arguments,
    missing_docs,
    non_camel_case_types,
    unused_attributes
)]
mod wallet_registry {
    alloy::sol!(
        #[sol(rpc, all_derives)]
        WalletRegistry,
        "abi/WalletRegistry.json"
    );
}

/// `IIdentityValidator.Allowance` of a [`RegistryRules`].
pub use wallet_registry::IIdentityValidator::Allowance as RegistryAllowance;
/// `IIdentityValidator.Policy` as `WalletRegistry` calls take it: the same
/// struct as [`IIdentityValidator::Policy`], generated from this contract's ABI.
pub use wallet_registry::IIdentityValidator::Policy as RegistryPolicy;
/// `IIdentityValidator.Rules` of a [`RegistryPolicy`].
pub use wallet_registry::IIdentityValidator::Rules as RegistryRules;
/// `wallet/WalletRegistry.sol`: links proved identities to wallets.
pub use wallet_registry::WalletRegistry;

#[allow(
    clippy::too_many_arguments,
    missing_docs,
    non_camel_case_types,
    unused_attributes
)]
mod wallet_factory {
    alloy::sol!(
        #[sol(rpc, all_derives)]
        WalletFactory,
        "abi/WalletFactory.json"
    );
}

/// `wallet/WalletFactory.sol`: deploys wallets at addresses fixed by identity.
pub use wallet_factory::WalletFactory;

/// `rulesHashOf` and `policyHashOf` of `IIdentityValidator.sol`, on both
/// bindings of `Rules` and `Policy`.
macro_rules! policy_hashes {
    ($rules:ty, $policy:ty) => {
        impl $rules {
            /// `rulesHashOf(rules)`: stored in the session record, it keys the
            /// session's allowance counters.
            pub fn rules_hash(&self) -> B256 {
                let Self {
                    scopeRoot,
                    domainsRoot,
                    paymastersRoot,
                    allowances,
                } = self;
                keccak256(
                    (
                        *scopeRoot,
                        *domainsRoot,
                        *paymastersRoot,
                        allowances.clone(),
                    )
                        .abi_encode_params(),
                )
            }
        }

        impl $policy {
            /// `policyHashOf(policy)`: the policy hash a proof commits.
            pub fn policy_hash(&self) -> B256 {
                keccak256(
                    (
                        self.validAfter,
                        self.validUntil,
                        self.admin,
                        // `uint8` encodes as one word.
                        U256::from(self.signers),
                        self.rules.rules_hash(),
                    )
                        .abi_encode_params(),
                )
            }
        }
    };
}

policy_hashes!(IIdentityValidator::Rules, IIdentityValidator::Policy);
policy_hashes!(RegistryRules, RegistryPolicy);

/// What each signer signs below quorum:
/// `keccak256(abi.encode(hash, at, keccak256(governingKey)))`, where the
/// governing key is the first signature's. For an operation, `hash` is its
/// `userOpHash` and `at` picks the allowance period, which the EntryPoint
/// enforces as the operation's validity window. For a direct `execute`, `hash`
/// is its EIP-712 `Execute` digest and `at` the one it signs. For ERC-1271,
/// `hash` is the ERC-7739 nested hash and `at` is 0.
pub fn below_quorum_hash(hash: B256, at: U48, governing_key: &[u8]) -> B256 {
    keccak256((hash, at, keccak256(governing_key)).abi_encode_params())
}

/// `AUTHORIZED_MODE` of `wallet/IWebWallet.sol`, the direct path's mode: the
/// batch call type, the default exec type, the selector
/// `bytes4(keccak256("libid.webwallet.authorized"))` and a zero payload.
pub const AUTHORIZED_MODE: B256 =
    b256!("0x01000000000018f4a5a900000000000000000000000000000000000000000000");

#[allow(missing_docs)]
mod execute {
    alloy::sol! {
        #[derive(Debug, PartialEq, Eq)]
        struct Execute {
            bytes32 mode;
            bytes executionCalldata;
            uint48 at;
            uint256 nonce;
            uint48 deadline;
            uint256 callGas;
        }
    }
}

/// What the signers of a direct `execute(AUTHORIZED_MODE, data)` sign, as
/// `IdentityValidator.checkExecution` hashes it: `mode` is
/// [`AUTHORIZED_MODE`], `at` is `Authorization.at`, and `nonce` is the
/// wallet's full EntryPoint nonce under [`direct_nonce_key`] before the batch.
pub use execute::Execute;

impl Execute {
    /// The EIP-712 hash the signers sign: under the wallet's domain, name
    /// `WebWallet`, version `1`, `chain_id` and `wallet`. Below quorum each
    /// signer signs [`below_quorum_hash`] of it.
    pub fn digest(&self, chain_id: u64, wallet: Address) -> B256 {
        self.eip712_signing_hash(&eip712_domain! {
            name: "WebWallet",
            version: "1",
            chain_id: chain_id,
            verifying_contract: wallet,
        })
    }
}

/// The EntryPoint nonce key of the direct path for a wallet whose validator is
/// `validator`: `uint192(uint160(validator)) << 32`. UserOperations share it.
pub fn direct_nonce_key(validator: Address) -> U192 {
    U192::from_be_slice(validator.as_slice()) << 32
}

/// `data` of `execute(AUTHORIZED_MODE, data)`:
/// `abi.encode(executionCalldata, deadline, callGas, abi.encode(authorization))`.
pub fn authorized_data(
    execution_calldata: Bytes,
    deadline: U48,
    call_gas: U256,
    authorization: &IIdentityValidator::Authorization,
) -> Bytes {
    (
        execution_calldata,
        deadline,
        call_gas,
        Bytes::from(authorization.abi_encode()),
    )
        .abi_encode_params()
        .into()
}

#[cfg(test)]
mod tests {
    use std::fs;

    use alloy::{
        primitives::{
            address,
            b256,
        },
        sol_types::{
            SolStruct,
            SolValue,
        },
    };

    use serde::Deserialize;

    use super::*;

    /// `PolicyEncodingTest`'s vectors, which `cast` computes outside Solidity.
    #[test]
    fn hashes_match_the_solidity_vectors() {
        let rules = IIdentityValidator::Rules {
            scopeRoot: keccak256("s"),
            domainsRoot: keccak256("d"),
            paymastersRoot: keccak256("p"),
            allowances: vec![IIdentityValidator::Allowance {
                token: address!("0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE"),
                amount: 10u128.pow(18),
                period: U48::from(86_400),
            }],
        };
        let policy = IIdentityValidator::Policy {
            validAfter: U48::from(10),
            validUntil: U48::from(20),
            admin: false,
            signers: 2,
            rules,
        };
        let rules_hash =
            b256!("0x91a60d66d4b51055570ae803ab60eeb97f5719221a31686eb83fba2cd2169b20");
        let policy_hash =
            b256!("0xc51a04460ba256d1efcef52fde677904487eed95b705a198c65d40178196f7e8");
        assert_eq!(policy.rules.rules_hash(), rules_hash);
        assert_eq!(policy.policy_hash(), policy_hash);
        let registry = RegistryPolicy::abi_decode(&policy.abi_encode()).unwrap();
        assert_eq!(registry.rules.rules_hash(), rules_hash);
        assert_eq!(registry.policy_hash(), policy_hash);
        assert_eq!(
            below_quorum_hash(
                keccak256("op"),
                U48::from(1234),
                address!("0x0000000000000000000000000000000000001234").as_slice()
            ),
            b256!("0xf63e6147bfa910f2dab04a6910a61fbf42066f204e2344c197c154c1b5a6e8dc")
        );
    }

    /// `solidity/contracts/wallet/test/fixtures/direct-execute-vector.json`,
    /// which `ExecuteVectorTest` checks too.
    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct DirectExecuteVector {
        authorized_mode: B256,
        execute_typehash: B256,
        validator: Address,
        nonce_key: U256,
        nonce: U256,
        execution_calldata: Bytes,
        at: u64,
        deadline: u64,
        call_gas: u64,
        session_key: Bytes,
        signature: Bytes,
        data_hash: B256,
        chain_id: u64,
        wallet: Address,
        digest: B256,
    }

    #[test]
    fn the_direct_path_matches_the_solidity_vector() {
        let path = format!(
            "{}/../../solidity/contracts/wallet/test/fixtures/direct-execute-vector.json",
            env!("CARGO_MANIFEST_DIR")
        );
        let v: DirectExecuteVector =
            serde_json::from_str(&fs::read_to_string(&path).expect(&path)).expect(&path);

        assert_eq!(AUTHORIZED_MODE, v.authorized_mode);
        assert_eq!(AUTHORIZED_MODE[0], 0x01);
        assert_eq!(
            &AUTHORIZED_MODE[6..10],
            &keccak256("libid.webwallet.authorized")[..4]
        );
        assert_eq!(
            keccak256(Execute::eip712_encode_type().as_bytes()),
            v.execute_typehash
        );

        let key = direct_nonce_key(v.validator);
        assert_eq!(U256::from(key), v.nonce_key);
        assert_eq!((U256::from(key) << 64) | U256::from(7), v.nonce);

        let at = U48::from(v.at);
        let authorization = IIdentityValidator::Authorization {
            signatures: vec![IIdentityValidator::SessionSignature {
                key: v.session_key,
                signature: v.signature,
            }],
            at,
            calls: vec![],
            domainProof: vec![],
            paymasterProof: vec![],
        };
        let data = authorized_data(
            v.execution_calldata.clone(),
            U48::from(v.deadline),
            U256::from(v.call_gas),
            &authorization,
        );
        assert_eq!(keccak256(&data), v.data_hash);

        let execute = Execute {
            mode: AUTHORIZED_MODE,
            executionCalldata: v.execution_calldata,
            at,
            nonce: v.nonce,
            deadline: U48::from(v.deadline),
            callGas: U256::from(v.call_gas),
        };
        assert_eq!(execute.digest(v.chain_id, v.wallet), v.digest);
    }

    /// The two `Policy` bindings name one struct: either decodes the other, and
    /// one built from the registry's own types encodes the same.
    #[test]
    fn the_registry_policy_is_the_validator_policy() {
        assert_eq!(
            IIdentityValidator::Policy::eip712_encode_type(),
            RegistryPolicy::eip712_encode_type()
        );
        let policy = IIdentityValidator::Policy {
            validAfter: 1.try_into().unwrap(),
            validUntil: 2.try_into().unwrap(),
            admin: true,
            signers: 3,
            rules: IIdentityValidator::Rules {
                scopeRoot: [1; 32].into(),
                domainsRoot: [2; 32].into(),
                paymastersRoot: [6; 32].into(),
                allowances: vec![IIdentityValidator::Allowance {
                    token: [3; 20].into(),
                    amount: 4,
                    period: 5.try_into().unwrap(),
                }],
            },
        };
        let decoded = RegistryPolicy::abi_decode(&policy.abi_encode()).unwrap();
        assert_eq!(decoded.abi_encode(), policy.abi_encode());

        let built = RegistryPolicy {
            validAfter: 1.try_into().unwrap(),
            validUntil: 2.try_into().unwrap(),
            admin: true,
            signers: 3,
            rules: RegistryRules {
                scopeRoot: [1; 32].into(),
                domainsRoot: [2; 32].into(),
                paymastersRoot: [6; 32].into(),
                allowances: vec![RegistryAllowance {
                    token: [3; 20].into(),
                    amount: 4,
                    period: 5.try_into().unwrap(),
                }],
            },
        };
        assert_eq!(built.abi_encode(), policy.abi_encode());
    }
}
