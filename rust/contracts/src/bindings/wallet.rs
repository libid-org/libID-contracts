//! Bindings for the web wallet (`solidity/contracts/wallet/`), read from the
//! compiled artifacts. One `sol!` per contract: the structs they share, such
//! as `IIdentityValidator.Policy`, are generated once per contract, so
//! `WalletRegistry` calls take [`RegistryPolicy`], built from
//! [`RegistryRules`] and [`RegistryAllowance`].

use alloy::{
    primitives::{
        aliases::U48,
        keccak256,
        B256,
        U256,
    },
    sol_types::SolValue,
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

/// `wallet/WebWallet.sol`: the ERC-7579 account, whose only modules are the
/// IdentityValidator and the ClaimExecutor.
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

#[allow(
    clippy::too_many_arguments,
    missing_docs,
    non_camel_case_types,
    unused_attributes
)]
mod claim_executor {
    alloy::sol!(
        #[sol(rpc, all_derives)]
        ClaimExecutor,
        "abi/ClaimExecutor.json"
    );
}

/// `wallet/ClaimExecutor.sol`: the executor that binds a wallet's identity and
/// claims what the escrow holds for it.
pub use claim_executor::ClaimExecutor;

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

/// What each signer signs below quorum: `keccak256(abi.encode(userOpHash, at))`.
/// `at` picks the allowance period, which the EntryPoint enforces as the
/// operation's validity window.
pub fn below_quorum_hash(user_op_hash: B256, at: U48) -> B256 {
    keccak256((user_op_hash, at).abi_encode_params())
}

#[cfg(test)]
mod tests {
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
            below_quorum_hash(keccak256("op"), U48::from(1234)),
            b256!("0x8c0f295ba05cf4321f217414c5e4fb63b06d09e3e32556f3c183b88ebac155a4")
        );
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
