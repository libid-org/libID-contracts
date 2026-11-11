//! Bindings for the web wallet (`solidity/contracts/wallet/`), read from the
//! compiled artifacts. One `sol!` per contract: the structs they share, such
//! as `IIdentityValidator.Policy`, are generated once per contract, so
//! `WalletRegistry` calls take [`RegistryPolicy`].

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

/// `IIdentityValidator.Policy` as `WalletRegistry` calls take it: the same
/// struct as [`IIdentityValidator::Policy`], generated from this contract's ABI.
pub use wallet_registry::IIdentityValidator::Policy as RegistryPolicy;
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

#[cfg(test)]
mod tests {
    use alloy::sol_types::{
        SolStruct,
        SolValue,
    };

    use super::*;

    /// The two `Policy` bindings name one struct, so either decodes the other.
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
            rules: IIdentityValidator::Rules {
                scopeRoot: [1; 32].into(),
                domainsRoot: [2; 32].into(),
                allowances: vec![IIdentityValidator::Allowance {
                    token: [3; 20].into(),
                    amount: 4,
                    period: 5.try_into().unwrap(),
                }],
            },
        };
        let decoded = RegistryPolicy::abi_decode(&policy.abi_encode()).unwrap();
        assert_eq!(decoded.abi_encode(), policy.abi_encode());
    }
}
