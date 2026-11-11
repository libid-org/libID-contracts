//! Bindings for the web wallet (`solidity/contracts/wallet/`), read from the
//! compiled artifacts. One `sol!` per contract: the structs they share, such
//! as `IIdentityValidator.Policy`, are generated once per contract.

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
