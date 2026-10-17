//! Proxy plumbing shared by every proxied contract, read from OpenZeppelin's
//! compiled artifacts: the ERC1967 proxy constructor and the UUPS upgrade
//! entrypoint.

#[allow(
    clippy::too_many_arguments,
    missing_docs,
    non_camel_case_types,
    unused_attributes
)]
mod erc1967_proxy {
    alloy::sol!(
        #[sol(rpc, all_derives)]
        ERC1967Proxy,
        "abi/ERC1967Proxy.json"
    );
}

#[allow(
    clippy::too_many_arguments,
    missing_docs,
    non_camel_case_types,
    unused_attributes
)]
mod uups {
    alloy::sol!(
        #[sol(rpc, all_derives)]
        IUUPSUpgradeable,
        "abi/UUPSUpgradeable.json"
    );
}

/// OpenZeppelin `ERC1967Proxy`, deployed with the implementation address and
/// the ABI-encoded initializer calldata.
pub use erc1967_proxy::ERC1967Proxy;
/// OpenZeppelin `UUPSUpgradeable`: the upgrade surface every proxied contract
/// here exposes.
pub use uups::IUUPSUpgradeable;
