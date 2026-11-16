//! Generic deploy and upgrade primitives, usable over any alloy
//! [`Provider`] that has a wallet wired in. Signing is the consumer's
//! concern; nothing here constructs or holds keys.

use std::future::Future;

use alloy::{
    eips::BlockId,
    network::TransactionBuilder,
    primitives::{
        b256,
        Address,
        Bytes,
        B256,
    },
    providers::Provider,
    rpc::types::{
        TransactionReceipt,
        TransactionRequest,
    },
    sol_types::SolCall,
};

use crate::{
    artifacts::Artifacts,
    bindings::proxy::IUUPSUpgradeable,
    error::{
        Error,
        Result,
    },
    factory::CREATE2_DEPLOYER,
};

/// Send a contract call with automatic retry on "nonce too low" errors.
///
/// Alloy's nonce manager can get stale when earlier calls fail at dry-run
/// (e.g. a call reverting "already applied"). On each attempt the real nonce
/// is fetched from the chain and set explicitly, bypassing the cached nonce
/// manager entirely.
///
/// Usage:
/// `send_with_nonce_retry!(contract.doSomething(args), "label", provider, sender)?;`
#[macro_export]
macro_rules! send_with_nonce_retry {
    ($call_expr:expr, $label:expr, $provider:expr, $sender:expr) => {{
        const MAX_RETRIES: u32 = 3;
        let mut result: $crate::Result<alloy::rpc::types::TransactionReceipt> =
            Err($crate::Error::Rpc {
                detail: "unreachable".into(),
            });
        for attempt in 0..MAX_RETRIES {
            let nonce =
                alloy::providers::Provider::get_transaction_count($provider, $sender)
                    .await
                    .map_err(|e| $crate::Error::Rpc {
                        detail: format!("{} failed to fetch nonce: {e}", $label),
                    })?;
            match ($call_expr).nonce(nonce).send().await {
                Ok(pending) => {
                    result = pending
                        .get_receipt()
                        .await
                        .map_err(|e| $crate::Error::Rpc {
                            detail: format!("{} confirmation failed: {e}", $label),
                        })
                        .and_then(|receipt| {
                            $crate::deploy::Mined::succeeded(receipt, &$label)
                        });
                    break;
                }
                Err(e) => {
                    let msg = e.to_string();
                    let next_attempt = attempt.saturating_add(1);
                    if msg.contains("nonce too low") && next_attempt < MAX_RETRIES {
                        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                        continue;
                    }
                    result = Err($crate::Error::Rpc {
                        detail: format!("{} send failed: {e}", $label),
                    });
                    break;
                }
            }
        }
        result
    }};
}

/// The EIP-1967 implementation slot, one less than
/// `keccak256("eip1967.proxy.implementation")`: where an ERC1967 proxy keeps
/// the address of the code it runs.
pub const IMPLEMENTATION_SLOT: B256 =
    b256!("360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc");

/// A mined transaction's receipt.
pub trait Mined: Sized {
    /// The receipt, or [`Error::Reverted`] when the transaction reverted: a
    /// node mines a reverting transaction and hands back its receipt, so a
    /// receipt alone says nothing landed.
    fn succeeded(self, label: &str) -> Result<Self>;

    /// The block the transaction was mined in. A read of its effects at
    /// this block, not at `latest`, cannot land on a load-balanced
    /// backend that is a block behind: such a backend answers an error.
    fn block(&self) -> BlockId;
}

impl Mined for TransactionReceipt {
    fn succeeded(self, label: &str) -> Result<Self> {
        if self.status() {
            Ok(self)
        } else {
            Err(Error::Reverted {
                label: label.to_string(),
                tx_hash: self.transaction_hash,
            })
        }
    }

    fn block(&self) -> BlockId {
        self.block_hash.map_or(BlockId::latest(), BlockId::hash)
    }
}

/// Reads of an ERC1967 proxy through a provider.
pub trait ProxyReads {
    /// The implementation the ERC1967 proxy at `proxy` runs at `block`,
    /// from its EIP-1967 slot. Zero for an account that is no such proxy.
    fn implementation_of(
        &self,
        proxy: Address,
        block: BlockId,
    ) -> impl Future<Output = Result<Address>> + Send;
}

impl<P: Provider> ProxyReads for P {
    async fn implementation_of(&self, proxy: Address, block: BlockId) -> Result<Address> {
        let slot = self
            .get_storage_at(proxy, IMPLEMENTATION_SLOT.into())
            .block_id(block)
            .await
            .map_err(|e| Error::Rpc {
                detail: format!(
                    "failed to read the implementation slot of {proxy} at {block}: {e}"
                ),
            })?;
        Ok(Address::from_word(slot.into()))
    }
}

/// Deploy a contract and return its address.
pub async fn deploy_contract<P: Provider>(
    provider: &P,
    bytecode: Bytes,
    label: &str,
) -> Result<Address> {
    deploy_contract_from(provider, bytecode, label, None).await
}

/// Deploy a contract, optionally fetching the sender's nonce explicitly.
///
/// Pass `sender` when mixing provider-managed and manually-nonce'd
/// transactions in one run: the cached nonce manager goes stale otherwise.
pub async fn deploy_contract_from<P: Provider>(
    provider: &P,
    bytecode: Bytes,
    label: &str,
    sender: Option<Address>,
) -> Result<Address> {
    let mut tx = TransactionRequest::default().with_deploy_code(bytecode);

    if let Some(addr) = sender {
        let nonce =
            provider
                .get_transaction_count(addr)
                .await
                .map_err(|e| Error::Rpc {
                    detail: format!("failed to fetch nonce for {label}: {e}"),
                })?;
        tx = tx.with_nonce(nonce);
    }

    let pending = provider
        .send_transaction(tx)
        .await
        .map_err(|e| Error::Rpc {
            detail: format!("failed to send {label} deploy tx: {e}"),
        })?;

    let receipt = pending
        .get_receipt()
        .await
        .map_err(|e| Error::Rpc {
            detail: format!("failed to get {label} deploy receipt: {e}"),
        })?
        .succeeded(&format!("{label} deploy"))?;

    receipt.contract_address.ok_or_else(|| Error::Rpc {
        detail: format!("{label} deploy did not return contract address"),
    })
}

/// Deploy `bytecode` with ABI-encoded constructor args appended.
pub async fn deploy_with_ctor<P: Provider>(
    provider: &P,
    bytecode: &Bytes,
    constructor_args: &[u8],
    label: &str,
    sender: Option<Address>,
) -> Result<Address> {
    let mut deploy_bytecode = bytecode.to_vec();
    deploy_bytecode.extend_from_slice(constructor_args);
    deploy_contract_from(provider, Bytes::from(deploy_bytecode), label, sender).await
}

/// Deploy an ERC1967 proxy pointing at `implementation` with `init_data` (the
/// ABI-encoded initializer call).
pub async fn deploy_proxy<P: Provider>(
    provider: &P,
    proxy_bytecode: &Bytes,
    implementation: Address,
    init_data: Bytes,
    label: &str,
    sender: Option<Address>,
) -> Result<Address> {
    // ERC1967Proxy constructor: (address implementation, bytes memory _data)
    let constructor_args =
        alloy::sol_types::SolValue::abi_encode_params(&(implementation, init_data));
    deploy_with_ctor(provider, proxy_bytecode, &constructor_args, label, sender).await
}

/// Deploy an implementation from `artifacts` and put it behind a fresh
/// ERC1967 proxy whose init data is `init_call` ABI-encoded. Returns the
/// proxy address. The common shape of every UUPS deploy in the stack.
pub async fn deploy_behind_proxy<P: Provider, C: SolCall>(
    provider: &P,
    artifacts: &Artifacts,
    contract: &str,
    init_call: &C,
    sender: Option<Address>,
) -> Result<Address> {
    let implementation = deploy_contract_from(
        provider,
        artifacts.bytecode(contract)?,
        &format!("{contract} (impl)"),
        sender,
    )
    .await?;
    let proxy_bytecode = artifacts.bytecode("ERC1967Proxy")?;
    deploy_proxy(
        provider,
        &proxy_bytecode,
        implementation,
        init_call.abi_encode().into(),
        &format!("{contract} (proxy)"),
        sender,
    )
    .await
}

/// Upgrade a UUPS proxy: deploy `contract`'s current implementation from
/// `artifacts`, then call `upgradeToAndCall(new_impl, data)` on the proxy.
/// Returns the new implementation address. `data` is usually empty (state is
/// already initialized); pass a re-initializer call when the upgrade needs
/// one.
pub async fn upgrade_uups<P: Provider>(
    provider: &P,
    artifacts: &Artifacts,
    proxy: Address,
    contract: &str,
    data: Bytes,
    sender: Option<Address>,
) -> Result<Address> {
    let new_impl = deploy_contract_from(
        provider,
        artifacts.bytecode(contract)?,
        &format!("{contract} (new impl)"),
        sender,
    )
    .await?;
    let proxied = IUUPSUpgradeable::new(proxy, provider);
    let call = proxied.upgradeToAndCall(new_impl, data);
    let pending =
        match sender {
            Some(addr) => {
                let nonce = provider.get_transaction_count(addr).await.map_err(|e| {
                    Error::Rpc {
                        detail: format!("{contract} upgrade failed to fetch nonce: {e}"),
                    }
                })?;
                call.nonce(nonce).send().await
            }
            None => call.send().await,
        }
        .map_err(|e| Error::Rpc {
            detail: format!("{contract} upgradeToAndCall send failed: {e}"),
        })?;
    let receipt = pending
        .get_receipt()
        .await
        .map_err(|e| Error::Rpc {
            detail: format!("{contract} upgradeToAndCall confirmation failed: {e}"),
        })?
        .succeeded(&format!("{contract}.upgradeToAndCall"))?;
    let found = provider.implementation_of(proxy, receipt.block()).await?;
    if found != new_impl {
        return Err(Error::NotUpgraded {
            contract: contract.to_string(),
            proxy,
            wanted: new_impl,
            found,
        });
    }
    Ok(new_impl)
}

/// Deploy `salt ++ init_code` through the canonical CREATE2 deployer and
/// check that code landed at `predicted`.
///
/// `sender` opts into explicit nonce management (see
/// [`deploy_contract_from`]).
pub(crate) async fn deploy_via_create2<P: Provider>(
    provider: &P,
    salt: B256,
    init_code: &[u8],
    predicted: Address,
    label: &str,
    sender: Option<Address>,
) -> Result<()> {
    let mut input = salt.to_vec();
    input.extend_from_slice(init_code);
    let mut tx = TransactionRequest::default()
        .with_to(CREATE2_DEPLOYER)
        .with_input(Bytes::from(input));
    if let Some(addr) = sender {
        let nonce =
            provider
                .get_transaction_count(addr)
                .await
                .map_err(|e| Error::Rpc {
                    detail: format!("{label}: failed to fetch nonce: {e}"),
                })?;
        tx = tx.with_nonce(nonce);
    }
    let pending = provider
        .send_transaction(tx)
        .await
        .map_err(|e| Error::Rpc {
            detail: format!("{label}: CREATE2 deploy send failed: {e}"),
        })?;
    pending
        .get_receipt()
        .await
        .map_err(|e| Error::Rpc {
            detail: format!("{label}: CREATE2 deploy confirmation failed: {e}"),
        })?
        .succeeded(&format!("{label}: CREATE2 deploy"))?;
    if !code_present(provider, predicted, label).await? {
        return Err(Error::Rpc {
            detail: format!("{label}: no code at the predicted address {predicted}"),
        });
    }
    Ok(())
}

async fn code_present<P: Provider>(
    provider: &P,
    address: Address,
    label: &str,
) -> Result<bool> {
    let code = provider
        .get_code_at(address)
        .await
        .map_err(|e| Error::Rpc {
            detail: format!("{label}: failed to read code at {address}: {e}"),
        })?;
    Ok(!code.is_empty())
}

#[cfg(test)]
mod tests {
    use alloy::primitives::{
        keccak256,
        U256,
    };

    use super::*;

    /// The slot is the one EIP-1967 derives, not a mistyped copy.
    #[test]
    fn the_implementation_slot_is_eip_1967s() {
        let derived = U256::from_be_bytes(keccak256("eip1967.proxy.implementation").0)
            - U256::from(1);
        assert_eq!(IMPLEMENTATION_SLOT, B256::from(derived));
    }
}
