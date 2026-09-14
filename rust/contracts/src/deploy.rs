//! Generic deploy and upgrade primitives, usable over any alloy
//! [`Provider`] that has a wallet wired in. Signing is the consumer's
//! concern; nothing here constructs or holds keys.

use std::collections::BTreeMap;

use alloy::{
    hex,
    network::TransactionBuilder,
    primitives::{
        keccak256,
        Address,
        Bytes,
        B256,
    },
    providers::Provider,
    rpc::types::TransactionRequest,
    sol_types::SolCall,
};

use crate::{
    artifacts::Artifacts,
    bindings::proxy::IUUPSUpgradeable,
    error::{
        Error,
        Result,
    },
    factory::{
        ensure_create2_deployer,
        CREATE2_DEPLOYER,
    },
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
                    result =
                        pending.get_receipt().await.map_err(|e| $crate::Error::Rpc {
                            detail: format!("{} confirmation failed: {e}", $label),
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

    let receipt = pending.get_receipt().await.map_err(|e| Error::Rpc {
        detail: format!("failed to get {label} deploy receipt: {e}"),
    })?;

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
    pending.get_receipt().await.map_err(|e| Error::Rpc {
        detail: format!("{contract} upgradeToAndCall confirmation failed: {e}"),
    })?;
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
    pending.get_receipt().await.map_err(|e| Error::Rpc {
        detail: format!("{label}: CREATE2 deploy confirmation failed: {e}"),
    })?;
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

/// The salt every shared library deploys under. Fixed and empty on purpose:
/// a CREATE2 address is a function of the deployer, the salt and the hash
/// of the init code, and the init code is the whole key — the salt has
/// nothing to add.
pub const LIBRARY_SALT: B256 = B256::ZERO;

/// Where a library with this creation code lands, on every chain: through
/// the canonical [`CREATE2_DEPLOYER`] under [`LIBRARY_SALT`]. A pure
/// function of the bytes, computable before anything is deployed.
pub fn library_address(creation_code: &[u8]) -> Address {
    CREATE2_DEPLOYER.create2(LIBRARY_SALT, keccak256(creation_code))
}

/// External libraries deployed once per distinct bytecode, and the address
/// each linked contract substitutes for its placeholders.
///
/// Solidity links a contract against a library by `<File>.sol:<Name>`, so
/// two files that each carry a copy of the same library — bb writes
/// `RelationsLib` and `ZKTranscriptLib` into every verifier it generates —
/// link by different keys. This groups those keys by the hash of the
/// library's creation code, and that hash is the whole rule: identical
/// bytecode is one deployment, and every contract whose artifact names
/// that bytecode links against it; bytecode that differs is a deployment
/// of its own. No version, release or list of which libraries happen to
/// match takes part — a bb or solc bump that leaves a library identical
/// keeps it shared, one that changes it separates it, and a contract can
/// only ever link the bytes it was compiled against.
///
/// Each distinct library lands through the canonical CREATE2 deployer under
/// [`LIBRARY_SALT`], so its address is [`library_address`] of its creation
/// code: the same on every chain, and already holding code on a re-run,
/// which is how a library that is deployed is found and reused with no
/// record kept off chain. The deployer is installed if the chain lacks it,
/// as [`ensure_factory`](crate::factory::ensure_factory) does; there is no
/// plain-CREATE fallback, because an address that is not a function of the
/// code is one a later run cannot find.
///
/// Creation code rather than runtime code, because it is what the chain
/// receives and what the address derives from, and equal creation code is
/// equal runtime code.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Libraries {
    /// `(file, library)` as `linkReferences` names it -> the address linked.
    linked: BTreeMap<(String, String), Address>,
    /// Every distinct creation code, by hash -> its address, and whether
    /// this call deployed it (`true`) or found its code in place (`false`).
    distinct: BTreeMap<B256, (Address, bool)>,
}

impl Libraries {
    /// Deploy every library the `(file, contract)` artifacts link, once per
    /// distinct bytecode, skipping any whose code is already at its address.
    /// A library that links libraries of its own has those resolved first.
    /// Contracts that link nothing contribute nothing and cost nothing.
    ///
    /// `sender` opts into explicit nonce management (see
    /// [`deploy_contract_from`]).
    pub async fn deploy<P: Provider>(
        provider: &P,
        artifacts: &Artifacts,
        contracts: &[(&str, &str)],
        sender: Option<Address>,
    ) -> Result<Self> {
        let mut libraries = Self::default();
        for (file, contract) in contracts {
            libraries
                .resolve(provider, artifacts, file, contract, sender)
                .await?;
        }
        Ok(libraries)
    }

    /// The address `<file>.sol:<library>` links against, if it is in the
    /// set.
    pub fn address(&self, file: &str, library: &str) -> Option<Address> {
        self.linked
            .get(&(file.to_owned(), library.to_owned()))
            .copied()
    }

    /// Every distinct library, as the hash of its creation code and its
    /// address. One entry per deployment, however many files name it.
    pub fn distinct(&self) -> impl Iterator<Item = (B256, Address)> + '_ {
        self.distinct
            .iter()
            .map(|(hash, (address, _))| (*hash, *address))
    }

    /// The addresses this call sent a deploy for, as opposed to found.
    pub fn deployed(&self) -> impl Iterator<Item = Address> + '_ {
        self.distinct
            .values()
            .filter(|(_, deployed)| *deployed)
            .map(|(address, _)| *address)
    }

    /// The creation bytecode of `<file>.sol:<contract>` with every library
    /// it links substituted from the set. Pure: no transaction. Errors when
    /// the artifact names a library the set does not hold.
    pub fn link(
        &self,
        artifacts: &Artifacts,
        file: &str,
        contract: &str,
    ) -> Result<Bytes> {
        let mut hex_str = artifacts.bytecode_hex(file, contract)?;
        for (lib_path, libs) in artifacts.link_references(file, contract)? {
            let lib_file = file_stem(&lib_path)?;
            for (lib_name, refs) in libs.as_object().into_iter().flatten() {
                let address = self.address(lib_file, lib_name).ok_or_else(|| {
                    Error::Artifact {
                        detail: format!(
                            "{file}.sol:{contract} links {lib_file}.sol:{lib_name}, which \
                             is not among the deployed libraries"
                        ),
                    }
                })?;
                substitute(&mut hex_str, refs, address, lib_name)?;
            }
        }
        if hex_str.contains("__$") {
            return Err(Error::Artifact {
                detail: format!(
                    "{file}.sol:{contract} still has a link placeholder after linking"
                ),
            });
        }
        let bytes = hex::decode(&hex_str).map_err(|e| Error::Artifact {
            detail: format!(
                "invalid bytecode hex after linking {file}.sol:{contract}: {e}"
            ),
        })?;
        Ok(Bytes::from(bytes))
    }

    /// Put every library `<file>.sol:<contract>` links into the set.
    async fn resolve<P: Provider>(
        &mut self,
        provider: &P,
        artifacts: &Artifacts,
        file: &str,
        contract: &str,
        sender: Option<Address>,
    ) -> Result<()> {
        for (lib_path, libs) in artifacts.link_references(file, contract)? {
            let lib_file = file_stem(&lib_path)?;
            for lib_name in libs.as_object().into_iter().flatten().map(|(name, _)| name) {
                let key = (lib_file.to_owned(), lib_name.clone());
                if self.linked.contains_key(&key) {
                    continue;
                }
                // The library's own libraries first, so that its creation
                // code — and so its hash and its address — is final.
                Box::pin(self.resolve(provider, artifacts, lib_file, lib_name, sender))
                    .await?;
                let code = self.link(artifacts, lib_file, lib_name)?;
                let hash = keccak256(&code);
                let address = match self.distinct.get(&hash) {
                    Some((address, _)) => *address,
                    None => {
                        let label = format!("{lib_file}.sol:{lib_name} (library)");
                        let address = library_address(&code);
                        let found = code_present(provider, address, &label).await?;
                        if !found {
                            ensure_create2_deployer(provider).await?;
                            deploy_via_create2(
                                provider,
                                LIBRARY_SALT,
                                &code,
                                address,
                                &label,
                                sender,
                            )
                            .await?;
                        }
                        self.distinct.insert(hash, (address, !found));
                        address
                    }
                };
                self.linked.insert(key, address);
            }
        }
        Ok(())
    }
}

/// `contracts/circuits/X.sol` -> `X`, the artifact directory's name.
fn file_stem(path: &str) -> Result<&str> {
    std::path::Path::new(path)
        .file_stem()
        .and_then(|s| s.to_str())
        .ok_or_else(|| Error::Artifact {
            detail: format!("bad library file path {path}"),
        })
}

/// Write `address` over every `{start, length}` placeholder in `refs`.
fn substitute(
    hex_str: &mut String,
    refs: &serde_json::Value,
    address: Address,
    library: &str,
) -> Result<()> {
    let addr_hex = hex::encode(address.as_slice()); // 40 hex chars
    for r in refs.as_array().into_iter().flatten() {
        let start = r["start"]
            .as_u64()
            .and_then(|v| usize::try_from(v).ok())
            .ok_or_else(|| Error::Artifact {
                detail: format!("bad linkReference start for {library}"),
            })?;
        let length = r["length"]
            .as_u64()
            .and_then(|v| usize::try_from(v).ok())
            .ok_or_else(|| Error::Artifact {
                detail: format!("bad linkReference length for {library}"),
            })?;
        if length != Address::len_bytes() {
            return Err(Error::Artifact {
                detail: format!(
                    "linkReference for {library} is {length} bytes, not an address"
                ),
            });
        }
        // Byte offsets → hex-char offsets (×2).
        let begin = start.checked_mul(2);
        let end = start.checked_add(length).and_then(|v| v.checked_mul(2));
        let (begin, end) = begin.zip(end).ok_or_else(|| Error::Artifact {
            detail: format!("linkReference offset overflow for {library}"),
        })?;
        if end > hex_str.len() {
            return Err(Error::Artifact {
                detail: format!("linkReference for {library} runs past the bytecode"),
            });
        }
        hex_str.replace_range(begin..end, &addr_hex);
    }
    Ok(())
}

/// The creation bytecode of `<file>.sol:<contract>` with every library it
/// links deployed and substituted: [`Libraries::deploy`] over the one
/// contract, then [`Libraries::link`]. Mirrors what `forge` does
/// automatically, except that a library already at its address is reused
/// rather than deployed again. For artifacts with no `linkReferences` this
/// behaves like [`Artifacts::bytecode_named`] and sends nothing.
///
/// The bb-generated UltraHonk verifiers are what goes through here: each
/// links `RelationsLib` and `ZKTranscriptLib`, and
/// [`deploy_honk_verifier`](crate::circuits::deploy_honk_verifier) is the
/// call that links and deploys one.
pub async fn load_linked_bytecode<P: Provider>(
    provider: &P,
    artifacts: &Artifacts,
    file: &str,
    contract: &str,
    sender: Option<Address>,
) -> Result<Bytes> {
    Libraries::deploy(provider, artifacts, &[(file, contract)], sender)
        .await?
        .link(artifacts, file, contract)
}
