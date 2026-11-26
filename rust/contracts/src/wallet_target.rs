//! Whether the wallet contracts vouch for an address as one of their
//! wallets: a factory wallet, or an EIP-7702 account delegated to the
//! forwarder, either on a release the factory published.

use alloy::{
    primitives::{
        b256,
        Address,
        B256,
    },
    providers::Provider,
};

use crate::{
    bindings::wallet::{
        IWebWallet,
        WalletFactory,
    },
    error::{
        Error,
        Result,
    },
};

/// `WalletRelease.SLOT`, `erc7201:libid.webwallet.release`: a wallet's
/// release, `implementation | version << 160`.
pub const RELEASE_SLOT: B256 =
    b256!("0xe1dba8fb066a3b169f681c6818aeab86343e7484c7e0cee1cbf00e41a55c2800");

/// The code of an EIP-7702 account delegated to an address follows this.
const DELEGATION_PREFIX: [u8; 3] = [0xef, 0x01, 0x00];

/// A wallet's release slot.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Release {
    /// The `WebWallet` its calls run.
    pub implementation: Address,
    /// The release number.
    pub version: u64,
}

/// A wallet the contracts vouch for, and its release.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Target {
    /// A `WalletFactory` wallet at the address its genesis identity fixes.
    FactoryWallet(Release),
    /// An EIP-7702 account delegated to the `WalletForwarder`.
    Account(Release),
}

/// The release slot of `wallet`.
pub async fn read_release<P: Provider>(provider: &P, wallet: Address) -> Result<Release> {
    let word = provider
        .get_storage_at(wallet, RELEASE_SLOT.into())
        .await
        .map_err(|e| Error::Rpc {
            detail: format!("failed to read the release slot of {wallet}: {e}"),
        })?;
    Ok(Release {
        implementation: Address::from_word(word.into()),
        version: (word >> 160usize).wrapping_to(),
    })
}

/// Whether `factory` and `forwarder` vouch for `target`, and its release.
/// `None` for anything else, including an account whose `genesisIdentity`
/// reverts or answers junk, or halts where the node reports a halt as -32003
/// (anvil 1.8.5, reth); `Err` when the node gives no answer or any other
/// error, a halt anvil 1.7.1 reports as -32603 or geth as -32000 included.
pub async fn check_target<P: Provider>(
    provider: &P,
    factory: Address,
    forwarder: Address,
    target: Address,
) -> Result<Option<Target>> {
    let code = provider.get_code_at(target).await.map_err(|e| Error::Rpc {
        detail: format!("failed to read the code of {target}: {e}"),
    })?;
    let delegated = code.len() == 23 && code.starts_with(&DELEGATION_PREFIX);
    let kind: fn(Release) -> Target = if code.is_empty() {
        return Ok(None);
    } else if !delegated {
        if !is_factory_wallet(provider, factory, target).await? {
            return Ok(None);
        }
        Target::FactoryWallet
    } else if code[3..] == forwarder[..] {
        Target::Account
    } else {
        return Ok(None);
    };
    Ok(published_release(provider, factory, target)
        .await?
        .map(kind))
}

/// The release of `target`, when `factory` published it.
async fn published_release<P: Provider>(
    provider: &P,
    factory: Address,
    target: Address,
) -> Result<Option<Release>> {
    let release = read_release(provider, target).await?;
    let wallet_factory = WalletFactory::new(factory, provider);
    let published = answer(
        wallet_factory.release(release.version).call().await,
        REVERTS,
    )?;
    let vouched = release.implementation != Address::ZERO
        && published == Some(release.implementation);
    Ok(vouched.then_some(release))
}

/// Whether `factory` puts a wallet with `target`'s genesis identity at `target`.
async fn is_factory_wallet<P: Provider>(
    provider: &P,
    factory: Address,
    target: Address,
) -> Result<bool> {
    let wallet = IWebWallet::new(target, provider);
    let Some(genesis) = answer(wallet.genesisIdentity().call().await, FAILS)? else {
        return Ok(false);
    };
    let wallet_factory = WalletFactory::new(factory, provider);
    let address =
        wallet_factory.walletAddress(genesis.platformId, genesis.idNode, genesis.salt);
    Ok(answer(address.call().await, REVERTS)? == Some(target))
}

/// A revert, the one failure of a call to the trusted factory.
const REVERTS: &[i64] = &[3];
/// A revert or an EVM halt as anvil 1.8.5 and reth report it (-32003), the
/// failures of a call into code the target controls. Other nodes report a
/// halt with codes that also mean a node error: anvil 1.7.1 -32603, geth
/// -32000.
const FAILS: &[i64] = &[3, -32003];

/// A call's answer: `None` when it fails with one of `codes` or answers what
/// does not decode; `Err` for any other error.
fn answer<T>(result: alloy::contract::Result<T>, codes: &[i64]) -> Result<Option<T>> {
    use alloy::contract::Error as E;
    match result {
        Ok(value) => Ok(Some(value)),
        Err(E::AbiError(_) | E::ZeroData(..)) => Ok(None),
        Err(E::TransportError(e))
            if e.as_error_resp()
                .is_some_and(|resp| codes.contains(&resp.code)) =>
        {
            Ok(None)
        }
        Err(e) => Err(Error::Rpc {
            detail: format!("a wallet check's call failed: {e}"),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "testing")]
    #[tokio::test]
    async fn no_code_and_a_non_wallet_contract_are_not_vouched_for() {
        let provider =
            alloy::providers::ProviderBuilder::new().connect_anvil_with_wallet();
        let owner = provider.get_accounts().await.unwrap()[0];
        let artifacts = crate::Artifacts::embedded();
        let stack = crate::testing::deploy_wallet_stack(&provider, &artifacts, owner)
            .await
            .unwrap();
        for target in [Address::repeat_byte(0x99), stack.escrow] {
            let vouched = check_target(&provider, stack.factory, stack.forwarder, target);
            assert_eq!(vouched.await.unwrap(), None, "{target}");
        }
    }

    /// `keccak256(abi.encode(uint256(keccak256(id)) - 1)) & ~bytes32(uint256(0xff))`.
    #[test]
    fn the_release_slot_is_its_erc7201_derivation() {
        use alloy::primitives::{
            keccak256,
            U256,
        };
        let id = U256::from_be_bytes(keccak256("libid.webwallet.release").0);
        let mut slot = keccak256((id - U256::from(1)).to_be_bytes::<32>());
        slot[31] = 0;
        assert_eq!(slot, RELEASE_SLOT);
    }
}
