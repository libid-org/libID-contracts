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
        version: (word >> 160usize).saturating_to(),
    })
}

/// Whether `factory` and `forwarder` vouch for `target`, and its release.
/// `None` for anything else, including an account whose calls fail or
/// answer junk; `Err` only when the node gives no answer.
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
    let wallet_factory = WalletFactory::new(factory, provider);
    let kind: fn(Release) -> Target = if code.is_empty() {
        return Ok(None);
    } else if !delegated {
        let wallet = IWebWallet::new(target, provider);
        let Some(genesis) = answer(wallet.genesisIdentity().call().await)? else {
            return Ok(None);
        };
        let address = wallet_factory.walletAddress(
            genesis.platformId,
            genesis.idNode,
            genesis.salt,
        );
        if answer(address.call().await)? != Some(target) {
            return Ok(None);
        }
        Target::FactoryWallet
    } else if code[3..] == forwarder[..] {
        Target::Account
    } else {
        return Ok(None);
    };
    let release = read_release(provider, target).await?;
    let published = answer(wallet_factory.release(release.version).call().await)?;
    let vouched = release.implementation != Address::ZERO
        && published == Some(release.implementation);
    Ok(vouched.then(|| kind(release)))
}

/// A call's answer: `None` when the call fails in the EVM or answers what
/// does not decode; `Err` when the node gives no answer, or asks for a retry.
fn answer<T>(result: alloy::contract::Result<T>) -> Result<Option<T>> {
    use alloy::contract::Error as E;
    match result {
        Ok(value) => Ok(Some(value)),
        Err(E::AbiError(_) | E::ZeroData(..)) => Ok(None),
        Err(E::TransportError(e))
            if e.as_error_resp().is_some_and(|resp| !resp.is_retry_err()) =>
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

    #[test]
    fn the_release_slot_is_the_contracts() {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../solidity/contracts/wallet/WalletRelease.sol"
        );
        let source = std::fs::read_to_string(path).expect(path);
        assert!(
            source.contains(&format!("bytes32 internal constant SLOT = {RELEASE_SLOT};"))
        );
    }
}
