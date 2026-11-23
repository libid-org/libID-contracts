//! What a relayer needs from the crate: the batch codec, the AUTHORIZED data
//! decoder, the gas constants its quote adds, and the target check.
#![cfg(feature = "testing")]

use alloy::{
    primitives::{
        aliases::U48,
        *,
    },
    providers::{
        ext::AnvilApi,
        Provider,
        ProviderBuilder,
    },
};
use libid_contracts::{
    bindings::wallet::*,
    gas::*,
    testing::deploy_wallet_stack,
    wallet_target::*,
    Artifacts,
};

const FEE: U256 = U256::from_limbs([10_000_000_000_000_000, 0, 0, 0]);

/// The README's onboarding batch, its calldata opaque: link, bind, claim, refund.
fn readme_batch() -> Vec<Execution> {
    let call = |target: u8, value, data: Vec<u8>| Execution {
        target: Address::repeat_byte(target),
        value,
        callData: data.into(),
    };
    let mut link = vec![0xa1, 0xb2, 0xc3, 0xd4];
    link.extend([1; 36]);
    vec![
        call(0x11, FEE, link),
        call(0x22, U256::ZERO, vec![0xde, 0xad, 0xbe, 0xef]),
        call(0x33, U256::ZERO, vec![0x55; 64]),
        call(0x44, FEE, vec![]),
    ]
}

#[test]
fn the_readme_batch_round_trips_and_a_noncanonical_batch_is_refused() {
    let encoded = encode_executions(&readme_batch());
    // cast keccak $(cast abi-encode "f((address,uint256,bytes)[])" <the batch>)
    let cast =
        b256!("0x745146e5c47ae9d9704d0c7e4f80457534d10b87b443a2a7f3389460201f600e");
    assert_eq!(keccak256(&encoded), cast);
    let decoded = decode_executions(&encoded).expect("canonical");
    assert_eq!(decoded, readme_batch());

    // Each decodes leniently (cast) to the same calls; the wallet refuses all.
    let canonical = encoded.to_vec();
    let mut trailing = canonical.clone();
    trailing.extend([0; 32]);
    let mut moved = canonical.clone();
    moved[31] = 0x40;
    moved.splice(32..32, [0; 32]);
    let mut dirty = canonical.clone();
    dirty[192] = 1; // the high byte of the first call's target word
    let cut = canonical[..canonical.len() - 1].to_vec();
    for bad in [trailing, moved, dirty, cut] {
        assert!(decode_executions(&bad).is_err());
    }
}

/// The decoder inverts `authorized_data`, `nonce`, which the data does not
/// carry, as zero. Data with a pad word after the head, a dirty `uint48` or a
/// cut tail decodes leniently or not at all, and never re-encodes to itself.
#[test]
fn authorized_data_round_trips_and_only_canonical_data_re_encodes() {
    let message = ExecuteMessage {
        execution_calldata: encode_executions(&readme_batch()),
        value: FEE,
        at: U48::from(1_800_000_000u64),
        nonce: U256::ZERO,
        deadline: U48::from(1_800_000_600u64),
        call_gas: U256::from(200_000),
    };
    let authorization = ExecuteAuthorization {
        signatures: vec![SessionSignature {
            key: Bytes::from([0x0a; 20]),
            signature: Bytes::from([0x5a; 65]),
        }],
        calls: vec![CallProof::default(); 4],
        domain_proof: vec![B256::repeat_byte(7)],
        paymaster_proof: vec![],
    };
    let data = message.authorized_data(authorization.clone()).to_vec();
    let decoded = ExecuteMessage::from_authorized_data(&data).expect("decodes");
    assert_eq!(decoded, (message, authorization));
    assert_eq!(decoded.0.authorized_data(decoded.1.clone()).to_vec(), data);

    let mut moved = data.clone();
    moved.splice(160..160, [0; 32]);
    for at in [0..32, 128..160] {
        let offset = U256::from_be_slice(&moved[at.clone()]) + U256::from(32);
        moved[at].copy_from_slice(&offset.to_be_bytes::<32>());
    }
    let lenient = ExecuteMessage::from_authorized_data(&moved).expect("lenient decode");
    assert_eq!(lenient, decoded);
    let mut dirty = data.clone();
    dirty[64] = 0xff; // the deadline word's high byte
    for bad in [moved, dirty, data[..data.len() - 1].to_vec(), vec![]] {
        if let Ok((m, a)) = ExecuteMessage::from_authorized_data(&bad) {
            assert_ne!(m.authorized_data(a).to_vec(), bad);
        }
    }
}

const SNAPSHOT: &str = include_str!("../../../solidity/snapshots/wallet-verify.json");

#[test]
fn gas_reads_the_vendored_snapshot_and_refuses_a_renamed_entry() {
    let json: serde_json::Value = serde_json::from_str(SNAPSHOT).unwrap();
    let entry = |name: &str| json[name].as_str().expect(name).parse::<u64>().unwrap();
    let gas = WalletGas::vendored();
    assert_eq!(gas.verify(KeyKind::Ecdsa), entry("verify(ECDSA)"));
    assert_eq!(gas.verify(KeyKind::WebAuthn), entry("verify(WebAuthn)"));
    assert_eq!(gas.verify(KeyKind::P256), entry("verify(P-256)"));
    let (refund, per_call) = (entry("rules(refund)"), entry("rules(per call)"));
    assert_eq!(
        (gas.rules(1), gas.rules(3)),
        (refund, refund + 2 * per_call)
    );
    assert_eq!(CALL_OVERHEAD, 20_000); // IWebWallet.sol

    assert!(WalletGas::from_json(SNAPSHOT).is_ok());
    let names = [
        "verify(ECDSA)",
        "verify(WebAuthn)",
        "verify(P-256)",
        "rules(refund)",
    ];
    for name in names.into_iter().chain(["rules(per call)"]) {
        let renamed = SNAPSHOT.replace(&format!("\"{name}\""), "\"renamed\"");
        assert_ne!(renamed, SNAPSHOT);
        assert!(WalletGas::from_json(&renamed).is_err(), "{name}");
    }
}

/// By hand: 100 + 11 (n - 1), never below 1 call's, saturating.
#[test]
fn rules_adds_each_further_call_and_saturates() {
    let snapshot = |refund: &str, per_call: &str| {
        WalletGas::from_json(&format!(
            r#"{{"verify(ECDSA)": "1", "verify(WebAuthn)": "2", "verify(P-256)": "3",
                "rules(refund)": "{refund}", "rules(per call)": "{per_call}"}}"#
        ))
    };
    let gas = snapshot("100", "11").unwrap();
    assert_eq!(
        [0, 1, 2, 3, 4].map(|n| gas.rules(n)),
        [100, 100, 111, 122, 133]
    );
    assert_eq!(gas.rules(u64::MAX), u64::MAX);
    assert!(snapshot("100", "0xb").is_err());
}

/// The contracts vouch for a factory wallet and an account delegated to the
/// forwarder whose slot holds a published release, not for an unpublished
/// release planted in the slot, an empty slot or another delegate.
#[tokio::test]
async fn the_contracts_vouch_for_their_wallets_only() {
    let provider = ProviderBuilder::new().connect_anvil_with_wallet();
    let owner = provider.get_accounts().await.unwrap()[0];
    let artifacts = Artifacts::embedded();
    let stack = deploy_wallet_stack(&provider, &artifacts, owner)
        .await
        .unwrap();
    // cast index-erc7201 libid.webwallet.release
    let slot =
        b256!("0xe1dba8fb066a3b169f681c6818aeab86343e7484c7e0cee1cbf00e41a55c2800");
    assert_eq!(RELEASE_SLOT, slot);
    let entry_point = address!("0x433709009B8330FDa32311DF1C2AFA402eD8D009");
    assert_eq!(stack.entry_point, entry_point);
    assert!(!provider.get_code_at(entry_point).await.unwrap().is_empty());
    assert_eq!(stack.release.version, 1);
    let vouch = |a| check_target(&provider, stack.factory, stack.forwarder, a);

    let factory = WalletFactory::new(stack.factory, &provider);
    let (id_node, salt) = (B256::repeat_byte(0xa1), U256::ZERO);
    let wallet = factory.walletAddress(stack.platform, id_node, salt);
    let wallet = wallet.call().await.unwrap();
    let create = factory.createWallet(stack.platform, id_node, salt);
    create.send().await.unwrap().get_receipt().await.unwrap();
    let release = read_release(&provider, wallet).await.unwrap();
    assert_eq!(release, stack.release);
    assert_eq!(
        vouch(wallet).await.unwrap(),
        Some(Target::FactoryWallet(stack.release))
    );

    let account = Address::repeat_byte(0x77);
    let delegate = |to: Address| {
        let code = [&[0xef, 0x01, 0x00][..], to.as_slice()].concat();
        provider.anvil_set_code(account, code.into())
    };
    let plant = |implementation: Address, version: u64| {
        let word =
            U256::from_be_slice(implementation.as_slice()) | U256::from(version) << 160;
        provider.anvil_set_storage_at(account, slot.into(), B256::from(word))
    };
    delegate(stack.forwarder).await.unwrap();
    assert_eq!(vouch(account).await.unwrap(), None, "empty release slot");
    plant(stack.release.implementation, 1).await.unwrap();
    assert_eq!(
        vouch(account).await.unwrap(),
        Some(Target::Account(stack.release))
    );
    // `uint64(word >> 160)` drops the bits above the version.
    let word = U256::from_be_slice(stack.release.implementation.as_slice())
        | U256::from(1) << 160
        | U256::from(1) << 230;
    provider
        .anvil_set_storage_at(account, slot.into(), B256::from(word))
        .await
        .unwrap();
    assert_eq!(
        vouch(account).await.unwrap(),
        Some(Target::Account(stack.release))
    );

    let published = stack.release.implementation;
    for (implementation, version) in [(Address::repeat_byte(0xba), 1), (published, 2)] {
        plant(implementation, version).await.unwrap();
        let read = read_release(&provider, account).await.unwrap();
        assert_eq!(
            (read.implementation, read.version),
            (implementation, version)
        );
        assert_eq!(vouch(account).await.unwrap(), None, "{read:?}");
    }
    plant(stack.release.implementation, 1).await.unwrap();
    delegate(stack.factory).await.unwrap();
    assert_eq!(vouch(account).await.unwrap(), None, "another delegate");
    let code = [&[0xee, 0x01, 0x00][..], stack.forwarder.as_slice()].concat();
    provider.anvil_set_code(account, code.into()).await.unwrap();
    assert_eq!(
        vouch(account).await.unwrap(),
        None,
        "no delegation, no wallet"
    );
}

/// A factory call says "not a wallet" on a revert or no data, the target's
/// `genesisIdentity` also on a halt; any other error, a rate limit or no
/// answer is an error, never `None`.
#[tokio::test]
async fn a_check_call_is_none_only_when_the_node_answered_it() {
    use alloy::transports::mock::Asserter;
    let error = |code: i64, message: &str| {
        Some(Err(serde_json::json!({"code": code, "message": message})))
    };
    let delegated = [&[0xef, 0x01, 0x00][..], &[0; 20]].concat();
    for (genesis, factory) in [(true, None), (false, Some(Bytes::from(delegated)))] {
        for (call, none) in [
            (error(3, "execution reverted"), true),
            (error(-32003, "EVM error InvalidFEOpcode"), genesis),
            (error(-32000, "missing trie node"), false),
            (error(-32603, "internal error"), false),
            (error(429, "too many requests"), false),
            (Some(Ok(())), true),
            (None, false),
        ] {
            let asserter = Asserter::new();
            asserter.push_success(&factory.clone().unwrap_or(Bytes::from([0x60, 0x80])));
            if !genesis {
                asserter.push_success(&B256::ZERO);
            }
            match call.clone() {
                Some(Ok(())) => asserter.push_success(&Bytes::new()),
                Some(Err(error)) => {
                    asserter.push_failure(serde_json::from_value(error).unwrap())
                }
                None => {}
            }
            let provider = ProviderBuilder::new().connect_mocked_client(asserter);
            let target = Address::repeat_byte(0x66);
            let checked =
                check_target(&provider, Address::ZERO, Address::ZERO, target).await;
            assert_eq!(
                checked.ok(),
                none.then_some(None),
                "{call:?}, genesis {genesis}"
            );
        }
    }
}
