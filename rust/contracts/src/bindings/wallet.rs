//! Bindings for the web wallet (`solidity/contracts/wallet/`), read from the
//! compiled artifacts, and what its signers sign. A wallet's whole ABI is
//! [`IWebWallet`]: its proxy routes every call by the release slot.

use alloy::{
    dyn_abi::Eip712Domain,
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
        IWebWallet,
        "abi/IWebWallet.json"
    );
}

/// The structs of `IIdentityAdmin`, the half of [`IWebWallet`] that
/// `IdentityAdmin` answers.
pub use web_wallet::IIdentityAdmin::{
    Allowance,
    AllowanceState,
    Policy,
    RootOperation,
    Rules,
    Session,
};
/// `wallet/IWebWallet.sol`: every external of a wallet, on its address.
pub use web_wallet::IWebWallet;
/// The ERC-4337 operation `IWebWallet.validateUserOp` takes.
pub use web_wallet::IWebWallet::PackedUserOperation;

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

/// `wallet/WalletRegistry.sol`: verifies a wallet's link and login proofs.
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

/// `wallet/WalletFactory.sol`: numbered releases, and wallets at addresses
/// fixed by identity.
pub use wallet_factory::WalletFactory;

#[allow(
    clippy::too_many_arguments,
    missing_docs,
    non_camel_case_types,
    unused_attributes
)]
mod wallet_proxy {
    alloy::sol!(
        #[sol(rpc, all_derives)]
        WalletProxy,
        "abi/WalletProxy.json"
    );
}

/// `wallet/WalletProxy.sol`: a factory wallet's code.
pub use wallet_proxy::WalletProxy;

#[allow(
    clippy::too_many_arguments,
    missing_docs,
    non_camel_case_types,
    unused_attributes
)]
mod wallet_forwarder {
    alloy::sol!(
        #[sol(rpc, all_derives)]
        WalletForwarder,
        "abi/WalletForwarder.json"
    );
}

/// `wallet/WalletForwarder.sol`: the EIP-7702 delegate of an account.
pub use wallet_forwarder::WalletForwarder;

#[allow(missing_docs)]
mod signed {
    alloy::sol! {
        #[derive(Debug, Default, PartialEq, Eq)]
        struct SessionSignature {
            bytes key;
            bytes signature;
        }

        #[derive(Debug, Default, PartialEq, Eq)]
        struct CallProof {
            uint256 maxValue;
            bytes32[] proof;
        }

        #[derive(Debug, Default, PartialEq, Eq)]
        struct Authorization {
            SessionSignature[] signatures;
            uint48 at;
            CallProof[] calls;
            bytes32[] domainProof;
            bytes32[] paymasterProof;
        }

        #[derive(Debug, PartialEq, Eq)]
        struct Execute {
            bytes32 mode;
            bytes executionCalldata;
            uint256 value;
            uint48 at;
            uint256 nonce;
            uint48 deadline;
            uint256 callGas;
        }

        #[derive(Debug, PartialEq, Eq)]
        struct UserOperation {
            bytes32 userOpHash;
        }
    }
}

/// `IWalletCore.Authorization`, which no external's ABI carries.
/// [`encode_authorization`] makes it a signature.
pub use signed::Authorization;
/// `IWalletCore.CallProof`.
pub use signed::CallProof;
/// The EIP-712 `Execute` type of an `AUTHORIZED_MODE` batch. Build messages
/// with [`ExecuteMessage`], which sets `mode`.
pub use signed::Execute;
/// `IWalletCore.SessionSignature`.
pub use signed::SessionSignature;

impl Rules {
    /// Sorts the allowances into the strictly ascending token order the
    /// wallet requires. Sort before hashing and building calls.
    pub fn sort_allowances(&mut self) {
        self.allowances.sort_by_key(|allowance| allowance.token);
    }

    /// `rulesHashOf(rules)`: stored in the session record, it keys the
    /// session's allowance counters.
    pub fn rules_hash(&self) -> B256 {
        keccak256(
            (
                self.scopeRoot,
                self.domainsRoot,
                self.paymastersRoot,
                self.allowances.clone(),
            )
                .abi_encode_params(),
        )
    }
}

impl Policy {
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

/// What each signer signs below quorum:
/// `keccak256(abi.encode(hash, at, keccak256(governingKey)))`, where the
/// governing key is the first signature's. For a UserOperation, `hash` is
/// [`user_operation_digest`]; for an `AUTHORIZED_MODE` batch,
/// [`ExecuteMessage::digest`]; for ERC-1271, the ERC-7739 nested hash, at 0.
pub fn below_quorum_hash(hash: B256, at: U48, governing_key: &[u8]) -> B256 {
    keccak256((hash, at, keccak256(governing_key)).abi_encode_params())
}

/// `abi.encode(authorization)`: a UserOperation's signature, the inner
/// signature of an ERC-1271 check (at 0), and the last field of
/// [`ExecuteMessage::authorized_data`].
pub fn encode_authorization(authorization: &Authorization) -> Bytes {
    authorization.abi_encode().into()
}

/// `AUTHORIZED_MODE` of `wallet/IWebWallet.sol`: the batch call type, the
/// default exec type, the selector
/// `bytes4(keccak256("libid.webwallet.authorized"))` and a zero payload.
pub const AUTHORIZED_MODE: B256 =
    b256!("0x01000000000018f4a5a900000000000000000000000000000000000000000000");

/// The EntryPoint nonce key an `AUTHORIZED_MODE` batch consumes.
/// UserOperations may use any key.
pub const DIRECT_NONCE_KEY: U192 = U192::ZERO;

/// `keccak256("libid.webwallet.link-identity.v2")`: a link proof's operation
/// domain.
pub const LINK_IDENTITY_DOMAIN: B256 =
    b256!("0xc54c5212c2b86ae85d3512fac77763a8c85db053325daa622553f8d8e3e9317c");
/// `keccak256("libid.webwallet.add-session.v2")`: `addSessionByLogin`'s
/// domain.
pub const ADD_SESSION_DOMAIN: B256 =
    b256!("0x7fc89e16ebf11143534bd43e4c66eec788fbe6ad2b136b94076fdd20785c81d3");
/// `keccak256("libid.webwallet.remove-sessions.v2")`:
/// `removeSessionsByLogin`'s domain.
pub const REMOVE_SESSIONS_DOMAIN: B256 =
    b256!("0x38622a2e4869524e17fb3b190422abe5797dfb9ae1577aedd96ec002d8fbc897");

/// The transaction data a link or login proof commits:
/// `abi.encode(chainId, wallet, submitter, key, policyHash)`, where an empty
/// `key` (a link only, or a removal) commits policy hash 0. `submitter` is
/// the address that calls the wallet with the proof: the wallet itself for a
/// link or for a login in its own batch.
pub fn transaction_data(
    chain_id: u64,
    wallet: Address,
    submitter: Address,
    key: &Bytes,
    policy: &Policy,
) -> Bytes {
    let policy_hash = if key.is_empty() {
        B256::ZERO
    } else {
        policy.policy_hash()
    };
    (
        U256::from(chain_id),
        wallet,
        submitter,
        key.clone(),
        policy_hash,
    )
        .abi_encode_params()
        .into()
}

/// The domain's salt, `keccak256(abi.encode(epoch, rootEpoch))`. A wallet
/// reports it in `eip712Domain()`; a `reset` or a move of the root epoch
/// changes it.
pub fn wallet_salt(epoch: B256, root_epoch: u32) -> B256 {
    keccak256((epoch, root_epoch).abi_encode_params())
}

/// The wallet's EIP-712 domain: name `WebWallet`, the release's version as a
/// decimal string, `chain_id`, the wallet's address, and `salt`, the one
/// `eip712Domain()` reports ([`wallet_salt`]). A bump to another release
/// changes it too.
pub fn wallet_domain(
    chain_id: u64,
    wallet: Address,
    version: u64,
    salt: B256,
) -> Eip712Domain {
    eip712_domain! {
        name: "WebWallet",
        version: version.to_string(),
        chain_id: chain_id,
        verifying_contract: wallet,
        salt: salt,
    }
}

/// What the signers of `userOpHash` sign: `UserOperation(bytes32 userOpHash)`
/// under [`wallet_domain`]. Below quorum, [`below_quorum_hash`] of it.
pub fn user_operation_digest(
    user_op_hash: B256,
    chain_id: u64,
    wallet: Address,
    version: u64,
    salt: B256,
) -> B256 {
    signed::UserOperation {
        userOpHash: user_op_hash,
    }
    .eip712_signing_hash(&wallet_domain(chain_id, wallet, version, salt))
}

/// What the signers of `execute(AUTHORIZED_MODE, data)` sign, besides
/// `mode`, which is always [`AUTHORIZED_MODE`].
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ExecuteMessage {
    /// The ERC-7579 batch: `abi.encode(Execution[])`.
    pub execution_calldata: Bytes,
    /// The `msg.value` the batch must be sent with.
    pub value: U256,
    /// `Authorization.at`.
    pub at: U48,
    /// The wallet's EntryPoint nonce under [`DIRECT_NONCE_KEY`] before the
    /// batch.
    pub nonce: U256,
    /// The last second the batch may run.
    pub deadline: U48,
    /// The gas each of the batch's calls gets.
    pub call_gas: U256,
}

/// [`Authorization`] without `at`, which [`ExecuteMessage::authorized_data`]
/// takes from the message.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ExecuteAuthorization {
    /// `Authorization.signatures`.
    pub signatures: Vec<SessionSignature>,
    /// `Authorization.calls`: `calls[i]` is for the batch's i-th execution.
    pub calls: Vec<CallProof>,
    /// `Authorization.domainProof`.
    pub domain_proof: Vec<B256>,
    /// `Authorization.paymasterProof`.
    pub paymaster_proof: Vec<B256>,
}

impl ExecuteMessage {
    /// The EIP-712 hash the signers sign, under [`wallet_domain`]. Below
    /// quorum each signer signs [`below_quorum_hash`] of it.
    pub fn digest(
        &self,
        chain_id: u64,
        wallet: Address,
        version: u64,
        salt: B256,
    ) -> B256 {
        Execute {
            mode: AUTHORIZED_MODE,
            executionCalldata: self.execution_calldata.clone(),
            value: self.value,
            at: self.at,
            nonce: self.nonce,
            deadline: self.deadline,
            callGas: self.call_gas,
        }
        .eip712_signing_hash(&wallet_domain(chain_id, wallet, version, salt))
    }

    /// `data` of `execute(AUTHORIZED_MODE, data)` for this message:
    /// `abi.encode(executionCalldata, value, deadline, callGas, abi.encode(authorization))`,
    /// the authorization's `at` this message's.
    pub fn authorized_data(&self, authorization: ExecuteAuthorization) -> Bytes {
        let authorization = Authorization {
            signatures: authorization.signatures,
            at: self.at,
            calls: authorization.calls,
            domainProof: authorization.domain_proof,
            paymasterProof: authorization.paymaster_proof,
        };
        (
            self.execution_calldata.clone(),
            self.value,
            self.deadline,
            self.call_gas,
            encode_authorization(&authorization),
        )
            .abi_encode_params()
            .into()
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use serde::Deserialize;

    use super::*;

    /// The vector's policy, whose hashes and transaction data it carries.
    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct VectorPolicy {
        valid_after: u64,
        valid_until: u64,
        admin: bool,
        signers: u8,
        rules: VectorRules,
    }

    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct VectorRules {
        scope_root: B256,
        domains_root: B256,
        paymasters_root: B256,
        allowances: Vec<VectorAllowance>,
    }

    #[derive(Deserialize)]
    struct VectorAllowance {
        token: Address,
        amount: u128,
        period: u64,
    }

    impl From<VectorPolicy> for Policy {
        fn from(p: VectorPolicy) -> Self {
            Policy {
                validAfter: U48::from(p.valid_after),
                validUntil: U48::from(p.valid_until),
                admin: p.admin,
                signers: p.signers,
                rules: Rules {
                    scopeRoot: p.rules.scope_root,
                    domainsRoot: p.rules.domains_root,
                    paymastersRoot: p.rules.paymasters_root,
                    allowances: p
                        .rules
                        .allowances
                        .into_iter()
                        .map(|a| Allowance {
                            token: a.token,
                            amount: a.amount,
                            period: U48::from(a.period),
                        })
                        .collect(),
                },
            }
        }
    }

    fn vector() -> Vector {
        let path = format!(
            "{}/../../solidity/contracts/wallet/test/fixtures/direct-execute-vector.json",
            env!("CARGO_MANIFEST_DIR")
        );
        serde_json::from_str(&fs::read_to_string(&path).expect(&path)).expect(&path)
    }

    /// The vector's rules and policy hashes, which `cast` computes outside
    /// Solidity.
    #[test]
    fn hashes_match_the_vector() {
        let v = vector();
        let policy = Policy::from(v.policy);
        assert_eq!(policy.rules.rules_hash(), v.rules_hash);
        assert_eq!(policy.policy_hash(), v.policy_hash);
    }

    /// `solidity/contracts/wallet/test/fixtures/direct-execute-vector.json`,
    /// written by `cast` alone, which `WalletAbiTest.test_theClientVector`
    /// checks too.
    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct Vector {
        authorized_mode: B256,
        execute_typehash: B256,
        user_operation_typehash: B256,
        chain_id: u64,
        wallet: Address,
        version: u64,
        epoch: B256,
        root_epoch: u32,
        salt: B256,
        nonce: u64,
        execution_calldata: Bytes,
        value: u64,
        at: u64,
        deadline: u64,
        call_gas: u64,
        session_key: Bytes,
        signature: Bytes,
        call_max_value: u64,
        call_proof: B256,
        domain_proof: B256,
        paymaster_proof: B256,
        authorization_hash: B256,
        data_hash: B256,
        digest: B256,
        epoch_zero_digest: B256,
        below_quorum_hash: B256,
        user_op_hash: B256,
        user_op_digest: B256,
        link_identity_domain: B256,
        add_session_domain: B256,
        remove_sessions_domain: B256,
        submitter: Address,
        policy: VectorPolicy,
        rules_hash: B256,
        policy_hash: B256,
        keyed_transaction_data: Bytes,
        keyless_transaction_data: Bytes,
    }

    #[test]
    fn the_client_helpers_match_the_vector() {
        let v = vector();

        assert_eq!(AUTHORIZED_MODE, v.authorized_mode);
        assert_eq!(
            keccak256(Execute::eip712_encode_type().as_bytes()),
            v.execute_typehash
        );
        assert_eq!(
            keccak256(signed::UserOperation::eip712_encode_type().as_bytes()),
            v.user_operation_typehash
        );

        let execute = ExecuteMessage {
            execution_calldata: v.execution_calldata,
            value: U256::from(v.value),
            at: U48::from(v.at),
            // Nonce key 0: the full nonce is the sequence.
            nonce: (U256::from(DIRECT_NONCE_KEY) << 64) | U256::from(v.nonce),
            deadline: U48::from(v.deadline),
            call_gas: U256::from(v.call_gas),
        };
        let authorization = ExecuteAuthorization {
            signatures: vec![SessionSignature {
                key: v.session_key.clone(),
                signature: v.signature,
            }],
            calls: vec![CallProof {
                maxValue: U256::from(v.call_max_value),
                proof: vec![v.call_proof],
            }],
            domain_proof: vec![v.domain_proof],
            paymaster_proof: vec![v.paymaster_proof],
        };
        let data = execute.authorized_data(authorization.clone());
        assert_eq!(keccak256(&data), v.data_hash);
        let encoded = encode_authorization(&Authorization {
            signatures: authorization.signatures,
            at: execute.at,
            calls: authorization.calls,
            domainProof: authorization.domain_proof,
            paymasterProof: authorization.paymaster_proof,
        });
        assert_eq!(keccak256(&encoded), v.authorization_hash);

        assert_eq!(wallet_salt(v.epoch, v.root_epoch), v.salt);
        let digest = execute.digest(v.chain_id, v.wallet, v.version, v.salt);
        assert_eq!(digest, v.digest);
        assert_eq!(
            execute.digest(v.chain_id, v.wallet, v.version, wallet_salt(B256::ZERO, 0)),
            v.epoch_zero_digest
        );
        assert_eq!(
            below_quorum_hash(digest, execute.at, &v.session_key),
            v.below_quorum_hash
        );
        assert_eq!(
            user_operation_digest(
                v.user_op_hash,
                v.chain_id,
                v.wallet,
                v.version,
                v.salt
            ),
            v.user_op_digest
        );

        for (constant, name, expected) in [
            (
                LINK_IDENTITY_DOMAIN,
                "libid.webwallet.link-identity.v2",
                v.link_identity_domain,
            ),
            (
                ADD_SESSION_DOMAIN,
                "libid.webwallet.add-session.v2",
                v.add_session_domain,
            ),
            (
                REMOVE_SESSIONS_DOMAIN,
                "libid.webwallet.remove-sessions.v2",
                v.remove_sessions_domain,
            ),
        ] {
            assert_eq!(constant, keccak256(name), "{name}");
            assert_eq!(constant, expected, "{name}");
        }
        let policy = Policy::from(v.policy);
        assert_eq!(policy.policy_hash(), v.policy_hash);
        assert_eq!(
            transaction_data(v.chain_id, v.wallet, v.submitter, &v.session_key, &policy),
            v.keyed_transaction_data
        );
        assert_eq!(
            transaction_data(v.chain_id, v.wallet, v.submitter, &Bytes::new(), &policy),
            v.keyless_transaction_data
        );
    }

    /// Sorting puts any order in token order; hashing keeps the order given.
    #[test]
    fn allowances_sort_by_token() {
        let allowance = |token: u8| Allowance {
            token: [token; 20].into(),
            amount: token.into(),
            period: U48::from(1),
        };
        let rules = |tokens: &[u8]| Rules {
            scopeRoot: B256::ZERO,
            domainsRoot: B256::ZERO,
            paymastersRoot: B256::ZERO,
            allowances: tokens.iter().copied().map(allowance).collect(),
        };
        let sorted = rules(&[1, 2, 0xff]);
        let mut unsorted = rules(&[0xff, 1, 2]);
        assert_ne!(unsorted.rules_hash(), sorted.rules_hash());
        unsorted.sort_allowances();
        assert_eq!(unsorted.abi_encode(), sorted.abi_encode());
        assert_eq!(unsorted.rules_hash(), sorted.rules_hash());
    }
}
