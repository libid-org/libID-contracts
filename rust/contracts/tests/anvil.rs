//! Anvil integration tests: deploy the identity stack from the embedded
//! artifacts and read views back. Requires the `anvil` binary on PATH
//! (foundry).

use alloy::{
    primitives::{
        keccak256,
        Address,
        U256,
    },
    providers::{
        Provider,
        ProviderBuilder,
    },
};
use libid_contracts::{
    bindings::{
        ceremony::{
            CeremonyProofVerifier,
            GoogleJwtRoots,
            NotaryService,
        },
        identity::IdentityNames,
    },
    deploy::{
        deploy_behind_proxy,
        deploy_contract,
        upgrade_uups,
    },
    Artifacts,
};

fn test_provider() -> impl Provider + Clone {
    ProviderBuilder::new().connect_anvil_with_wallet()
}

async fn default_signer(provider: &impl Provider) -> Address {
    provider.get_accounts().await.expect("accounts")[0]
}

/// (a) The identity stack in the order `script/Deploy.s.sol` uses: the
/// Notary Service first, then the Proof Verifier, the naming system given a
/// keyspace and pointed at the Proof Verifier, and the Google JWT root list
/// pointed at the Notary Service — every one behind an ERC1967 proxy. Then the views
/// that prove the wiring took.
#[tokio::test]
async fn deploys_the_identity_stack_behind_proxies() {
    let provider = test_provider();
    let artifacts = Artifacts::embedded();
    let deployer = default_signer(&provider).await;
    let notary_key = Address::repeat_byte(0x11);
    let fee = U256::from(1_000);

    let notary_proxy = deploy_behind_proxy(
        &provider,
        &artifacts,
        "NotaryService",
        &NotaryService::initializeCall {
            owner_: deployer,
            notary_: notary_key,
            fee_: fee,
        },
        None,
    )
    .await
    .unwrap();

    let verifier_proxy = deploy_behind_proxy(
        &provider,
        &artifacts,
        "CeremonyProofVerifier",
        &CeremonyProofVerifier::initializeCall { owner_: deployer },
        None,
    )
    .await
    .unwrap();

    let names_proxy = deploy_behind_proxy(
        &provider,
        &artifacts,
        "IdentityNames",
        &IdentityNames::initializeCall { owner_: deployer },
        None,
    )
    .await
    .unwrap();

    let roots_proxy = deploy_behind_proxy(
        &provider,
        &artifacts,
        "GoogleJwtRoots",
        &GoogleJwtRoots::initializeCall {
            owner_: deployer,
            notary_: notary_proxy,
        },
        None,
    )
    .await
    .unwrap();

    // Wire the naming system: the Proof Verifier it dispatches through, and
    // a keyspace. The platform id is the platform's own bare name: libID
    // namespaces only its own strings.
    let names = IdentityNames::new(names_proxy, &provider);
    names
        .setProofVerifier(verifier_proxy)
        .send()
        .await
        .unwrap()
        .get_receipt()
        .await
        .unwrap();
    let platform_id = keccak256(b"github");
    names
        .setPlatform(
            platform_id,
            IdentityNames::Rules {
                maxLength: 39,
                stripLeadingAt: true,
                isEmail: false,
                allowUnderscore: false,
                allowHyphen: true,
            },
        )
        .send()
        .await
        .unwrap()
        .get_receipt()
        .await
        .unwrap();

    // The Notary Service holds the key and the fee it was given.
    let notary = NotaryService::new(notary_proxy, &provider);
    assert!(notary.isTrustedNotary(notary_key).call().await.unwrap());
    assert_eq!(notary.fee().call().await.unwrap(), fee);

    // Nothing is registered against any version yet, and the Proof Verifier
    // says so rather than answering for a platform it cannot verify.
    let verifier = CeremonyProofVerifier::new(verifier_proxy, &provider);
    assert!(!verifier.verifiesPlatform(platform_id).call().await.unwrap());
    assert_eq!(
        verifier.verifierOf(platform_id, 1).call().await.unwrap(),
        Address::ZERO
    );

    assert_eq!(names.proofVerifier().call().await.unwrap(), verifier_proxy);
    // A platform that owns a keyspace and can verify nothing says so:
    // answering `address(0)` would tell the caller "nobody holds this name"
    // about a platform that is not wired yet.
    let unwired = names.resolveId(platform_id, "12345".into()).call().await;
    assert!(
        unwired.is_err(),
        "an unwired platform answered instead of reverting UnknownPlatform"
    );

    // The root list points at the Notary Service, quotes its fee, and starts
    // with both generations empty — so it wants a rotation before any Google
    // name can bind.
    let roots = GoogleJwtRoots::new(roots_proxy, &provider);
    assert_eq!(roots.notaryService().call().await.unwrap(), notary_proxy);
    assert_eq!(roots.quoteRotation().call().await.unwrap(), fee);
    assert!(roots.needsRotation().call().await.unwrap());
    let keys = roots.currentKeys().call().await.unwrap();
    assert_eq!(keys.current.observedAt, 0);
    assert!(keys.current.moduli.is_empty());
    assert_eq!(keys.previous.observedAt, 0);
    assert!(keys.previous.moduli.is_empty());
}

/// (b) The Notary Service lifecycle: deploy behind a proxy, add a second
/// trusted key with `setNotary`, change the fee with `setFee`, upgrade the
/// proxy to a freshly deployed implementation via `upgrade_uups`, and check
/// the rotated state survives the upgrade.
#[tokio::test]
async fn rotates_and_upgrades_the_notary_service() {
    let provider = test_provider();
    let artifacts = Artifacts::embedded();
    let deployer = default_signer(&provider).await;
    let first = Address::repeat_byte(0x11);
    let incoming = Address::repeat_byte(0x33);

    let notary_proxy = deploy_behind_proxy(
        &provider,
        &artifacts,
        "NotaryService",
        &NotaryService::initializeCall {
            owner_: deployer,
            notary_: first,
            fee_: U256::ZERO,
        },
        None,
    )
    .await
    .unwrap();

    let notary = NotaryService::new(notary_proxy, &provider);
    assert!(notary.isTrustedNotary(first).call().await.unwrap());
    assert!(!notary.isTrustedNotary(incoming).call().await.unwrap());
    assert_eq!(notary.fee().call().await.unwrap(), U256::ZERO);

    // Rotate: the incoming key is trusted before the outgoing one goes, so
    // attestations already made under `first` stay presentable meanwhile.
    notary
        .setNotary(incoming, true)
        .send()
        .await
        .unwrap()
        .get_receipt()
        .await
        .unwrap();
    notary
        .setNotary(first, false)
        .send()
        .await
        .unwrap()
        .get_receipt()
        .await
        .unwrap();
    notary
        .setFee(U256::from(7))
        .send()
        .await
        .unwrap()
        .get_receipt()
        .await
        .unwrap();
    assert!(!notary.isTrustedNotary(first).call().await.unwrap());
    assert!(notary.isTrustedNotary(incoming).call().await.unwrap());
    assert_eq!(notary.fee().call().await.unwrap(), U256::from(7));

    // Upgrade the proxy to a re-deployed implementation; state survives.
    let new_impl = upgrade_uups(
        &provider,
        &artifacts,
        notary_proxy,
        "NotaryService",
        Default::default(),
        None,
    )
    .await
    .unwrap();
    assert_ne!(new_impl, notary_proxy);
    assert!(!notary.isTrustedNotary(first).call().await.unwrap());
    assert!(notary.isTrustedNotary(incoming).call().await.unwrap());
    assert_eq!(notary.fee().call().await.unwrap(), U256::from(7));
    assert_eq!(notary.owner().call().await.unwrap(), deployer);
}

/// (c) The deterministic factory, from truly nothing: anvil is started
/// WITHOUT its predeployed CREATE2 deployer, so `ensure_factory` must
/// install it via the keyless presigned transaction (funding the one-time
/// signer first), then deploy the factory impl + proxy at their canonical
/// addresses. Then a Notary Service proxy goes through the factory at its
/// name-derived CREATE3 address.
#[tokio::test]
async fn bootstraps_the_deterministic_factory_and_deploys_through_it() {
    use alloy::{
        primitives::Bytes,
        sol_types::{
            SolCall,
            SolValue,
        },
    };
    use libid_contracts::{
        bindings::factory::LibidFactory,
        factory::{
            ensure_factory,
            factory_deploy,
            predict_address,
            predict_factory_address,
            CREATE2_DEPLOYER,
            FACTORY_GENESIS_ADMIN,
        },
    };

    let provider = ProviderBuilder::new()
        .connect_anvil_with_wallet_and_config(|anvil| {
            anvil.arg("--disable-default-create2-deployer")
        })
        .expect("anvil spawns");
    let artifacts = Artifacts::embedded();
    let deployer0 = default_signer(&provider).await;

    // Truly bare chain: no CREATE2 deployer.
    assert!(provider
        .get_code_at(CREATE2_DEPLOYER)
        .await
        .unwrap()
        .is_empty());

    let factory = ensure_factory(&provider, &artifacts).await.unwrap();
    assert_eq!(factory, predict_factory_address(&artifacts).unwrap());
    assert!(!provider.get_code_at(factory).await.unwrap().is_empty());

    // The instant the proxy exists it is owned by the baked genesis admin —
    // initialization was atomic with deployment.
    let factory_contract = LibidFactory::new(factory, &provider);
    assert_eq!(
        factory_contract.owner().call().await.unwrap(),
        FACTORY_GENESIS_ADMIN
    );

    // Rerun = read-only no-op.
    assert_eq!(
        ensure_factory(&provider, &artifacts).await.unwrap(),
        factory
    );

    // Hand ownership to the test signer: impersonate the genesis admin
    // (a placeholder address nobody holds a key for) through anvil.
    provider
        .raw_request::<_, serde_json::Value>(
            "anvil_setBalance".into(),
            (FACTORY_GENESIS_ADMIN, "0xde0b6b3a7640000"),
        )
        .await
        .unwrap();
    provider
        .raw_request::<_, serde_json::Value>(
            "anvil_impersonateAccount".into(),
            (FACTORY_GENESIS_ADMIN,),
        )
        .await
        .unwrap();
    let transfer = LibidFactory::transferOwnershipCall {
        newOwner: deployer0,
    }
    .abi_encode();
    provider
        .raw_request::<_, serde_json::Value>(
            "eth_sendTransaction".into(),
            (serde_json::json!({
                "from": FACTORY_GENESIS_ADMIN,
                "to": factory,
                "data": Bytes::from(transfer),
            }),),
        )
        .await
        .unwrap();
    factory_contract
        .acceptOwnership()
        .send()
        .await
        .unwrap()
        .get_receipt()
        .await
        .unwrap();
    assert_eq!(factory_contract.owner().call().await.unwrap(), deployer0);

    // A Notary Service PROXY through the factory: impl via plain CREATE (its
    // address doesn't matter), proxy creation code = ERC1967Proxy ++ (impl,
    // initData).
    let notary_key = Address::repeat_byte(0x11);
    let notary_impl = deploy_contract(
        &provider,
        artifacts.bytecode("NotaryService").unwrap(),
        "NotaryService (impl)",
    )
    .await
    .unwrap();
    let init_data = NotaryService::initializeCall {
        owner_: deployer0,
        notary_: notary_key,
        fee_: U256::from(7),
    }
    .abi_encode();
    let mut creation_code = artifacts.bytecode("ERC1967Proxy").unwrap().to_vec();
    creation_code
        .extend_from_slice(&(notary_impl, Bytes::from(init_data)).abi_encode_params());

    let predicted = predict_address(factory, "libid.NotaryService");
    let deployed = factory_deploy(
        &provider,
        factory,
        "libid.NotaryService",
        creation_code.into(),
    )
    .await
    .unwrap();
    assert_eq!(deployed, predicted);

    let notary = NotaryService::new(deployed, &provider);
    assert!(notary.isTrustedNotary(notary_key).call().await.unwrap());
    assert_eq!(notary.fee().call().await.unwrap(), U256::from(7));
    assert_eq!(notary.owner().call().await.unwrap(), deployer0);
}

/// The ENS resolver: a plain contract with constructor arguments, deployed
/// through `deploy_with_ctor` from the embedded artifact, then read back.
#[tokio::test]
async fn deploys_the_ens_resolver_with_its_constructor_arguments() {
    use alloy::{
        primitives::FixedBytes,
        sol_types::SolValue,
    };
    use libid_contracts::{
        bindings::ens::HandleResolver,
        deploy::deploy_with_ctor,
    };

    let provider = test_provider();
    let artifacts = Artifacts::embedded();
    let deployer = default_signer(&provider).await;
    let gateway_signer = Address::repeat_byte(0x51);
    let urls = vec!["https://gw.handles.link/{sender}/{data}.json".to_string()];

    let ctor_args = (deployer, urls.clone(), vec![gateway_signer]).abi_encode_params();
    let resolver_addr = deploy_with_ctor(
        &provider,
        &artifacts.bytecode("HandleResolver").unwrap(),
        &ctor_args,
        "HandleResolver",
        None,
    )
    .await
    .unwrap();

    let resolver = HandleResolver::new(resolver_addr, &provider);
    assert_eq!(resolver.owner().call().await.unwrap(), deployer);
    assert_eq!(resolver.urlCount().call().await.unwrap(), U256::from(1));
    assert_eq!(resolver.urls(U256::ZERO).call().await.unwrap(), urls[0]);
    assert!(resolver.signers(gateway_signer).call().await.unwrap());
    // ENSIP-10, or no wildcard name ever reaches it.
    let ensip10 = FixedBytes::<4>::from([0x90, 0x61, 0xb9, 0x23]);
    assert!(resolver.supportsInterface(ensip10).call().await.unwrap());

    // The owner rotates the signer set; the read follows.
    let next = Address::repeat_byte(0x52);
    resolver
        .setSigner(next, true)
        .send()
        .await
        .unwrap()
        .get_receipt()
        .await
        .unwrap();
    assert!(resolver.signers(next).call().await.unwrap());
}

/// (e) The three Platform Verifiers through `deploy_platform_verifier`, on
/// the collaborators they pin: the Notary Service (the two TLSNotary ones),
/// the JWT root list (Google), and the real Honk verifier for each one's
/// circuit, deployed with its libraries linked. The code hash the
/// initializer computes is the one the chain reports for that verifier,
/// and the one the contract records. Each comes back initialized as the
/// views say, registers with the Proof Verifier, and the ceilings the crate
/// restates are the contract's. Then the rules: an initializer the wrapper
/// refuses is one the contract refuses too, and a Honk verifier with no
/// code is caught before any transaction.
#[tokio::test]
async fn deploys_and_initializes_every_platform_verifier() {
    use alloy::{
        hex,
        primitives::keccak256,
        sol_types::SolError,
    };
    use libid_contracts::{
        bindings::ceremony::{
            GooglePlatformVerifier,
            TlsNotaryPlatformVerifier,
        },
        circuits::{
            deploy_honk_verifiers,
            Circuit,
        },
        platform_verifier::{
            codehash_at,
            deploy_platform_verifier,
            GoogleRoots,
            Initializer,
            PlatformVerifier,
            TlsNotaryRoots,
            MAX_FUTURE_ATTESTATION_SKEW,
            MAX_FUTURE_OBSERVATION_ALLOWANCE,
            MAX_PROOF_LIFETIME,
        },
        Error,
    };

    let provider = test_provider();
    let artifacts = Artifacts::embedded();
    let deployer = default_signer(&provider).await;
    let fee = U256::from(1_000);

    let notary_proxy = deploy_behind_proxy(
        &provider,
        &artifacts,
        "NotaryService",
        &NotaryService::initializeCall {
            owner_: deployer,
            notary_: Address::repeat_byte(0x11),
            fee_: fee,
        },
        None,
    )
    .await
    .unwrap();
    let proof_verifier_proxy = deploy_behind_proxy(
        &provider,
        &artifacts,
        "CeremonyProofVerifier",
        &CeremonyProofVerifier::initializeCall { owner_: deployer },
        None,
    )
    .await
    .unwrap();
    let roots_proxy = deploy_behind_proxy(
        &provider,
        &artifacts,
        "GoogleJwtRoots",
        &GoogleJwtRoots::initializeCall {
            owner_: deployer,
            notary_: notary_proxy,
        },
        None,
    )
    .await
    .unwrap();
    // The real verifiers, one per circuit, linked against one deployment
    // of each library. The hash a Platform Verifier pins is read off the
    // chain, never computed from the vendored bytes: it is what the chain
    // holds for the artifact, shared library addresses included.
    let honk_verifiers =
        deploy_honk_verifiers(&provider, &artifacts, &Circuit::ALL, None)
            .await
            .unwrap();
    let honk_at = |circuit: Circuit| honk_verifiers.verifiers[&circuit];
    let bearer_link = honk_at(Circuit::BearerLink);
    let oidc_google = honk_at(Circuit::OidcGoogle);
    let honk = bearer_link;
    let honk_codehash = codehash_at(&provider, honk).await.unwrap();
    assert_ne!(honk_codehash, keccak256([]));
    assert_ne!(
        honk_codehash,
        codehash_at(&provider, oidc_google).await.unwrap(),
        "one artifact for two circuits"
    );

    let tls = TlsNotaryRoots {
        owner: deployer,
        notary_service: notary_proxy,
        honk_verifier: bearer_link,
        proof_lifetime: libid_profiles::PROOF_LIFETIME_SECONDS_X,
        max_future_attestation_skew: libid_profiles::MAX_FUTURE_ATTESTATION_SKEW_SECONDS,
        future_observation_allowance: 300,
    };
    let google = GoogleRoots {
        owner: deployer,
        honk_verifier: oidc_google,
        future_observation_allowance: 7200,
        jwt_roots: roots_proxy,
    };
    let proof_verifier = CeremonyProofVerifier::new(proof_verifier_proxy, &provider);

    for init in [
        Initializer::X(tls),
        Initializer::GitHub(tls),
        Initializer::Google(google),
    ] {
        let verifier = init.verifier();
        // The initializer pins its circuit's verifier, and computes the hash
        // the chain reports for it — `EXTCODEHASH`, `keccak256` of the
        // runtime code — which is what `initialize` then checks.
        let honk = honk_at(verifier.circuit());
        assert_eq!(
            init.honk_verifier(),
            honk,
            "{verifier:?} pins the wrong circuit"
        );
        let honk_codehash = keccak256(provider.get_code_at(honk).await.unwrap());
        assert_eq!(
            init.call(&provider).await.unwrap().honk_verifier_codehash(),
            honk_codehash,
            "{verifier:?}: the initializer computed a hash the chain does not hold"
        );
        let proxy = deploy_platform_verifier(&provider, &artifacts, &init, None)
            .await
            .unwrap_or_else(|e| panic!("{verifier:?}: {e}"));
        assert!(!provider.get_code_at(proxy).await.unwrap().is_empty());

        // The quote is what the Proof Verifier forwards whole: one Notary
        // Fee per attestation the profile requires.
        let quote = match verifier {
            PlatformVerifier::X | PlatformVerifier::GitHub => {
                let v = TlsNotaryPlatformVerifier::new(proxy, &provider);
                assert_eq!(v.owner().call().await.unwrap(), deployer);
                assert_eq!(v.notaryService().call().await.unwrap(), notary_proxy);
                assert_eq!(v.honkVerifier().call().await.unwrap(), honk);
                assert_eq!(
                    v.honkVerifierCodehash().call().await.unwrap(),
                    honk_codehash
                );
                let params = v.protocolParameters().call().await.unwrap();
                assert_eq!(params.proofLifetime, tls.proof_lifetime);
                assert_eq!(
                    params.maxFutureAttestationSkew,
                    tls.max_future_attestation_skew
                );
                assert_eq!(
                    params.futureObservationAllowance,
                    tls.future_observation_allowance
                );
                assert_eq!(
                    v.MAX_PROOF_LIFETIME().call().await.unwrap(),
                    MAX_PROOF_LIFETIME
                );
                assert_eq!(
                    v.MAX_FUTURE_ATTESTATION_SKEW().call().await.unwrap(),
                    MAX_FUTURE_ATTESTATION_SKEW
                );
                assert_eq!(
                    v.MAX_FUTURE_OBSERVATION_ALLOWANCE().call().await.unwrap(),
                    MAX_FUTURE_OBSERVATION_ALLOWANCE
                );
                let quote = v.quote().call().await.unwrap();
                assert_eq!(quote, fee * U256::from(2));
                quote
            }
            PlatformVerifier::Google => {
                let v = GooglePlatformVerifier::new(proxy, &provider);
                assert_eq!(v.owner().call().await.unwrap(), deployer);
                assert_eq!(v.notaryService().call().await.unwrap(), Address::ZERO);
                assert_eq!(v.honkVerifier().call().await.unwrap(), honk);
                assert_eq!(
                    v.honkVerifierCodehash().call().await.unwrap(),
                    honk_codehash
                );
                assert_eq!(v.jwtRoots().call().await.unwrap(), roots_proxy);
                let params = v.protocolParameters().call().await.unwrap();
                assert_eq!(params.proofLifetime, 0);
                assert_eq!(params.maxFutureAttestationSkew, 0);
                assert_eq!(
                    params.futureObservationAllowance,
                    google.future_observation_allowance
                );
                let quote = v.quote().call().await.unwrap();
                assert_eq!(quote, U256::ZERO);
                quote
            }
        };

        // The contract answers for the platform the crate says it serves,
        // and the Proof Verifier registers it under that platform.
        let platform_id = TlsNotaryPlatformVerifier::new(proxy, &provider)
            .platformId()
            .call()
            .await
            .unwrap();
        assert_eq!(platform_id, verifier.platform_id());
        proof_verifier
            .setVerifier(platform_id, 1, proxy)
            .send()
            .await
            .unwrap()
            .get_receipt()
            .await
            .unwrap();
        assert_eq!(
            proof_verifier
                .verifierOf(platform_id, 1)
                .call()
                .await
                .unwrap(),
            proxy
        );
        assert_eq!(
            proof_verifier.quote(platform_id, 1).call().await.unwrap(),
            quote
        );
    }

    // A Honk verifier that is not deployed is caught before any transaction:
    // the hash of nothing is exactly what the contract refuses to pin.
    let err = Initializer::X(TlsNotaryRoots {
        honk_verifier: Address::repeat_byte(0x99),
        ..tls
    })
    .call(&provider)
    .await
    .unwrap_err();
    assert!(matches!(err, Error::Initializer { .. }), "{err}");
    assert!(err.to_string().contains("no code at"), "{err}");

    // The rules the wrapper enforces are the contract's, not its own: a
    // hand-built Google initializer carrying a Notary Service, and an X one
    // naming the wrong artifact, both revert at the proxy constructor with
    // the error the wrapper's refusal names. Explicit nonces from here:
    // a send that fails at gas estimation leaves alloy's cached nonce
    // manager one ahead of the chain, and every later transaction would
    // wait on a gap that never fills.
    let google_with_notary = GooglePlatformVerifier::initializeCall {
        owner_: deployer,
        notary_: notary_proxy,
        honkVerifier_: honk,
        honkVerifierCodehash_: honk_codehash,
        futureObservationAllowance_: 7200,
        jwtRoots_: roots_proxy,
    };
    let err = deploy_behind_proxy(
        &provider,
        &artifacts,
        "GooglePlatformVerifier",
        &google_with_notary,
        Some(deployer),
    )
    .await
    .unwrap_err();
    assert!(
        err.to_string().contains(&hex::encode(
            GooglePlatformVerifier::WrongNotaryForProfile::SELECTOR
        )),
        "{err}"
    );
    let x_wrong_artifact = TlsNotaryPlatformVerifier::initializeCall {
        owner_: deployer,
        notary_: notary_proxy,
        honkVerifier_: honk,
        honkVerifierCodehash_: keccak256("some other artifact"),
        proofLifetime_: 3600,
        maxFutureAttestationSkew_: 300,
        futureObservationAllowance_: 300,
    };
    let err = deploy_behind_proxy(
        &provider,
        &artifacts,
        "XPlatformVerifier",
        &x_wrong_artifact,
        Some(deployer),
    )
    .await
    .unwrap_err();
    assert!(
        err.to_string().contains(&hex::encode(
            TlsNotaryPlatformVerifier::WrongVerifierArtifact::SELECTOR
        )),
        "{err}"
    );
}

/// (f) The two Honk verifiers through `deploy_honk_verifiers`: each library
/// is deployed once and both verifiers link against it — four transactions
/// for the set, not six — and each lands under EIP-170 and answers for its
/// OWN circuit. A bb verifier has no getter for its verification key; the
/// one thing it says about itself is the `logN` a wrong-length proof comes
/// back with. That separates a real verifier from a contract that merely
/// has code, and the two circuits from each other — the check that would
/// catch a release whose tarballs were swapped, or a vendor run that wrote
/// one circuit's verifier under the other's name. Then the per-circuit call
/// alone: it finds the libraries where the set deploy put them.
#[tokio::test]
async fn deploys_the_linked_honk_verifiers_over_their_own_circuits() {
    use alloy::{
        primitives::Bytes,
        sol_types::SolError,
    };
    use libid_contracts::{
        bindings::circuits::HonkVerifier,
        circuits::{
            deploy_honk_verifier,
            deploy_honk_verifiers,
            version,
            Circuit,
            LIBRARIES,
        },
        deploy::library_address,
        platform_verifier::codehash_at,
    };

    let provider = test_provider();
    let artifacts = Artifacts::embedded();
    let deployer = default_signer(&provider).await;
    assert!(!version(&artifacts).unwrap().is_empty());

    let before = provider.get_transaction_count(deployer).await.unwrap();
    let honk = deploy_honk_verifiers(&provider, &artifacts, &Circuit::ALL, None)
        .await
        .unwrap();
    let sent = provider.get_transaction_count(deployer).await.unwrap() - before;

    // One transaction per distinct library and one per verifier. Two
    // circuits, two libraries between them: four, where a copy per circuit
    // was six. Should a circuits release ever ship the two circuits with
    // different library bytecode, this is where it shows.
    assert_eq!(honk.verifiers.len(), Circuit::ALL.len());
    assert_eq!(
        honk.libraries.distinct().count(),
        LIBRARIES.len(),
        "the circuits' libraries are no longer one deployment each"
    );
    assert_eq!(honk.libraries.deployed().count(), LIBRARIES.len());
    assert_eq!(sent, (Circuit::ALL.len() + LIBRARIES.len()) as u64);
    for library in LIBRARIES {
        // Both files resolve to one address, and it is the address the
        // bytecode derives: the same on every chain.
        let shared = honk
            .libraries
            .address(Circuit::BearerLink.contract(), library)
            .unwrap();
        assert_eq!(
            honk.libraries
                .address(Circuit::OidcGoogle.contract(), library),
            Some(shared),
            "{library} is not shared"
        );
        let code = artifacts
            .bytecode_named(Circuit::BearerLink.contract(), library)
            .unwrap();
        assert_eq!(shared, library_address(&code));
        assert!(!provider.get_code_at(shared).await.unwrap().is_empty());
    }

    let mut log_n = Vec::new();
    for circuit in Circuit::ALL {
        let address = honk.verifiers[&circuit];
        let code = provider.get_code_at(address).await.unwrap();
        assert!(!code.is_empty(), "{circuit:?} has no code at {address:#x}");
        // anvil runs the default limit, so deploying at all is the EIP-170
        // proof; the number is asserted so a release that grows past it
        // says so here rather than in a failed deploy.
        assert!(
            code.len() <= 24_576,
            "{circuit:?} is {} bytes, over EIP-170",
            code.len()
        );
        assert_eq!(
            codehash_at(&provider, address).await.unwrap(),
            keccak256(&code)
        );
        // The verifier's runtime code carries the shared addresses: it is
        // linked against the one deployment, not a copy of its own.
        for library in LIBRARIES {
            let shared = honk.libraries.address(circuit.contract(), library).unwrap();
            assert!(
                code.windows(20).any(|window| window == shared.as_slice()),
                "{circuit:?} does not link {library} at {shared:#x}"
            );
        }

        let err = HonkVerifier::new(address, &provider)
            .verify(Bytes::new(), Vec::new())
            .call()
            .await
            .expect_err("an empty proof is the wrong length");
        let data = err
            .as_revert_data()
            .expect("the verifier reverted with data");
        let decoded = HonkVerifier::ProofLengthWrongWithLogN::abi_decode(&data)
            .expect("only a Honk verifier raises ProofLengthWrongWithLogN");
        assert!(
            decoded.logN > U256::ZERO,
            "{circuit:?} reports no circuit size"
        );
        log_n.push(decoded.logN);
    }
    assert_ne!(
        log_n[0], log_n[1],
        "both platforms would verify under one circuit"
    );

    // The published per-circuit call, alone: the libraries are at the
    // addresses their bytecode derives, so it links them and sends one
    // transaction, its verifier's — with the same code hash as the set's,
    // because the linked addresses are the same.
    let before = provider.get_transaction_count(deployer).await.unwrap();
    let again = deploy_honk_verifier(&provider, &artifacts, Circuit::BearerLink, None)
        .await
        .unwrap();
    assert_eq!(
        provider.get_transaction_count(deployer).await.unwrap() - before,
        1
    );
    assert_ne!(again, honk.verifiers[&Circuit::BearerLink]);
    assert_eq!(
        codehash_at(&provider, again).await.unwrap(),
        codehash_at(&provider, honk.verifiers[&Circuit::BearerLink])
            .await
            .unwrap()
    );
}

/// (g) The other half of the sharing rule, on a case the vendored verifiers
/// cannot provide while their libraries are identical: `LinkFixture.sol`
/// links libraries NAMED `RelationsLib` and `ZKTranscriptLib` whose bytecode
/// is its own, read from the forge `out/` the crate's artifacts were vendored
/// from. Deployed in one set with the two circuits, its libraries are two
/// more deployments, not two more links against the verifiers' — the key is
/// the bytecode, never the name — and every contract still runs on what it
/// was compiled against.
#[tokio::test]
async fn a_library_with_other_bytecode_under_the_same_name_is_not_shared() {
    use alloy::sol;
    use libid_contracts::{
        circuits::{
            Circuit,
            LIBRARIES,
        },
        deploy::{
            library_address,
            Libraries,
        },
    };

    sol! {
        #[sol(rpc)]
        interface ILinkFixture {
            function relate(uint256 value) external pure returns (uint256);
            function transcribe(uint256 value) external pure returns (uint256);
        }
    }

    // The raw forge output: the fixture is a test source, not a covered
    // contract, so it is not among the embedded artifacts.
    let out = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../solidity/out");
    assert!(
        out.join("LinkFixture.sol/LinkFixture.json").is_file(),
        "no LinkFixture artifact under {}: run `forge build` in solidity/",
        out.display()
    );
    let artifacts = Artifacts::from_dir(&out);
    let provider = test_provider();
    let deployer = default_signer(&provider).await;
    const FIXTURE: &str = "LinkFixture";

    // The fixture's libraries really differ from bb's, name for name.
    for library in LIBRARIES {
        assert_ne!(
            artifacts.bytecode_named(FIXTURE, library).unwrap(),
            artifacts
                .bytecode_named(Circuit::BearerLink.contract(), library)
                .unwrap(),
            "{library}: the fixture compiled to bb's bytecode"
        );
    }

    let before = provider.get_transaction_count(deployer).await.unwrap();
    let libraries = Libraries::deploy(
        &provider,
        &artifacts,
        &[
            (
                Circuit::BearerLink.contract(),
                Circuit::BearerLink.contract(),
            ),
            (
                Circuit::OidcGoogle.contract(),
                Circuit::OidcGoogle.contract(),
            ),
            (FIXTURE, FIXTURE),
        ],
        None,
    )
    .await
    .unwrap();
    // Two names, three files, four deployments: the circuits' pair once,
    // the fixture's pair on their own.
    assert_eq!(libraries.distinct().count(), 2 * LIBRARIES.len());
    assert_eq!(
        provider.get_transaction_count(deployer).await.unwrap() - before,
        (2 * LIBRARIES.len()) as u64
    );
    for library in LIBRARIES {
        let bb = libraries
            .address(Circuit::BearerLink.contract(), library)
            .unwrap();
        assert_eq!(
            libraries.address(Circuit::OidcGoogle.contract(), library),
            Some(bb)
        );
        let own = libraries.address(FIXTURE, library).unwrap();
        assert_ne!(
            own, bb,
            "{library}: shared by name across different bytecode"
        );
        assert_eq!(
            own,
            library_address(&artifacts.bytecode_named(FIXTURE, library).unwrap())
        );
    }

    // The fixture links its own copies and runs on them.
    let fixture = deploy_contract(
        &provider,
        libraries.link(&artifacts, FIXTURE, FIXTURE).unwrap(),
        FIXTURE,
    )
    .await
    .unwrap();
    let code = provider.get_code_at(fixture).await.unwrap();
    for library in LIBRARIES {
        let own = libraries.address(FIXTURE, library).unwrap();
        let bb = libraries
            .address(Circuit::BearerLink.contract(), library)
            .unwrap();
        assert!(code.windows(20).any(|window| window == own.as_slice()));
        assert!(!code.windows(20).any(|window| window == bb.as_slice()));
    }
    let fixture = ILinkFixture::new(fixture, &provider);
    assert_eq!(
        fixture.relate(U256::from(41)).call().await.unwrap(),
        U256::from(42)
    );
    assert_eq!(
        fixture.transcribe(U256::from(21)).call().await.unwrap(),
        U256::from(42)
    );

    // A contract whose library is not in the set cannot be linked against
    // what happens to share a name with it.
    let only_bb = Libraries::deploy(
        &provider,
        &artifacts,
        &[(
            Circuit::BearerLink.contract(),
            Circuit::BearerLink.contract(),
        )],
        None,
    )
    .await
    .unwrap();
    let err = only_bb.link(&artifacts, FIXTURE, FIXTURE).unwrap_err();
    assert!(
        err.to_string().contains("not among the deployed libraries"),
        "{err}"
    );
}
