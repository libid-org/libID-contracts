//! Anvil integration tests: deploy the identity stack from the embedded
//! artifacts and read views back. Requires foundry's `anvil` on PATH.

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
        identity::IdentityRegistry,
    },
    deploy::{
        deploy_behind_proxy,
        deploy_contract,
        upgrade_uups,
    },
    Artifacts,
};
use libid_identity::platforms::PLATFORM_GITHUB;

fn test_provider() -> impl Provider + Clone {
    ProviderBuilder::new().connect_anvil_with_wallet()
}

async fn default_signer(provider: &impl Provider) -> Address {
    provider.get_accounts().await.expect("accounts")[0]
}

/// The identity stack in the order `script/Deploy.s.sol` uses, each behind
/// an ERC1967 proxy: the Notary Service, the Proof Verifier, the registry
/// pointed at the Proof Verifier, and the Google JWT root list pointed at the
/// Notary Service. Then the views that prove the wiring.
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

    let registry_proxy = deploy_behind_proxy(
        &provider,
        &artifacts,
        "IdentityRegistry",
        &IdentityRegistry::initializeCall { owner_: deployer },
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

    // Wire the registry to the Proof Verifier it dispatches through.
    let registry = IdentityRegistry::new(registry_proxy, &provider);
    registry
        .setProofVerifier(verifier_proxy)
        .send()
        .await
        .unwrap()
        .get_receipt()
        .await
        .unwrap();
    let platform_id = keccak256(b"github");

    // The Notary Service holds the key and the fee it was given.
    let notary = NotaryService::new(notary_proxy, &provider);
    assert!(notary.isTrustedNotary(notary_key).call().await.unwrap());
    assert_eq!(notary.fee().call().await.unwrap(), fee);

    // No version is registered yet.
    let verifier = CeremonyProofVerifier::new(verifier_proxy, &provider);
    assert!(!verifier.verifiesPlatform(platform_id).call().await.unwrap());
    assert_eq!(
        verifier.verifierOf(platform_id, 1).call().await.unwrap(),
        Address::ZERO
    );

    assert_eq!(
        registry.proofVerifier().call().await.unwrap(),
        verifier_proxy
    );
    // A known platform no verifier serves answers nobody.
    let unwired = registry
        .resolveHandle(platform_id, "octocat".into())
        .call()
        .await
        .unwrap();
    assert_eq!(unwired, Address::ZERO);
    // The chain's fold and tag give the node libid-identity computes.
    assert_eq!(
        registry
            .handleNodeOf(platform_id, "OctoCat".into())
            .call()
            .await
            .unwrap()
            .0,
        PLATFORM_GITHUB.handle_node("OctoCat").unwrap()
    );

    // The root list points at the Notary Service, quotes its fee, and starts
    // with both generations empty, wanting a rotation.
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

/// The Notary Service lifecycle: deploy behind a proxy, add a second trusted
/// key, change the fee, upgrade with `upgrade_uups`, and check the state
/// survives the upgrade.
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

    // Rotate: trust the incoming key before removing the outgoing one, so
    // attestations made under `first` stay presentable.
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

/// The deterministic factory on a chain without the CREATE2 deployer:
/// `FactoryGenesis::ensure` installs it with the keyless presigned
/// transaction, then deploys the factory at its canonical address, owned by
/// the genesis admin from the first block. Then a Notary Service proxy goes
/// through the factory at its name-derived CREATE3 address.
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
            factory_deploy,
            predict_address,
            FactoryGenesis,
            CREATE2_DEPLOYER,
        },
    };

    let provider = ProviderBuilder::new()
        .connect_anvil_with_wallet_and_config(|anvil| {
            anvil.arg("--disable-default-create2-deployer")
        })
        .expect("anvil spawns");
    let artifacts = Artifacts::embedded();
    let deployer0 = default_signer(&provider).await;
    let genesis = FactoryGenesis { admin: deployer0 };

    // No CREATE2 deployer.
    assert!(provider
        .get_code_at(CREATE2_DEPLOYER)
        .await
        .unwrap()
        .is_empty());

    let factory = genesis.ensure(&provider, &artifacts).await.unwrap();
    assert_eq!(factory, genesis.address(&artifacts).unwrap());
    assert!(!provider.get_code_at(factory).await.unwrap().is_empty());

    // Initialized in the deploy: the genesis admin owns it.
    let factory_contract = LibidFactory::new(factory, &provider);
    assert_eq!(factory_contract.owner().call().await.unwrap(), deployer0);

    // A rerun sends nothing.
    assert_eq!(
        genesis.ensure(&provider, &artifacts).await.unwrap(),
        factory
    );

    // Another admin is another factory, at another address.
    let other = FactoryGenesis {
        admin: Address::repeat_byte(0x22),
    };
    assert_ne!(other.address(&artifacts).unwrap(), factory);

    // A Notary Service proxy through the factory: the implementation by plain
    // CREATE, the proxy's creation code `ERC1967Proxy ++ (impl, initData)`.
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

/// The ENS resolver, deployed with constructor arguments through
/// `deploy_with_ctor`, then read back.
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

/// The three Platform Verifiers through `deploy_platform_verifier`, on the
/// Notary Service (TLSNotary), the JWT root list (Google) and the real Honk
/// verifier for each circuit. Each pins the code hash the chain reports,
/// reads back its initializer and window, and registers with the Proof
/// Verifier. Then the refusals: what the wrapper refuses the contract
/// refuses too, and a Honk verifier with no code is caught before sending.
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
            IPlatformVerifier,
            PlatformVerifierBase,
            XPlatformVerifier,
        },
        circuits::{
            deploy_honk_verifier,
            Circuit,
        },
        platform_verifier::{
            codehash_at,
            deploy_platform_verifier,
            GoogleRoots,
            Initializer,
            PlatformVerifier,
            TlsNotaryRoots,
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
    // The real verifiers, one per circuit.
    let bearer_link =
        deploy_honk_verifier(&provider, &artifacts, Circuit::BearerLink, None)
            .await
            .unwrap();
    let oidc_google =
        deploy_honk_verifier(&provider, &artifacts, Circuit::OidcGoogle, None)
            .await
            .unwrap();
    let honk_at = |circuit: Circuit| match circuit {
        Circuit::BearerLink => bearer_link,
        Circuit::OidcGoogle => oidc_google,
    };
    let mut codehashes = Vec::new();
    for circuit in Circuit::ALL {
        let codehash = codehash_at(&provider, honk_at(circuit)).await.unwrap();
        assert_ne!(codehash, keccak256([]));
        assert!(
            !codehashes.contains(&codehash),
            "one artifact for two circuits"
        );
        codehashes.push(codehash);
    }
    let honk = bearer_link;

    let tls = |honk_verifier| TlsNotaryRoots {
        owner: deployer,
        notary_service: notary_proxy,
        honk_verifier,
    };
    let google = GoogleRoots {
        owner: deployer,
        honk_verifier: oidc_google,
        jwt_roots: roots_proxy,
    };
    let proof_verifier = CeremonyProofVerifier::new(proof_verifier_proxy, &provider);

    let mut github_proxy = Address::ZERO;
    for init in [
        Initializer::X(tls(bearer_link)),
        Initializer::GitHub(tls(bearer_link)),
        Initializer::Google(google),
    ] {
        let verifier = init.verifier();
        // The initializer wires its circuit's verifier; the contract pins
        // that verifier's `EXTCODEHASH`.
        let honk = honk_at(verifier.circuit());
        assert_eq!(
            init.honk_verifier(),
            honk,
            "{verifier:?} pins the wrong circuit"
        );
        let honk_codehash = keccak256(provider.get_code_at(honk).await.unwrap());
        let proxy = deploy_platform_verifier(&provider, &artifacts, &init, None)
            .await
            .unwrap_or_else(|e| panic!("{verifier:?}: {e}"));
        assert!(!provider.get_code_at(proxy).await.unwrap().is_empty());
        if verifier == PlatformVerifier::GitHub {
            github_proxy = proxy;
        }

        // One Notary Fee per attestation the profile requires.
        let quote = match verifier {
            PlatformVerifier::X | PlatformVerifier::GitHub => {
                let v = PlatformVerifierBase::new(proxy, &provider);
                assert_eq!(v.owner().call().await.unwrap(), deployer);
                assert_eq!(v.notaryService().call().await.unwrap(), notary_proxy);
                assert_eq!(v.honkVerifier().call().await.unwrap(), honk);
                assert_eq!(v.circuitCodehash().call().await.unwrap(), honk_codehash);
                // The contract's window comes from the same profile table as
                // the generated constants.
                let window = if verifier == PlatformVerifier::X {
                    (
                        libid_profiles::PROOF_LIFETIME_SECONDS_X,
                        libid_profiles::MAX_FUTURE_ATTESTATION_SKEW_SECONDS_X,
                        libid_profiles::FUTURE_OBSERVATION_ALLOWANCE_SECONDS_X,
                    )
                } else {
                    (
                        libid_profiles::PROOF_LIFETIME_SECONDS_GITHUB,
                        libid_profiles::MAX_FUTURE_ATTESTATION_SKEW_SECONDS_GITHUB,
                        libid_profiles::FUTURE_OBSERVATION_ALLOWANCE_SECONDS_GITHUB,
                    )
                };
                let params = v.protocolParameters().call().await.unwrap();
                assert_eq!(
                    (
                        params.proofLifetime,
                        params.maxFutureAttestationSkew,
                        params.futureObservationAllowance
                    ),
                    window,
                    "{verifier:?}"
                );
                let quote = IPlatformVerifier::new(proxy, &provider)
                    .quote()
                    .call()
                    .await
                    .unwrap();
                assert_eq!(quote, fee * U256::from(2));
                quote
            }
            PlatformVerifier::Google => {
                let v = GooglePlatformVerifier::new(proxy, &provider);
                assert_eq!(v.owner().call().await.unwrap(), deployer);
                assert_eq!(v.notaryService().call().await.unwrap(), Address::ZERO);
                assert_eq!(v.honkVerifier().call().await.unwrap(), honk);
                assert_eq!(v.circuitCodehash().call().await.unwrap(), honk_codehash);
                assert_eq!(v.jwtRoots().call().await.unwrap(), roots_proxy);
                let params = v.protocolParameters().call().await.unwrap();
                assert_eq!(params.proofLifetime, 0);
                assert_eq!(params.maxFutureAttestationSkew, 0);
                assert_eq!(
                    params.futureObservationAllowance,
                    libid_profiles::FUTURE_OBSERVATION_ALLOWANCE_SECONDS_GOOGLE
                );
                let quote = v.quote().call().await.unwrap();
                assert_eq!(quote, U256::ZERO);
                quote
            }
        };

        // The contract answers for the platform the crate says it serves,
        // and the Proof Verifier registers it under that platform.
        let platform_id = IPlatformVerifier::new(proxy, &provider)
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

    // A Honk verifier that is not deployed is caught before any transaction.
    let err = deploy_platform_verifier(
        &provider,
        &artifacts,
        &Initializer::X(tls(Address::repeat_byte(0x99))),
        None,
    )
    .await
    .unwrap_err();
    assert!(matches!(err, Error::Initializer { .. }), "{err}");
    assert!(err.to_string().contains("no code at"), "{err}");

    // Each deployed verifier's code hash is its vendored runtime code's.
    for circuit in Circuit::ALL {
        assert_eq!(
            circuit.runtime_codehash(&artifacts).unwrap(),
            codehash_at(&provider, honk_at(circuit)).await.unwrap(),
            "{circuit:?}"
        );
    }

    // X wired to GitHub's circuit, or to no vendored verifier, is refused
    // before any transaction.
    let err = deploy_platform_verifier(
        &provider,
        &artifacts,
        &Initializer::X(tls(oidc_google)),
        None,
    )
    .await
    .unwrap_err();
    match &err {
        Error::WrongCircuit {
            contract,
            address,
            expected,
            found,
            ..
        } => {
            assert_eq!(*contract, "XPlatformVerifier");
            assert_eq!(*address, oidc_google);
            assert_eq!(*expected, Some(Circuit::BearerLink));
            assert_eq!(*found, Some(Circuit::OidcGoogle));
        }
        other => panic!("expected WrongCircuit, got {other}"),
    }
    assert!(
        err.to_string().contains("oidc-google")
            && err.to_string().contains("bearer-link"),
        "{err}"
    );
    // A rotation hash is handed out only for the circuit the proxy pins.
    assert_eq!(
        PlatformVerifier::GitHub
            .rotation_codehash_at(&provider, &artifacts, github_proxy, bearer_link)
            .await
            .unwrap(),
        codehash_at(&provider, bearer_link).await.unwrap()
    );
    assert!(matches!(
        PlatformVerifier::GitHub
            .rotation_codehash_at(&provider, &artifacts, github_proxy, oidc_google)
            .await,
        Err(Error::WrongCircuit {
            found: Some(Circuit::OidcGoogle),
            ..
        })
    ));
    // Asked about another platform, the proxy is refused before any hash.
    match PlatformVerifier::Google
        .rotation_codehash_at(&provider, &artifacts, github_proxy, oidc_google)
        .await
    {
        Err(Error::WrongPlatform {
            proxy,
            expected,
            found,
        }) => {
            assert_eq!(proxy, github_proxy);
            assert_eq!(expected, PlatformVerifier::Google.platform_id());
            assert_eq!(found, PlatformVerifier::GitHub.platform_id());
        }
        other => panic!("expected WrongPlatform, got {other:?}"),
    }
    let err = deploy_platform_verifier(
        &provider,
        &artifacts,
        &Initializer::GitHub(tls(notary_proxy)),
        None,
    )
    .await
    .unwrap_err();
    assert!(
        matches!(
            err,
            Error::WrongCircuit {
                expected: Some(Circuit::BearerLink),
                found: None,
                ..
            }
        ),
        "{err}"
    );

    // Hand-built bad initializers revert at the proxy constructor with the
    // wrapper's error. Explicit nonces: a send that fails estimation leaves
    // alloy's nonce cache one ahead.
    let google_with_notary = GooglePlatformVerifier::initializeCall {
        owner_: deployer,
        notary_: notary_proxy,
        honkVerifier_: honk,
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
    let x_wrong_circuit = XPlatformVerifier::initializeCall {
        owner_: deployer,
        notary_: notary_proxy,
        honkVerifier_: oidc_google,
    };
    let err = deploy_behind_proxy(
        &provider,
        &artifacts,
        "XPlatformVerifier",
        &x_wrong_circuit,
        Some(deployer),
    )
    .await
    .unwrap_err();
    assert!(
        err.to_string()
            .contains(&hex::encode(XPlatformVerifier::WrongCircuit::SELECTOR)),
        "{err}"
    );
}

/// The handle escrow: pay an unclaimed handle by its node, check the value
/// lands on the registry's node, and refund it once its date has come. The
/// payout path needs a stub Platform Verifier, which this crate does not
/// ship, so the Solidity suite covers it.
#[tokio::test]
async fn escrows_value_against_an_unclaimed_handle() {
    use alloy::{
        hex,
        primitives::b256,
        sol_types::SolError,
    };
    use libid_contracts::{
        bindings::escrow::HandleEscrow,
        circuits::{
            deploy_honk_verifier,
            Circuit,
        },
        platform_verifier::{
            deploy_platform_verifier,
            Initializer,
            PlatformVerifier,
            TlsNotaryRoots,
        },
    };

    let provider = test_provider();
    let artifacts = Artifacts::embedded();
    let deployer = default_signer(&provider).await;
    let stranger = provider.get_accounts().await.unwrap()[1];

    let notary_proxy = deploy_behind_proxy(
        &provider,
        &artifacts,
        "NotaryService",
        &NotaryService::initializeCall {
            owner_: deployer,
            notary_: Address::repeat_byte(0x11),
            fee_: U256::from(1_000),
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
    let registry_proxy = deploy_behind_proxy(
        &provider,
        &artifacts,
        "IdentityRegistry",
        &IdentityRegistry::initializeCall { owner_: deployer },
        None,
    )
    .await
    .unwrap();

    let platform_id = keccak256(b"github");
    assert_eq!(
        platform_id,
        PlatformVerifier::GitHub.platform_id(),
        "the test and the crate name GitHub differently"
    );
    let registry = IdentityRegistry::new(registry_proxy, &provider);
    registry
        .setProofVerifier(proof_verifier_proxy)
        .send()
        .await
        .unwrap()
        .get_receipt()
        .await
        .unwrap();

    // The real GitHub Platform Verifier, on the real Honk verifier for its
    // circuit, registered as version 1.
    let honk = deploy_honk_verifier(&provider, &artifacts, Circuit::BearerLink, None)
        .await
        .unwrap();
    let github = Initializer::GitHub(TlsNotaryRoots {
        owner: deployer,
        notary_service: notary_proxy,
        honk_verifier: honk,
    });
    let github_proxy = deploy_platform_verifier(&provider, &artifacts, &github, None)
        .await
        .unwrap();
    CeremonyProofVerifier::new(proof_verifier_proxy, &provider)
        .setVerifier(platform_id, 1, github_proxy)
        .send()
        .await
        .unwrap()
        .get_receipt()
        .await
        .unwrap();
    assert!(registry.acceptsBindings(platform_id).call().await.unwrap());

    let escrow_proxy = deploy_behind_proxy(
        &provider,
        &artifacts,
        "HandleEscrow",
        &HandleEscrow::initializeCall {
            owner_: deployer,
            registry_: registry_proxy,
        },
        None,
    )
    .await
    .unwrap();
    let escrow = HandleEscrow::new(escrow_proxy, &provider);
    let native = escrow.NATIVE().call().await.unwrap();

    // Registry and libid-identity agree, pinned against Python's hashlib:
    //   hashlib.sha256(b"libid.github.handlealice-1")
    let node = registry
        .handleNodeOf(platform_id, "Alice-1".into())
        .call()
        .await
        .unwrap();
    assert_eq!(
        node,
        b256!("308384ccaaa9a343d9ff4eee1905eb96c737a7151658d8f8af847ef5ce363fb1")
    );
    assert_eq!(node.0, PLATFORM_GITHUB.handle_node("Alice-1").unwrap());

    // Escrowed for nobody; an unheld node refuses a claim with the bound error.
    let amount = U256::from(1_000_000_000_000_000_000u64);
    let receipt = escrow
        .deposit(platform_id, node, native, amount)
        .value(amount)
        .send()
        .await
        .unwrap()
        .get_receipt()
        .await
        .unwrap();
    let deposited = receipt
        .decoded_log::<HandleEscrow::Deposited>()
        .expect("no Deposited event");
    let grace = escrow.REFUND_GRACE().call().await.unwrap();
    let landed = provider
        .get_block_by_number(receipt.block_number.unwrap().into())
        .await
        .unwrap()
        .unwrap()
        .header
        .timestamp;
    let refundable_at = landed + grace.to::<u64>();
    assert_eq!(
        (
            deposited.handleNode,
            deposited.token,
            deposited.sender,
            deposited.round,
            deposited.amount,
            deposited.refundableAt
        ),
        (node, native, deployer, U256::ZERO, amount, refundable_at)
    );
    let contribution = escrow
        .contribution(node, native, deployer)
        .call()
        .await
        .unwrap();
    assert_eq!(
        (contribution.amount, contribution.refundableAt),
        (amount, refundable_at)
    );
    assert_eq!(escrow.escrowed(node, native).call().await.unwrap(), amount);
    let err = escrow
        .claim(node, vec![native], stranger)
        .from(stranger)
        .call()
        .await
        .err()
        .expect("an unheld handle was claimable")
        .to_string();
    assert!(
        err.contains(&hex::encode(HandleEscrow::NotTheHolder::SELECTOR)),
        "{err}"
    );

    // The refund waits for its date, then pays a recipient the sender names.
    let err = escrow
        .refund(node, native, stranger)
        .call()
        .await
        .err()
        .expect("a refund opened before its date")
        .to_string();
    assert!(
        err.contains(&hex::encode(HandleEscrow::RefundLocked::SELECTOR)),
        "{err}"
    );
    let _: serde_json::Value = provider
        .raw_request("evm_increaseTime".into(), (grace,))
        .await
        .unwrap();
    let before = provider.get_balance(stranger).await.unwrap();
    let receipt = escrow
        .refund(node, native, stranger)
        .send()
        .await
        .unwrap()
        .get_receipt()
        .await
        .unwrap();
    let refunded = receipt
        .decoded_log::<HandleEscrow::Refunded>()
        .expect("no Refunded event");
    assert_eq!(
        (
            refunded.handleNode,
            refunded.sender,
            refunded.recipient,
            refunded.round,
            refunded.released,
            refunded.received
        ),
        (node, deployer, stranger, U256::ZERO, amount, amount)
    );
    assert_eq!(
        provider.get_balance(stranger).await.unwrap() - before,
        amount
    );
}

/// The two Honk verifiers through `deploy_honk_verifier`: one transaction
/// each, under EIP-170, distinct, and each a real verifier that answers a
/// wrong-length proof with its `logN`. A second deploy of one circuit has
/// the first's code hash.
#[tokio::test]
async fn deploys_the_honk_verifiers_over_their_own_circuits() {
    use alloy::{
        primitives::Bytes,
        sol_types::SolError,
    };
    use libid_contracts::{
        bindings::circuits::{
            HonkVerifier,
            IHonkVerifierErrors,
        },
        circuits::{
            deploy_honk_verifier,
            version,
            Circuit,
        },
        platform_verifier::codehash_at,
    };

    let provider = test_provider();
    let artifacts = Artifacts::embedded();
    let deployer = default_signer(&provider).await;
    assert!(!version(&artifacts).unwrap().is_empty());

    let mut deployed = Vec::new();
    for circuit in Circuit::ALL {
        let before = provider.get_transaction_count(deployer).await.unwrap();
        let address = deploy_honk_verifier(&provider, &artifacts, circuit, None)
            .await
            .unwrap();
        assert_eq!(
            provider.get_transaction_count(deployer).await.unwrap() - before,
            1,
            "{circuit:?} took more than its own deploy"
        );
        let code = provider.get_code_at(address).await.unwrap();
        assert!(!code.is_empty(), "{circuit:?} has no code at {address:#x}");
        // anvil enforces EIP-170 already; the explicit check names the size.
        assert!(
            code.len() <= 24_576,
            "{circuit:?} is {} bytes, over EIP-170",
            code.len()
        );
        assert_eq!(
            codehash_at(&provider, address).await.unwrap(),
            keccak256(&code)
        );

        let err = HonkVerifier::new(address, &provider)
            .verify(Bytes::new(), Vec::new())
            .call()
            .await
            .expect_err("an empty proof is the wrong length");
        let data = err
            .as_revert_data()
            .expect("the verifier reverted with data");
        // `ProofLengthWrongWithLogN(logN, actualLength, expectedLength)`.
        let decoded = IHonkVerifierErrors::ProofLengthWrongWithLogN::abi_decode(&data)
            .expect("only a Honk verifier raises ProofLengthWrongWithLogN");
        assert!(
            decoded._0 > U256::ZERO,
            "{circuit:?} reports no circuit size"
        );
        deployed.push((address, decoded._0));
    }
    // One verification key per circuit.
    for (i, (a, _)) in deployed.iter().enumerate() {
        for (b, _) in &deployed[i + 1..] {
            assert_ne!(
                codehash_at(&provider, *a).await.unwrap(),
                codehash_at(&provider, *b).await.unwrap(),
                "two circuits would verify under one key"
            );
        }
    }

    // What a Platform Verifier pins is the same on every deployment.
    let again = deploy_honk_verifier(&provider, &artifacts, Circuit::BearerLink, None)
        .await
        .unwrap();
    assert_ne!(again, deployed[0].0);
    assert_eq!(
        codehash_at(&provider, again).await.unwrap(),
        codehash_at(&provider, deployed[0].0).await.unwrap()
    );
}

/// A consumer's test stack from the crate alone: the registry and Proof
/// Verifier behind proxies, the `testing` stub as X's Platform Verifier, and
/// a bind through it that records the stub's nodes.
#[cfg(feature = "testing")]
#[tokio::test]
async fn binds_through_the_stub_platform_verifier() {
    use alloy::{
        primitives::B256,
        sol_types::SolValue,
    };
    use libid_contracts::{
        platform_verifier::PlatformVerifier,
        testing::{
            deploy_stub_platform_verifier,
            stub_payload,
            StubPayload,
            StubPlatformVerifier,
        },
    };
    use libid_identity::platforms::PLATFORM_X;

    let provider = test_provider();
    let artifacts = Artifacts::embedded();
    let deployer = default_signer(&provider).await;
    let x = PlatformVerifier::X.platform_id();
    let fee = U256::from(7);

    let verifier_proxy = deploy_behind_proxy(
        &provider,
        &artifacts,
        "CeremonyProofVerifier",
        &CeremonyProofVerifier::initializeCall { owner_: deployer },
        None,
    )
    .await
    .unwrap();
    let registry_proxy = deploy_behind_proxy(
        &provider,
        &artifacts,
        "IdentityRegistry",
        &IdentityRegistry::initializeCall { owner_: deployer },
        None,
    )
    .await
    .unwrap();
    let stub_address = deploy_stub_platform_verifier(&provider, &artifacts, x, fee, None)
        .await
        .unwrap();

    let registry = IdentityRegistry::new(registry_proxy, &provider);
    registry
        .setProofVerifier(verifier_proxy)
        .send()
        .await
        .unwrap()
        .get_receipt()
        .await
        .unwrap();
    CeremonyProofVerifier::new(verifier_proxy, &provider)
        .setVerifier(x, 1, stub_address)
        .send()
        .await
        .unwrap()
        .get_receipt()
        .await
        .unwrap();
    let stub = StubPlatformVerifier::new(stub_address, &provider);
    stub.set("1234567890".into(), "Alice_X".into())
        .send()
        .await
        .unwrap()
        .get_receipt()
        .await
        .unwrap();
    assert_eq!(stub.platformId().call().await.unwrap(), x);
    assert_eq!(registry.quoteBind(x, 1).call().await.unwrap(), fee);

    // The registry's transaction data: the target alone; the bind pays no fee.
    let payload = stub_payload(&StubPayload {
        ceremonyVersion: 1,
        operationDomain: registry.OPERATION_DOMAIN().call().await.unwrap(),
        authorizationNonce: B256::repeat_byte(0x01),
        transactionData: (deployer,).abi_encode_params().into(),
    });
    let receipt = registry
        .bind(
            x,
            1,
            payload.clone(),
            "alice_x".into(),
            true,
            U256::ZERO,
            Address::ZERO,
        )
        .value(fee)
        .send()
        .await
        .unwrap()
        .get_receipt()
        .await
        .unwrap();
    assert!(receipt.status());

    let id_node = PLATFORM_X.id_node("1234567890").unwrap();
    let handle_node = PLATFORM_X.handle_node("Alice_X").unwrap();
    let bound = receipt
        .decoded_log::<IdentityRegistry::IdentityBound>()
        .expect("IdentityBound");
    assert_eq!(bound.holder, deployer);
    assert_eq!(bound.idNode, id_node);
    assert_eq!(bound.handleNode, handle_node);
    assert_eq!(bound.platformId, x);
    assert_eq!(bound.observedAt, stub.observedAt().call().await.unwrap());
    assert_eq!(bound.ceremonyVersion, 1);

    // The stub decoded the payload it was sent, and took the fee.
    assert_eq!(stub.lastPayload().call().await.unwrap(), payload);
    assert_eq!(stub.lastValue().call().await.unwrap(), fee);
    assert_eq!(
        registry
            .resolveHandle(x, "alice_x".into())
            .call()
            .await
            .unwrap(),
        deployer
    );
}
