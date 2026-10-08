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
        identity::IdentityRegistry,
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
/// Notary Service first, then the Proof Verifier, the registry given its
/// platform rules and pointed at the Proof Verifier, and the Google JWT root list
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

    // Wire the registry: the Proof Verifier it dispatches through, and the
    // platform's rules. The platform id is keccak256 of the platform key:
    // libID namespaces only its own strings.
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
    registry
        .setPlatform(
            platform_id,
            IdentityRegistry::Rules {
                maxLength: 39,
                isEmail: false,
                allowUnderscore: false,
                allowHyphen: true,
            },
            libid_identity::handle_vectors::HANDLE_TAG_GITHUB
                .as_bytes()
                .to_vec()
                .into(),
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

    assert_eq!(
        registry.proofVerifier().call().await.unwrap(),
        verifier_proxy
    );
    // A platform that has rules and can verify nothing says so: answering
    // `address(0)` would tell the caller "nobody holds this handle" about a
    // platform that is not wired yet.
    let unwired = registry
        .resolveHandle(platform_id, "octocat".into())
        .call()
        .await;
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
/// WITHOUT its predeployed CREATE2 deployer, so `FactoryGenesis::ensure`
/// must install it via the keyless presigned transaction (funding the
/// one-time signer first), then deploy the factory impl + proxy at their
/// canonical addresses, owned by the genesis admin from the first block.
/// Then a Notary Service proxy goes through the factory at its name-derived
/// CREATE3 address.
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

    // Truly bare chain: no CREATE2 deployer.
    assert!(provider
        .get_code_at(CREATE2_DEPLOYER)
        .await
        .unwrap()
        .is_empty());

    let factory = genesis.ensure(&provider, &artifacts).await.unwrap();
    assert_eq!(factory, genesis.address(&artifacts).unwrap());
    assert!(!provider.get_code_at(factory).await.unwrap().is_empty());

    // The instant the proxy exists it is owned by its genesis admin —
    // initialization was atomic with deployment.
    let factory_contract = LibidFactory::new(factory, &provider);
    assert_eq!(factory_contract.owner().call().await.unwrap(), deployer0);

    // Rerun = read-only no-op.
    assert_eq!(
        genesis.ensure(&provider, &artifacts).await.unwrap(),
        factory
    );

    // Another admin is another factory, at another address.
    let other = FactoryGenesis {
        admin: Address::repeat_byte(0x22),
    };
    assert_ne!(other.address(&artifacts).unwrap(), factory);

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
/// circuit. The code hash the
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
    // The real verifiers, one per circuit. The hash a Platform Verifier
    // pins is read off the chain, never computed from the vendored bytes:
    // it is what the chain holds for the artifact.
    let bearer_link_x =
        deploy_honk_verifier(&provider, &artifacts, Circuit::BearerLinkX, None)
            .await
            .unwrap();
    let bearer_link_github =
        deploy_honk_verifier(&provider, &artifacts, Circuit::BearerLinkGithub, None)
            .await
            .unwrap();
    let oidc_google =
        deploy_honk_verifier(&provider, &artifacts, Circuit::OidcGoogle, None)
            .await
            .unwrap();
    let honk_at = |circuit: Circuit| match circuit {
        Circuit::BearerLinkX => bearer_link_x,
        Circuit::BearerLinkGithub => bearer_link_github,
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
    let honk = bearer_link_x;
    let honk_codehash = codehash_at(&provider, honk).await.unwrap();

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

    for init in [
        Initializer::X(tls(bearer_link_x)),
        Initializer::GitHub(tls(bearer_link_github)),
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
                // The window is compiled into the contract from the same
                // profile table the generated constants come from.
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
                    libid_profiles::FUTURE_OBSERVATION_ALLOWANCE_SECONDS_GOOGLE
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
    let err = Initializer::X(tls(Address::repeat_byte(0x99)))
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

/// (e2) The handle escrow against a real chain: pay an unclaimed handle by its
/// hash, check the value lands on the registry's node, and refund it. The
/// payout path needs a stub Platform Verifier, which is kept out of this
/// crate's artifacts; the Solidity suite covers it.
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
    registry
        .setPlatform(
            platform_id,
            IdentityRegistry::Rules {
                maxLength: 39,
                isEmail: false,
                allowUnderscore: false,
                allowHyphen: true,
            },
            libid_identity::handle_vectors::HANDLE_TAG_GITHUB
                .as_bytes()
                .to_vec()
                .into(),
        )
        .send()
        .await
        .unwrap()
        .get_receipt()
        .await
        .unwrap();

    // The real GitHub Platform Verifier, on the real Honk verifier for its
    // circuit, registered as version 1.
    let honk =
        deploy_honk_verifier(&provider, &artifacts, Circuit::BearerLinkGithub, None)
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

    // The registry folds and hashes the text into the node the circuit
    // binds; libid-identity computes the same node off chain, and both are
    // pinned against Python's hashlib:
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
    assert_eq!(
        node.0,
        libid_identity::handle_node("github", "Alice-1")
            .unwrap()
            .unwrap()
    );

    // Escrowed for nobody; an unheld node refuses a claim with the bound error.
    let amount = U256::from(1_000_000_000_000_000_000u64);
    escrow
        .deposit(platform_id, node, native, amount, deployer)
        .value(amount)
        .send()
        .await
        .unwrap()
        .get_receipt()
        .await
        .unwrap();
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

    // The depositor refunds to a recipient it names, and the event decodes.
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
            refunded.refundTo,
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

/// (f) The two Honk verifiers through `deploy_honk_verifier`: one
/// transaction each, each under EIP-170, and each answering for its OWN
/// circuit. A bb verifier has no getter for its verification key; the one
/// thing it says about itself is the `logN` a wrong-length proof comes back
/// with. That separates a real verifier from a contract that merely has
/// code, and the two circuits from each other — the check that would catch
/// a release whose tarballs were swapped, or a vendor run that wrote one
/// circuit's verifier under the other's name. Then a second deploy of one
/// circuit: its code hash is the first's, a function of the artifact alone.
#[tokio::test]
async fn deploys_the_honk_verifiers_over_their_own_circuits() {
    use alloy::{
        primitives::Bytes,
        sol_types::SolError,
    };
    use libid_contracts::{
        bindings::circuits::HonkVerifier,
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
        deployed.push((address, decoded.logN));
    }
    // One verification key per circuit: X and GitHub prove at the same size,
    // so the code, not the size, is what tells their verifiers apart.
    for (i, (a, _)) in deployed.iter().enumerate() {
        for (b, _) in &deployed[i + 1..] {
            assert_ne!(
                codehash_at(&provider, *a).await.unwrap(),
                codehash_at(&provider, *b).await.unwrap(),
                "two platforms would verify under one circuit"
            );
        }
    }

    // What a Platform Verifier pins is the same on every deployment.
    let again = deploy_honk_verifier(&provider, &artifacts, Circuit::BearerLinkX, None)
        .await
        .unwrap();
    assert_ne!(again, deployed[0].0);
    assert_eq!(
        codehash_at(&provider, again).await.unwrap(),
        codehash_at(&provider, deployed[0].0).await.unwrap()
    );
}
