// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Script, console} from "forge-std/Script.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {IdentityRegistry} from "../contracts/identity/IdentityRegistry.sol";
import {NotaryService} from "../contracts/ceremony/NotaryService.sol";
import {INotaryService} from "../contracts/ceremony/INotaryService.sol";
import {CeremonyProofVerifier} from "../contracts/ceremony/CeremonyProofVerifier.sol";
import {IProofVerifier} from "../contracts/ceremony/IProofVerifier.sol";
import {GoogleJwtRoots} from "../contracts/ceremony/GoogleJwtRoots.sol";

/// @notice Deploy the identity stack to any EVM chain: four UUPS proxies for the
/// Notary Service, Proof Verifier, identity registry and Google JWT root list.
/// No Platform Verifier is registered.
///
/// Usage:
///   forge script script/Deploy.s.sol \
///     --rpc-url http://127.0.0.1:8545 \
///     --broadcast \
///     --private-key $PRIVATE_KEY
///
/// Env:
///   DEPLOYER_KEY / PRIVATE_KEY — deployer private key (one of the two).
///   NOTARY_ADDRESS   — the first trusted notary signing key (default: deployer).
///   NOTARY_FEE_WEI   — what one attestation verification costs (default: 0).
contract Deploy is Script {
    function run() external {
        string memory deployerKeyHex = vm.envOr("DEPLOYER_KEY", vm.envOr("PRIVATE_KEY", string("")));
        require(bytes(deployerKeyHex).length > 0, "set DEPLOYER_KEY or PRIVATE_KEY");
        // Accept a 64-hex key without its 0x prefix.
        if (bytes(deployerKeyHex).length == 64) {
            deployerKeyHex = string.concat("0x", deployerKeyHex);
        }
        uint256 deployerKey = vm.parseUint(deployerKeyHex);
        address deployer = vm.addr(deployerKey);
        address notaryAddr = vm.envOr("NOTARY_ADDRESS", deployer);
        uint256 notaryFee = vm.envOr("NOTARY_FEE_WEI", uint256(0));

        vm.startBroadcast(deployerKey);

        // 1. The Notary Service, the one place a notary attestation is
        //    authenticated (REQ-COMMON-33). First, so consumers can be
        //    initialized with its address.
        NotaryService notaryServiceImpl = new NotaryService();
        address notaryServiceAddr = address(
            new ERC1967Proxy(
                address(notaryServiceImpl), abi.encodeCall(NotaryService.initialize, (deployer, notaryAddr, notaryFee))
            )
        );

        // 2. The Proof Verifier every binding is verified through.
        CeremonyProofVerifier pvImpl = new CeremonyProofVerifier();
        address proofVerifierAddr =
            address(new ERC1967Proxy(address(pvImpl), abi.encodeCall(CeremonyProofVerifier.initialize, (deployer))));

        // 3. The identity registry, pointed at the Proof Verifier.
        IdentityRegistry registryImpl = new IdentityRegistry();
        address identityRegistryAddr =
            address(new ERC1967Proxy(address(registryImpl), abi.encodeCall(IdentityRegistry.initialize, (deployer))));
        IdentityRegistry registry = IdentityRegistry(identityRegistryAddr);
        registry.setProofVerifier(IProofVerifier(proofVerifierAddr));
        // A platform is enabled by `CeremonyProofVerifier.setVerifier`, which needs circuit artifacts.

        // 4. The Google JWT root list the Google Platform Verifier reads its
        //    trusted moduli from. It verifies notarized JWKS readings through
        //    the Notary Service and starts empty.
        GoogleJwtRoots rootsImpl = new GoogleJwtRoots();
        address jwtRootsAddr = address(
            new ERC1967Proxy(
                address(rootsImpl),
                abi.encodeCall(GoogleJwtRoots.initialize, (deployer, INotaryService(notaryServiceAddr)))
            )
        );

        vm.stopBroadcast();

        console.log("=== Deployment complete ===");
        console.log("Deployer:               ", deployer);
        console.log("NOTARY_SERVICE_ADDRESS= ", notaryServiceAddr);
        console.log("CEREMONY_PROOF_VERIFIER_ADDRESS= ", proofVerifierAddr);
        console.log("IDENTITY_REGISTRY_ADDRESS= ", identityRegistryAddr);
        console.log("GOOGLE_JWT_ROOTS_ADDRESS= ", jwtRootsAddr);
        console.log("NOTE: no Platform Verifier is registered yet. Add one with");
        console.log("      CeremonyProofVerifier.setVerifier once the ceremony");
        console.log("      circuit artifacts are released. Until then no");
        console.log("      platform can bind.");
        // Until the first JWKS reading lands, every Google binding reverts `UntrustedModulus`.
        console.log("NOTE: point the keeper at GOOGLE_JWT_ROOTS_ADDRESS");
        console.log("      before Google bindings work. The trust list starts empty.");
    }
}
