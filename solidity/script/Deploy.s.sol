// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Script, console} from "forge-std/Script.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {IdentityRegistry} from "../contracts/identity/IdentityRegistry.sol";
import {NotaryService} from "../contracts/ceremony/NotaryService.sol";
import {INotaryService} from "../contracts/ceremony/INotaryService.sol";
import {CeremonyProofVerifier} from "../contracts/ceremony/CeremonyProofVerifier.sol";
import {IProofVerifier} from "../contracts/ceremony/IProofVerifier.sol";
import {HandleVectors} from "../contracts/identity/HandleVectors.sol";
import {GoogleJwtRoots} from "../contracts/ceremony/GoogleJwtRoots.sol";

/// @notice Deploy the identity stack to any EVM chain.
///
/// Four UUPS proxies, in dependency order: the Notary Service every notarized
/// session is verified through, the Proof Verifier the identity registry
/// dispatches bindings through, the registry itself with handle rules per
/// platform, and the Google JWT root list that pays the Notary Service for
/// each rotation. No Platform Verifier is registered here -- that needs the
/// ceremony circuit artifacts, which arrive with their own release.
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
        // Forge injects PRIVATE_KEY without 0x prefix via --private-key flag.
        if (bytes(deployerKeyHex).length == 64) {
            deployerKeyHex = string.concat("0x", deployerKeyHex);
        }
        uint256 deployerKey = vm.parseUint(deployerKeyHex);
        address deployer = vm.addr(deployerKey);
        address notaryAddr = vm.envOr("NOTARY_ADDRESS", deployer);
        uint256 notaryFee = vm.envOr("NOTARY_FEE_WEI", uint256(0));

        vm.startBroadcast(deployerKey);

        // 1. The Notary Service (UUPS proxy) -- the ONE place a notary
        //    attestation is authenticated, deployed first so its proxy address
        //    can be wired into every consumer's initialize. It derives the
        //    digest from the attested bytes itself (REQ-COMMON-33) and charges
        //    the Notary Fee. Key rotation is `setNotary`; a fee change is
        //    `setFee`; a proof-system change is a UUPS upgrade of this proxy
        //    alone.
        NotaryService notaryServiceImpl = new NotaryService();
        address notaryServiceAddr = address(
            new ERC1967Proxy(
                address(notaryServiceImpl), abi.encodeCall(NotaryService.initialize, (deployer, notaryAddr, notaryFee))
            )
        );

        // 2. The ceremony core the Consumer dispatches through. Without it
        //    `proofVerifier` reads zero, `quoteBind` calls address zero and
        //    every resolver reverts `UnknownPlatform` -- a deployment that can
        //    bind nothing.
        CeremonyProofVerifier pvImpl = new CeremonyProofVerifier();
        address proofVerifierAddr =
            address(new ERC1967Proxy(address(pvImpl), abi.encodeCall(CeremonyProofVerifier.initialize, (deployer))));

        // 3. The identity registry: one contract holding the bindings,
        //    dispatching every one through the Proof Verifier above.
        IdentityRegistry registryImpl = new IdentityRegistry();
        address identityRegistryAddr =
            address(new ERC1967Proxy(address(registryImpl), abi.encodeCall(IdentityRegistry.initialize, (deployer))));
        IdentityRegistry registry = IdentityRegistry(identityRegistryAddr);
        registry.setProofVerifier(IProofVerifier(proofVerifierAddr));

        // Handle rules per platform. Registering a Platform Verifier against a
        // version is `CeremonyProofVerifier.setVerifier`, and one needs the
        // ceremony circuit's artifact and its code hash -- neither of which
        // this script has until that release lands.
        _wireIdentityPlatform(registry, HandleVectors.PLATFORM_X);
        _wireIdentityPlatform(registry, HandleVectors.PLATFORM_GITHUB);
        _wireIdentityPlatform(registry, HandleVectors.PLATFORM_GOOGLE);

        // 4. The Google JWT root list, beside the Platform Verifier it serves.
        //    That verifier reads the trusted moduli through it, and nothing
        //    is trusted until a notarized reading of Google's JWKS lands --
        //    verified through the Notary Service above, like every other
        //    notarized session, and paying the same fee.
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
        console.log("      circuit artifacts are released. Until then a platform");
        console.log("      has its rules and can verify nothing.");
        // Nothing is trusted until a notarized reading of Google's JWKS lands.
        // Until then every Google binding reverts `UntrustedModulus`, which reads
        // as a bad proof rather than an unseeded list.
        console.log("NOTE: point the keeper at GOOGLE_JWT_ROOTS_ADDRESS");
        console.log("      before Google bindings work. The trust list starts empty.");
    }

    /// @dev Give a platform its handle rules.
    ///
    ///      One helper rather than the call spelled out per platform: the rules
    ///      come from the generated table keyed by platform id, so a new
    ///      platform is one line here and cannot pick up a neighbour's rules by
    ///      a copy-paste slip.
    function _wireIdentityPlatform(IdentityRegistry registry, bytes32 platformId) internal {
        registry.setPlatform(platformId, HandleVectors.rulesFor(platformId));
    }
}
