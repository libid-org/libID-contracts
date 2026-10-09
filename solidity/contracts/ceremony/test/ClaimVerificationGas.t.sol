// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {TlsNotaryProof} from "../CeremonyPayloads.sol";
import {Test} from "forge-std/Test.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

import {AttestationBuilder} from "./AttestationBuilder.sol";
import {GitHubPlatformVerifier} from "../GitHubPlatformVerifier.sol";
import {ICeremony} from "../ICeremony.sol";
import {INotaryService} from "../INotaryService.sol";
import {IPlatformVerifier} from "../IPlatformVerifier.sol";
import {NotaryService} from "../NotaryService.sol";
import {IHonkVerifier} from "../PlatformVerifierBase.sol";
import {XPlatformVerifier} from "../XPlatformVerifier.sol";

/// @notice The gas of each verifier's `verify` on a real claim, recorded in
///         `snapshots/claim-verification.json`.
///
/// @dev Each number is what the `verify` frame used (`vm.lastCallGas`), not
///      what the test spends around it. `FOUNDRY_PROFILE=gas forge test`
///      records them under Osaka, the rules eden-testnet executes. A default
///      run makes the same calls under cancun and leaves the file as it is.
///
///      The X and GitHub sessions are the records libid-rs's
///      `ceremony_fixtures` produces, laid out as the anchor-only reveal lays
///      them out -- the id and handle each committed, their anchors revealed
///      -- with the proof bb made of each session's witness. Nothing is
///      re-signed: the real Honk verifier checks a valid proof of exactly the
///      commitments the notary signed, and the nodes the payload names are
///      the ones that proof outputs. The captured ceremonies reveal the id and
///      handle, which the framing refuses, so they are not measured until
///      they are recaptured.
///
///      Wired as eden-testnet runs them: Platform Verifiers behind proxies and
///      no Notary Fee. `quote` runs right before `verify`, as the Proof
///      Verifier calls it, so what the quote reads is warm as it is on chain.
///      The Honk verifiers are deployed from their artifacts, for the reason
///      `HonkVerifiersTest` gives.
contract ClaimVerificationGasTest is Test {
    string constant GROUP = "claim-verification";

    address constant OWNER = address(0xA11CE);
    /// The notary key the fixture sessions are signed with.
    uint256 constant NOTARY_KEY = 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80;

    string constant X_CEREMONY = "contracts/ceremony/test/fixtures/x-ceremony-session.json";
    string constant X_PROOF = "contracts/ceremony/test/fixtures/x-ceremony-session-proof.json";
    string constant GITHUB_CEREMONY = "contracts/ceremony/test/fixtures/github-ceremony-session.json";
    string constant GITHUB_PROOF = "contracts/ceremony/test/fixtures/github-ceremony-session-proof.json";
    string constant BEARER_LINK_X_PROOF = "contracts/circuits/test/fixtures/bearer-link-x-proof.json";
    string constant BEARER_LINK_GITHUB_PROOF = "contracts/circuits/test/fixtures/bearer-link-github-proof.json";
    string constant OIDC_GOOGLE_PROOF = "contracts/circuits/test/fixtures/oidc-google-proof.json";

    IHonkVerifier bearerLinkX;
    IHonkVerifier bearerLinkGithub;
    IHonkVerifier oidcGoogle;
    IPlatformVerifier x;
    IPlatformVerifier gitHub;

    function setUp() public {
        bearerLinkX = IHonkVerifier(vm.deployCode("BearerLinkXHonkVerifier.sol:BearerLinkXHonkVerifier"));
        bearerLinkGithub = IHonkVerifier(vm.deployCode("BearerLinkGithubHonkVerifier.sol:BearerLinkGithubHonkVerifier"));
        oidcGoogle = IHonkVerifier(vm.deployCode("OidcGoogleHonkVerifier.sol:OidcGoogleHonkVerifier"));

        INotaryService notary = INotaryService(
            address(
                new ERC1967Proxy(
                    address(new NotaryService()),
                    abi.encodeCall(NotaryService.initialize, (OWNER, vm.addr(NOTARY_KEY), 0))
                )
            )
        );
        x = IPlatformVerifier(
            address(
                new ERC1967Proxy(
                    address(new XPlatformVerifier()),
                    abi.encodeCall(
                        XPlatformVerifier.initialize, (OWNER, notary, bearerLinkX, address(bearerLinkX).codehash)
                    )
                )
            )
        );
        gitHub = IPlatformVerifier(
            address(
                new ERC1967Proxy(
                    address(new GitHubPlatformVerifier()),
                    abi.encodeCall(
                        GitHubPlatformVerifier.initialize,
                        (OWNER, notary, bearerLinkGithub, address(bearerLinkGithub).codehash)
                    )
                )
            )
        );
    }

    function test_verifyXCeremony() public {
        _verifyCeremony(x, X_CEREMONY, X_PROOF, "XPlatformVerifier.verify");
    }

    function test_verifyGitHubCeremony() public {
        _verifyCeremony(gitHub, GITHUB_CEREMONY, GITHUB_PROOF, "GitHubPlatformVerifier.verify");
    }

    function test_verifyBearerLinkXProof() public {
        _verifyProof(bearerLinkX, BEARER_LINK_X_PROOF, "BearerLinkXHonkVerifier.verify");
    }

    function test_verifyBearerLinkGithubProof() public {
        _verifyProof(bearerLinkGithub, BEARER_LINK_GITHUB_PROOF, "BearerLinkGithubHonkVerifier.verify");
    }

    function test_verifyOidcGoogleProof() public {
        _verifyProof(oidcGoogle, OIDC_GOOGLE_PROOF, "OidcGoogleHonkVerifier.verify");
    }

    function _verifyCeremony(
        IPlatformVerifier verifier,
        string memory ceremony,
        string memory proofFixture,
        string memory name
    ) private {
        string memory session = vm.readFile(ceremony);
        string memory proof = vm.readFile(proofFixture);
        bytes32[] memory inputs = vm.parseJsonBytes32Array(proof, ".public_inputs");

        TlsNotaryProof memory p;
        p.ceremonyVersion = uint16(vm.parseJsonUint(session, ".ceremony_version"));
        p.operationDomain = vm.parseJsonBytes32(session, ".operation_domain");
        p.authorizationNonce = vm.parseJsonBytes32(session, ".authorization_nonce");
        p.transactionData = vm.parseJsonBytes(session, ".transaction_data");
        p.tokenSession = ICeremony.Attestation({
            attestedData: vm.parseJsonBytes(session, ".token.attested_data"),
            proof: vm.parseJsonBytes(session, ".token.notary_signature")
        });
        p.identitySession = ICeremony.Attestation({
            attestedData: vm.parseJsonBytes(session, ".identity.attested_data"),
            proof: vm.parseJsonBytes(session, ".identity.notary_signature")
        });
        // The nodes the circuit output, `[high, low]` at fields 8 to 11.
        p.idNode = AttestationBuilder.nodeAt(inputs, 8);
        p.handleNode = AttestationBuilder.nodeAt(inputs, 10);
        p.proof = vm.parseJsonBytes(proof, ".proof");
        bytes memory payload = abi.encode(p);

        vm.chainId(vm.parseJsonUint(session, ".chain_id"));
        vm.warp(vm.parseJsonUint(session, ".created_at") + 60);
        uint256 fee = verifier.quote();
        verifier.verify{value: fee}(payload);
        vm.snapshotValue(GROUP, name, vm.lastCallGas().gasTotalUsed);
    }

    function _verifyProof(IHonkVerifier verifier, string memory fixture, string memory name) private {
        string memory json = vm.readFile(fixture);
        bytes memory proof = vm.parseJsonBytes(json, ".proof");
        bytes32[] memory inputs = vm.parseJsonBytes32Array(json, ".public_inputs");
        assertTrue(verifier.verify(proof, inputs), "the proof does not verify");
        vm.snapshotValue(GROUP, name, vm.lastCallGas().gasTotalUsed);
    }
}
