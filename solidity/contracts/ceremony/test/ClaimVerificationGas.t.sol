// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

import {CeremonyAttestation} from "../CeremonyAttestation.sol";
import {GitHubPlatformVerifier} from "../GitHubPlatformVerifier.sol";
import {ICeremony} from "../ICeremony.sol";
import {INotaryService} from "../INotaryService.sol";
import {IPlatformVerifier} from "../IPlatformVerifier.sol";
import {NotaryService} from "../NotaryService.sol";
import {IHonkVerifier} from "../PlatformVerifierBase.sol";
import {TlsNotaryVerifierBase} from "../TlsNotaryVerifierBase.sol";
import {XPlatformVerifier} from "../XPlatformVerifier.sol";

/// @notice The gas of each verifier's `verify` on a real claim, recorded in
///         `snapshots/claim-verification.json`.
///
/// @dev Each number is what the `verify` frame used (`vm.lastCallGas`), not
///      what the test spends around it. `FOUNDRY_PROFILE=gas forge test`
///      records them under Osaka, the rules eden-testnet executes. A default
///      run makes the same calls under cancun and leaves the file as it is.
///
///      The X and GitHub sessions are captured ceremonies, and they carry no
///      proof: proving their bearer takes the bearer itself. So each session's
///      bearer commitment is swapped for the one the bearer-link fixture
///      proves, and the attestation signed again with the key the capture
///      used. The real Honk verifier then checks a valid proof inside the
///      call. Every other check reads the session as captured, since none of
///      them reads a commitment's value.
///
///      Wired as eden-testnet runs them: Platform Verifiers behind proxies and
///      no Notary Fee. `quote` runs right before `verify`, as the Proof
///      Verifier calls it, so what the quote reads is warm as it is on chain.
///      The Honk verifiers are deployed from their artifacts, for the reason
///      `HonkVerifiersTest` gives.
contract ClaimVerificationGasTest is Test {
    string constant GROUP = "claim-verification";

    address constant OWNER = address(0xA11CE);
    /// The notary key the ceremonies were captured with.
    uint256 constant NOTARY_KEY = 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80;
    uint64 constant LIFETIME = 3600;
    uint64 constant SKEW = 300;

    string constant X_CEREMONY = "contracts/ceremony/test/fixtures/x-ceremony-real.json";
    string constant GITHUB_CEREMONY = "contracts/ceremony/test/fixtures/github-ceremony-real.json";
    string constant BEARER_LINK_PROOF = "contracts/circuits/test/fixtures/bearer-link-proof.json";
    string constant OIDC_GOOGLE_PROOF = "contracts/circuits/test/fixtures/oidc-google-proof.json";

    IHonkVerifier bearerLink;
    IHonkVerifier oidcGoogle;
    IPlatformVerifier x;
    IPlatformVerifier gitHub;

    function setUp() public {
        bearerLink = IHonkVerifier(vm.deployCode("BearerLinkHonkVerifier.sol:BearerLinkHonkVerifier"));
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
                        XPlatformVerifier.initialize,
                        (OWNER, notary, bearerLink, address(bearerLink).codehash, LIFETIME, SKEW, SKEW)
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
                        (OWNER, notary, bearerLink, address(bearerLink).codehash, LIFETIME, SKEW, SKEW)
                    )
                )
            )
        );
    }

    function test_verifyXCeremony() public {
        _verifyCeremony(x, X_CEREMONY, "XPlatformVerifier.verify");
    }

    function test_verifyGitHubCeremony() public {
        _verifyCeremony(gitHub, GITHUB_CEREMONY, "GitHubPlatformVerifier.verify");
    }

    function test_verifyBearerLinkProof() public {
        _verifyProof(bearerLink, BEARER_LINK_PROOF, "BearerLinkHonkVerifier.verify");
    }

    function test_verifyOidcGoogleProof() public {
        _verifyProof(oidcGoogle, OIDC_GOOGLE_PROOF, "OidcGoogleHonkVerifier.verify");
    }

    function _verifyCeremony(IPlatformVerifier verifier, string memory ceremony, string memory name) private {
        string memory session = vm.readFile(ceremony);
        string memory proof = vm.readFile(BEARER_LINK_PROOF);
        bytes32[] memory inputs = vm.parseJsonBytes32Array(proof, ".public_inputs");
        bytes memory token = vm.parseJsonBytes(session, ".token.attested_data");
        bytes memory identity = vm.parseJsonBytes(session, ".identity.attested_data");

        TlsNotaryVerifierBase.TlsNotaryProof memory p;
        p.ceremonyVersion = uint16(vm.parseJsonUint(session, ".ceremony_version"));
        p.operationDomain = vm.parseJsonBytes32(session, ".operation_domain");
        p.authorizationNonce = vm.parseJsonBytes32(session, ".authorization_nonce");
        p.transactionData = vm.parseJsonBytes(session, ".transaction_data");
        // Token commitment first, then identity: the circuit's order.
        p.tokenSession = _resigned(token, _tokenCommitment(token), _commitment(inputs, 0));
        p.identitySession = _resigned(identity, _identityCommitment(identity), _commitment(inputs, 32));
        p.proof = vm.parseJsonBytes(proof, ".proof");
        bytes memory payload = abi.encode(p);

        vm.warp(vm.parseJsonUint(session, ".identity.created_at") + 60);
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

    /// `decode` reads calldata, so the test calls itself to decode.
    function decodeAttestation(bytes calldata attested)
        external
        pure
        returns (CeremonyAttestation.AttestedData memory)
    {
        return CeremonyAttestation.decode(attested);
    }

    /// The bearer's commitment, found as the verifier finds it.
    function _tokenCommitment(bytes memory attested) private view returns (bytes32) {
        CeremonyAttestation.AttestedData memory data = this.decodeAttestation(attested);
        return CeremonyAttestation.requireFramedCommitment(data.received, '"access_token":"', '"').commitment;
    }

    function _identityCommitment(bytes memory attested) private view returns (bytes32) {
        CeremonyAttestation.AttestedData memory data = this.decodeAttestation(attested);
        (CeremonyAttestation.RangeCommitment memory bearer,) =
            CeremonyAttestation.requireBearerHeaderRequest(data.sent, data.sentTranscriptLength);
        return bearer.commitment;
    }

    /// The commitment a proof's public inputs spell from `offset`, one byte
    /// per input.
    function _commitment(bytes32[] memory inputs, uint256 offset) private pure returns (bytes32 commitment) {
        for (uint256 i = 0; i < 32; ++i) {
            commitment |= inputs[offset + i] << (8 * (31 - i));
        }
    }

    /// `attested` with the commitment `from` replaced by `to`, signed by the
    /// notary key.
    function _resigned(bytes memory attested, bytes32 from, bytes32 to)
        private
        pure
        returns (ICeremony.Attestation memory)
    {
        bytes memory swapped = bytes.concat(attested);
        uint256 found;
        for (uint256 at = 0; at + 32 <= swapped.length; ++at) {
            bytes32 word;
            assembly ("memory-safe") {
                word := mload(add(add(swapped, 0x20), at))
            }
            if (word != from) continue;
            assembly ("memory-safe") {
                mstore(add(add(swapped, 0x20), at), to)
            }
            ++found;
        }
        assertEq(found, 1, "the commitment occurs once");

        bytes32 digest = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", keccak256(swapped)));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(NOTARY_KEY, digest);
        return ICeremony.Attestation({attestedData: swapped, proof: abi.encodePacked(r, s, v)});
    }
}
