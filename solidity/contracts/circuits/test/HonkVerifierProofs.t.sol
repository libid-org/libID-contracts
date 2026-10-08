// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";

import {IHonkVerifier} from "../../ceremony/PlatformVerifierBase.sol";

/// @notice A vendored Honk verifier accepts a real proof of its circuit, and
///         no proof or public input one bit away from it.
///
/// @dev The fixtures are proofs bb 6.0.0-rc.2 made with `bb prove -t evm` of the
///      witnesses libid-circuits commits as `circuits/<circuit>/Prover.toml`:
///      each bearer-link circuit's witness of the libid-rs ceremony fixture
///      session for its platform, and a Google-shaped token signed by a
///      synthetic RSA-2048 key. A circuits release that changes a verification
///      key fails here until they are proved again under it.
///
///      The verifier is deployed from its artifact, not imported, for the
///      reason `HonkVerifiersTest` gives.
abstract contract HonkVerifierProofTest is Test {
    IHonkVerifier private verifier;
    bytes private proof;
    bytes32[] private publicInputs;

    /// `<file>.sol:<contract>` of the verifier under test.
    function _artifact() internal pure virtual returns (string memory);

    /// The proof fixture, relative to the Foundry root.
    function _fixture() internal pure virtual returns (string memory);

    /// The most gas `verify` may spend on the fixture's proof.
    function _verifyGasBound() internal pure virtual returns (uint64);

    function setUp() public {
        verifier = IHonkVerifier(vm.deployCode(_artifact()));
        string memory json = vm.readFile(_fixture());
        proof = vm.parseJsonBytes(json, ".proof");
        publicInputs = vm.parseJsonBytes32Array(json, ".public_inputs");
    }

    function test_acceptsTheProof() public {
        bytes memory p = proof;
        bytes32[] memory inputs = publicInputs;
        assertTrue(verifier.verify(p, inputs), "the proof does not verify");
        uint64 used = vm.lastCallGas().gasTotalUsed;
        emit log_named_uint("verify gas", used);
        assertLe(used, _verifyGasBound(), "verify costs more than its bound");
    }

    function test_rejectsEveryProofWordChanged() public view {
        bytes32[] memory inputs = publicInputs;
        assertTrue(_verifies(proof, inputs), "the unchanged proof does not verify");
        uint256 words = proof.length / 32;
        for (uint256 i = 0; i < words; ++i) {
            bytes memory changed = bytes.concat(proof);
            changed[i * 32 + 31] ^= 0x01;
            assertFalse(_verifies(changed, inputs), string.concat("proof word ", vm.toString(i)));
        }
    }

    function test_rejectsEveryPublicInputChanged() public view {
        bytes memory p = proof;
        assertTrue(_verifies(p, publicInputs), "the unchanged proof does not verify");
        for (uint256 i = 0; i < publicInputs.length; ++i) {
            bytes32[] memory changed = publicInputs;
            changed[i] ^= bytes32(uint256(1));
            assertFalse(_verifies(p, changed), string.concat("public input ", vm.toString(i)));
        }
    }

    /// Whether `verify` says yes. A Honk verifier rejects by reverting, so a
    /// revert is a no. The call gets twice the bound, plenty for a proof it
    /// accepts: an invalid curve point makes the precompile consume all the
    /// gas the verifier forwards, and uncapped that would be the whole test's.
    function _verifies(bytes memory p, bytes32[] memory inputs) private view returns (bool) {
        try verifier.verify{gas: 2 * _verifyGasBound()}(p, inputs) returns (bool ok) {
            return ok;
        } catch {
            return false;
        }
    }
}

contract BearerLinkXHonkVerifierProofTest is HonkVerifierProofTest {
    function _artifact() internal pure override returns (string memory) {
        return "BearerLinkXHonkVerifier.sol:BearerLinkXHonkVerifier";
    }

    function _fixture() internal pure override returns (string memory) {
        return "contracts/circuits/test/fixtures/bearer-link-x-proof.json";
    }

    function _verifyGasBound() internal pure override returns (uint64) {
        return 750_000;
    }
}

contract BearerLinkGithubHonkVerifierProofTest is HonkVerifierProofTest {
    function _artifact() internal pure override returns (string memory) {
        return "BearerLinkGithubHonkVerifier.sol:BearerLinkGithubHonkVerifier";
    }

    function _fixture() internal pure override returns (string memory) {
        return "contracts/circuits/test/fixtures/bearer-link-github-proof.json";
    }

    function _verifyGasBound() internal pure override returns (uint64) {
        return 750_000;
    }
}

contract OidcGoogleHonkVerifierProofTest is HonkVerifierProofTest {
    function _artifact() internal pure override returns (string memory) {
        return "OidcGoogleHonkVerifier.sol:OidcGoogleHonkVerifier";
    }

    function _fixture() internal pure override returns (string memory) {
        return "contracts/circuits/test/fixtures/oidc-google-proof.json";
    }

    function _verifyGasBound() internal pure override returns (uint64) {
        return 785_000;
    }
}
