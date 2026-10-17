// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";

import {IHonkVerifier} from "../../ceremony/PlatformVerifierBase.sol";

/// @notice A vendored Honk verifier rejects a proof whose field elements or
///         point coordinates are non-canonical, and one whose public-input
///         array is the wrong length.
///
/// @dev Covers the range checks that `HonkVerifierProofTest`'s bit flips never
///      trip: a scalar `>= r`, a coordinate `>= q` and an over-wide pairing limb.
///      Uses the same real fixtures and artifacts as `HonkVerifierProofTest`.
abstract contract HonkVerifierEncodingTest is Test {
    // BN254 base field modulus q: G1 point coordinates.
    uint256 internal constant Q = 21888242871839275222246405745257275088696311157297823662689037894645226208583;
    // BN254 scalar field modulus r: the proof's Fr elements.
    uint256 internal constant R = 21888242871839275222246405745257275088548364400416034343698204186575808495617;

    // Proof-word offsets in bb's ZK keccak layout, independent of log_n up to the
    // first Gemini fold. Word 0 is a pairing "lo" limb, bound 2^136; word 8 is the
    // Gemini masking commitment's x, an Fq coordinate; word 28 is the Libra sum, an Fr.
    uint256 internal constant PAIRING_LO_LIMB_WORD = 0;
    uint256 internal constant COORDINATE_WORD = 8;
    uint256 internal constant SCALAR_WORD = 28;

    IHonkVerifier private verifier;
    bytes private proof;
    bytes32[] private publicInputs;

    function _artifact() internal pure virtual returns (string memory);
    function _fixture() internal pure virtual returns (string memory);
    function _gasCap() internal pure virtual returns (uint64);

    function setUp() public {
        verifier = IHonkVerifier(vm.deployCode(_artifact()));
        string memory json = vm.readFile(_fixture());
        proof = vm.parseJsonBytes(json, ".proof");
        publicInputs = vm.parseJsonBytes32Array(json, ".public_inputs");
    }

    function test_acceptsTheUnchangedProof() public view {
        assertTrue(_verifies(proof, publicInputs), "the fixture proof does not verify");
    }

    /// A scalar carried as `value + r` decodes to the same field element; the
    /// verifier must reject the non-canonical form rather than reduce it.
    function test_rejectsNonCanonicalScalar() public view {
        bytes memory tampered = _addAtWord(proof, SCALAR_WORD, R);
        assertFalse(_verifies(tampered, publicInputs), "accepted a scalar >= r");
    }

    /// A coordinate carried as `value + q` is the same point coordinate reduced;
    /// the verifier must reject it before it reaches a precompile.
    function test_rejectsNonCanonicalCoordinate() public view {
        bytes memory tampered = _addAtWord(proof, COORDINATE_WORD, Q);
        assertFalse(_verifies(tampered, publicInputs), "accepted a coordinate >= q");
    }

    /// A pairing limb wider than its 2^136 bound must be refused: the aggregation
    /// packs two limbs into one coordinate, so an over-wide limb forges the point.
    function test_rejectsOverwidePairingLimb() public view {
        bytes memory tampered = proof;
        _setWord(tampered, PAIRING_LO_LIMB_WORD, bytes32(uint256(1) << 200));
        assertFalse(_verifies(tampered, publicInputs), "accepted an over-wide pairing limb");
    }

    /// A public-input array one element too long must be refused: the count is
    /// bound into the transcript, and an extra element shifts every challenge.
    function test_rejectsWrongPublicInputCount() public view {
        bytes32[] memory extended = new bytes32[](publicInputs.length + 1);
        for (uint256 i = 0; i < publicInputs.length; ++i) {
            extended[i] = publicInputs[i];
        }
        assertFalse(_verifies(proof, extended), "accepted a wrong-length public-input array");
    }

    function _addAtWord(bytes memory data, uint256 word, uint256 addend) private pure returns (bytes memory out) {
        out = bytes.concat(data);
        uint256 slot = word * 32;
        uint256 current;
        assembly {
            current := mload(add(add(out, 32), slot))
        }
        unchecked {
            current += addend;
        }
        assembly {
            mstore(add(add(out, 32), slot), current)
        }
    }

    function _setWord(bytes memory data, uint256 word, bytes32 value) private pure {
        uint256 slot = word * 32;
        assembly {
            mstore(add(add(data, 32), slot), value)
        }
    }

    /// Whether `verify` says yes; a Honk verifier rejects by reverting, and an
    /// invalid point makes a precompile consume the gas forwarded, so the call
    /// is capped.
    function _verifies(bytes memory p, bytes32[] memory inputs) private view returns (bool) {
        try verifier.verify{gas: _gasCap()}(p, inputs) returns (bool ok) {
            return ok;
        } catch {
            return false;
        }
    }
}

contract BearerLinkXHonkVerifierEncodingTest is HonkVerifierEncodingTest {
    function _artifact() internal pure override returns (string memory) {
        return "BearerLinkHonkVerifier.sol:BearerLinkHonkVerifier";
    }

    function _fixture() internal pure override returns (string memory) {
        return "contracts/circuits/test/fixtures/bearer-link-x-proof.json";
    }

    function _gasCap() internal pure override returns (uint64) {
        return 1_500_000;
    }
}

contract BearerLinkGithubHonkVerifierEncodingTest is HonkVerifierEncodingTest {
    function _artifact() internal pure override returns (string memory) {
        return "BearerLinkHonkVerifier.sol:BearerLinkHonkVerifier";
    }

    function _fixture() internal pure override returns (string memory) {
        return "contracts/circuits/test/fixtures/bearer-link-github-proof.json";
    }

    function _gasCap() internal pure override returns (uint64) {
        return 1_500_000;
    }
}

contract OidcGoogleHonkVerifierEncodingTest is HonkVerifierEncodingTest {
    function _artifact() internal pure override returns (string memory) {
        return "OidcGoogleHonkVerifier.sol:OidcGoogleHonkVerifier";
    }

    function _fixture() internal pure override returns (string memory) {
        return "contracts/circuits/test/fixtures/oidc-google-proof.json";
    }

    function _gasCap() internal pure override returns (uint64) {
        return 1_600_000;
    }
}
