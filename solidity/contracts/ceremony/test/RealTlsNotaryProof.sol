// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";

import {AttestationBuilder} from "./AttestationBuilder.sol";
import {TlsNotaryProof} from "../CeremonyPayloads.sol";
import {ICeremony} from "../ICeremony.sol";
import {INotaryService} from "../INotaryService.sol";
import {IPlatformVerifier} from "../IPlatformVerifier.sol";
import {IHonkVerifier, PlatformVerifierBase} from "../PlatformVerifierBase.sol";

/// @notice What a real proof binds through a TLSNotary Platform Verifier: the
///         records libid-rs produced, the proof bb made of their witness, and
///         the circuit's own verifier wired in place of the stub.
///
/// @dev Each suite supplies its verifier, its fixtures and the other notarized
///      platform's session fixture; the refusals are shared. The fixtures are
///      signed by `NOTARY_KEY`, which every suite's Notary Service trusts.
abstract contract RealTlsNotaryProofTest is Test {
    address constant OWNER = address(0xA11CE);
    uint256 constant NOTARY_KEY = 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80;

    /// The error the bearer-link verifier raises for a sumcheck round that
    /// does not hold. That verifier never returns false: it refuses by
    /// reverting, and `verify` passes the revert through. A public input
    /// other than the one proved fails here too, since every input enters
    /// the sumcheck through the public-input delta.
    error SumcheckFailed();

    /// The low byte of proof word 29, the first sumcheck coefficient in bb's
    /// ZK layout. Flipping its low bit leaves a field element, which the
    /// sumcheck refuses. A flipped curve point would instead make the
    /// verifier's precompile call burn all the gas it is given.
    uint256 constant FLIPPED_PROOF_BYTE = 29 * 32 + 31;

    // ─── What each suite supplies ───────────────────────────────────

    function _platformVerifier() internal view virtual returns (PlatformVerifierBase);

    function _notary() internal view virtual returns (INotaryService);

    /// The suite's honest payload, which the fixtures' records replace the
    /// sessions of.
    function _payload() internal view virtual returns (TlsNotaryProof memory);

    /// The circuit's Honk verifier, as `vm.deployCode` names its artifact.
    function _circuitArtifact() internal pure virtual returns (string memory);

    /// The session fixture libid-rs wrote, and the proof bb made of it.
    function _session() internal pure virtual returns (string memory);

    function _proofFile() internal pure virtual returns (string memory);

    /// The other notarized platform's session fixture.
    function _otherSession() internal pure virtual returns (string memory);

    // ─── The fixture's records and proof ────────────────────────────

    /// `_session()`'s records with the proof bb made of their witness, and
    /// the circuit's own verifier wired in place of the stub. Returns that
    /// verifier and the public inputs bb proved.
    function _realProofPayload() internal returns (TlsNotaryProof memory s, address circuit, bytes32[] memory proved) {
        circuit = vm.deployCode(_circuitArtifact());
        vm.prank(OWNER);
        _platformVerifier().setTrustRoots(_notary(), IHonkVerifier(circuit), circuit.codehash);

        string memory session = vm.readFile(_session());
        string memory proof = vm.readFile(_proofFile());
        s = _payload();
        s.tokenSession = AttestationBuilder.fixtureSession(session, ".token");
        s.identitySession = AttestationBuilder.fixtureSession(session, ".identity");
        s.proof = vm.parseJsonBytes(proof, ".proof");
        proved = vm.parseJsonBytes32Array(proof, ".public_inputs");
    }

    /// `s` sent to the verifier under test, which must refuse it with `reason`.
    function _refuses(TlsNotaryProof memory s, bytes4 reason) internal {
        IPlatformVerifier verifier = IPlatformVerifier(address(_platformVerifier()));
        uint256 value = verifier.quote();
        bytes memory payload = abi.encode(s);
        vm.expectPartialRevert(reason);
        verifier.verify{value: value}(payload);
    }

    function test_refusesARealProofWithOneByteFlipped() public {
        (TlsNotaryProof memory s,,) = _realProofPayload();
        s.proof[FLIPPED_PROOF_BYTE] ^= 0x01;
        _refuses(s, SumcheckFailed.selector);
    }

    // ─── What the real proof binds ──────────────────────────────────

    /// @dev The nodes leave only through the proof's public inputs, so a
    ///      payload claiming any other id node or handle node, or the two
    ///      real ones in each other's place, is a proof of nothing.
    function test_refusesARealProofUnderNodesItDidNotProve() public {
        (TlsNotaryProof memory s,,) = _realProofPayload();
        (bytes32 idNode, bytes32 handleNode) = (s.idNode, s.handleNode);

        s.idNode = idNode ^ bytes32(uint256(1));
        _refuses(s, SumcheckFailed.selector);

        (s.idNode, s.handleNode) = (idNode, handleNode ^ bytes32(uint256(1) << 255));
        _refuses(s, SumcheckFailed.selector);

        (s.idNode, s.handleNode) = (handleNode, idNode);
        _refuses(s, SumcheckFailed.selector);
    }

    /// @dev Each commitment the circuit opens comes from the record, so a
    ///      record whose commitment is the other platform's fixture's --
    ///      re-signed by the notary this suite trusts, so every check before
    ///      the proof passes -- leaves the proof opening nothing.
    function test_refusesARealProofOverAnotherSessionsCommitments() public {
        string[2][4] memory substituted = [
            [".identity", ".identity_link_witness.handle.commitment"],
            [".identity", ".identity_link_witness.id.commitment"],
            [".identity", ".identity_link_witness.identity_bearer.commitment"],
            [".token", ".identity_link_witness.token_bearer.commitment"]
        ];
        string memory ours = vm.readFile(_session());
        string memory theirs = vm.readFile(_otherSession());
        (TlsNotaryProof memory s,,) = _realProofPayload();
        for (uint256 i = 0; i < substituted.length; ++i) {
            (string memory session, string memory key) = (substituted[i][0], substituted[i][1]);
            s.tokenSession = AttestationBuilder.fixtureSession(ours, ".token");
            s.identitySession = AttestationBuilder.fixtureSession(ours, ".identity");
            ICeremony.Attestation memory resigned = _resigned(
                AttestationBuilder.fixtureSession(ours, session).attestedData,
                vm.parseJsonBytes32(ours, key),
                vm.parseJsonBytes32(theirs, key),
                bytes32(0),
                bytes32(0)
            );
            if (keccak256(bytes(session)) == keccak256(".token")) s.tokenSession = resigned;
            else s.identitySession = resigned;
            _refuses(s, SumcheckFailed.selector);
        }
    }

    /// @dev The id and handle commitments exchanged in the record. The
    ///      framing still finds one behind each anchor, so the verifier puts
    ///      the handle's commitment where the circuit opens an id, and the
    ///      proof refuses it.
    function test_refusesARealProofWithTheIdAndHandleCommitmentsSwapped() public {
        (TlsNotaryProof memory s,,) = _realProofPayload();
        string memory json = vm.readFile(_session());
        bytes32 id = vm.parseJsonBytes32(json, ".identity_link_witness.id.commitment");
        bytes32 handle = vm.parseJsonBytes32(json, ".identity_link_witness.handle.commitment");
        s.identitySession = _resigned(s.identitySession.attestedData, id, handle, handle, id);
        _refuses(s, SumcheckFailed.selector);
    }

    /// @dev The other platform's identity session, as signed, is refused
    ///      before the proof: the notary authenticated that platform's host,
    ///      and this verifier pins its own.
    function test_refusesAnotherPlatformsIdentitySession() public {
        (TlsNotaryProof memory s,,) = _realProofPayload();
        s.identitySession = AttestationBuilder.fixtureSession(vm.readFile(_otherSession()), ".identity");
        _refuses(s, PlatformVerifierBase.WrongAuthority.selector);
    }

    // ─── Helpers ────────────────────────────────────────────────────

    /// The 16-byte blinder libid-rs recorded at `key`.
    function _blinder(string memory json, string memory key) internal pure returns (bytes memory b) {
        b = vm.parseJsonBytes(json, key);
        assertEq(b.length, 16, "tlsn's blinder is 16 bytes");
    }

    /// `attested` with the 32-byte commitment `a` replaced by `aTo` and, when
    /// `b` is nonzero, `b` by `bTo`, re-signed by the notary this suite
    /// trusts. Each must occur exactly once.
    function _resigned(bytes memory attested, bytes32 a, bytes32 aTo, bytes32 b, bytes32 bTo)
        internal
        pure
        returns (ICeremony.Attestation memory)
    {
        uint256 atA = _onlyOffsetOf(attested, abi.encodePacked(a));
        uint256 atB = b == bytes32(0) ? type(uint256).max : _onlyOffsetOf(attested, abi.encodePacked(b));
        for (uint256 i = 0; i < 32; ++i) {
            attested[atA + i] = aTo[i];
            if (atB != type(uint256).max) attested[atB + i] = bTo[i];
        }
        return ICeremony.Attestation({attestedData: attested, proof: AttestationBuilder.sign(NOTARY_KEY, attested)});
    }

    function _onlyOffsetOf(bytes memory haystack, bytes memory needle) private pure returns (uint256 at) {
        at = AttestationBuilder.indexOf(haystack, needle);
        assertTrue(at != type(uint256).max, "commitment not in the record");
        bytes memory rest = new bytes(haystack.length - at - 1);
        for (uint256 i = 0; i < rest.length; ++i) {
            rest[i] = haystack[at + 1 + i];
        }
        assertEq(AttestationBuilder.indexOf(rest, needle), type(uint256).max, "commitment twice in the record");
    }
}
