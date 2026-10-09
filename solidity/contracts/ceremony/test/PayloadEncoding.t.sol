// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {TlsNotaryProof} from "../CeremonyPayloads.sol";
import {Test} from "forge-std/Test.sol";

import {AttestationBuilder} from "./AttestationBuilder.sol";
import {ICeremony} from "../ICeremony.sol";
import {ICeremonyPayloads} from "../ICeremonyPayloads.sol";

/// @notice The X fixture's payload encodes to the hash in
///         `x-ceremony-payload.json`, which the Rust and TS encoders also reach.
contract PayloadEncodingTest is Test {
    string constant SESSION = "contracts/ceremony/test/fixtures/x-ceremony-session.json";
    string constant PROOF = "contracts/ceremony/test/fixtures/x-ceremony-session-proof.json";
    string constant PAYLOAD = "contracts/ceremony/test/fixtures/x-ceremony-payload.json";

    function _payload() internal view returns (TlsNotaryProof memory p) {
        string memory session = vm.readFile(SESSION);
        string memory extra = vm.readFile(PAYLOAD);
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
        p.idNode = vm.parseJsonBytes32(extra, ".id_node");
        p.handleNode = vm.parseJsonBytes32(extra, ".handle_node");
        p.handle = vm.parseJsonString(extra, ".handle");
        p.proof = vm.parseJsonBytes(vm.readFile(PROOF), ".proof");
    }

    /// The pinned hash is the encoding the other languages are compared to.
    function test_theXFixturePayloadEncodesToThePinnedBytes() public view {
        bytes memory encoded = abi.encode(_payload());
        string memory extra = vm.readFile(PAYLOAD);
        assertEq(encoded.length, vm.parseJsonUint(extra, ".length"), "length");
        assertEq(keccak256(encoded), vm.parseJsonBytes32(extra, ".keccak256"), "keccak256");
    }

    /// The nodes the fixture names are the proof's outputs, `[high, low]` at
    /// fields 8 to 11, so the pinned payload is one the verifier accepts.
    function test_theNodesAreTheProofsOutputs() public view {
        bytes32[] memory inputs = vm.parseJsonBytes32Array(vm.readFile(PROOF), ".public_inputs");
        string memory extra = vm.readFile(PAYLOAD);
        assertEq(AttestationBuilder.nodeAt(inputs, 8), vm.parseJsonBytes32(extra, ".id_node"));
        assertEq(AttestationBuilder.nodeAt(inputs, 10), vm.parseJsonBytes32(extra, ".handle_node"));
    }

    /// The interface's ABI is the struct's: its arguments encode as the
    /// payload does.
    function test_theInterfaceArgumentsAreThePayload() public view {
        TlsNotaryProof memory p = _payload();
        assertEq(
            abi.encodeCall(ICeremonyPayloads.tlsNotaryProof, (p)),
            abi.encodePacked(ICeremonyPayloads.tlsNotaryProof.selector, abi.encode(p))
        );
    }
}
