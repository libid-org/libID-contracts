// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {GoogleProof, TlsNotaryProof} from "../../ceremony/CeremonyPayloads.sol";
import {Vm} from "forge-std/Test.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

import {AttestationBuilder} from "../../ceremony/test/AttestationBuilder.sol";
import {TrustingJwtRoots} from "../../ceremony/test/TrustingJwtRoots.sol";
import {CeremonyProfile} from "../../ceremony/CeremonyProfile.sol";
import {CeremonyProofVerifier} from "../../ceremony/CeremonyProofVerifier.sol";
import {GitHubPlatformVerifier} from "../../ceremony/GitHubPlatformVerifier.sol";
import {GooglePlatformVerifier, IGoogleJwtRoots} from "../../ceremony/GooglePlatformVerifier.sol";
import {ICeremony} from "../../ceremony/ICeremony.sol";
import {INotaryService} from "../../ceremony/INotaryService.sol";
import {IPlatformVerifier} from "../../ceremony/IPlatformVerifier.sol";
import {IProofVerifier} from "../../ceremony/IProofVerifier.sol";
import {NotaryService} from "../../ceremony/NotaryService.sol";
import {HandleDisclosure, IHonkVerifier} from "../../ceremony/PlatformVerifierBase.sol";
import {XPlatformVerifier} from "../../ceremony/XPlatformVerifier.sol";
import {IdentityRegistry} from "../IdentityRegistry.sol";
import {PrivacyScan} from "./PrivacyScan.sol";
import {TestNodes} from "./TestNodes.sol";

/// @notice A platform's identity bound through the whole deployed stack with a real proof.
/// @dev Each fixture's Authorized Transaction Data is the registry's own `(0xBEEF, 0, 0)`.
abstract contract RealProofBindBase is PrivacyScan {
    IdentityRegistry registry;
    CeremonyProofVerifier proofVerifier;

    address constant OWNER = address(0xA11CE);
    address constant BINDER = address(0xBEEF);

    // ─── What each platform supplies ────────────────────────────────

    function _platform() internal pure virtual returns (bytes32);

    /// The payload over the fixture, disclosing `handle` (empty when private).
    function _payload(string memory handle) internal view virtual returns (bytes memory);

    function _idNode() internal pure virtual returns (bytes32);

    function _handleNode() internal pure virtual returns (bytes32);

    /// The contracts a bind may write besides the registry and the Proof Verifier.
    function _verifiers() internal view virtual returns (address[] memory);

    /// The proof's public inputs, and where the id node's `[high, low]` halves start.
    function _publicInputs() internal view virtual returns (bytes32[] memory);

    function _idNodeAt() internal pure virtual returns (uint256);

    // ─── The stack ──────────────────────────────────────────────────

    /// The Proof Verifier and the registry, with `verifier` as version 1.
    function _deployStack(address verifier) internal {
        proofVerifier = CeremonyProofVerifier(
            address(
                new ERC1967Proxy(
                    address(new CeremonyProofVerifier()), abi.encodeCall(CeremonyProofVerifier.initialize, (OWNER))
                )
            )
        );
        registry = IdentityRegistry(
            address(
                new ERC1967Proxy(address(new IdentityRegistry()), abi.encodeCall(IdentityRegistry.initialize, (OWNER)))
            )
        );
        vm.startPrank(OWNER);
        proofVerifier.setVerifier(_platform(), 1, IPlatformVerifier(verifier));
        registry.setProofVerifier(IProofVerifier(address(proofVerifier)));
        vm.stopPrank();
        vm.deal(BINDER, 1 ether);
        vm.deal(address(0xCAFE), 1 ether);
    }

    function _bind(bytes memory payload) internal {
        uint256 value = registry.quoteBind(_platform(), 1);
        vm.prank(BINDER);
        registry.bind{value: value}(_platform(), 1, payload);
    }

    // ─── Bind, privately ────────────────────────────────────────────

    /// @dev A private bind leaves no byte of the id or the handle in logs, storage or calldata.
    function test_bindsPrivatelyAndDisclosesNothing() public {
        bytes memory payload = _payload("");
        assertFalse(_containsAny(payload), "the payload carries an id or handle");

        vm.record();
        vm.recordLogs();
        _bind(payload);
        emit log_named_uint("bind gas", vm.lastCallGas().gasTotalUsed);

        _assertLogsHideTheSecrets(vm.getRecordedLogs());
        _assertStorageHidesTheSecrets(address(registry));
        _assertStorageHidesTheSecrets(address(proofVerifier));
        address[] memory verifiers = _verifiers();
        for (uint256 i = 0; i < verifiers.length; ++i) {
            _assertStorageHidesTheSecrets(verifiers[i]);
        }

        assertEq(registry.resolveId(_idNode()), BINDER);
        (address holder,) = registry.handleBinding(_handleNode());
        assertEq(holder, BINDER);
        assertEq(registry.resolveHandle(_platform(), _secrets()[1]), BINDER);
        assertEq(registry.resolveHandle(_platform(), _secrets()[2]), BINDER);
        assertEq(registry.publishedHandleOf(BINDER, _platform()), "", "a private bind publishes nothing");
    }

    // ─── Disclose in the payload ────────────────────────────────────

    /// @dev A handle disclosed in the payload is checked against the proved node and stored folded.
    function test_bindsAndPublishesInOneCall() public {
        bytes memory payload = _payload(_secrets()[1]);
        vm.recordLogs();
        vm.expectEmit(address(registry));
        emit IdentityRegistry.HandlePublished(BINDER, _platform(), _handleNode(), _secrets()[2]);
        _bind(payload);
        assertEq(registry.publishedHandleOf(BINDER, _platform()), _secrets()[2]);

        Vm.Log[] memory logs = vm.getRecordedLogs();
        bool seen;
        for (uint256 i = 0; i < logs.length; ++i) {
            seen = seen || _containsAny(logs[i].data);
        }
        assertTrue(seen, "a disclosure logs the handle");
    }

    /// @dev A disclosure the proof does not back is refused before anything is written.
    function test_refusesToBindAHandleTheProofDidNotBind() public {
        (string memory other, bytes32 otherNode) = _otherHandle();
        bytes memory payload = _payload(other);
        uint256 value = registry.quoteBind(_platform(), 1);
        vm.expectRevert(abi.encodeWithSelector(HandleDisclosure.HandleNotProved.selector, otherNode, _handleNode()));
        vm.prank(BINDER);
        registry.bind{value: value}(_platform(), 1, payload);
        assertEq(registry.resolveId(_idNode()), address(0));
    }

    /// A handle the rules accept that the proof did not bind, and its node.
    function _otherHandle() internal pure virtual returns (string memory, bytes32);

    /// @dev The nodes this test names are the ones the proof outputs.
    function test_theNodesAreTheProofsOutputs() public view {
        bytes32[] memory inputs = _publicInputs();
        assertEq(AttestationBuilder.nodeAt(inputs, _idNodeAt()), _idNode());
        assertEq(AttestationBuilder.nodeAt(inputs, _idNodeAt() + 2), _handleNode());
    }
}

/// @notice The notarized platforms' fixtures, under a notary trusting the fixture's key.
abstract contract RealTlsNotaryBind is RealProofBindBase {
    uint256 constant NOTARY_KEY = 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80;
    uint256 constant NOTARY_FEE = 0.001 ether;

    NotaryService notary;
    address platformVerifier;

    function _session() internal pure virtual returns (string memory);

    function _proofFile() internal pure virtual returns (string memory);

    function setUp() public {
        string memory session = vm.readFile(_session());
        vm.chainId(vm.parseJsonUint(session, ".chain_id"));
        vm.warp(vm.parseJsonUint(session, ".created_at") + 60);

        notary = NotaryService(
            address(
                new ERC1967Proxy(
                    address(new NotaryService()),
                    abi.encodeCall(NotaryService.initialize, (OWNER, vm.addr(NOTARY_KEY), NOTARY_FEE))
                )
            )
        );
        platformVerifier = _deployVerifier(INotaryService(address(notary)));
        _deployStack(platformVerifier);
    }

    function _deployVerifier(INotaryService notary_) internal virtual returns (address);

    function _verifiers() internal view override returns (address[] memory v) {
        v = new address[](2);
        (v[0], v[1]) = (platformVerifier, address(notary));
    }

    /// The fixture's payload, naming its own transaction data.
    function _payload(string memory handle) internal view override returns (bytes memory) {
        string memory session = vm.readFile(_session());
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
        p.idNode = _idNode();
        p.handleNode = _handleNode();
        p.handle = handle;
        p.proof = vm.parseJsonBytes(vm.readFile(_proofFile()), ".proof");
        return abi.encode(p);
    }

    /// @dev The fixture names the binder and no fee, in the registry's shape.
    function test_theProducedFixtureCarriesTheRegistryTriple() public view {
        assertEq(
            vm.parseJsonBytes(vm.readFile(_session()), ".transaction_data"), abi.encode(BINDER, uint256(0), address(0))
        );
    }

    function _publicInputs() internal view override returns (bytes32[] memory) {
        return vm.parseJsonBytes32Array(vm.readFile(_proofFile()), ".public_inputs");
    }

    /// `[high, low]` at fields 8 to 11.
    function _idNodeAt() internal pure override returns (uint256) {
        return 8;
    }
}

/// @notice X: `Alice_1`, id `2244994945`, from the `x-ceremony-session` fixture.
contract RealProofBindTest is RealTlsNotaryBind {
    bytes32 constant X = CeremonyProfile.PLATFORM_X;
    /// hashlib.sha256(b"libid.x.user-id2244994945")
    bytes32 constant ID_NODE = 0x68291869976ffad2abf3e933ec9ab2623395ff8b3b9242e655e1da3ef43d4f94;
    /// hashlib.sha256(b"libid.x.handlealice_1")
    bytes32 constant HANDLE_NODE = 0xe09c4f5bfbbc723bc35701ea9d718a1c5edb29b1ed5bb0cb0fabb3c43d8136af;

    function _platform() internal pure override returns (bytes32) {
        return X;
    }

    function _session() internal pure override returns (string memory) {
        return "contracts/ceremony/test/fixtures/x-ceremony-session.json";
    }

    function _proofFile() internal pure override returns (string memory) {
        return "contracts/ceremony/test/fixtures/x-ceremony-session-proof.json";
    }

    function _secrets() internal pure override returns (string[3] memory) {
        return ["2244994945", "Alice_1", "alice_1"];
    }

    function _idNode() internal pure override returns (bytes32) {
        return ID_NODE;
    }

    function _handleNode() internal pure override returns (bytes32) {
        return HANDLE_NODE;
    }

    function _otherHandle() internal pure override returns (string memory, bytes32) {
        // hashlib.sha256(b"libid.x.handlebob")
        return ("bob", 0xa48e7da67389935eacd89176ab4b723dd9dbad5833fd777344590fd04c62418f);
    }

    function _deployVerifier(INotaryService notary_) internal override returns (address) {
        address circuit = vm.deployCode("BearerLinkXHonkVerifier.sol:BearerLinkXHonkVerifier");
        return address(
            new ERC1967Proxy(
                address(new XPlatformVerifier()),
                abi.encodeCall(XPlatformVerifier.initialize, (OWNER, notary_, IHonkVerifier(circuit), circuit.codehash))
            )
        );
    }

    // ─── Publish ────────────────────────────────────────────────────

    /// @dev The disclosed handle, in any case, is stored folded.
    function test_publishesTheHandleFolded() public {
        _bind(_payload(""));
        vm.expectEmit(address(registry));
        emit IdentityRegistry.HandlePublished(BINDER, X, HANDLE_NODE, "alice_1");
        vm.prank(BINDER);
        registry.publish(X, "ALICE_1");
        assertEq(registry.publishedHandleOf(BINDER, X), "alice_1");
    }

    function test_refusesToPublishAHandleTheHolderDidNotProve() public {
        _bind(_payload(""));
        vm.expectRevert(abi.encodeWithSelector(IdentityRegistry.NotYourHandle.selector, TestNodes.handleNode(X, "bob")));
        vm.prank(BINDER);
        registry.publish(X, "bob");
    }

    function test_refusesToPublishAnotherHoldersHandle() public {
        _bind(_payload(""));
        vm.expectRevert(abi.encodeWithSelector(IdentityRegistry.NotYourHandle.selector, HANDLE_NODE));
        vm.prank(address(0xCAFE));
        registry.publish(X, "alice_1");
    }
}

/// @notice GitHub: `OctoCat`, id `583231`, from the `github-ceremony-session` fixture.
contract RealProofBindGitHubTest is RealTlsNotaryBind {
    function _platform() internal pure override returns (bytes32) {
        return CeremonyProfile.PLATFORM_GITHUB;
    }

    function _session() internal pure override returns (string memory) {
        return "contracts/ceremony/test/fixtures/github-ceremony-session.json";
    }

    function _proofFile() internal pure override returns (string memory) {
        return "contracts/ceremony/test/fixtures/github-ceremony-session-proof.json";
    }

    function _secrets() internal pure override returns (string[3] memory) {
        return ["583231", "OctoCat", "octocat"];
    }

    /// hashlib.sha256(b"libid.github.user-id583231")
    function _idNode() internal pure override returns (bytes32) {
        return 0x475902b27989feb395b9b0cd3156aa573a9676c13155b8e7e3ddaf3e77181847;
    }

    /// hashlib.sha256(b"libid.github.handleoctocat")
    function _handleNode() internal pure override returns (bytes32) {
        return 0x381fb9d7d3b01214e58b94202ea10f78e169adef68bcc20d40c130deca6dfe74;
    }

    function _otherHandle() internal pure override returns (string memory, bytes32) {
        // hashlib.sha256(b"libid.github.handlebob")
        return ("bob", 0x8d6d26894b3f7b464a314d1539926c23b4f432fdf8315f6fba9b08d0223969c2);
    }

    function _deployVerifier(INotaryService notary_) internal override returns (address) {
        address circuit = vm.deployCode("BearerLinkGithubHonkVerifier.sol:BearerLinkGithubHonkVerifier");
        return address(
            new ERC1967Proxy(
                address(new GitHubPlatformVerifier()),
                abi.encodeCall(
                    GitHubPlatformVerifier.initialize, (OWNER, notary_, IHonkVerifier(circuit), circuit.codehash)
                )
            )
        );
    }
}

/// @notice Google: `Fixture@Example.com`, sub `100000000000000000001`, from
///         `google-ceremony-proof.json` over a synthetic signing key.
contract RealProofBindGoogleTest is RealProofBindBase {
    string constant PROOF = "contracts/ceremony/test/fixtures/google-ceremony-proof.json";
    /// The signed `exp` of the fixture's token.
    uint64 constant EXP = 1_893_456_000;
    /// The handle node's low half among the public inputs.
    uint256 constant HANDLE_LOW = 37;

    TrustingJwtRoots roots;
    address platformVerifier;

    function setUp() public {
        roots = new TrustingJwtRoots();
        address circuit = vm.deployCode("OidcGoogleHonkVerifier.sol:OidcGoogleHonkVerifier");
        platformVerifier = address(
            new ERC1967Proxy(
                address(new GooglePlatformVerifier()),
                abi.encodeCall(
                    GooglePlatformVerifier.initialize,
                    (
                        OWNER,
                        INotaryService(address(0)),
                        IHonkVerifier(circuit),
                        circuit.codehash,
                        IGoogleJwtRoots(address(roots))
                    )
                )
            )
        );
        _deployStack(platformVerifier);

        // The modulus the proof exposes, `[39, 57)`, is the one trusted.
        bytes32[] memory inputs = vm.parseJsonBytes32Array(vm.readFile(PROOF), ".public_inputs");
        bytes memory modulus;
        for (uint256 i = 39; i < 57; ++i) {
            modulus = bytes.concat(modulus, inputs[i]);
        }
        roots.trust(keccak256(modulus), EXP + 86400);
        vm.warp(EXP - 3600);
    }

    function _platform() internal pure override returns (bytes32) {
        return CeremonyProfile.PLATFORM_GOOGLE;
    }

    function _verifiers() internal view override returns (address[] memory v) {
        v = new address[](2);
        (v[0], v[1]) = (platformVerifier, address(roots));
    }

    function _secrets() internal pure override returns (string[3] memory) {
        return ["100000000000000000001", "Fixture@Example.com", "fixture@example.com"];
    }

    /// hashlib.sha256(b"libid.google.user-id100000000000000000001")
    function _idNode() internal pure override returns (bytes32) {
        return 0x5e13b7e56f17994a08b7464e5c5c5758228d6816db0a0af9bbd73f65335fcec8;
    }

    // hashlib.sha256(b"libid.google.handlefixture@example.com")
    function _handleNode() internal pure override returns (bytes32) {
        return 0xfbda24950a7bc55993b7aacc3acbde636931dbb45f04c1ff6f6909027962885f;
    }

    function _otherHandle() internal pure override returns (string memory, bytes32) {
        // hashlib.sha256(b"libid.google.handleother@example.com")
        return ("other@example.com", 0x952d5e757983e3af1d1671b554bd9644d0934e06bbd97b6c5a2b0448bc0cb52c);
    }

    function _payload(string memory handle) internal view override returns (bytes memory) {
        return abi.encode(_proof(handle));
    }

    /// The `google/v1` payload the proof was made for, on chain 31337.
    function _proof(string memory handle) internal view returns (GoogleProof memory s) {
        string memory json = vm.readFile(PROOF);
        s.ceremonyVersion = 1;
        s.operationDomain = keccak256(bytes("libid.claim-identity"));
        s.authorizationNonce = bytes32(uint256(0x5555555555555555555555555555555555555555555555555555555555555555));
        s.transactionData = abi.encode(BINDER, uint256(0), address(0));
        s.clientIdentifier = bytes(vm.parseJsonString(json, ".client_identifier"));
        s.publicInputs = vm.parseJsonBytes32Array(json, ".public_inputs");
        s.handle = handle;
        s.proof = vm.parseJsonBytes(json, ".proof");
    }

    function _publicInputs() internal view override returns (bytes32[] memory) {
        return vm.parseJsonBytes32Array(vm.readFile(PROOF), ".public_inputs");
    }

    /// `[high, low]` at fields 34 to 37.
    function _idNodeAt() internal pure override returns (uint256) {
        return 34;
    }

    /// @dev A private payload naming another handle node fails the Honk verifier.
    function test_anotherHandleNodeFailsTheProof() public {
        GoogleProof memory s = _proof("");
        s.publicInputs[HANDLE_LOW] ^= bytes32(uint256(1));
        bytes memory payload = abi.encode(s);
        vm.prank(BINDER);
        vm.expectRevert(abi.encodeWithSignature("SumcheckFailed()"));
        registry.bind(_platform(), 1, payload);
        assertEq(registry.resolveId(_idNode()), address(0));
        (address holder,) = registry.handleBinding(_handleNode());
        assertEq(holder, address(0));
    }
}
