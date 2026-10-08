// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, Vm} from "forge-std/Test.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

import {CeremonyProfile} from "../../ceremony/CeremonyProfile.sol";
import {CeremonyProofVerifier} from "../../ceremony/CeremonyProofVerifier.sol";
import {ICeremony} from "../../ceremony/ICeremony.sol";
import {INotaryService} from "../../ceremony/INotaryService.sol";
import {IPlatformVerifier} from "../../ceremony/IPlatformVerifier.sol";
import {IProofVerifier} from "../../ceremony/IProofVerifier.sol";
import {NotaryService} from "../../ceremony/NotaryService.sol";
import {IHonkVerifier, PlatformVerifierBase} from "../../ceremony/PlatformVerifierBase.sol";
import {TlsNotaryVerifierBase} from "../../ceremony/TlsNotaryVerifierBase.sol";
import {XPlatformVerifier} from "../../ceremony/XPlatformVerifier.sol";
import {IdentityRegistry} from "../IdentityRegistry.sol";

/// @notice An X identity bound, published and withdrawn through the whole
///         deployed stack with a real proof: the registry over the Proof
///         Verifier over the X Platform Verifier over the circuit's own Honk
///         verifier, and a notary trusting the fixture's key.
///
/// @dev The sessions are libid-rs's `ceremony_fixtures` records and the proof
///      the one bb made of their witness (`x-ceremony-session-proof.json`).
///      The account is `Alice_1`, id `2244994945`; the nodes below are
///      Python hashlib's. The records' Authorized Transaction Data is the
///      registry's own triple `(0xBEEF, 0, 0)`, so they bind unedited.
contract RealProofBindTest is Test {
    IdentityRegistry registry;
    CeremonyProofVerifier proofVerifier;
    XPlatformVerifier xVerifier;
    NotaryService notary;

    address constant OWNER = address(0xA11CE);
    address constant BINDER = address(0xBEEF);
    uint256 constant NOTARY_KEY = 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80;
    uint256 constant NOTARY_FEE = 0.001 ether;
    bytes32 constant X = CeremonyProfile.PLATFORM_X;

    string constant SESSION = "contracts/ceremony/test/fixtures/x-ceremony-session.json";
    string constant PROOF = "contracts/ceremony/test/fixtures/x-ceremony-session-proof.json";

    /// hashlib.sha256(b"libid.x.user-id2244994945")
    bytes32 constant ID_NODE = 0x68291869976ffad2abf3e933ec9ab2623395ff8b3b9242e655e1da3ef43d4f94;
    /// hashlib.sha256(b"libid.x.handlealice_1")
    bytes32 constant HANDLE_NODE = 0xe09c4f5bfbbc723bc35701ea9d718a1c5edb29b1ed5bb0cb0fabb3c43d8136af;

    function setUp() public {
        string memory session = vm.readFile(SESSION);
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
        address circuit = vm.deployCode("BearerLinkXHonkVerifier.sol:BearerLinkXHonkVerifier");
        xVerifier = XPlatformVerifier(
            address(
                new ERC1967Proxy(
                    address(new XPlatformVerifier()),
                    abi.encodeCall(
                        XPlatformVerifier.initialize,
                        (OWNER, INotaryService(address(notary)), IHonkVerifier(circuit), circuit.codehash)
                    )
                )
            )
        );
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
        proofVerifier.setVerifier(X, 1, IPlatformVerifier(address(xVerifier)));
        registry.setProofVerifier(IProofVerifier(address(proofVerifier)));
        vm.stopPrank();
        vm.deal(BINDER, 1 ether);
        vm.deal(address(0xCAFE), 1 ether);
    }

    // ─── The payloads ───────────────────────────────────────────────

    /// The `x/v1` payload over `token`, the fixture's identity record and
    /// the fixture's proof, naming `transactionData`.
    function _payload(ICeremony.Attestation memory token, bytes memory transactionData, string memory handle)
        private
        view
        returns (bytes memory)
    {
        string memory session = vm.readFile(SESSION);
        TlsNotaryVerifierBase.TlsNotaryProof memory p;
        p.ceremonyVersion = uint16(vm.parseJsonUint(session, ".ceremony_version"));
        p.operationDomain = vm.parseJsonBytes32(session, ".operation_domain");
        p.authorizationNonce = vm.parseJsonBytes32(session, ".authorization_nonce");
        p.transactionData = transactionData;
        p.tokenSession = token;
        p.identitySession = ICeremony.Attestation({
            attestedData: vm.parseJsonBytes(session, ".identity.attested_data"),
            proof: vm.parseJsonBytes(session, ".identity.notary_signature")
        });
        p.idNode = ID_NODE;
        p.handleNode = HANDLE_NODE;
        p.handle = handle;
        p.proof = vm.parseJsonBytes(vm.readFile(PROOF), ".proof");
        return abi.encode(p);
    }

    /// The fixture exactly as libid-rs wrote it, disclosing nothing.
    function _producedPayload() private view returns (bytes memory) {
        return _producedPayload("");
    }

    /// The fixture, disclosing `handle`.
    function _producedPayload(string memory handle) private view returns (bytes memory) {
        string memory session = vm.readFile(SESSION);
        return _payload(
            ICeremony.Attestation({
                attestedData: vm.parseJsonBytes(session, ".token.attested_data"),
                proof: vm.parseJsonBytes(session, ".token.notary_signature")
            }),
            vm.parseJsonBytes(session, ".transaction_data"),
            handle
        );
    }

    function _bind(bytes memory payload) private {
        uint256 value = registry.quoteBind(X, 1);
        vm.prank(BINDER);
        registry.bind{value: value}(X, 1, payload);
    }

    // ─── The fixture as produced ────────────────────────────────────

    /// @dev The fixture names the binder and no fee, in the registry's shape.
    function test_theProducedFixtureCarriesTheRegistryTriple() public view {
        assertEq(
            vm.parseJsonBytes(vm.readFile(SESSION), ".transaction_data"), abi.encode(BINDER, uint256(0), address(0))
        );
    }

    // ─── Bind, privately ────────────────────────────────────────────

    /// @dev The stage-A gate: a private bind with a real proof. Nothing it
    ///      writes or logs carries the id or the handle, in any case: not the
    ///      events' topics or data, not a storage slot of the registry or the
    ///      verifiers, not the calldata.
    function test_bindsPrivatelyAndDisclosesNothing() public {
        bytes memory payload = _producedPayload();
        assertFalse(_containsAny(payload), "the payload carries an id or handle");

        vm.record();
        vm.recordLogs();
        _bind(payload);
        uint256 gasUsed = vm.lastCallGas().gasTotalUsed;
        emit log_named_uint("bind gas", gasUsed);

        Vm.Log[] memory logs = vm.getRecordedLogs();
        assertGt(logs.length, 0);
        for (uint256 i = 0; i < logs.length; ++i) {
            assertFalse(_containsAny(logs[i].data), "an event's data carries an id or handle");
            for (uint256 j = 0; j < logs[i].topics.length; ++j) {
                assertFalse(_containsAny(abi.encode(logs[i].topics[j])), "an event's topic carries an id or handle");
            }
        }
        _assertNoSlotCarriesAny(address(registry));
        _assertNoSlotCarriesAny(address(proofVerifier));
        _assertNoSlotCarriesAny(address(xVerifier));

        assertEq(registry.resolveId(ID_NODE), BINDER);
        (address holder,) = registry.handleBinding(HANDLE_NODE);
        assertEq(holder, BINDER);
        assertEq(registry.resolveHandle(X, "Alice_1"), BINDER);
        assertEq(registry.resolveHandle(X, "alice_1"), BINDER);
        assertEq(registry.publishedHandleOf(BINDER, X), "", "a private bind publishes nothing");
    }

    // ─── Publish, then withdraw ─────────────────────────────────────

    /// @dev The holder discloses its handle in any case; the registry checks
    ///      it hashes to the bound node and stores the folded form.
    function test_publishesTheHandleFolded() public {
        _bind(_producedPayload());
        vm.expectEmit(address(registry));
        emit IdentityRegistry.HandlePublished(BINDER, X, HANDLE_NODE, "alice_1");
        vm.prank(BINDER);
        registry.publish(X, "ALICE_1");
        assertEq(registry.publishedHandleOf(BINDER, X), "alice_1");
    }

    function test_refusesToPublishAHandleTheHolderDidNotProve() public {
        _bind(_producedPayload());
        vm.expectRevert(abi.encodeWithSelector(IdentityRegistry.NotYourHandle.selector, sha256("libid.x.handlebob")));
        vm.prank(BINDER);
        registry.publish(X, "bob");
    }

    function test_refusesToPublishAnotherHoldersHandle() public {
        _bind(_producedPayload());
        vm.expectRevert(abi.encodeWithSelector(IdentityRegistry.NotYourHandle.selector, HANDLE_NODE));
        vm.prank(address(0xCAFE));
        registry.publish(X, "alice_1");
    }

    function test_unpublishClearsTheName() public {
        _bind(_producedPayload());
        vm.prank(BINDER);
        registry.publish(X, "Alice_1");
        vm.expectEmit(address(registry));
        emit IdentityRegistry.HandleUnpublished(BINDER, X);
        vm.prank(BINDER);
        registry.unpublish(X);
        assertEq(registry.publishedHandleOf(BINDER, X), "");
        // The binding itself stays.
        assertEq(registry.resolveHandle(X, "alice_1"), BINDER);
    }

    /// @dev Disclosing in the payload: the X Platform Verifier checks the
    ///      handle against the node its real proof bound and returns it
    ///      folded. The folded handle is then in the logs, which is also what
    ///      says the scan in the private test can see one.
    function test_bindsAndPublishesInOneCall() public {
        bytes memory payload = _producedPayload("Alice_1");
        vm.recordLogs();
        vm.expectEmit(address(registry));
        emit IdentityRegistry.HandlePublished(BINDER, X, HANDLE_NODE, "alice_1");
        _bind(payload);
        assertEq(registry.publishedHandleOf(BINDER, X), "alice_1");

        Vm.Log[] memory logs = vm.getRecordedLogs();
        bool seen;
        for (uint256 i = 0; i < logs.length; ++i) {
            seen = seen || _containsAny(logs[i].data);
        }
        assertTrue(seen, "a disclosure logs the handle");
    }

    // ─── Helpers ────────────────────────────────────────────────────

    /// Whether `data` carries the id, the handle as sent, or the handle
    /// folded.
    function _containsAny(bytes memory data) private pure returns (bool) {
        return _indexOf(data, "2244994945") != type(uint256).max || _indexOf(data, "Alice_1") != type(uint256).max
            || _indexOf(data, "alice_1") != type(uint256).max;
    }

    /// Every slot `target` wrote since `vm.record`, read back and scanned.
    function _assertNoSlotCarriesAny(address target) private view {
        (, bytes32[] memory writes) = vm.accesses(target);
        for (uint256 i = 0; i < writes.length; ++i) {
            assertFalse(
                _containsAny(abi.encode(vm.load(target, writes[i]))),
                string.concat("a storage slot carries an id or handle: ", vm.toString(writes[i]))
            );
        }
    }

    function _indexOf(bytes memory haystack, bytes memory needle) private pure returns (uint256) {
        if (needle.length > haystack.length) return type(uint256).max;
        for (uint256 i = 0; i + needle.length <= haystack.length; ++i) {
            bool same = true;
            for (uint256 j = 0; j < needle.length && same; ++j) {
                same = haystack[i + j] == needle[j];
            }
            if (same) return i;
        }
        return type(uint256).max;
    }

    /// @dev A disclosure the real proof does not back is refused by the
    ///      Platform Verifier, before anything is written.
    function test_refusesToBindAHandleTheProofDidNotBind() public {
        bytes memory payload = _producedPayload("bob");
        uint256 value = registry.quoteBind(X, 1);
        bytes32 bob = sha256("libid.x.handlebob");
        vm.expectRevert(abi.encodeWithSelector(PlatformVerifierBase.HandleNotProved.selector, bob, HANDLE_NODE));
        vm.prank(BINDER);
        registry.bind{value: value}(X, 1, payload);
        assertEq(registry.resolveId(ID_NODE), address(0));
    }
}
