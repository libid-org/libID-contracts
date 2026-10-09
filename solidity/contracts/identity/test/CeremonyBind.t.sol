// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, Vm} from "forge-std/Test.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

import {CeremonyAuthorization} from "../../ceremony/CeremonyAuthorization.sol";
import {CeremonyProfile} from "../../ceremony/CeremonyProfile.sol";
import {CeremonyProofVerifier} from "../../ceremony/CeremonyProofVerifier.sol";
import {IPlatformVerifier} from "../../ceremony/IPlatformVerifier.sol";
import {IProofVerifier} from "../../ceremony/IProofVerifier.sol";
import {IdentityRegistry} from "../IdentityRegistry.sol";
import {TestNodes} from "./TestNodes.sol";
import {StubPlatformVerifier} from "./StubPlatformVerifier.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {ReentrancyGuardUpgradeable} from "@openzeppelin/contracts-upgradeable/utils/ReentrancyGuardUpgradeable.sol";

/// @notice IdentityRegistry wearing the Consumer role, over a real Proof Verifier
///         and a stubbed Platform Verifier.
contract CeremonyBindTest is Test {
    IdentityRegistry registry;
    CeremonyProofVerifier proofVerifier;
    StubPlatformVerifier verifier;

    address constant OWNER = address(0xA11CE);
    address constant WALLET = address(0xBEEF);
    bytes32 constant PLATFORM = CeremonyProfile.PLATFORM_X;
    bytes32 constant DOMAIN = keccak256(bytes("libid.claim-identity"));
    uint256 constant FEE = 0.002 ether;
    /// A hosted application, and what it charges for composing the ceremony.
    address constant HOST = address(0x405);
    uint256 constant SERVICE_FEE = 0.01 ether;
    uint64 constant T0 = 1_770_000_000;

    function setUp() public {
        vm.warp(T0 + 100);
        IdentityRegistry impl = new IdentityRegistry();
        registry = IdentityRegistry(
            address(new ERC1967Proxy(address(impl), abi.encodeCall(IdentityRegistry.initialize, (OWNER))))
        );
        CeremonyProofVerifier pvImpl = new CeremonyProofVerifier();
        proofVerifier = CeremonyProofVerifier(
            address(new ERC1967Proxy(address(pvImpl), abi.encodeCall(CeremonyProofVerifier.initialize, (OWNER))))
        );

        vm.startPrank(OWNER);
        registry.setProofVerifier(IProofVerifier(address(proofVerifier)));
        verifier = new StubPlatformVerifier(PLATFORM, FEE);
        proofVerifier.setVerifier(PLATFORM, 1, IPlatformVerifier(address(verifier)));
        vm.stopPrank();
        vm.deal(WALLET, 100 ether);
    }

    /// The Authorized Transaction Data of `libid.claim-identity`.
    function _txData(address target, uint256 feeAmount, address feeReceiver) private pure returns (bytes memory) {
        return abi.encode(target, feeAmount, feeReceiver);
    }

    /// The same, for a ceremony composed by hand: no application to pay.
    function _free(address target) private pure returns (bytes memory) {
        return _txData(target, 0, address(0));
    }

    /// The stub's payload for one authorization. The Consumer never sees
    /// inside it; only the stub does.
    function _payload(bytes32 domain, bytes memory txData, bytes32 nonce) private pure returns (bytes memory) {
        return abi.encode(
            StubPlatformVerifier.StubPayload({
                ceremonyVersion: 1,
                operationDomain: domain,
                authorizationNonce: nonce,
                transactionData: txData,
                handle: ""
            })
        );
    }

    function _payload(bytes32 domain, address target, bytes32 nonce) private pure returns (bytes memory) {
        return _payload(domain, _free(target), nonce);
    }

    function _payload(address target, bytes32 nonce) private pure returns (bytes memory) {
        return _payload(DOMAIN, _free(target), nonce);
    }

    function _bind(bytes memory payload, uint256 value) private {
        vm.prank(WALLET);
        registry.bind{value: value}(PLATFORM, 1, payload);
    }

    function _digest(bytes memory txData, bytes32 nonce) private view returns (bytes32) {
        return CeremonyAuthorization.digestFor(DOMAIN, 1, nonce, txData);
    }

    function _digest(address target, bytes32 nonce) private view returns (bytes32) {
        return _digest(_free(target), nonce);
    }

    // ─── The happy path ─────────────────────────────────────────────

    function test_bindsAnIdentityFromACeremony() public {
        _bind(_payload(WALLET, bytes32(uint256(1))), FEE);
        assertEq(registry.resolveHandle(PLATFORM, "alice"), WALLET);
        assertEq(registry.resolveId(TestNodes.idNode(PLATFORM, "2244994945")), WALLET);
    }

    /// @dev The Consumer hands the payload through as opaque bytes. What the
    ///      Platform Verifier decoded and digested is what it acted on.
    function test_recordsTheDigestTheVerifierBuilt() public {
        _bind(_payload(WALLET, bytes32(uint256(7))), FEE);
        assertEq(verifier.lastDigest(), _digest(WALLET, bytes32(uint256(7))));
        assertTrue(registry.digestSpent(verifier.lastDigest()));
    }

    /// @dev Which OAuth client produced a binding is answerable only from the
    ///      call that wrote it -- nothing stores the value, and the contract
    ///      has no use for it. So a ceremony logs it, in the exact bytes the
    ///      platform authenticated, keyed by the digest that identifies the
    ///      ceremony.
    function test_logsTheAuthenticatedClientIdentifier() public {
        vm.recordLogs();
        _bind(_payload(WALLET, bytes32(uint256(11))), FEE);

        Vm.Log[] memory logs = vm.getRecordedLogs();
        bytes32 topic = keccak256("CeremonyBound(bytes32,address,bytes32,bytes)");
        for (uint256 i = logs.length; i > 0; i--) {
            if (logs[i - 1].topics[0] != topic) continue;
            assertEq(string(abi.decode(logs[i - 1].data, (bytes))), "client");
            return;
        }
        revert("no CeremonyBound in the logs");
    }

    /// @dev Logged, not stored. Nothing on chain reads which ceremony version
    ///      proved a binding; an operator asking which bindings a version
    ///      touched reads `IdentityBound`.
    function test_logsTheCeremonyVersionAndStoresNothingOfIt() public {
        vm.recordLogs();
        _bind(_payload(WALLET, bytes32(uint256(88))), FEE);

        Vm.Log[] memory logs = vm.getRecordedLogs();
        bytes32 topic = keccak256("IdentityBound(address,bytes32,bytes32,bytes32,uint64,uint16)");
        for (uint256 i = logs.length; i > 0; i--) {
            if (logs[i - 1].topics[0] != topic) continue;
            (,, uint16 version) = abi.decode(logs[i - 1].data, (bytes32, uint64, uint16));
            assertEq(version, 1);
            return;
        }
        revert("no IdentityBound in the logs");
    }

    function test_quotesAndForwardsTheWholePath() public {
        assertEq(registry.quoteBind(PLATFORM, 1), FEE);
        _bind(_payload(WALLET, bytes32(uint256(2))), FEE);
        assertEq(verifier.lastValue(), FEE);
    }

    function test_rejectsAnyValueOtherThanTheQuote() public {
        bytes memory p = _payload(WALLET, bytes32(uint256(3)));
        vm.prank(WALLET);
        vm.expectRevert(abi.encodeWithSelector(IdentityRegistry.WrongBindValue.selector, FEE, FEE - 1));
        registry.bind{value: FEE - 1}(PLATFORM, 1, p);
    }

    // ─── The digest is its own replay nullifier ─────────────────────

    /// @dev REQ-COMMON-03A. The circuit dropped its nullifier because this
    ///      exists; without it the drop would have opened a replay.
    function test_aDigestIsSpendableOnce() public {
        bytes memory p = _payload(WALLET, bytes32(uint256(9)));
        _bind(p, FEE);
        bytes32 digest = _digest(WALLET, bytes32(uint256(9)));
        assertTrue(registry.digestSpent(digest));

        vm.prank(WALLET);
        vm.expectRevert(abi.encodeWithSelector(IdentityRegistry.DigestAlreadySpent.selector, digest));
        registry.bind{value: FEE}(PLATFORM, 1, p);
    }

    /// @dev A fresh nonce is a fresh digest, so re-proving is always available.
    function test_aFreshNonceIsAFreshDigest() public {
        verifier.setObservedAt(T0);
        _bind(_payload(WALLET, bytes32(uint256(1))), FEE);
        verifier.setObservedAt(T0 + 1);
        _bind(_payload(WALLET, bytes32(uint256(2))), FEE);
        assertEq(registry.resolveHandle(PLATFORM, "alice"), WALLET);
    }

    // ─── The authorization predicate ────────────────────────────────

    /// @dev The Consumer binds to the AUTHENTICATED caller, not to an address
    ///      the submitter names. A Consumer doing otherwise would turn
    ///      consent-phishing into identity theft: anyone could spend a genuine
    ///      proof at an address of their choosing.
    function test_rejectsAProofSpentAtAnotherAddress() public {
        bytes memory p = _payload(address(0xDEAD), bytes32(uint256(4)));
        vm.prank(WALLET);
        vm.expectRevert(abi.encodeWithSelector(IdentityRegistry.NotProofTarget.selector, address(0xDEAD), WALLET));
        registry.bind{value: FEE}(PLATFORM, 1, p);
    }

    /// @dev REQ-COMMON-01F: one exact encoding, and trailing bytes refused.
    function test_rejectsMalformedTransactionData() public {
        bytes memory p = _payload(DOMAIN, abi.encodePacked(_free(WALLET), hex"00"), bytes32(uint256(5)));
        vm.prank(WALLET);
        vm.expectRevert(abi.encodeWithSelector(IdentityRegistry.BadTransactionData.selector, 97));
        registry.bind{value: FEE}(PLATFORM, 1, p);
    }

    // ─── The operation domain ───────────────────────────────────────

    /// @dev REQ-COMMON-06A. The domain is inside the payload, so the Consumer
    ///      learns it from the verifier's report and refuses one it does not
    ///      own before applying anything.
    function test_rejectsAForeignOperationDomain() public {
        bytes32 foreign = keccak256(bytes("someone.else.operation"));
        bytes memory p = _payload(foreign, WALLET, bytes32(uint256(6)));
        vm.prank(WALLET);
        vm.expectRevert(abi.encodeWithSelector(IdentityRegistry.ForeignOperationDomain.selector, foreign));
        registry.bind{value: FEE}(PLATFORM, 1, p);
    }

    // ─── The Supported Version Set ──────────────────────────────────

    function test_rejectsAnUnregisteredVerifierVersion() public {
        bytes memory p = _payload(WALLET, bytes32(uint256(8)));
        vm.prank(WALLET);
        vm.expectRevert(abi.encodeWithSelector(CeremonyProofVerifier.UnknownVersion.selector, PLATFORM, uint16(2)));
        registry.bind{value: FEE}(PLATFORM, 2, p);
    }

    /// @dev REQ-COMMON-05B: more than one verifier version of one platform at
    ///      a time, so a deployment runs a new one beside the one it replaces.
    function test_supportsTwoVerifierVersionsAtOnce() public {
        StubPlatformVerifier second = new StubPlatformVerifier(PLATFORM, FEE);
        second.set("999", "bob");
        vm.prank(OWNER);
        proofVerifier.setVerifier(PLATFORM, 2, IPlatformVerifier(address(second)));

        _bind(_payload(WALLET, bytes32(uint256(10))), FEE);
        vm.prank(WALLET);
        registry.bind{value: FEE}(PLATFORM, 2, _payload(WALLET, bytes32(uint256(11))));

        assertEq(registry.resolveHandle(PLATFORM, "alice"), WALLET);
        assertEq(registry.resolveHandle(PLATFORM, "bob"), WALLET);
    }

    /// @dev CeremonyProofVerifier's own doc says removing a version "strands no
    ///      name already bound under it". Routing resolution through the
    ///      Supported Version Set made that false: retiring the last version
    ///      stopped every binding on the platform from resolving, for
    ///      identities that were bound and still current. A binding does not
    ///      belong to the proof that established it.
    function test_aBindingOutlivesTheVersionThatEstablishedIt() public {
        _bind(_payload(WALLET, bytes32(uint256(77))), FEE);
        assertEq(registry.resolveId(TestNodes.idNode(PLATFORM, "2244994945")), WALLET);

        vm.prank(OWNER);
        proofVerifier.setVerifier(PLATFORM, 1, IPlatformVerifier(address(0)));

        assertEq(registry.resolveId(TestNodes.idNode(PLATFORM, "2244994945")), WALLET);
        assertEq(registry.resolveHandle(PLATFORM, "alice"), WALLET);
    }

    /// @dev The set is authority, not configuration (REQ-COMMON-05C).
    function test_onlyTheOwnerChangesTheSupportedVersionSet() public {
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, address(this)));
        proofVerifier.setVerifier(PLATFORM, 3, IPlatformVerifier(address(verifier)));
    }

    /// @dev A verifier for another platform in this platform's slot would
    ///      dispatch a payload to code that reads a different format.
    function test_refusesAVerifierForAnotherPlatform() public {
        StubPlatformVerifier other = new StubPlatformVerifier(CeremonyProfile.PLATFORM_GITHUB, FEE);
        vm.prank(OWNER);
        vm.expectRevert(
            abi.encodeWithSelector(
                CeremonyProofVerifier.VerifierPlatformMismatch.selector, PLATFORM, CeremonyProfile.PLATFORM_GITHUB
            )
        );
        proofVerifier.setVerifier(PLATFORM, 4, IPlatformVerifier(address(other)));
    }

    // ─── The nodes are the verifier's ───────────────────────────────

    /// @dev A mixed-case handle binds the node of its folded form.
    function test_bindsTheNodeTheVerifierFolded() public {
        verifier.set("2244994945", "Alice_1");
        _bind(_payload(WALLET, bytes32(uint256(12))), FEE);
        (address holder,) = registry.handleBinding(TestNodes.handleNode(PLATFORM, "alice_1"));
        assertEq(holder, WALLET);
        assertEq(registry.resolveHandle(PLATFORM, "ALICE_1"), WALLET);
    }

    /// @dev The binding is keyed by the nodes the verifier reports, as reported.
    function test_storesTheNodesItIsGiven() public {
        bytes32 idNode = keccak256("an id node");
        bytes32 handleNode = keccak256("a handle node");
        verifier.setNodes(idNode, handleNode);
        _bind(_payload(WALLET, bytes32(uint256(14))), FEE);

        assertEq(registry.resolveId(idNode), WALLET);
        (address holder,) = registry.handleBinding(handleNode);
        assertEq(holder, WALLET);
    }

    /// @dev A zero id node is refused.
    function test_rejectsAnEmptyIdNode() public {
        verifier.setNodes(bytes32(0), keccak256("a handle node"));
        bytes memory p = _payload(WALLET, bytes32(uint256(13)));
        vm.prank(WALLET);
        vm.expectRevert(IdentityRegistry.NoId.selector);
        registry.bind{value: FEE}(PLATFORM, 1, p);
    }

    function test_rejectsAnEmptyHandleNode() public {
        verifier.setNodes(keccak256("an id node"), bytes32(0));
        bytes memory p = _payload(WALLET, bytes32(uint256(15)));
        vm.prank(WALLET);
        vm.expectRevert(IdentityRegistry.NoHandle.selector);
        registry.bind{value: FEE}(PLATFORM, 1, p);
    }

    function test_rejectsANoncanonicalAddressEncoding() public {
        // 96 bytes of the right length, whose first word is not an address.
        bytes memory bad = abi.encodePacked(bytes12(0xffffffffffffffffffffffff), WALLET, uint256(0), uint256(0));
        bytes memory p = _payload(DOMAIN, bad, bytes32(uint256(20)));
        vm.prank(WALLET);
        vm.expectRevert(); // abi.decode's own check
        registry.bind{value: FEE}(PLATFORM, 1, p);
    }

    function test_rejectsShortTransactionData() public {
        bytes memory p = _payload(DOMAIN, abi.encodePacked(WALLET), bytes32(uint256(21)));
        vm.prank(WALLET);
        vm.expectRevert(abi.encodeWithSelector(IdentityRegistry.BadTransactionData.selector, 20));
        registry.bind{value: FEE}(PLATFORM, 1, p);
    }

    function test_rejectsEmptyTransactionData() public {
        bytes memory p = _payload(DOMAIN, hex"", bytes32(uint256(22)));
        vm.prank(WALLET);
        vm.expectRevert(abi.encodeWithSelector(IdentityRegistry.BadTransactionData.selector, 0));
        registry.bind{value: FEE}(PLATFORM, 1, p);
    }

    /// @dev A wei short of the verification path is caught before the payload
    ///      is verified: that much is knowable without decoding anything.
    function test_rejectsOneWeiLessThanTheQuote() public {
        bytes memory p = _payload(WALLET, bytes32(uint256(23)));
        vm.prank(WALLET);
        vm.expectRevert(abi.encodeWithSelector(IdentityRegistry.WrongBindValue.selector, FEE, FEE - 1));
        registry.bind{value: FEE - 1}(PLATFORM, 1, p);
    }

    /// @dev A wei more is caught after: everything above the quote is the fee,
    ///      and this ceremony authorized none. There is no refund path, so
    ///      overpayment is refused rather than kept or forwarded.
    function test_rejectsOneWeiMoreThanTheBindCosts() public {
        bytes memory p = _payload(WALLET, bytes32(uint256(24)));
        vm.prank(WALLET);
        vm.expectRevert(abi.encodeWithSelector(IdentityRegistry.WrongFeeValue.selector, 0, 1));
        registry.bind{value: FEE + 1}(PLATFORM, 1, p);
    }

    function test_setProofVerifierIsOwnerOnlyAndNonZero() public {
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, address(this)));
        registry.setProofVerifier(IProofVerifier(address(proofVerifier)));
        vm.prank(OWNER);
        vm.expectRevert(IdentityRegistry.ZeroAddress.selector);
        registry.setProofVerifier(IProofVerifier(address(0)));
    }

    function test_aRejectedBindSpendsNoDigest() public {
        verifier.setObservedAt(0);
        bytes memory p = _payload(WALLET, bytes32(uint256(30)));
        vm.prank(WALLET);
        vm.expectRevert(IdentityRegistry.NoObservationTime.selector);
        registry.bind{value: FEE}(PLATFORM, 1, p);
        assertFalse(registry.digestSpent(_digest(WALLET, bytes32(uint256(30)))));
    }

    function test_theDomainIsJudgedBeforeTransactionDataIsDecoded() public {
        bytes memory p = _payload(keccak256("other"), hex"00", bytes32(uint256(40)));
        vm.prank(WALLET);
        vm.expectRevert(abi.encodeWithSelector(IdentityRegistry.ForeignOperationDomain.selector, keccak256("other")));
        registry.bind{value: FEE}(PLATFORM, 1, p);
    }

    function test_onePayloadIsSpentOnceAcrossTwoVerifierVersions() public {
        StubPlatformVerifier second = new StubPlatformVerifier(PLATFORM, FEE);
        vm.prank(OWNER);
        proofVerifier.setVerifier(PLATFORM, 2, IPlatformVerifier(address(second)));
        bytes memory p = _payload(WALLET, bytes32(uint256(50)));
        _bind(p, FEE);
        vm.prank(WALLET);
        vm.expectRevert(
            abi.encodeWithSelector(IdentityRegistry.DigestAlreadySpent.selector, _digest(WALLET, bytes32(uint256(50))))
        );
        registry.bind{value: FEE}(PLATFORM, 2, p);
    }

    function test_namesCannotReinitialize() public {
        vm.expectRevert(Initializable.InvalidInitialization.selector);
        registry.initialize(address(this));
    }

    // ─── The service fee ────────────────────────────────────────────

    /// @dev The whole point of carrying the fee in the Authorized Transaction
    ///      Data: this number was approved at consent time, because it is
    ///      inside the digest the proof opens against. A hosted application
    ///      cannot raise it afterwards, and it is paid to the address the
    ///      ceremony named -- not to the caller, who is the target.
    function test_paysTheFeeTheCeremonyNamed() public {
        bytes memory p = _payload(DOMAIN, _txData(WALLET, SERVICE_FEE, HOST), bytes32(uint256(60)));
        uint256 hostBefore = HOST.balance;
        uint256 walletBefore = WALLET.balance;

        vm.expectEmit(true, true, false, true, address(registry));
        emit IdentityRegistry.BindFeePaid(
            _digest(_txData(WALLET, SERVICE_FEE, HOST), bytes32(uint256(60))), HOST, SERVICE_FEE
        );
        _bind(p, FEE + SERVICE_FEE);

        assertEq(HOST.balance - hostBefore, SERVICE_FEE);
        assertEq(walletBefore - WALLET.balance, FEE + SERVICE_FEE);
        assertEq(registry.resolveHandle(PLATFORM, "alice"), WALLET);
        assertEq(address(registry).balance, 0, "nothing was captured in transit");
    }

    /// @dev Anyone who composes their own ceremony names no fee and pays only
    ///      the verification path. Nothing on this chain knows who is hosted
    ///      and who is not; the difference is entirely in what was consented to.
    function test_aFreeBindPaysOnlyTheVerificationPath() public {
        uint256 hostBefore = HOST.balance;
        vm.recordLogs();
        _bind(_payload(WALLET, bytes32(uint256(61))), FEE);

        Vm.Log[] memory logs = vm.getRecordedLogs();
        for (uint256 i = 0; i < logs.length; ++i) {
            assertTrue(logs[i].topics[0] != IdentityRegistry.BindFeePaid.selector, "a free bind paid something");
        }
        assertEq(HOST.balance, hostBefore);
        assertEq(registry.resolveHandle(PLATFORM, "alice"), WALLET);
    }

    function test_rejectsAFeeTheCallerDidNotDeliver() public {
        bytes memory p = _payload(DOMAIN, _txData(WALLET, SERVICE_FEE, HOST), bytes32(uint256(62)));
        vm.prank(WALLET);
        vm.expectRevert(abi.encodeWithSelector(IdentityRegistry.WrongFeeValue.selector, SERVICE_FEE, 0));
        registry.bind{value: FEE}(PLATFORM, 1, p);
    }

    /// @dev Over is refused as firmly as under. Nobody consented to more, and
    ///      there is nowhere to send the difference back to.
    function test_rejectsMoreThanTheCeremonyAuthorized() public {
        bytes memory p = _payload(DOMAIN, _txData(WALLET, SERVICE_FEE, HOST), bytes32(uint256(63)));
        vm.prank(WALLET);
        vm.expectRevert(abi.encodeWithSelector(IdentityRegistry.WrongFeeValue.selector, SERVICE_FEE, SERVICE_FEE + 1));
        registry.bind{value: FEE + SERVICE_FEE + 1}(PLATFORM, 1, p);
    }

    /// @dev REQ-COMMON-01F: one encoding per intent. A free bind is
    ///      `(0, address(0))`, so a receiver left beside a zero amount is a
    ///      second spelling of it and is refused rather than normalized.
    function test_rejectsAReceiverBesideAZeroFee() public {
        bytes memory p = _payload(DOMAIN, _txData(WALLET, 0, HOST), bytes32(uint256(64)));
        vm.prank(WALLET);
        vm.expectRevert(abi.encodeWithSelector(IdentityRegistry.NoncanonicalFee.selector, 0, HOST));
        registry.bind{value: FEE}(PLATFORM, 1, p);
    }

    /// @dev The other half of the same rule. Paying a fee to nobody would burn
    ///      value that was consented to, which is worse than refusing.
    function test_rejectsAFeeBesideNoReceiver() public {
        bytes memory p = _payload(DOMAIN, _txData(WALLET, SERVICE_FEE, address(0)), bytes32(uint256(65)));
        vm.prank(WALLET);
        vm.expectRevert(abi.encodeWithSelector(IdentityRegistry.NoncanonicalFee.selector, SERVICE_FEE, address(0)));
        registry.bind{value: FEE + SERVICE_FEE}(PLATFORM, 1, p);
    }

    /// @dev What makes the fee unforgeable: it is a digest input. Change the
    ///      amount or the receiver and the digest moves, so the authorized
    ///      proof no longer opens against it.
    function test_theFeeIsInsideTheDigest() public view {
        bytes32 n = bytes32(uint256(66));
        bytes32 asAgreed = _digest(_txData(WALLET, SERVICE_FEE, HOST), n);
        assertTrue(asAgreed != _digest(_txData(WALLET, SERVICE_FEE * 2, HOST), n), "the amount does not bind");
        assertTrue(asAgreed != _digest(_txData(WALLET, SERVICE_FEE, address(0xF00)), n), "the receiver does not bind");
        assertTrue(asAgreed != _digest(_free(WALLET), n), "a free bind is not a distinct digest");
    }

    /// @dev The receiver is an address the ceremony named, so it can be
    ///      hostile or simply broken. It cannot take the handle without paying
    ///      for it: the bind is one transaction, and a fee that cannot be
    ///      delivered undoes the write with it.
    function test_aReceiverThatRefusesTheFeeUndoesTheWholeBind() public {
        RejectingReceiver bad = new RejectingReceiver();
        bytes memory p = _payload(DOMAIN, _txData(WALLET, SERVICE_FEE, address(bad)), bytes32(uint256(67)));
        vm.prank(WALLET);
        vm.expectRevert(abi.encodeWithSelector(IdentityRegistry.FeeTransferFailed.selector, address(bad), SERVICE_FEE));
        registry.bind{value: FEE + SERVICE_FEE}(PLATFORM, 1, p);

        assertEq(registry.resolveHandle(PLATFORM, "alice"), address(0));
        assertFalse(registry.digestSpent(_digest(_txData(WALLET, SERVICE_FEE, address(bad)), bytes32(uint256(67)))));
    }

    /// @dev The fee is the one call out of this contract, and it happens after
    ///      every write. A receiver that calls back in finds the guard closed;
    ///      it may still take the value, and the bind it re-entered stands.
    function test_aFeeReceiverCannotReenterTheBind() public {
        ReenteringReceiver host = new ReenteringReceiver(registry, PLATFORM, _payload(WALLET, bytes32(uint256(69))));
        bytes memory p = _payload(DOMAIN, _txData(WALLET, SERVICE_FEE, address(host)), bytes32(uint256(68)));
        _bind(p, FEE + SERVICE_FEE);

        assertTrue(host.reentryReverted(), "the guard let a fee receiver back in");
        assertEq(address(host).balance, SERVICE_FEE);
        assertEq(registry.resolveHandle(PLATFORM, "alice"), WALLET);
        assertFalse(registry.digestSpent(_digest(WALLET, bytes32(uint256(69)))));
    }

    // Reentrancy (the stronger, negative-paths shape: zero-fee verifier, re-enters via raw call, re-raises)

    function test_aReenteringVerifierIsRefused() public {
        ReenteringVerifier evil = new ReenteringVerifier(registry, PLATFORM);
        vm.prank(OWNER);
        proofVerifier.setVerifier(PLATFORM, 1, IPlatformVerifier(address(evil)));
        bytes memory p = _payload(WALLET, bytes32(uint256(1)));
        evil.setInner(_payload(address(evil), bytes32(uint256(2))));
        vm.prank(WALLET);
        vm.expectRevert(ReentrancyGuardUpgradeable.ReentrancyGuardReentrantCall.selector);
        registry.bind(PLATFORM, 1, p);
        assertFalse(registry.digestSpent(_digest(WALLET, bytes32(uint256(1)))));
        assertFalse(registry.digestSpent(_digest(address(evil), bytes32(uint256(2)))));
    }
}

contract ReenteringVerifier is IPlatformVerifier {
    IdentityRegistry immutable REGISTRY;
    bytes32 immutable PLATFORM;
    bytes innerPayload;
    bool armed;

    constructor(IdentityRegistry n, bytes32 p) {
        REGISTRY = n;
        PLATFORM = p;
    }

    function setInner(bytes memory p) external {
        innerPayload = p;
        armed = true;
    }

    function platformId() external view returns (bytes32) {
        return PLATFORM;
    }

    function quote() external pure returns (uint256) {
        return 0;
    }

    /// @dev The `VerifiedClaim` it returns is zeroed; the reentry is the whole point.
    function verify(bytes calldata) external payable returns (VerifiedClaim memory c) {
        if (armed) {
            armed = false;
            (bool ok, bytes memory ret) =
                address(REGISTRY).call(abi.encodeCall(IdentityRegistry.bind, (PLATFORM, 1, innerPayload)));
            if (!ok) assembly { revert(add(ret, 32), mload(ret)) }
        }
        return c;
    }
}

/// @notice A fee receiver that will not take the value.
contract RejectingReceiver {
    receive() external payable {
        revert("no");
    }
}

/// @notice A fee receiver that tries to bind again while being paid.
contract ReenteringReceiver {
    IdentityRegistry immutable REGISTRY;
    bytes32 immutable PLATFORM;
    bytes payload;
    bool public reentryReverted;

    constructor(IdentityRegistry n, bytes32 p, bytes memory inner) {
        REGISTRY = n;
        PLATFORM = p;
        payload = inner;
    }

    receive() external payable {
        (bool ok,) = address(REGISTRY).call(abi.encodeCall(IdentityRegistry.bind, (PLATFORM, 1, payload)));
        reentryReverted = !ok;
    }
}
