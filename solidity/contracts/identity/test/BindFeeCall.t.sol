// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, Vm} from "forge-std/Test.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

import {CeremonyAuthorization} from "../../ceremony/CeremonyAuthorization.sol";
import {CeremonyProfile} from "../../ceremony/CeremonyProfile.sol";
import {CeremonyProofVerifier} from "../../ceremony/CeremonyProofVerifier.sol";
import {IPlatformVerifier} from "../../ceremony/IPlatformVerifier.sol";
import {IProofVerifier} from "../../ceremony/IProofVerifier.sol";
import {IHandleReveal} from "../../handles/IHandleReveal.sol";
import {IBindFeeReceiver} from "../IBindFeeReceiver.sol";
import {IdentityRegistry} from "../IdentityRegistry.sol";
import {StubPlatformVerifier} from "./StubPlatformVerifier.sol";
import {TestNodes} from "./TestNodes.sol";

/// @notice `bindWithFeeCall`: a bind whose service fee goes to a contract's
///         `onBindFee`, over a real Proof Verifier and a stubbed Platform Verifier.
contract BindFeeCallTest is Test {
    IdentityRegistry registry;
    CeremonyProofVerifier proofVerifier;
    StubPlatformVerifier verifier;

    address constant OWNER = address(0xA11CE);
    address constant WALLET = address(0xBEEF);
    bytes32 constant PLATFORM = CeremonyProfile.PLATFORM_X;
    bytes32 constant DOMAIN = keccak256(bytes("libid.bind-identity"));
    /// What the stub charges for verification.
    uint256 constant QUOTE = 0.002 ether;
    uint256 constant SERVICE_FEE = 0.01 ether;
    bytes constant FEE_DATA = abi.encode(bytes32("referrer platform"), bytes32("referrer node"));

    uint256 private nonce;

    function setUp() public {
        vm.warp(1_770_000_100);
        IdentityRegistry impl = new IdentityRegistry();
        registry = IdentityRegistry(
            address(new ERC1967Proxy(address(impl), abi.encodeCall(IdentityRegistry.initialize, (OWNER))))
        );
        CeremonyProofVerifier pvImpl = new CeremonyProofVerifier();
        proofVerifier = CeremonyProofVerifier(
            address(new ERC1967Proxy(address(pvImpl), abi.encodeCall(CeremonyProofVerifier.initialize, (OWNER))))
        );
        verifier = new StubPlatformVerifier(PLATFORM, QUOTE);
        vm.startPrank(OWNER);
        registry.setProofVerifier(IProofVerifier(address(proofVerifier)));
        proofVerifier.setVerifier(PLATFORM, 1, IPlatformVerifier(address(verifier)));
        vm.stopPrank();
        vm.deal(WALLET, 100 ether);
    }

    /// A payload binding `target` under a nonce no other bind used.
    function _payload(address target) private returns (bytes memory) {
        return abi.encode(
            StubPlatformVerifier.StubPayload({
                ceremonyVersion: 1,
                operationDomain: DOMAIN,
                authorizationNonce: bytes32(++nonce),
                transactionData: abi.encode(target)
            })
        );
    }

    /// The digest of the last payload `_payload` built for `target`.
    function _digest(address target) private view returns (bytes32) {
        return CeremonyAuthorization.digest(DOMAIN, 1, bytes32(nonce), abi.encode(target));
    }

    /// Bind as WALLET through `bindWithFeeCall`, unlisted, with the exact value.
    function _bindWithFeeCall(address receiver) private {
        bytes memory payload = _payload(WALLET);
        vm.prank(WALLET);
        registry.bindWithFeeCall{value: QUOTE + SERVICE_FEE}(
            PLATFORM, 1, payload, "", false, SERVICE_FEE, receiver, FEE_DATA
        );
    }

    /// Expect `bindWithFeeCall` as WALLET to revert with `reason` and leave no trace.
    function _expectRefused(uint256 value, uint256 feeAmount, address receiver, bytes memory reason) private {
        bytes memory payload = _payload(WALLET);
        vm.prank(WALLET);
        vm.expectRevert(reason);
        registry.bindWithFeeCall{value: value}(PLATFORM, 1, payload, "", false, feeAmount, receiver, FEE_DATA);

        assertEq(registry.resolveHandle(PLATFORM, "alice"), address(0), "a refused bind wrote a binding");
        assertFalse(registry.digestSpent(_digest(WALLET)), "a refused bind spent its digest");
    }

    function _alice() private pure returns (bytes32) {
        return TestNodes.handleNode(PLATFORM, "alice");
    }

    // ─── Paying through the callback ────────────────────────────────

    function test_paysTheFeeThroughTheReceiversCallback() public {
        RecordingReceiver receiver = new RecordingReceiver(registry);
        uint256 walletBefore = WALLET.balance;
        bytes32 alice = _alice();

        bytes memory payload = _payload(WALLET);
        vm.expectEmit(true, true, false, true, address(registry));
        emit IdentityRegistry.BindFeePaid(_digest(WALLET), address(receiver), SERVICE_FEE);
        vm.prank(WALLET);
        registry.bindWithFeeCall{value: QUOTE + SERVICE_FEE}(
            PLATFORM, 1, payload, "", false, SERVICE_FEE, address(receiver), FEE_DATA
        );

        assertEq(receiver.binder(), WALLET);
        assertEq(receiver.platformId(), PLATFORM);
        assertEq(receiver.handleNode(), alice);
        assertEq(receiver.sessionId(), _digest(WALLET));
        assertEq(receiver.feeData(), FEE_DATA);
        assertEq(receiver.value(), SERVICE_FEE);
        assertEq(address(receiver).balance, SERVICE_FEE);
        assertEq(walletBefore - WALLET.balance, QUOTE + SERVICE_FEE);
        assertEq(registry.resolveHandle(PLATFORM, "alice"), WALLET);
    }

    /// @dev The callback follows the write, so the receiver reads the new holder.
    function test_theReceiverSeesTheBindingItIsPaidFor() public {
        RecordingReceiver receiver = new RecordingReceiver(registry);
        _bindWithFeeCall(address(receiver));
        assertEq(receiver.holderSeen(), WALLET);
    }

    function test_anEmptyHandleBindsUnlisted() public {
        RecordingReceiver receiver = new RecordingReceiver(registry);
        vm.recordLogs();
        _bindWithFeeCall(address(receiver));

        Vm.Log[] memory logs = vm.getRecordedLogs();
        for (uint256 i = 0; i < logs.length; ++i) {
            assertTrue(logs[i].topics[0] != IHandleReveal.HandleRevealed.selector, "an unlisted bind revealed");
        }
        (bytes32 on, string memory name) = registry.primaryHandleOf(WALLET);
        assertEq(on, bytes32(0));
        assertEq(name, "");
    }

    function test_aDisclosedHandleIsRevealedAndNamedAsBindDoes() public {
        RecordingReceiver receiver = new RecordingReceiver(registry);
        bytes memory payload = _payload(WALLET);
        bytes32 alice = _alice();

        vm.expectEmit(true, true, false, true, address(registry));
        emit IHandleReveal.HandleRevealed(PLATFORM, alice, "alice");
        vm.prank(WALLET);
        registry.bindWithFeeCall{value: QUOTE + SERVICE_FEE}(
            PLATFORM, 1, payload, "Alice", true, SERVICE_FEE, address(receiver), FEE_DATA
        );

        (bytes32 on, string memory name) = registry.primaryHandleOf(WALLET);
        assertEq(on, PLATFORM);
        assertEq(name, "alice");
    }

    /// @dev `bind` keeps paying by plain transfer, even to a receiver contract.
    function test_bindPaysAReceiverContractByTransfer() public {
        RecordingReceiver receiver = new RecordingReceiver(registry);
        bytes memory payload = _payload(WALLET);
        vm.prank(WALLET);
        registry.bind{value: QUOTE + SERVICE_FEE}(PLATFORM, 1, payload, "", false, SERVICE_FEE, address(receiver));

        assertEq(address(receiver).balance, SERVICE_FEE);
        assertEq(receiver.binder(), address(0), "bind called onBindFee");
    }

    // ─── The value ──────────────────────────────────────────────────

    function test_refusesOneWeiLessThanTheQuoteAndTheFee() public {
        RecordingReceiver receiver = new RecordingReceiver(registry);
        _expectRefused(
            QUOTE + SERVICE_FEE - 1,
            SERVICE_FEE,
            address(receiver),
            abi.encodeWithSelector(IdentityRegistry.WrongFeeValue.selector, SERVICE_FEE, SERVICE_FEE - 1)
        );
    }

    function test_refusesOneWeiMoreThanTheQuoteAndTheFee() public {
        RecordingReceiver receiver = new RecordingReceiver(registry);
        _expectRefused(
            QUOTE + SERVICE_FEE + 1,
            SERVICE_FEE,
            address(receiver),
            abi.encodeWithSelector(IdentityRegistry.WrongFeeValue.selector, SERVICE_FEE, SERVICE_FEE + 1)
        );
    }

    /// @dev The receiver gets the named fee, never value the registry already held.
    function test_theRegistrysBalanceIsTheSameAfterACallbackBind() public {
        vm.deal(address(registry), 1 ether);
        RecordingReceiver receiver = new RecordingReceiver(registry);
        _bindWithFeeCall(address(receiver));

        assertEq(address(registry).balance, 1 ether);
        assertEq(receiver.value(), SERVICE_FEE);
    }

    // ─── What the path refuses ──────────────────────────────────────

    /// @dev A free bind uses `bind`; this path always pays someone.
    function test_refusesAZeroFee() public {
        RecordingReceiver receiver = new RecordingReceiver(registry);
        _expectRefused(QUOTE, 0, address(0), abi.encodeWithSelector(IdentityRegistry.NoFee.selector));
        _expectRefused(QUOTE, 0, address(receiver), abi.encodeWithSelector(IdentityRegistry.NoFee.selector));
    }

    function test_refusesAFeeBesideNoReceiver() public {
        _expectRefused(
            QUOTE + SERVICE_FEE,
            SERVICE_FEE,
            address(0),
            abi.encodeWithSelector(IdentityRegistry.NoncanonicalFee.selector, SERVICE_FEE, address(0))
        );
    }

    function test_refusesAnAccountWithoutCode() public {
        address host = makeAddr("host");
        _expectRefused(
            QUOTE + SERVICE_FEE,
            SERVICE_FEE,
            host,
            abi.encodeWithSelector(IdentityRegistry.FeeCallRefused.selector, host)
        );
        assertEq(host.balance, 0);
    }

    /// @dev A Safe takes plain transfers, and a call with data and value reverts without a reason.
    function test_refusesAContractThatOnlyTakesTransfers() public {
        TransferOnlyReceiver safe = new TransferOnlyReceiver();
        _expectRefused(
            QUOTE + SERVICE_FEE,
            SERVICE_FEE,
            address(safe),
            abi.encodeWithSelector(IdentityRegistry.FeeCallRefused.selector, address(safe))
        );
    }

    function test_refusesAContractThatAnswersNothing() public {
        _expectAnswerRefused("");
    }

    function test_refusesAnotherSelector() public {
        _expectAnswerRefused(abi.encode(bytes4(0xdeadbeef)));
    }

    function test_refusesTheSelectorWithDirtyPadding() public {
        _expectAnswerRefused(abi.encodePacked(IBindFeeReceiver.onBindFee.selector, uint224(1)));
    }

    function test_refusesTheSelectorFollowedByMoreData() public {
        _expectAnswerRefused(abi.encode(IBindFeeReceiver.onBindFee.selector, uint256(0)));
    }

    function test_acceptsTheSelectorAsOneWord() public {
        AnsweringReceiver receiver = new AnsweringReceiver(abi.encode(IBindFeeReceiver.onBindFee.selector));
        _bindWithFeeCall(address(receiver));
        assertEq(address(receiver).balance, SERVICE_FEE);
    }

    function _expectAnswerRefused(bytes memory answer) private {
        AnsweringReceiver receiver = new AnsweringReceiver(answer);
        _expectRefused(
            QUOTE + SERVICE_FEE,
            SERVICE_FEE,
            address(receiver),
            abi.encodeWithSelector(IdentityRegistry.FeeCallRefused.selector, address(receiver))
        );
    }

    /// @dev A client simulating the bind sees why the receiver refused it.
    function test_aReceiversRevertReachesTheSenderAndUndoesTheBind() public {
        RefusingReceiver receiver = new RefusingReceiver();
        _expectRefused(
            QUOTE + SERVICE_FEE,
            SERVICE_FEE,
            address(receiver),
            abi.encodeWithSelector(RefusingReceiver.BadFeeData.selector)
        );
    }

    // ─── Reentrancy ─────────────────────────────────────────────────

    /// @dev Each attempt names the receiver as its target, so only the guard refuses it.
    function test_aReceiverCannotReenterAnyBind() public {
        ReenteringFeeReceiver receiver = new ReenteringFeeReceiver(registry, PLATFORM, QUOTE);
        receiver.arm(_payload(address(receiver)), _payload(address(receiver)), _payload(address(receiver)));
        vm.deal(address(receiver), 1 ether);

        _bindWithFeeCall(address(receiver));

        bytes memory guarded = abi.encodeWithSelector(ReentrancyGuard.ReentrancyGuardReentrantCall.selector);
        assertEq(receiver.refusalCount(), 3);
        assertEq(receiver.refusals(0), guarded, "bind let the receiver in");
        assertEq(receiver.refusals(1), guarded, "bindPrivately let the receiver in");
        assertEq(receiver.refusals(2), guarded, "bindWithFeeCall let the receiver in");
        assertEq(registry.identityCount(address(receiver)), 0);
        assertEq(registry.resolveHandle(PLATFORM, "alice"), WALLET);
    }

    /// @dev `publish` and `unpublish` act on their caller, so a receiver changes only its own name.
    function test_aReceiverPublishingChangesOnlyItsOwnName() public {
        PublishingReceiver receiver = new PublishingReceiver(registry, PLATFORM);
        vm.deal(address(receiver), 1 ether);
        verifier.set("1000000001", "bob");
        bytes memory own = _payload(address(receiver));
        vm.prank(address(receiver));
        registry.bind{value: QUOTE}(PLATFORM, 1, own, "bob", true, 0, address(0));

        verifier.set("2244994945", "alice");
        bytes32 alice = _alice();
        bytes memory payload = _payload(WALLET);
        vm.prank(WALLET);
        registry.bindWithFeeCall{value: QUOTE + SERVICE_FEE}(
            PLATFORM, 1, payload, "alice", true, SERVICE_FEE, address(receiver), FEE_DATA
        );

        assertEq(receiver.publishRefusal(), abi.encodeWithSelector(IdentityRegistry.NotYourHandle.selector, alice));
        (bytes32 walletOn, string memory walletName) = registry.primaryHandleOf(WALLET);
        assertEq(walletOn, PLATFORM);
        assertEq(walletName, "alice");
        (bytes32 receiverOn, string memory receiverName) = registry.primaryHandleOf(address(receiver));
        assertEq(receiverOn, bytes32(0));
        assertEq(receiverName, "");
        assertEq(registry.resolveHandle(PLATFORM, "bob"), address(receiver));
    }
}

/// @notice Records what `onBindFee` was told, and the holder of the node while it runs.
contract RecordingReceiver is IBindFeeReceiver {
    IdentityRegistry immutable REGISTRY;
    address public binder;
    bytes32 public platformId;
    bytes32 public handleNode;
    bytes32 public sessionId;
    bytes public feeData;
    uint256 public value;
    address public holderSeen;

    constructor(IdentityRegistry registry) {
        REGISTRY = registry;
    }

    receive() external payable {}

    function onBindFee(
        address binder_,
        bytes32 platformId_,
        bytes32 handleNode_,
        bytes32 sessionId_,
        bytes calldata data
    ) external payable returns (bytes4) {
        binder = binder_;
        platformId = platformId_;
        handleNode = handleNode_;
        sessionId = sessionId_;
        feeData = data;
        value = msg.value;
        (holderSeen,) = REGISTRY.handleBinding(handleNode_);
        return IBindFeeReceiver.onBindFee.selector;
    }
}

/// @notice Answers any call, value included, with fixed return data.
contract AnsweringReceiver {
    bytes answer;

    constructor(bytes memory answer_) {
        answer = answer_;
    }

    fallback(bytes calldata) external payable returns (bytes memory) {
        return answer;
    }
}

/// @notice Takes plain transfers only: its fallback takes no value, as a Safe's does.
contract TransferOnlyReceiver {
    receive() external payable {}

    fallback() external {}
}

/// @notice Refuses every fee with its own error.
contract RefusingReceiver is IBindFeeReceiver {
    error BadFeeData();

    function onBindFee(address, bytes32, bytes32, bytes32, bytes calldata) external payable returns (bytes4) {
        revert BadFeeData();
    }
}

/// @notice Tries `bind`, `bindPrivately` and `bindWithFeeCall` from inside its callback,
///         each with a payload of its own, and keeps each revert.
contract ReenteringFeeReceiver is IBindFeeReceiver {
    IdentityRegistry immutable REGISTRY;
    bytes32 immutable PLATFORM;
    uint256 immutable QUOTE;
    bytes[3] payloads;
    bytes[] public refusals;

    constructor(IdentityRegistry registry, bytes32 platform, uint256 quote) {
        REGISTRY = registry;
        PLATFORM = platform;
        QUOTE = quote;
    }

    function arm(bytes memory forBind, bytes memory forBindPrivately, bytes memory forBindWithFeeCall) external {
        payloads = [forBind, forBindPrivately, forBindWithFeeCall];
    }

    function refusalCount() external view returns (uint256) {
        return refusals.length;
    }

    function onBindFee(address, bytes32, bytes32, bytes32, bytes calldata) external payable returns (bytes4) {
        _try(QUOTE, abi.encodeCall(IdentityRegistry.bind, (PLATFORM, 1, payloads[0], "", false, 0, address(0))));
        _try(QUOTE, abi.encodeCall(IdentityRegistry.bindPrivately, (PLATFORM, 1, payloads[1], 0, address(0))));
        _try(
            QUOTE + 1,
            abi.encodeCall(
                IdentityRegistry.bindWithFeeCall, (PLATFORM, 1, payloads[2], "", false, 1, address(this), "")
            )
        );
        return IBindFeeReceiver.onBindFee.selector;
    }

    function _try(uint256 value, bytes memory call) private {
        (bool ok, bytes memory ret) = address(REGISTRY).call{value: value}(call);
        refusals.push(ok ? bytes("") : ret);
    }
}

/// @notice Withdraws its own name and tries to publish the binder's handle from its callback.
contract PublishingReceiver is IBindFeeReceiver {
    IdentityRegistry immutable REGISTRY;
    bytes32 immutable PLATFORM;
    bytes public publishRefusal;

    constructor(IdentityRegistry registry, bytes32 platform) {
        REGISTRY = registry;
        PLATFORM = platform;
    }

    function onBindFee(address, bytes32, bytes32, bytes32, bytes calldata) external payable returns (bytes4) {
        REGISTRY.unpublish();
        (bool ok, bytes memory ret) =
            address(REGISTRY).call(abi.encodeCall(IdentityRegistry.publish, (PLATFORM, "alice")));
        publishRefusal = ok ? bytes("") : ret;
        return IBindFeeReceiver.onBindFee.selector;
    }
}
