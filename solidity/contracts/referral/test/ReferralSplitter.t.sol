// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, Vm} from "forge-std/Test.sol";
import {Clones} from "@openzeppelin/contracts/proxy/Clones.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

import {CeremonyProfile} from "../../ceremony/CeremonyProfile.sol";
import {CeremonyProofVerifier} from "../../ceremony/CeremonyProofVerifier.sol";
import {IPlatformVerifier} from "../../ceremony/IPlatformVerifier.sol";
import {IProofVerifier} from "../../ceremony/IProofVerifier.sol";
import {HandleEscrow, NATIVE_TOKEN} from "../../escrow/HandleEscrow.sol";
import {IdentityRegistry} from "../../identity/IdentityRegistry.sol";
import {IIdentityRegistry} from "../../identity/IIdentityRegistry.sol";
import {StubPlatformVerifier} from "../../identity/test/StubPlatformVerifier.sol";
import {TestNodes} from "../../identity/test/TestNodes.sol";
import {ReferralSplitter} from "../ReferralSplitter.sol";

/// @notice The splitter behind the registry's `bindWithFeeCall`, over a real
///         registry, Proof Verifier and escrow, and a stubbed Platform Verifier.
contract ReferralSplitterTest is Test {
    IdentityRegistry registry;
    CeremonyProofVerifier proofVerifier;
    StubPlatformVerifier verifier;
    HandleEscrow escrow;
    ReferralSplitter splitter;

    address constant OWNER = address(0xA11CE);
    address constant WALLET = address(0xBEEF);
    address constant REFERRER = address(0xCAFE);
    address treasury = makeAddr("treasury");

    bytes32 constant X = CeremonyProfile.PLATFORM_X;
    bytes32 constant GITHUB = CeremonyProfile.PLATFORM_GITHUB;
    bytes32 constant DOMAIN = keccak256(bytes("libid.bind-identity"));
    uint256 constant QUOTE = 0.002 ether;
    uint256 constant FEE = 0.01 ether;
    uint16 constant SHARE_BPS = 3_000;
    uint256 constant SHARE = FEE * SHARE_BPS / 10_000;
    uint256 constant MIN_FEE = 0.001 ether;

    uint256 private nonce;
    uint256 private nextId = 1_000_000_000;

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
        verifier = new StubPlatformVerifier(X, QUOTE);
        vm.startPrank(OWNER);
        registry.setProofVerifier(IProofVerifier(address(proofVerifier)));
        proofVerifier.setVerifier(X, 1, IPlatformVerifier(address(verifier)));
        vm.stopPrank();

        HandleEscrow escrowImpl = new HandleEscrow();
        escrow = HandleEscrow(
            address(
                new ERC1967Proxy(
                    address(escrowImpl), abi.encodeCall(HandleEscrow.initialize, (OWNER, IIdentityRegistry(registry)))
                )
            )
        );
        splitter = new ReferralSplitter(registry, escrow, OWNER, treasury, SHARE_BPS, MIN_FEE);
        vm.deal(WALLET, 100 ether);
    }

    // ─── Helpers ────────────────────────────────────────────────────

    function _node(string memory handle) private pure returns (bytes32) {
        return TestNodes.handleNode(X, handle);
    }

    function _referral(bytes32 node) private pure returns (bytes memory) {
        return abi.encode(X, node);
    }

    /// The next payload for `target`, with the stub reporting a fresh id and `handle`.
    function _stage(address target, string memory handle) private returns (bytes memory) {
        verifier.set(vm.toString(++nextId), handle);
        return abi.encode(
            StubPlatformVerifier.StubPayload({
                ceremonyVersion: 1,
                operationDomain: DOMAIN,
                authorizationNonce: bytes32(++nonce),
                transactionData: abi.encode(target)
            })
        );
    }

    /// `who` binds `handle` with no fee.
    function _hold(address who, string memory handle) private {
        bytes memory payload = _stage(who, handle);
        vm.deal(who, who.balance + QUOTE);
        vm.prank(who);
        registry.bind{value: QUOTE}(X, 1, payload, "", false, 0, address(0));
    }

    /// WALLET binds `handle` through the splitter, paying `fee` with `feeData`.
    function _referredBind(string memory handle, uint256 fee, bytes memory feeData) private {
        bytes memory payload = _stage(WALLET, handle);
        vm.prank(WALLET);
        registry.bindWithFeeCall{value: QUOTE + fee}(X, 1, payload, "", false, fee, address(splitter), feeData);
    }

    function _digest() private view returns (bytes32) {
        return keccak256(abi.encode(nonce));
    }

    /// The outcome of the one `Referred` in `logs`; fails if there is none or more.
    function _outcome(Vm.Log[] memory logs) private view returns (ReferralSplitter.Outcome outcome) {
        uint256 found;
        for (uint256 i = 0; i < logs.length; ++i) {
            if (logs[i].emitter == address(splitter) && logs[i].topics[0] == ReferralSplitter.Referred.selector) {
                (,,,,, outcome) =
                    abi.decode(logs[i].data, (bytes32, bytes32, bytes32, uint256, uint256, ReferralSplitter.Outcome));
                ++found;
            }
        }
        assertEq(found, 1, "one Referred per referred bind");
    }

    function _referredCount(Vm.Log[] memory logs) private view returns (uint256 n) {
        for (uint256 i = 0; i < logs.length; ++i) {
            if (logs[i].emitter == address(splitter) && logs[i].topics[0] == ReferralSplitter.Referred.selector) ++n;
        }
    }

    // ─── Paying the referrer ────────────────────────────────────────

    function test_aReferralToAHeldHandlePaysItsHolder() public {
        _hold(REFERRER, "carol");
        bytes32 carol = _node("carol");
        bytes32 alice = _node("alice");
        uint256 referrerBefore = REFERRER.balance;

        bytes memory payload = _stage(WALLET, "alice");
        vm.expectEmit(true, true, true, true, address(escrow));
        emit HandleEscrow.Forwarded(carol, NATIVE_TOKEN, address(splitter), REFERRER, SHARE, SHARE);
        vm.expectEmit(true, true, false, true, address(splitter));
        emit ReferralSplitter.Referred(
            carol, WALLET, bytes32(0), X, X, alice, FEE, SHARE, ReferralSplitter.Outcome.Paid
        );
        vm.prank(WALLET);
        registry.bindWithFeeCall{value: QUOTE + FEE}(X, 1, payload, "", false, FEE, address(splitter), _referral(carol));

        assertEq(REFERRER.balance - referrerBefore, SHARE);
        assertEq(treasury.balance, FEE - SHARE);
        assertEq(address(splitter).balance, 0);
    }

    function test_aReferralNamesTheBindsDigest() public {
        _hold(REFERRER, "carol");
        vm.recordLogs();
        _referredBind("alice", FEE, _referral(_node("carol")));
        Vm.Log[] memory logs = vm.getRecordedLogs();
        bytes32 digest = verifier.lastDigest();
        for (uint256 i = 0; i < logs.length; ++i) {
            if (logs[i].topics[0] == ReferralSplitter.Referred.selector) assertEq(logs[i].topics[3], digest);
        }
    }

    function test_aReferralToAnUnheldHandleIsHeldForIt() public {
        bytes32 dave = _node("dave");
        bytes memory payload = _stage(WALLET, "alice");
        vm.expectEmit(true, true, true, false, address(escrow));
        emit HandleEscrow.Deposited(dave, NATIVE_TOKEN, address(splitter), 0, SHARE, 0);
        vm.prank(WALLET);
        registry.bindWithFeeCall{value: QUOTE + FEE}(X, 1, payload, "", false, FEE, address(splitter), _referral(dave));

        assertEq(escrow.escrowed(dave, NATIVE_TOKEN), SHARE);
        (uint256 booked,) = escrow.contribution(dave, NATIVE_TOKEN, address(splitter));
        assertEq(booked, SHARE);
        assertEq(treasury.balance, FEE - SHARE);

        _hold(REFERRER, "dave");
        address[] memory tokens = new address[](1);
        tokens[0] = NATIVE_TOKEN;
        uint256 before = REFERRER.balance;
        vm.prank(REFERRER);
        escrow.claim(dave, tokens, REFERRER);
        assertEq(REFERRER.balance - before, SHARE);
    }

    function test_noReferralPaysTheTreasuryTheWholeFee() public {
        vm.recordLogs();
        _referredBind("alice", FEE, "");
        assertEq(_referredCount(vm.getRecordedLogs()), 0);
        assertEq(treasury.balance, FEE);
    }

    function test_aFeeBelowTheMinimumIgnoresTheReferral() public {
        _hold(REFERRER, "carol");
        uint256 before = REFERRER.balance;
        vm.recordLogs();
        _referredBind("alice", MIN_FEE - 1, _referral(_node("carol")));
        assertEq(_referredCount(vm.getRecordedLogs()), 0);
        assertEq(treasury.balance, MIN_FEE - 1);
        assertEq(REFERRER.balance, before);
    }

    function test_aFeeAtTheMinimumCarriesTheReferral() public {
        _hold(REFERRER, "carol");
        vm.recordLogs();
        _referredBind("alice", MIN_FEE, _referral(_node("carol")));
        assertEq(uint8(_outcome(vm.getRecordedLogs())), uint8(ReferralSplitter.Outcome.Paid));
    }

    function test_aZeroShareSendsTheWholeFeeAndNoReferral() public {
        vm.prank(OWNER);
        splitter.setShare(0);
        _hold(REFERRER, "carol");
        vm.recordLogs();
        _referredBind("alice", FEE, _referral(_node("carol")));
        assertEq(_referredCount(vm.getRecordedLogs()), 0);
        assertEq(treasury.balance, FEE);
    }

    function test_theShareMayBeTheWholeFee() public {
        vm.prank(OWNER);
        splitter.setShare(10_000);
        _hold(REFERRER, "carol");
        uint256 before = REFERRER.balance;
        _referredBind("alice", FEE, _referral(_node("carol")));
        assertEq(REFERRER.balance - before, FEE);
        assertEq(treasury.balance, 0);
    }

    function test_theShareRoundsDownAndThePartsAddUpToTheFee() public {
        _hold(REFERRER, "carol");
        uint256 fee = 0.01 ether + 9_999;
        uint256 before = REFERRER.balance;
        _referredBind("alice", fee, _referral(_node("carol")));
        uint256 share = REFERRER.balance - before;
        assertEq(share, fee * SHARE_BPS / 10_000);
        assertEq(share + treasury.balance, fee);
    }

    // ─── Self-referral ──────────────────────────────────────────────

    function test_aBinderReferringItsOwnHandlePaysTheTreasury() public {
        _hold(WALLET, "carol");
        uint256 before = WALLET.balance;
        vm.recordLogs();
        _referredBind("alice", FEE, _referral(_node("carol")));
        assertEq(uint8(_outcome(vm.getRecordedLogs())), uint8(ReferralSplitter.Outcome.SelfReferral));
        assertEq(treasury.balance, FEE);
        assertEq(before - WALLET.balance, QUOTE + FEE);
    }

    /// @dev The callback follows the write, so referring the handle being bound is a self-referral.
    function test_referringTheHandleBeingBoundIsASelfReferral() public {
        vm.recordLogs();
        _referredBind("dave", FEE, _referral(_node("dave")));
        assertEq(uint8(_outcome(vm.getRecordedLogs())), uint8(ReferralSplitter.Outcome.SelfReferral));
        assertEq(treasury.balance, FEE);
        assertEq(escrow.escrowed(_node("dave"), NATIVE_TOKEN), 0);
    }

    // ─── Refused shares ─────────────────────────────────────────────

    function _expectRefused(bytes memory feeData) private {
        vm.recordLogs();
        _referredBind("alice", FEE, feeData);
        assertEq(uint8(_outcome(vm.getRecordedLogs())), uint8(ReferralSplitter.Outcome.Refused));
        assertEq(treasury.balance, FEE, "the treasury took the whole fee");
        assertEq(address(splitter).balance, 0);
    }

    function test_aHolderThatRefusesValueLosesItsShareToTheTreasury() public {
        address holder = address(new RefusingHolder());
        _hold(holder, "carol");
        _expectRefused(_referral(_node("carol")));
    }

    function test_aHolderThatBurnsGasLosesOnlyItsShare() public {
        address holder = address(new BurningHolder());
        _hold(holder, "carol");
        _expectRefused(_referral(_node("carol")));
    }

    function test_aPlatformNobodyCanBindRefusesTheShare() public {
        _expectRefused(abi.encode(GITHUB, TestNodes.handleNode(GITHUB, "dave")));
    }

    function test_anUnknownPlatformRefusesTheShare() public {
        _expectRefused(abi.encode(bytes32("no such platform"), _node("dave")));
    }

    // ─── Amounts ────────────────────────────────────────────────────

    /// @dev Value the splitter holds by force is never paid out.
    function test_theTreasuryIsPaidFromTheFeeNotTheBalance() public {
        vm.deal(address(splitter), 1 ether);
        _hold(REFERRER, "carol");
        _referredBind("alice", FEE, _referral(_node("carol")));
        assertEq(treasury.balance, FEE - SHARE);
        assertEq(address(splitter).balance, 1 ether);
    }

    function test_theTreasuryIsPaidAfterTheShare() public {
        RecordingTreasury recorder = new RecordingTreasury(escrow, _node("dave"));
        vm.prank(OWNER);
        splitter.setTreasury(address(recorder));
        _referredBind("alice", FEE, _referral(_node("dave")));
        assertEq(recorder.escrowedWhenPaid(), SHARE);
        assertEq(address(recorder).balance, FEE - SHARE);
    }

    function test_aTreasuryThatRefusesRevertsTheBind() public {
        address refusing = address(new RefusingHolder());
        vm.prank(OWNER);
        splitter.setTreasury(refusing);
        bytes memory payload = _stage(WALLET, "alice");
        vm.prank(WALLET);
        vm.expectRevert(abi.encodeWithSelector(ReferralSplitter.TreasuryRefused.selector, refusing, FEE));
        registry.bindWithFeeCall{value: QUOTE + FEE}(X, 1, payload, "", false, FEE, address(splitter), "");
        assertEq(registry.resolveHandle(X, "alice"), address(0));
    }

    // ─── Who may pay in ─────────────────────────────────────────────

    function test_onlyTheRegistryCallsTheSplitter() public {
        vm.deal(address(this), FEE);
        bytes32 alice = _node("alice");
        bytes memory feeData = _referral(_node("carol"));
        vm.expectRevert(abi.encodeWithSelector(ReferralSplitter.NotRegistry.selector, address(this)));
        splitter.onBindFee{value: FEE}(WALLET, X, alice, bytes32(0), feeData);
    }

    function test_takesNoPlainTransfer() public {
        vm.deal(address(this), 1);
        (bool ok,) = address(splitter).call{value: 1}("");
        assertFalse(ok);
    }

    function test_refusesFeeDataOfAnyOtherShape() public {
        uint256[4] memory lengths = [uint256(32), 63, 65, 96];
        for (uint256 i = 0; i < lengths.length; ++i) {
            bytes memory payload = _stage(WALLET, "alice");
            vm.prank(WALLET);
            vm.expectRevert(abi.encodeWithSelector(ReferralSplitter.BadFeeData.selector, lengths[i]));
            registry.bindWithFeeCall{value: QUOTE + FEE}(
                X, 1, payload, "", false, FEE, address(splitter), new bytes(lengths[i])
            );
        }
        assertEq(registry.resolveHandle(X, "alice"), address(0));
    }

    // ─── Reentrancy ─────────────────────────────────────────────────

    /// A share already held for `dave` and past its expiry, the target of a holder's re-entry.
    function _expiredHeldShare() private returns (bytes32 dave) {
        dave = _node("dave");
        vm.prank(OWNER);
        splitter.setExpiry(30 days);
        _referredBind("bob", FEE, _referral(dave));
        vm.warp(vm.getBlockTimestamp() + 30 days);
        vm.deal(treasury, 0);
    }

    /// @dev The escrow is mid-deposit, so `expire` and every escrow entry refuse;
    ///      the holder swallows the refusals and takes the share.
    function test_aHolderReenteringExpireAndTheEscrowLeavesTheTreasuryWhole() public {
        bytes32 dave = _expiredHeldShare();
        ReenteringHolder holder = new ReenteringHolder(splitter, escrow, dave, false);
        _hold(address(holder), "carol");

        _referredBind("alice", FEE, _referral(_node("carol")));

        bytes memory guarded = abi.encodeWithSelector(ReentrancyGuard.ReentrancyGuardReentrantCall.selector);
        assertEq(holder.expireRefusal(), guarded);
        assertEq(holder.refundRefusal(), guarded);
        assertEq(holder.depositRefusal(), guarded);
        assertEq(address(holder).balance, SHARE);
        assertEq(treasury.balance, FEE - SHARE);
        assertEq(address(splitter).balance, 0);
        (uint256 held,) = escrow.contribution(dave, NATIVE_TOKEN, address(splitter));
        assertEq(held, SHARE, "the held share stayed");
    }

    /// @dev The same holder passing a refusal on: the deposit fails and the treasury takes the fee.
    function test_aHolderFailingOnReentryLosesItsShareToTheTreasury() public {
        bytes32 dave = _expiredHeldShare();
        ReenteringHolder holder = new ReenteringHolder(splitter, escrow, dave, true);
        _hold(address(holder), "carol");

        _expectRefused(_referral(_node("carol")));
        (uint256 held,) = escrow.contribution(dave, NATIVE_TOKEN, address(splitter));
        assertEq(held, SHARE);
    }

    // ─── Gas ────────────────────────────────────────────────────────

    /// Each gas limit in 1k steps around the bind's cost: the bind either reverts
    /// or ends in `expected`.
    function _sweep(bytes32 referrerNode, ReferralSplitter.Outcome expected) private {
        bytes memory payload = _stage(WALLET, "alice");
        bytes memory call = abi.encodeCall(
            IdentityRegistry.bindWithFeeCall,
            (X, 1, payload, "", false, FEE, address(splitter), _referral(referrerNode))
        );
        uint256 snap = vm.snapshotState();
        uint256 start = gasleft();
        vm.prank(WALLET);
        (bool ok,) = address(registry).call{value: QUOTE + FEE}(call);
        uint256 used = start - gasleft();
        assertTrue(ok, "the bind succeeds with ample gas");
        vm.revertToState(snap);

        uint256 successes;
        for (uint256 limit = used - 60_000; limit <= used + 120_000; limit += 1_000) {
            snap = vm.snapshotState();
            vm.recordLogs();
            vm.prank(WALLET);
            (ok,) = address(registry).call{value: QUOTE + FEE, gas: limit}(call);
            if (ok) {
                assertEq(uint8(_outcome(vm.getRecordedLogs())), uint8(expected), "a gas limit changed the outcome");
                ++successes;
            }
            vm.revertToState(snap);
        }
        assertGt(successes, 0);
    }

    function test_everyGasLimitRevertsOrBooksTheShare() public {
        _sweep(_node("dave"), ReferralSplitter.Outcome.Paid);
    }

    function test_everyGasLimitRevertsOrForwardsTheShare() public {
        address wallet = Clones.clone(address(new LoggingWallet()));
        _hold(wallet, "carol");
        _sweep(_node("carol"), ReferralSplitter.Outcome.Paid);
    }

    // ─── Expiry ─────────────────────────────────────────────────────

    function test_expiryIsOffByDefault() public {
        bytes32 dave = _node("dave");
        _referredBind("alice", FEE, _referral(dave));
        vm.warp(vm.getBlockTimestamp() + 3650 days);
        vm.expectRevert(ReferralSplitter.ExpiryOff.selector);
        splitter.expire(dave);
    }

    function test_anyoneReturnsAHeldShareToTheTreasuryOnceItExpired() public {
        bytes32 dave = _node("dave");
        vm.prank(OWNER);
        splitter.setExpiry(60 days);
        _referredBind("alice", FEE, _referral(dave));
        uint256 expiresAt = vm.getBlockTimestamp() + 60 days;
        vm.deal(treasury, 0);

        vm.warp(expiresAt - 1);
        vm.expectRevert(abi.encodeWithSelector(ReferralSplitter.NotExpired.selector, dave, expiresAt));
        splitter.expire(dave);

        vm.warp(expiresAt);
        vm.expectEmit(true, false, false, true, address(splitter));
        emit ReferralSplitter.Expired(dave, SHARE);
        vm.prank(makeAddr("anyone"));
        splitter.expire(dave);
        assertEq(treasury.balance, SHARE);
        assertEq(escrow.escrowed(dave, NATIVE_TOKEN), 0);

        vm.expectRevert(abi.encodeWithSelector(ReferralSplitter.NothingToExpire.selector, dave));
        splitter.expire(dave);
    }

    function test_expiryCountsFromTheLastReferral() public {
        bytes32 dave = _node("dave");
        vm.prank(OWNER);
        splitter.setExpiry(60 days);
        _referredBind("alice", FEE, _referral(dave));
        uint256 first = vm.getBlockTimestamp();
        vm.warp(first + 10 days);
        _referredBind("bob", FEE, _referral(dave));

        vm.warp(first + 60 days);
        vm.expectRevert(abi.encodeWithSelector(ReferralSplitter.NotExpired.selector, dave, first + 70 days));
        splitter.expire(dave);
        vm.warp(first + 70 days);
        splitter.expire(dave);
        assertEq(escrow.escrowed(dave, NATIVE_TOKEN), 0);
    }

    function test_expiryIsZeroOrAtLeastTheRefundGrace() public {
        vm.startPrank(OWNER);
        vm.expectRevert(abi.encodeWithSelector(ReferralSplitter.ExpiryTooShort.selector, uint64(30 days - 1)));
        splitter.setExpiry(30 days - 1);
        vm.expectEmit(false, false, false, true, address(splitter));
        emit ReferralSplitter.ExpirySet(30 days);
        splitter.setExpiry(30 days);
        splitter.setExpiry(0);
        vm.stopPrank();
        assertEq(splitter.expiry(), 0);
    }

    // ─── Settings ───────────────────────────────────────────────────

    function test_onlyTheOwnerChangesTheSettings() public {
        bytes memory notOwner = abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, address(this));
        vm.expectRevert(notOwner);
        splitter.setShare(1);
        vm.expectRevert(notOwner);
        splitter.setTreasury(address(1));
        vm.expectRevert(notOwner);
        splitter.setExpiry(0);
        vm.expectRevert(notOwner);
        splitter.setMinReferralFee(0);
    }

    function test_theSettingsAreBoundedAndLogged() public {
        vm.startPrank(OWNER);
        vm.expectRevert(abi.encodeWithSelector(ReferralSplitter.ShareAboveWhole.selector, uint16(10_001)));
        splitter.setShare(10_001);
        vm.expectRevert(abi.encodeWithSelector(ReferralSplitter.BadTreasury.selector, address(0)));
        splitter.setTreasury(address(0));
        vm.expectRevert(abi.encodeWithSelector(ReferralSplitter.BadTreasury.selector, address(splitter)));
        splitter.setTreasury(address(splitter));

        vm.expectEmit(false, false, false, true, address(splitter));
        emit ReferralSplitter.ShareSet(2_500);
        splitter.setShare(2_500);
        vm.expectEmit(false, false, false, true, address(splitter));
        emit ReferralSplitter.TreasurySet(address(1));
        splitter.setTreasury(address(1));
        vm.expectEmit(false, false, false, true, address(splitter));
        emit ReferralSplitter.MinReferralFeeSet(7);
        splitter.setMinReferralFee(7);
        vm.stopPrank();

        assertEq(splitter.shareBps(), 2_500);
        assertEq(splitter.treasury(), address(1));
        assertEq(splitter.minReferralFee(), 7);
    }

    function test_ownershipMovesInTwoStepsAndStays() public {
        address next = makeAddr("next owner");
        vm.prank(OWNER);
        splitter.transferOwnership(next);
        assertEq(splitter.owner(), OWNER);
        vm.prank(next);
        splitter.acceptOwnership();
        assertEq(splitter.owner(), next);

        vm.prank(next);
        vm.expectRevert(ReferralSplitter.RenounceDisabled.selector);
        splitter.renounceOwnership();
    }

    function test_theConstructorChecksItsContracts() public {
        vm.expectRevert(ReferralSplitter.ZeroAddress.selector);
        new ReferralSplitter(IIdentityRegistry(address(0)), escrow, OWNER, treasury, SHARE_BPS, MIN_FEE);
        vm.expectRevert(ReferralSplitter.ZeroAddress.selector);
        new ReferralSplitter(registry, HandleEscrow(address(0)), OWNER, treasury, SHARE_BPS, MIN_FEE);

        IdentityRegistry other = IdentityRegistry(
            address(
                new ERC1967Proxy(address(new IdentityRegistry()), abi.encodeCall(IdentityRegistry.initialize, (OWNER)))
            )
        );
        vm.expectRevert(abi.encodeWithSelector(ReferralSplitter.EscrowOfAnotherRegistry.selector, address(registry)));
        new ReferralSplitter(other, escrow, OWNER, treasury, SHARE_BPS, MIN_FEE);

        vm.expectRevert(abi.encodeWithSelector(ReferralSplitter.ShareAboveWhole.selector, uint16(10_001)));
        new ReferralSplitter(registry, escrow, OWNER, treasury, 10_001, MIN_FEE);
    }

    function test_theConstructorSetsTheSettings() public view {
        assertEq(address(splitter.REGISTRY()), address(registry));
        assertEq(address(splitter.ESCROW()), address(escrow));
        assertEq(splitter.owner(), OWNER);
        assertEq(splitter.treasury(), treasury);
        assertEq(splitter.shareBps(), SHARE_BPS);
        assertEq(splitter.minReferralFee(), MIN_FEE);
        assertEq(splitter.expiry(), 0);
    }
}

/// @notice Holds a handle and refuses any value.
contract RefusingHolder {}

/// @notice Holds a handle and spends all the gas any payment brings.
contract BurningHolder {
    receive() external payable {
        while (true) {}
    }
}

/// @notice A smart account's implementation, behind a clone: logs what it receives.
contract LoggingWallet {
    event Received(address indexed from, uint256 amount);

    receive() external payable {
        emit Received(msg.sender, msg.value);
    }
}

/// @notice A treasury that records what the escrow held for a node when it was paid.
contract RecordingTreasury {
    HandleEscrow immutable ESCROW;
    bytes32 immutable NODE;
    uint256 public escrowedWhenPaid;

    constructor(HandleEscrow escrow, bytes32 node) {
        ESCROW = escrow;
        NODE = node;
    }

    receive() external payable {
        escrowedWhenPaid = ESCROW.escrowed(NODE, NATIVE_TOKEN);
    }
}

/// @notice Holds a handle; while its share is forwarded, calls `expire` on a held
///         share, then the escrow's `refund` and `deposit`, keeping each refusal.
///         `failing` passes the first refusal on, failing the forward.
contract ReenteringHolder {
    ReferralSplitter immutable SPLITTER;
    HandleEscrow immutable ESCROW;
    bytes32 immutable HELD;
    bool immutable FAILING;
    bytes public expireRefusal;
    bytes public refundRefusal;
    bytes public depositRefusal;

    constructor(ReferralSplitter splitter, HandleEscrow escrow, bytes32 held, bool failing) {
        SPLITTER = splitter;
        ESCROW = escrow;
        HELD = held;
        FAILING = failing;
    }

    receive() external payable {
        (bool ok, bytes memory ret) = address(SPLITTER).call(abi.encodeCall(ReferralSplitter.expire, (HELD)));
        if (!ok && FAILING) {
            assembly {
                revert(add(ret, 32), mload(ret))
            }
        }
        expireRefusal = ok ? bytes("") : ret;
        (ok, ret) = address(ESCROW).call(abi.encodeCall(HandleEscrow.refund, (HELD, NATIVE_TOKEN, address(this))));
        refundRefusal = ok ? bytes("") : ret;
        (ok, ret) = address(ESCROW).call{value: msg.value}(
            abi.encodeCall(HandleEscrow.deposit, (bytes32(0), HELD, NATIVE_TOKEN, msg.value))
        );
        depositRefusal = ok ? bytes("") : ret;
    }
}
