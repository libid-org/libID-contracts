// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {Account as OzAccount} from "@openzeppelin/contracts/account/Account.sol";
import {IEntryPoint, PackedUserOperation} from "@openzeppelin/contracts/interfaces/IERC4337.sol";
import {Execution} from "@openzeppelin/contracts/interfaces/draft-IERC7579.sol";

import {IPlatformVerifier} from "../../ceremony/IPlatformVerifier.sol";
import {IProofVerifier} from "../../ceremony/IProofVerifier.sol";
import {operationList} from "../../ceremony/test/OperationListVector.sol";
import {NATIVE_TOKEN} from "../../common/Constants.sol";
import {HandleEscrow} from "../../escrow/HandleEscrow.sol";
import {TestERC20} from "../../escrow/test/EscrowMocks.sol";
import {IdentityRegistry} from "../../identity/IdentityRegistry.sol";
import {StubPlatformVerifier} from "../../identity/test/StubPlatformVerifier.sol";
import {AUTHORIZED_MODE, IIdentityAdmin, INonceIncrement, IWalletCore, IWebWallet} from "../IWebWallet.sol";
import {CallTarget, IUserOpHash} from "./WalletBase.sol";
import {OtherClientVerifier, WalletSuite} from "./WalletSuite.sol";

/// Reverts until opened.
contract Gate {
    bool public open;

    function openUp() external {
        open = true;
    }

    function pass() external view {
        require(open, "closed");
    }
}

/// Records the gas it got, then spends half of it in a call whose failure it swallows.
contract GasProbe {
    uint256 public got;

    function run() external payable {
        uint256 g = gasleft();
        got = g;
        try this.burn{gas: g / 2}() {} catch {}
    }

    function burn() external pure {
        assembly {
            invalid()
        }
    }
}

/// Called from a batch, submits another signed batch to the wallet; a failure bubbles.
contract Reenter {
    function go(address w, bytes calldata data) external {
        IWebWallet(w).execute(AUTHORIZED_MODE, data);
    }
}

/// Records an account's EntryPoint nonce when called.
contract NonceProbe {
    uint256 public seen;

    function look(address ep, address account) external {
        seen = IEntryPoint(ep).getNonce(account, 0);
    }
}

/// @notice `execute(AUTHORIZED_MODE, data)` from anyone, checked at the end, and the default mode only the
///         EntryPoint sends: 0e2721f's DirectExecute, DirectExecuteEdges and NoncanonicalBatch suites.
contract WalletExecuteTest is WalletSuite {
    uint256 internal constant OTHER_PK = 0x07E4;

    /// Alice's wallet at threshold 2: her X admin and Bob's GitHub admin.
    function _twoOfTwo() internal returns (address w) {
        w = _claim();
        _link(w, GITHUB, BOB, _key(BOB_PK), _admin());
        _threshold(w, 2);
        assertEq(IWebWallet(w).threshold(), 2, "threshold");
    }

    function _self(address w, bytes memory data) internal view returns (bytes memory) {
        return _then(_x(w, 0, data));
    }

    function _hits(uint256 n) internal view returns (Execution[] memory x) {
        x = new Execution[](n);
        for (uint256 i; i < n; ++i) {
            x[i] = _hitX();
        }
    }

    // ─── Acceptance ─────────────────────────────────────────────────

    /// A stranger submits; the nonce is the EntryPoint's under key 0, and the batch sees it spent.
    function test_aStrangerSubmitsAnAdminSignedBatch() public {
        address w = _claim();
        uint256 n = _nonce(w);
        assertEq(n >> 64, 0, "the nonce key");
        NonceProbe probe = new NonceProbe();
        bytes memory calls = _then(_x(address(probe), 0, abi.encodeCall(NonceProbe.look, (EP, w))));
        vm.prank(mallory);
        IWebWallet(w).execute(AUTHORIZED_MODE, _data(calls, _aliceFor(w, calls, n)));
        assertEq(_nonce(w), n + 1, "the nonce was not consumed");
        assertEq(probe.seen(), n + 1, "the batch saw its nonce unspent");
    }

    // ─── No writer helps its own batch's check ──────────────────────

    function test_aSessionAddedInTheBatchCannotSignIt() public {
        address w = _twoOfTwo();
        bytes32 bob = _identity(GITHUB, BOB);
        bytes memory add = abi.encodeCall(IIdentityAdmin.addSession, (bob, _key(NEW_PK), _admin()));
        _refusesBy(w, _self(w, add), _pks(ALICE_PK, NEW_PK), NOT_SIGNED);

        _addSession(w, bob, _key(NEW_PK), _admin());
        assertEq(IWebWallet(w).sessionOf(_key(NEW_PK)).activeAt, _now(), "activeAt is not the block time");
        _refusesBy(w, _one(_hitX()), _pks(ALICE_PK, NEW_PK), NOT_SIGNED);
        vm.warp(_now() + 1);
        _runsBy(w, _one(_hitX()), _pks(ALICE_PK, NEW_PK));
    }

    function test_anIdentityLinkedInTheBatchCannotSignIt() public {
        address w = _twoOfTwo();
        bytes32 carol = _identity(GOOGLE, CAROL);
        IIdentityAdmin.Policy memory none;
        bytes memory payload = _linkPayload(w, GOOGLE, CAROL, "", none);
        Execution[] memory x = new Execution[](3);
        x[0] = _x(w, 0, abi.encodeCall(IIdentityAdmin.linkIdentity, (GOOGLE, V1, payload, "", none)));
        x[1] = _x(w, 0, abi.encodeCall(IIdentityAdmin.addSession, (carol, _key(CAROL_PK), _admin())));
        x[2] = _hitX();
        _refusesBy(w, abi.encode(x), _pks(ALICE_PK, CAROL_PK), NOT_SIGNED);
        assertFalse(IWebWallet(w).isLinked(carol), "the link stayed");

        _link(w, GOOGLE, CAROL, _key(CAROL_PK), _admin());
        assertEq(IWebWallet(w).sessionOf(_key(CAROL_PK)).activeAt, _now(), "activeAt is not the block time");
        vm.warp(_now() + 1);
        _runsBy(w, _one(_hitX()), _pks(ALICE_PK, CAROL_PK));
    }

    /// A7: a batch cannot queue or execute a root operation that lowers its own check: `executeRoot` takes the
    /// lock the batch holds.
    function test_executingSetThresholdInTheBatchIsRefused() public {
        address w = _twoOfTwo();
        bytes memory one = abi.encodeCall(IIdentityAdmin.setThreshold, (1));
        bytes32 id = _queueW(w, one);
        // A root operation never matures in the second it was queued.
        vm.expectRevert(abi.encodeWithSelector(IWebWallet.RootOperationNotReady.selector, id));
        IWebWallet(w).executeRoot(id);
        vm.warp(_now() + 48 hours);
        bytes memory exec = abi.encodeCall(IIdentityAdmin.executeRoot, (id));
        _refusesBy(w, _self(w, exec), _pks(ALICE_PK), IWebWallet.Locked.selector);
        Execution[] memory x = new Execution[](3);
        x[0] = _x(w, 0, abi.encodeCall(IIdentityAdmin.queueRoot, (one)));
        x[1] = _x(w, 0, exec);
        x[2] = _hitX();
        _refusesBy(w, abi.encode(x), _pks(ALICE_PK, BOB_PK), IWebWallet.Locked.selector);
        assertEq(IWebWallet(w).threshold(), 2, "the threshold changed");

        IWebWallet(w).executeRoot(id);
        _runsBy(w, _one(_hitX()), _pks(ALICE_PK));
    }

    /// Below quorum, revoking the other admin platform is refused; at quorum, a batch revokes a session that does
    /// not sign it.
    function test_revokingAnAdminInTheBatchDoesNotHelpIt() public {
        address w = _twoOfTwo();
        bytes memory revokeBob = abi.encodeCall(IIdentityAdmin.revokeSession, (_key(BOB_PK)));
        _refusesBy(w, _self(w, revokeBob), _pks(ALICE_PK), IWebWallet.ThresholdTooHigh.selector);
        assertEq(IWebWallet(w).sessionOf(_key(BOB_PK)).identity, _identity(GITHUB, BOB), "Bob's session revoked");

        _addSession(w, _identity(X, ALICE), _key(NEW_PK), _admin());
        _runsBy(w, _self(w, abi.encodeCall(IIdentityAdmin.revokeSession, (_key(NEW_PK)))), _pks(ALICE_PK, BOB_PK));
        assertEq(IWebWallet(w).sessionOf(_key(NEW_PK)).identity, bytes32(0), "the session was not revoked");
    }

    // ─── The genesis bootstrap ──────────────────────────────────────

    /// The first session comes from any OAuth client's proof, and signs at once.
    function test_aFirstSessionFromAnyClientSignsAtOnce() public {
        OtherClientVerifier other = new OtherClientVerifier(xStub);
        vm.prank(owner);
        proofVerifier.setVerifier(X, V1, other);
        address w = _claim();
        assertEq(other.lastClient(), "another-app", "not the other client's proof");
        assertEq(IWebWallet(w).sessionOf(_key(ALICE_PK)).activeAt, 0, "the first session is pending");
        _runsBy(w, _one(_hitX()), _pks(ALICE_PK));
    }

    /// Without an admin policy, the genesis bootstrap adds no session.
    function test_theBootstrapNeedsAnAdmin() public {
        vm.prank(relayer);
        address w = factory.createWallet(X, ALICE, 0);
        bytes memory app = _one(_linkX(w, X, ALICE, _key(APP_PK), _hitOnly()));
        _refuses(w, app, _direct(w, _pks(APP_PK), app, true), IWebWallet.LinkSessionRefused.selector);
        assertFalse(IWebWallet(w).hadSession(), "a session was added");
    }

    // ─── The nonce ──────────────────────────────────────────────────

    function test_theNonceIsSharedWithUserOperations() public {
        address w = _claim();
        bytes memory hit = _one(_hitX());
        uint256 n = _nonce(w);
        _runsBy(w, hit, _pks(ALICE_PK));
        _refused(_signed(_opN(w, n, _hitCall()), _pks(ALICE_PK)), "a UserOperation reused the batch nonce");
        _handle(_signed(_op(w, _hitCall()), _pks(ALICE_PK)));
        assertEq(target.calls(), 2, "the next UserOperation did not run");
        _refuses(w, hit, _aliceFor(w, hit, n + 1), NOT_SIGNED);
        _runsBy(w, hit, _pks(ALICE_PK));
    }

    /// With no EntryPoint code, the batch names the missing dependency.
    function test_aMissingEntryPointIsNamed() public {
        address w = _claim();
        bytes memory hit = _one(_hitX());
        bytes memory auth = _direct(w, _pks(ALICE_PK), hit, false);
        bytes memory code = EP.code;
        vm.etch(EP, "");
        vm.prank(relayer);
        vm.expectRevert(abi.encodeWithSelector(IWebWallet.EntryPointMissing.selector, EP));
        IWebWallet(w).execute(AUTHORIZED_MODE, _data(hit, auth));
        vm.etch(EP, code);
        _runs(w, hit, auth);
    }

    /// Signed for the nonce after next, the batch cannot spend the next one itself.
    function test_aBatchCallingIncrementNonceDoesNotHelp() public {
        address w = _claim();
        uint256 n = _nonce(w);
        bytes memory calls = _then(_x(EP, 0, abi.encodeCall(INonceIncrement.incrementNonce, (0))));
        _refuses(w, calls, _aliceFor(w, calls, n + 1), NOT_SIGNED);
        _runs(w, calls, _aliceFor(w, calls, n));
        assertEq(_nonce(w), n + 2, "nonce");
    }

    /// A reverted call reverts the batch with its data, or `FailedCall` with none, and leaves the nonce.
    function test_aRevertedBatchLeavesItsNonce() public {
        address w = _claim();
        Gate gate = new Gate();
        bytes memory calls = _then(_x(address(gate), 0, abi.encodeCall(Gate.pass, ())));
        bytes memory auth = _direct(w, _pks(ALICE_PK), calls, false);
        _refuses(w, calls, auth, bytes4(keccak256("Error(string)")));
        bytes memory silent = _then(_x(address(this), 0, abi.encodeCall(this.revertsEmpty, ())));
        _refuses(w, silent, _direct(w, _pks(ALICE_PK), silent, false), bytes4(keccak256("FailedCall()")));
        gate.openUp();
        _runs(w, calls, auth);
    }

    function revertsEmpty() external pure {
        revert();
    }

    /// The submitter cannot run the signed batch with less than the signed `callGas`.
    function test_tooLittleGasRevertsBeforeAnyCall() public {
        address w = _claim();
        uint48 at = uint48(_now());
        uint48 deadline = at + 1 hours;
        bytes memory calls = _one(_hitX());
        uint256 n = _nonce(w);
        bytes32 h = _execDigestGas(w, AUTHORIZED_MODE, calls, at, n, deadline, 5_000_000);
        bytes memory data =
            _data(calls, abi.encode(_authOf(_pks(ALICE_PK), h, at, false, _hitProofs(0)), deadline, 5_000_000));
        vm.prank(relayer);
        vm.expectPartialRevert(IWebWallet.InsufficientCallGas.selector);
        IWebWallet(w).execute{gas: 1_000_000}(AUTHORIZED_MODE, data);
        assertEq(target.calls(), 0, "a call ran");
        assertEq(_nonce(w), n, "nonce");
        vm.prank(relayer);
        IWebWallet(w).execute{gas: 6_000_000}(AUTHORIZED_MODE, data);
        assertEq(target.calls(), 1, "control");
    }

    function _probeX(GasProbe probe, uint256 size) internal pure returns (Execution memory) {
        return _x(address(probe), 1, bytes.concat(abi.encodeCall(GasProbe.run, ()), new bytes(size)));
    }

    /// Runs `calls`, signed for `callGas`, with each gas from `from` below `to`; every probe of a run that passed
    /// got at least `callGas`. Returns the runs that passed.
    function _sweep(address w, bytes memory calls, GasProbe[] memory probes, uint256 callGas, uint256 from, uint256 to)
        internal
        returns (uint256 runs)
    {
        uint48 at = uint48(_now());
        uint48 deadline = at + 1 hours;
        bytes32 h = _execDigestGas(w, AUTHORIZED_MODE, calls, at, _nonce(w), deadline, callGas);
        bytes memory data =
            _data(calls, abi.encode(_authOf(_pks(ALICE_PK), h, at, false, _hitProofs(0)), deadline, callGas));
        bytes memory exec = abi.encodeCall(IWalletCore.execute, (AUTHORIZED_MODE, data));
        for (uint256 g = from; g < to; g += 2_000) {
            uint256 snap = vm.snapshotState();
            for (uint256 i; i < probes.length; ++i) {
                vm.cool(address(probes[i]));
            }
            vm.prank(relayer);
            (bool ok,) = w.call{gas: g}(exec);
            if (ok) {
                ++runs;
                for (uint256 i; i < probes.length; ++i) {
                    // The probe's dispatch runs before it reads `gasleft()`.
                    assertGe(probes[i].got() + 1_000, callGas, "a call got less than callGas");
                }
            }
            vm.revertToState(snap);
        }
    }

    /// Any gas that passes the checks gives every call, cold, with value and 64 KiB of call data, at least `callGas`.
    function test_everyCallGetsTheSignedCallGas() public {
        address w = _claim();
        GasProbe[] memory probes = new GasProbe[](2);
        (probes[0], probes[1]) = (new GasProbe(), new GasProbe());
        bytes memory one = _one(_probeX(probes[0], 64 << 10));
        bytes memory two = _two(_probeX(probes[0], 64 << 10), _probeX(probes[1], 64 << 10));
        GasProbe[] memory first = new GasProbe[](1);
        first[0] = probes[0];
        uint256 callGas = 10_000_000;
        // The proxy keeps 1/64 too: the check passes from about `callGas * (64/63)^2`.
        assertGt(_sweep(w, one, first, callGas, callGas, callGas * 33 / 32 + 300_000), 0, "control: one call");
        callGas = 1_000_000;
        assertGt(_sweep(w, two, probes, callGas, 2 * callGas, 2 * callGas * 33 / 32 + 600_000), 0, "control: two");
    }

    /// Copying 256 KiB of call data costs more than `CALL_OVERHEAD`; the call still gets `callGas`.
    function test_largeCallDataLeavesTheCallItsGas() public {
        address w = _claim();
        GasProbe[] memory probes = new GasProbe[](1);
        probes[0] = new GasProbe();
        uint256 callGas = 1_000_000;
        bytes memory one = _one(_probeX(probes[0], 256 << 10));
        assertGt(_sweep(w, one, probes, callGas, callGas, callGas + 2_500_000), 0, "control");
    }

    // ─── Reentry ────────────────────────────────────────────────────

    /// The inner batch is signed for the nonce the outer one leaves: only the lock refuses it, inside a batch, the
    /// wallet's own default mode or a UserOperation.
    function test_theLockRefusesReentry() public {
        address w = _claim();
        Reenter re = new Reenter();
        uint256 n = _nonce(w);
        bytes memory inner = _one(_hitX());
        bytes memory innerAuth = _aliceFor(w, inner, n + 1);
        bytes memory outer = _then(_x(address(re), 0, abi.encodeCall(Reenter.go, (w, _data(inner, innerAuth)))));
        _refuses(w, outer, _aliceFor(w, outer, n), IWebWallet.Locked.selector, "a batch in a batch");
        bytes memory self = _self(w, abi.encodeCall(IWalletCore.execute, (MODE_BATCH, inner)));
        _refuses(w, self, _aliceFor(w, self, n), IWebWallet.Locked.selector, "default mode in a batch");

        _handle(_signed(_op(w, abi.encodeCall(IWalletCore.execute, (MODE_BATCH, outer))), _pks(ALICE_PK)));
        assertEq(target.calls(), 0, "the reentered batch ran");
        assertEq(_nonce(w), n + 1, "the UserOperation's nonce");
        _runs(w, inner, innerAuth);
    }

    // ─── Periods below quorum ───────────────────────────────────────

    /// Value is charged to NATIVE, gas is not, and only the period holding the block time is accepted.
    function test_belowQuorumTheSignedPeriodMustBeNow() public {
        address w = _claim();
        IIdentityAdmin.Policy memory p = _app();
        p.rules.scopeRoot = _leaf(address(target), CallTarget.hit.selector, 1 ether);
        p.rules.allowances = new IIdentityAdmin.Allowance[](1);
        p.rules.allowances[0] = IIdentityAdmin.Allowance({token: NATIVE_TOKEN, amount: 1 ether, period: 1 days});
        _addSession(w, _identity(X, ALICE), _key(APP_PK), p);
        vm.warp(_now() + 1);

        bytes memory calls = _one(_x(address(target), 0.1 ether, abi.encodeCall(CallTarget.hit, ())));
        IWalletCore.CallProof[] memory proofs = _hitProofs(1);
        proofs[0].maxValue = 1 ether;
        uint256 n = _nonce(w);
        uint48 t = uint48(_now());
        _refuses(w, calls, _directAt(w, _pks(APP_PK), calls, n, t + 1 days, true, proofs), OUTSIDE_WINDOW);
        _refuses(w, calls, _directAt(w, _pks(APP_PK), calls, n, t - 1 days, true, proofs), OUTSIDE_WINDOW);
        _runs(w, calls, _directAt(w, _pks(APP_PK), calls, n, t, true, proofs));
        assertEq(address(target).balance, 0.1 ether, "value");
        assertEq(IWebWallet(w).allowanceOf(_key(APP_PK), NATIVE_TOKEN).spent, 0.1 ether, "NATIVE charge");
    }

    // ─── Replay ─────────────────────────────────────────────────────

    /// A signature for one of a batch, a UserOperation and ERC-1271 serves neither other.
    function test_signaturesDoNotCrossPaths() public {
        address w = _claim();
        bytes memory calls = _one(_hitX());
        uint48 at = uint48(_now());
        uint48 deadline = at + 1 hours;
        bytes32 d = _execDigest(w, AUTHORIZED_MODE, calls, at, _nonce(w), deadline);
        bytes memory execute = abi.encodeCall(IWalletCore.execute, (MODE_BATCH, calls));
        PackedUserOperation memory op = _op(w, execute);

        bytes32 opSigned = _signable(w, IUserOpHash(EP).getUserOpHash(op));
        _refuses(w, calls, _alice(opSigned, at, deadline), NOT_SIGNED, "userOpHash");
        _refuses(w, calls, _alice(_wrapped(w, d), at, deadline), NOT_SIGNED, "ERC-1271 hash");
        op.signature = abi.encode(_authOf(_pks(ALICE_PK), d, at, false, _hitProofs(0)));
        _refused(op, "a batch signature as a UserOperation");
        op.signature = _alice(d, at, deadline);
        _refused(op, "a batch envelope as a UserOperation");
        assertFalse(_isValid1271(w, d, ALICE_PK, d), "a batch signature passed ERC-1271");

        assertTrue(_isValid1271(w, d, ALICE_PK, _wrapped(w, d)), "control: ERC-1271");
        _runs(w, calls, _alice(d, at, deadline));
        _handle(_signed(_op(w, execute), _pks(ALICE_PK)));
        assertEq(target.calls(), 2, "control: a UserOperation");
    }

    // ─── Modes, values and changed batches ──────────────────────────

    /// Only the exact `AUTHORIZED_MODE` word is a signed batch. Its variants, another selector and delegatecall are
    /// other modes: only the EntryPoint, or no one, sends them, and the wallet refuses them.
    function test_otherModesRevert() public {
        address w = _claim();
        bytes memory batch = _one(_hitX());
        bytes32[5] memory modes = [
            AUTHORIZED_MODE | bytes32(uint256(0x01) << 240),
            AUTHORIZED_MODE ^ bytes32(uint256(0x01) << 248),
            AUTHORIZED_MODE | bytes32(uint256(1)),
            MODE_BATCH | bytes32(uint256(0xdeadbeef) << 176),
            bytes32(uint256(0xff) << 248)
        ];
        for (uint256 i; i < modes.length; ++i) {
            bytes memory data = _data(batch, _aliceFor(w, batch, _nonce(w)));
            address[2] memory callers = [relayer, w];
            for (uint256 j; j < callers.length; ++j) {
                vm.prank(callers[j]);
                vm.expectRevert(abi.encodeWithSelector(OzAccount.AccountUnauthorized.selector, callers[j]));
                IWebWallet(w).execute(modes[i], data);
            }
            vm.prank(EP);
            vm.expectRevert(abi.encodeWithSelector(IWebWallet.UnsupportedMode.selector, modes[i]));
            IWebWallet(w).execute(modes[i], data);
        }
        // The default modes take neither a stranger nor the factory wallet itself, outside any batch.
        bytes memory single = abi.encodePacked(address(target), uint256(0), abi.encodeCall(CallTarget.hit, ()));
        bytes32[2] memory defaults = [MODE_BATCH, MODE_SINGLE];
        bytes[2] memory payloads = [batch, single];
        for (uint256 j; j < defaults.length; ++j) {
            for (uint256 k; k < 2; ++k) {
                address caller = k == 0 ? mallory : w;
                vm.prank(caller);
                vm.expectRevert(abi.encodeWithSelector(OzAccount.AccountUnauthorized.selector, caller));
                IWebWallet(w).execute(defaults[j], payloads[j]);
            }
        }
        // No executor module exists: `executeFromExecutor` has no route.
        (bool ok,) = w.call(abi.encodeWithSignature("executeFromExecutor(bytes32,bytes)", MODE_SINGLE, single));
        assertFalse(ok, "executeFromExecutor answered");
        assertEq(target.calls(), 0, "a refused mode ran");
    }

    /// Validation refuses a nonzero mode selector, `AUTHORIZED_MODE` included.
    function test_theEntryPointRefusesNonZeroSelectorsInValidation() public {
        address w = _claim();
        bytes memory hits = _one(_hitX());
        bytes32 unknown = MODE_BATCH | bytes32(uint256(0xdeadbeef) << 176);
        _refused(
            _signed(_op(w, abi.encodeCall(IWalletCore.execute, (unknown, hits))), _pks(ALICE_PK)),
            "an unknown selector through the EntryPoint"
        );
        bytes memory data = _data(hits, _aliceFor(w, hits, _nonce(w)));
        _refused(
            _signed(_op(w, abi.encodeCall(IWalletCore.execute, (AUTHORIZED_MODE, data))), _pks(ALICE_PK)),
            "AUTHORIZED_MODE through the EntryPoint"
        );
        _handle(_signed(_op(w, abi.encodeCall(IWalletCore.execute, (MODE_BATCH, hits))), _pks(ALICE_PK)));
        assertEq(target.calls(), 1, "the default selector");
    }

    /// The batch is sent with exactly the value it signs, and `data` carries that value.
    function test_theSignedValueIsSent() public {
        address w = _claim();
        bytes memory hit = _one(_hitX());
        bytes memory auth = _direct(w, _pks(ALICE_PK), hit, false);
        vm.deal(relayer, 1);
        vm.prank(relayer);
        vm.expectRevert(abi.encodeWithSelector(IWebWallet.WrongBatchValue.selector, 0, 1));
        IWebWallet(w).execute{value: 1}(AUTHORIZED_MODE, _data(hit, auth));
        signedValue = 1;
        _refuses(w, hit, auth, NOT_SIGNED);
        _runs(w, hit, _direct(w, _pks(ALICE_PK), hit, false));
    }

    /// Below quorum too: the delegatecall to SessionRules keeps the batch's value.
    function test_aBelowQuorumBatchTakesItsSignedValue() public {
        address w = _claim();
        _addSession(w, _identity(X, ALICE), _key(BOT_PK), _hitOnly());
        vm.warp(_now() + 1);
        bytes memory hit = _one(_hitX());
        signedValue = 1;
        uint256 balance = w.balance;
        _runs(w, hit, _direct(w, _pks(BOT_PK), hit, true));
        assertEq(w.balance, balance + 1, "the value did not arrive");
    }

    /// An expired batch fails before its calls run: a reverting call does not stand in for the expiry.
    function test_anExpiredBatchFailsBeforeItsCalls() public {
        address w = _claim();
        bytes memory calls = _one(_x(w, 0, abi.encodeCall(IIdentityAdmin.revokeSession, (_key(MALLORY_PK)))));
        uint48 at = uint48(_now());
        bytes32 h = _execDigest(w, AUTHORIZED_MODE, calls, at, _nonce(w), at - 1);
        _refuses(w, calls, _alice(h, at, at - 1), IWebWallet.ExecutionExpired.selector, "expired");
    }

    /// Signed for one batch, mode, deadline, gas and chain; submitted with one of them changed, or no deadline.
    function test_aChangedBatchIsRefused() public {
        address w = _claim();
        Execution[] memory x = _hits(2);
        x[1].value = 0.1 ether;
        bytes memory calls = abi.encode(x);
        uint256 n = _nonce(w);
        uint48 at = uint48(_now());
        uint48 deadline = at + 1 hours;
        IWalletCore.Authorization memory a =
            _authOf(_pks(ALICE_PK), _execDigest(w, AUTHORIZED_MODE, calls, at, n, deadline), at, false, _hitProofs(0));
        bytes memory auth = _env(a, deadline);
        Execution[][6] memory batches;
        for (uint256 i; i < 6; ++i) {
            batches[i] = abi.decode(calls, (Execution[]));
        }
        batches[0][0].target = address(new CallTarget());
        batches[1][1].value = 0.2 ether;
        batches[2][0].callData = abi.encodeWithSelector(CallTarget.hit.selector, uint256(1));
        (batches[3][0], batches[3][1]) = (x[1], x[0]);
        batches[4] = _hits(3);
        batches[4][1].value = 0.1 ether;
        batches[5] = _hits(1);
        for (uint256 i; i < batches.length; ++i) {
            _refuses(w, abi.encode(batches[i]), auth, NOT_SIGNED, string.concat("batch ", vm.toString(i)));
        }
        bytes32 h = _execDigest(w, AUTHORIZED_MODE | bytes32(uint256(1)), calls, at, n, deadline);
        _refuses(w, calls, _alice(h, at, deadline), NOT_SIGNED, "mode");
        _refuses(w, bytes.concat(calls, hex"00"), auth, IWebWallet.NoncanonicalBatch.selector, "a trailing byte");
        _refuses(w, calls, abi.encode(a, deadline + 1, CALL_GAS), NOT_SIGNED, "deadline");
        _refuses(w, calls, abi.encode(a, deadline, CALL_GAS - 1), NOT_SIGNED, "callGas");
        h = _execDigest(w, AUTHORIZED_MODE, calls, at, n, 0);
        _refuses(w, calls, _alice(h, at, 0), IWebWallet.ExecutionExpired.selector, "no deadline");
        uint256 chain = vm.getChainId();
        vm.chainId(chain + 1);
        _refuses(w, calls, auth, NOT_SIGNED, "chain");
        vm.chainId(chain);
        _runs(w, calls, auth);
        // The deadline's own second still runs.
        at = uint48(_now());
        _runs(w, _one(_hitX()), _alice(_execDigest(w, AUTHORIZED_MODE, _one(_hitX()), at, _nonce(w), at), at, at));
    }

    /// Expired, not yet valid, revoked and unlinked sessions sign nothing; below quorum, a call outside the scope is
    /// refused once the signatures pass.
    function test_signersOutsideTheirWindowAreRefused() public {
        address w = _claim();
        bytes32 alice = _identity(X, ALICE);
        _link(w, GITHUB, BOB, _key(BOB_PK), _admin());
        _rootW(w, abi.encodeCall(IIdentityAdmin.unlink, (_identity(GITHUB, BOB))));
        IIdentityAdmin.Policy memory p = _hitOnly();
        p.validUntil = uint48(_now() + 1 hours);
        _addSession(w, alice, _key(CAROL_PK), p);
        p = _admin();
        p.validAfter = uint48(_now() + 3 hours);
        _addSession(w, alice, _key(MALLORY_PK), p);
        _addSession(w, alice, _key(OTHER_PK), _admin());
        _revoke(w, _key(OTHER_PK));
        _addSession(w, alice, _key(APP_PK), _hitOnly());
        vm.warp(_now() + 2 hours);
        bytes memory hit = _one(_hitX());
        _refuses(w, hit, _direct(w, _pks(CAROL_PK), hit, true), OUTSIDE_WINDOW, "expired");
        _refuses(w, hit, _direct(w, _pks(MALLORY_PK), hit, false), OUTSIDE_WINDOW, "not yet");
        _refuses(w, hit, _direct(w, _pks(OTHER_PK), hit, false), NOT_SIGNED, "revoked");
        _refuses(w, hit, _direct(w, _pks(BOB_PK), hit, false), NOT_SIGNED, "unlinked");
        bytes memory outside = _one(_x(address(new CallTarget()), 0, abi.encodeCall(CallTarget.hit, ())));
        _refuses(w, outside, _direct(w, _pks(APP_PK), outside, true), NOT_ALLOWED, "outside the scope");
        _runs(w, hit, _direct(w, _pks(ALICE_PK), hit, false));
    }

    /// A signed batch whose element offset points past its own bytes: the wallet would read that element from the
    /// rest of its `data`, a call no signer signed.
    function test_aBatchReadingPastItsBytesIsRefused() public {
        address w = _claim();
        Gate gate = new Gate();
        uint48 at = uint48(_now());
        uint48 deadline = at + 1 hours;
        // The batch is its pointer table alone: [0x20][1][0x40]; its element lands 0x40 past its heads, in `data`.
        bytes memory batch = abi.encodePacked(uint256(0x20), uint256(1), uint256(0x40));
        bytes memory auth = abi.encode(
            _authOf(
                _pks(ALICE_PK),
                _execDigest(w, AUTHORIZED_MODE, batch, at, _nonce(w), deadline),
                at,
                false,
                _hitProofs(0)
            )
        );
        bytes memory data = abi.encodePacked(
            uint256(0xa0), uint256(0), uint256(deadline), CALL_GAS, uint256(0x1e0), uint256(0x60), batch, uint256(0)
        );
        data = abi.encodePacked(
            data,
            abi.encodePacked(uint256(uint160(address(gate))), uint256(0), uint256(0x60), uint256(4)),
            bytes32(Gate.openUp.selector),
            auth.length,
            auth
        );
        vm.prank(relayer);
        vm.expectRevert(IWebWallet.NoncanonicalBatch.selector);
        IWebWallet(w).execute(AUTHORIZED_MODE, data);
        assertFalse(gate.open(), "the wallet ran a call no signer signed");
    }
}

/// @notice Onboarding in one `createAndExecute`: the batch Alice's first session K signs links K from a genesis
///         Operation List proof, binds her handle, claims the escrow, repays the relayer and adds a bot's session.
contract WalletOnboardingTest is WalletSuite {
    bytes32 internal constant HANDLE = keccak256("alice's handle node");
    uint16 internal constant V2 = 2;
    uint256 internal constant FEE = 0.001 ether;
    uint256 internal constant CLAIMED = 1 ether;

    StubPlatformVerifier internal paid;
    IdentityRegistry internal identities;
    HandleEscrow internal escrow;
    TestERC20 internal token;
    address internal bob = makeAddr("bob");
    address internal w;
    bytes internal list;
    bytes internal linkData;
    uint256 internal linkFee;

    function setUp() public override {
        super.setUp();
        identities = IdentityRegistry(
            address(
                new ERC1967Proxy(address(new IdentityRegistry()), abi.encodeCall(IdentityRegistry.initialize, (owner)))
            )
        );
        escrow = HandleEscrow(
            address(
                new ERC1967Proxy(
                    address(new HandleEscrow()), abi.encodeCall(HandleEscrow.initialize, (owner, identities))
                )
            )
        );
        paid = new StubPlatformVerifier(X, FEE);
        paid.setNodes(ALICE, HANDLE);
        vm.startPrank(owner);
        identities.setProofVerifier(IProofVerifier(address(proofVerifier)));
        proofVerifier.setVerifier(X, V2, IPlatformVerifier(address(paid)));
        vm.stopPrank();
        w = factory.walletAddress(X, ALICE, 0);
        linkData = _txData(w, _key(ALICE_PK), _ph(_admin()));
        list = abi.encode(
            StubPlatformVerifier.StubPayload({
                ceremonyVersion: 1,
                operationDomain: OPERATIONS,
                authorizationNonce: bytes32(uint256(1)),
                transactionData: operationList(BIND, abi.encode(w), LINK, linkData)
            })
        );
        linkFee = registry.quote(X, V2);
        signedValue = linkFee;
        token = new TestERC20();
        vm.deal(bob, CLAIMED);
        token.mint(bob, CLAIMED);
        vm.startPrank(bob);
        token.approve(address(escrow), CLAIMED);
        escrow.deposit{value: CLAIMED}(X, HANDLE, NATIVE_TOKEN, CLAIMED);
        escrow.deposit(X, HANDLE, address(token), CLAIMED);
        vm.stopPrank();
        vm.deal(relayer, 1 ether);
    }

    function _link(uint256 value) internal view returns (Execution memory) {
        return _x(w, value, abi.encodeCall(IIdentityAdmin.linkIdentity, (X, V2, list, linkData, _admin())));
    }

    function _bind(uint256 value) internal view returns (Execution memory) {
        return
            _x(address(identities), value, abi.encodeCall(IdentityRegistry.bindPrivately, (X, V2, list, 0, address(0))));
    }

    /// The batch for a wallet that does not exist yet. A bind after the link pays no second Notary Fee.
    function _onboarding(uint256 bindFee) internal view returns (bytes memory) {
        address[] memory tokens = new address[](2);
        (tokens[0], tokens[1]) = (NATIVE_TOKEN, address(token));
        Execution[] memory x = new Execution[](5);
        x[0] = _link(linkFee);
        x[1] = _bind(bindFee);
        x[2] = _x(address(escrow), 0, abi.encodeCall(HandleEscrow.claim, (HANDLE, tokens, w)));
        x[3] = _x(relayer, linkFee + bindFee, "");
        x[4] = _x(w, 0, abi.encodeCall(IIdentityAdmin.addSession, (_identity(X, ALICE), _key(BOT_PK), _hitOnly())));
        return abi.encode(x);
    }

    /// `pk` signs `calls` for nonce 0, written by hand: the wallet has no code yet.
    function _signedBy(uint256 pk, bytes memory calls) internal view returns (bytes memory) {
        return _directAt(w, _pks(pk), calls, 0, uint48(_now()), false, _hitProofs(0));
    }

    function _send(bytes memory calls, bytes memory auth) internal {
        vm.prank(relayer, relayer);
        factory.createAndExecute{value: signedValue}(X, ALICE, 0, AUTHORIZED_MODE, _data(calls, auth));
    }

    function test_oneCreateAndExecuteOnboardsAlice() public {
        bytes memory calls = _onboarding(0);
        vm.expectRevert(NOT_SIGNED);
        _send(calls, _signedBy(MALLORY_PK, calls));
        assertEq(w.code.length, 0, "the wallet was created");

        _send(calls, _signedBy(ALICE_PK, calls));
        (address holder,) = identities.handleBinding(HANDLE);
        assertEq(holder, w, "handle not bound to the wallet");
        assertEq(escrow.escrowed(HANDLE, NATIVE_TOKEN) + escrow.escrowed(HANDLE, address(token)), 0, "left in escrow");
        assertEq(w.balance, CLAIMED - linkFee, "wallet native");
        assertEq(token.balanceOf(w), CLAIMED, "wallet token");
        assertEq(relayer.balance, 1 ether, "the relayer is not even");
        assertEq(address(factory).balance, 0, "value left in the factory");
        assertEq(_nonce(w), 1, "nonce");
        IIdentityAdmin.Session memory k = IWebWallet(w).sessionOf(_key(ALICE_PK));
        assertTrue(k.admin && !k.byProof && k.activeAt == 0, "K is not the first session");
        IIdentityAdmin.Session memory bot = IWebWallet(w).sessionOf(_key(BOT_PK));
        assertEq(bot.identity, _identity(X, ALICE), "no bot session");
        assertTrue(!bot.admin && !bot.byProof && bot.activeAt == _now(), "the bot session");
        // The bot acts alone within its rules, from the next second.
        signedValue = 0;
        bytes memory hit = _one(_hitX());
        _refuses(w, hit, _direct(w, _pks(BOT_PK), hit, true), NOT_SIGNED);
        vm.warp(_now() + 1);
        _runs(w, hit, _direct(w, _pks(BOT_PK), hit, true));
    }

    /// The bind pays the Notary Fee and the link after it, with no value, takes the bind's claim.
    function test_aLinkAfterTheBindTakesItsClaim() public {
        address[] memory tokens = new address[](1);
        tokens[0] = NATIVE_TOKEN;
        Execution[] memory x = new Execution[](4);
        (x[0], x[1]) = (_bind(FEE), _link(0));
        x[2] = _x(address(escrow), 0, abi.encodeCall(HandleEscrow.claim, (HANDLE, tokens, w)));
        x[3] = _x(relayer, FEE, "");
        signedValue = FEE;
        vm.expectCall(address(paid), abi.encodeWithSelector(IPlatformVerifier.verify.selector), 1);
        bytes memory calls = abi.encode(x);
        _send(calls, _signedBy(ALICE_PK, calls));
        (address holder,) = identities.handleBinding(HANDLE);
        assertEq(holder, w, "handle not bound to the wallet");
        assertTrue(IWebWallet(w).sessionOf(_key(ALICE_PK)).admin, "K not linked");
        assertEq(relayer.balance, 1 ether, "the relayer is not even");
    }

    /// A bind priced in full verifies again, even after someone else verified the proof earlier in the transaction.
    function test_aFullPricedBindSurvivesAnEarlierVerification() public {
        vm.deal(address(this), FEE);
        this.verifyThenOnboard();
        (address holder,) = identities.handleBinding(HANDLE);
        assertEq(holder, w, "handle not bound to the wallet");
        assertEq(w.balance, CLAIMED - linkFee - FEE, "wallet native");
        assertEq(relayer.balance, 1 ether, "the relayer is not even");
    }

    function verifyThenOnboard() external {
        vm.expectCall(address(paid), abi.encodeWithSelector(IPlatformVerifier.verify.selector), 3);
        proofVerifier.verify{value: FEE}(X, V2, list);
        signedValue = linkFee + FEE;
        bytes memory calls = _onboarding(FEE);
        _send(calls, _signedBy(ALICE_PK, calls));
    }
}
