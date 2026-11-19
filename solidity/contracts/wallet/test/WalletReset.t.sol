// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IAccount, PackedUserOperation} from "@openzeppelin/contracts/interfaces/IERC4337.sol";
import {Execution} from "@openzeppelin/contracts/interfaces/draft-IERC7579.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

import {IWalletFactory} from "../IWalletFactory.sol";
import {IWalletForwarder} from "../IWalletForwarder.sol";
import {AUTHORIZED_MODE, IWebWallet} from "../IWebWallet.sol";
import {CallTarget, IUserOpHash, WalletBase} from "./WalletBase.sol";

/// Measures one call from its own isolated transaction, where the target and everything it reads are cold.
contract ColdMeter {
    function cost(address target) external view returns (uint256 gas) {
        gas = gasleft();
        IWebWallet(target).VERSION();
        gas -= gasleft();
    }
}

/// Code a key delegates to while away: it points the release slot at its own implementation.
contract Planter {
    fallback() external {}

    function plant(address impl) external {
        bytes32 slot = 0xe1dba8fb066a3b169f681c6818aeab86343e7484c7e0cee1cbf00e41a55c2800;
        assembly {
            sstore(slot, or(impl, shl(160, 99)))
        }
    }
}

/// @notice EIP-7702 accounts on WalletForwarder: `reset` and its epoch, the forwarder's routing, and the key's
///         own powers.
/// forge-config: default.evm_version = "prague"
contract WalletResetTest is WalletBase {
    uint256 internal constant KEY_PK = 0x7702;
    uint256 internal constant SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;

    address internal a;
    address internal fwd;

    function setUp() public override {
        super.setUp();
        a = vm.addr(KEY_PK);
        fwd = deployCode("WalletForwarder.sol:WalletForwarder", abi.encode(address(factory)));
    }

    function _delegateTo(address code) internal {
        vm.signAndAttachDelegation(code, KEY_PK);
        vm.prank(relayer);
        (bool ok,) = a.call("");
        assertTrue(ok, "an empty call reverted");
        assertEq(a.code, abi.encodePacked(hex"ef0100", code), "not delegated");
    }

    /// The key's onboarding batch: link Alice's X identity, then add her admin session.
    function _onboarding() internal returns (bytes memory) {
        return _two(
            _linkX(a, X, ALICE, "", _admin()),
            _x(a, 0, abi.encodeCall(IWebWallet.addSession, (_identity(X, ALICE), _key(ALICE_PK), _admin())))
        );
    }

    function _reset(bytes memory calls) internal {
        vm.prank(a, a);
        IWebWallet(a).reset(calls);
    }

    function _onboard() internal {
        _delegateTo(fwd);
        _reset(_onboarding());
        vm.deal(a, 1 ether);
        vm.warp(_now() + 1);
    }

    function test_resetOnboardsAndTheSessionActs() public {
        _onboard();
        (address impl, uint64 version) = IWebWallet(a).release();
        (address latest, uint64 latestVersion) = factory.latest();
        assertEq(abi.encode(impl, version), abi.encode(latest, latestVersion), "not the factory's latest");
        assertTrue(IWebWallet(a).isLinked(_identity(X, ALICE)), "not linked");
        (bytes32 p,,) = IWebWallet(a).genesisIdentity();
        assertEq(p, bytes32(0), "a forwarder account has a genesis");
        _run(a, _one(_hitX()));
        _handle(_ops(_signOp(_op(a, _hitCall()), 1, _pks(ALICE_PK))));
        assertEq(target.calls(), 2, "the session did not act");
    }

    /// Acceptance 9: before `reset`, only an empty call returns; a UserOperation is refused, and a stranger's
    /// `reset` writes nothing.
    function test_beforeResetNothingRuns() public {
        _delegateTo(fwd);
        vm.prank(a, a);
        vm.expectRevert(IWalletForwarder.NotSetUp.selector);
        IWebWallet(a).execute(MODE_BATCH, _one(_hitX()));
        _refusedOp(_signOp(_op(a, _hitCall()), 1, _pks(ALICE_PK)));
        bytes memory onboarding = _onboarding();
        vm.prank(mallory, mallory);
        vm.expectRevert(IWebWallet.ResetRefused.selector);
        IWebWallet(a).reset(onboarding);
        assertEq(vm.load(a, RELEASE_SLOT), bytes32(0), "a stranger's reset wrote the slot");
    }

    /// The epoch moves to `keccak256(abi.encode(old, blockhash(n - 1), timestamp))`, and kills what code the key
    /// ran while away planted: sessions and the release slot.
    function test_plantedStateIsDeadAfterReset() public {
        _onboard();
        bytes32 old = IWebWallet(a).epoch();
        address planter = address(new Planter());
        _delegateTo(planter);
        vm.prank(a, a);
        Planter(a).plant(makeAddr("evil implementation"));
        _delegateTo(fwd);

        vm.roll(vm.getBlockNumber() + 1);
        bytes32 expected = keccak256(abi.encode(old, blockhash(vm.getBlockNumber() - 1), _now()));
        _reset(_one(_hitX()));
        assertEq(IWebWallet(a).epoch(), expected, "epoch");
        assertEq(IWebWallet(a).sessionOf(_key(ALICE_PK)).identity, bytes32(0), "a planted session lives");
        assertFalse(IWebWallet(a).isLinked(_identity(X, ALICE)), "a planted link lives");
        (address impl,) = IWebWallet(a).release();
        (address latest,) = factory.latest();
        assertEq(impl, latest, "the planted release survived");
        bytes memory data = _signed(a, _pks(ALICE_PK), _one(_hitX()));
        vm.expectPartialRevert(IWebWallet.ExecutionNotSigned.selector);
        IWebWallet(a).execute(AUTHORIZED_MODE, data);
    }

    /// Acceptance 9: `reset` only from the key's own top-level transaction, never under the lock.
    function test_resetRefusals() public {
        _onboard();
        bytes32 epoch = IWebWallet(a).epoch();
        bytes memory reset = abi.encodeCall(IWebWallet.reset, (_one(_hitX())));
        address[2] memory senders = [mallory, mallory];
        address[2] memory origins = [mallory, a];
        for (uint256 i; i < senders.length; ++i) {
            vm.prank(senders[i], origins[i]);
            vm.expectRevert(IWebWallet.ResetRefused.selector);
            IWebWallet(a).reset(_one(_hitX()));
        }
        // Inside the key's own batch, and inside a relayed session batch the key's transaction carries.
        vm.prank(a, a);
        vm.expectRevert(IWebWallet.ResetRefused.selector);
        IWebWallet(a).execute(MODE_BATCH, _one(_x(a, 0, reset)));
        bytes memory data = _signed(a, _pks(ALICE_PK), _one(_x(a, 0, reset)));
        vm.prank(a, a);
        vm.expectRevert(IWebWallet.ResetRefused.selector);
        IWebWallet(a).execute(AUTHORIZED_MODE, data);
        // Never a root operation, so never inside `executeRoot`.
        bytes memory queue = abi.encodeCall(IWebWallet.queueRoot, (reset));
        vm.prank(a, a);
        vm.expectPartialRevert(IWebWallet.RootOperationNotAllowed.selector);
        IWebWallet(a).execute(MODE_BATCH, _one(_x(a, 0, queue)));
        assertEq(IWebWallet(a).epoch(), epoch, "the epoch moved");
        assertEq(target.calls(), 0, "a refused reset ran its batch");
    }

    /// The key's top-level call reaches a root-only entry; its batch does not.
    function test_theKeysRootOnlyCallsAreTopLevel() public {
        _onboard();
        _publish(2);
        bytes[4] memory calls = [
            abi.encodeCall(IWebWallet.bump, (2)),
            abi.encodeCall(IWebWallet.setThreshold, (2)),
            abi.encodeCall(IWebWallet.setRootDelay, (72 hours)),
            abi.encodeCall(IWebWallet.unlink, (_identity(X, ALICE)))
        ];
        for (uint256 i; i < calls.length; ++i) {
            vm.prank(a, a);
            vm.expectRevert(IWebWallet.RootOperationRequired.selector);
            IWebWallet(a).execute(MODE_BATCH, _one(_x(a, 0, calls[i])));
        }
        vm.prank(mallory, mallory);
        vm.expectRevert(IWebWallet.RootOperationRequired.selector);
        IWebWallet(a).setRootDelay(72 hours);
        vm.prank(a, a);
        IWebWallet(a).setRootDelay(72 hours);
        assertEq(IWebWallet(a).rootDelay(), 72 hours, "the key's own call");
    }

    /// The default mode in direct: the key's own call on its account runs; anyone else's does not.
    function test_defaultModeInDirect() public {
        _onboard();
        bytes memory hit = abi.encodePacked(address(target), uint256(0), abi.encodeWithSignature("hit()"));
        vm.prank(mallory, mallory);
        vm.expectRevert();
        IWebWallet(a).execute(MODE_SINGLE, hit);
        address w = _claim();
        vm.prank(relayer, relayer);
        vm.expectRevert();
        IWebWallet(w).execute(MODE_SINGLE, hit);
        assertEq(target.calls(), 0, "a stranger's default mode ran");
        vm.prank(a, a);
        IWebWallet(a).execute(MODE_SINGLE, hit);
        assertEq(target.calls(), 1, "the key's default mode");
    }

    /// A1: no genesis bootstrap on a forwarder account, and a login is never the first session.
    function test_noFirstSessionWithoutTheKeysAddSession() public {
        _delegateTo(fwd);
        bytes memory keyed = _one(_linkX(a, X, ALICE, _key(ALICE_PK), _admin()));
        vm.prank(a, a);
        vm.expectRevert(IWebWallet.LinkSessionRefused.selector);
        IWebWallet(a).reset(keyed);
        _reset(_one(_linkX(a, X, ALICE, "", _admin())));
        bytes memory login = _loginPayload(a, X, ALICE, _key(ALICE_PK), _admin());
        vm.prank(relayer);
        vm.expectRevert(IWebWallet.FirstSessionRefused.selector);
        IWebWallet(a).addSessionByLogin(X, V1, login, "", _admin());
        // A stranger's batch adding her own session signs only from the next second: still refused.
        Execution[] memory x = new Execution[](2);
        x[0] = _linkX(a, X, MALLORY, "", _admin());
        x[1] = _x(a, 0, abi.encodeCall(IWebWallet.addSession, (_identity(X, MALLORY), _key(MALLORY_PK), _admin())));
        bytes memory data = _signed(a, _pks(MALLORY_PK), abi.encode(x));
        vm.prank(mallory);
        vm.expectRevert();
        IWebWallet(a).execute(AUTHORIZED_MODE, data);
        assertEq(IWebWallet(a).sessionOf(_key(MALLORY_PK)).identity, bytes32(0), "a stranger's first session");
    }

    // ─── The forwarder ──────────────────────────────────────────────

    /// At its own address the forwarder refuses every call, `reset` and plain ETH included.
    function test_theForwarderRefusesDirectCalls() public {
        bytes[3] memory calls =
            [abi.encodeCall(IWebWallet.reset, (_one(_hitX()))), abi.encodeCall(IWebWallet.release, ()), ""];
        for (uint256 i; i < calls.length; ++i) {
            (bool ok, bytes memory err) = fwd.call{value: i == 2 ? 1 : 0}(calls[i]);
            assertFalse(ok, "the forwarder answered");
            assertEq(err, abi.encodeWithSelector(IWebWallet.NotDelegated.selector), "the error");
        }
    }

    /// With no release published, `reset` has nowhere to go.
    function test_resetWithoutAReleaseIsNotSetUp() public {
        bytes memory init = abi.encodeCall(IWalletFactory.initialize, (owner));
        address bare = address(new ERC1967Proxy(deployCode("WalletFactory.sol:WalletFactory"), init));
        fwd = deployCode("WalletForwarder.sol:WalletForwarder", abi.encode(bare));
        _delegateTo(fwd);
        bytes memory onboarding = _onboarding();
        vm.prank(a, a);
        vm.expectRevert(IWalletForwarder.NotSetUp.selector);
        IWebWallet(a).reset(onboarding);
    }

    /// Delegating away and back without `reset` resumes the sessions: the state is the account's.
    function test_reDelegatingBackResumesSessions() public {
        _onboard();
        _delegateTo(address(new Planter()));
        _delegateTo(fwd);
        _handle(_ops(_signOp(_op(a, _hitCall()), 1, _pks(ALICE_PK))));
        assertEq(target.last(), a, "the old session did not act");
    }

    /// A root-executed bump moves the account to the next release, whose sessions then act.
    function test_theAccountFollowsABump() public {
        _onboard();
        address impl2 = _publish(2);
        _root(a, abi.encodeCall(IWebWallet.bump, (2)));
        (address impl, uint64 version) = IWebWallet(a).release();
        assertEq(abi.encode(impl, version, IWebWallet(a).VERSION()), abi.encode(impl2, 2, 2), "release");
        _run(a, _one(_hitX()));
        assertEq(target.calls(), 1, "the session did not act on release 2");
    }

    /// A cold view through the forwarder costs one through a factory proxy plus the delegation lookup.
    /// forge-config: default.isolate = true
    function test_forwarderOverheadPerCall() public {
        _onboard();
        address w = factory.createWallet(X, BOB, 0);
        ColdMeter meter = new ColdMeter();
        uint256 viaForwarder = meter.cost(a);
        uint256 viaProxy = meter.cost(w);
        assertGt(viaForwarder, viaProxy, "the forwarder's path was not cold");
        emit log_named_uint("forwarder overhead", viaForwarder - viaProxy);
        assertLt(viaForwarder, viaProxy + 10_000, "forwarder overhead");
    }

    /// The account's validation reads neither the factory nor the registry.
    function test_validationReadsNoFactoryOrRegistry() public {
        _onboard();
        PackedUserOperation memory op = _signOp(_op(a, _hitCall()), 1, _pks(ALICE_PK));
        bytes32 h = IUserOpHash(EP).getUserOpHash(op);
        vm.record();
        vm.prank(EP);
        assertEq(IAccount(a).validateUserOp(op, h, 0) & 1, 0, "not validated");
        (bytes32[] memory reads,) = vm.accesses(address(factory));
        assertEq(reads.length, 0, "validation read the factory");
        (reads,) = vm.accesses(address(registry));
        assertEq(reads.length, 0, "validation read the registry");
    }

    // ─── The key ────────────────────────────────────────────────────

    /// Acceptance 4: the key's own call to the registry spends its proof and links nothing.
    function test_theKeysDirectCheckLinksNothing() public {
        _onboard();
        bytes memory payload = _linkPayload(a, GITHUB, BOB, "", _admin());
        vm.prank(a, a);
        registry.check(LINK, GITHUB, V1, payload, "", 0);
        assertTrue(registry.spentDigests(_digestOf(payload)), "the proof is unspent");
        assertFalse(IWebWallet(a).isLinked(_identity(GITHUB, BOB)), "a direct check linked");
    }

    /// ERC-1271 takes the account's own key's 65-byte ECDSA signature, never a stranger's or a high-s one, and only
    /// under an EIP-7702 delegation: a factory wallet's code at a key's address refuses it.
    function test_theKeySignsWith65Bytes() public {
        _onboard();
        bytes32 h = keccak256("a message");
        assertEq(IWebWallet(a).isValidSignature(h, _sig65(KEY_PK, h)), bytes4(0x1626ba7e), "the key");
        assertEq(IWebWallet(a).isValidSignature(h, _sig65(MALLORY_PK, h)), bytes4(0xffffffff), "a stranger");
        assertEq(IWebWallet(a).isValidSignature(h, _highS(_sig65(KEY_PK, h))), bytes4(0xffffffff), "high s");
        assertTrue(_valid1271(a, 1, ALICE_PK, h), "the session");

        address w = _claim();
        assertEq(IWebWallet(w).isValidSignature(h, _sig65(ALICE_PK, h)), bytes4(0xffffffff), "a factory wallet");
        address k = vm.addr(BOB_PK);
        vm.etch(k, w.code);
        vm.store(k, RELEASE_SLOT, vm.load(w, RELEASE_SLOT));
        assertEq(IWebWallet(k).VERSION(), 1, "control: the etched wallet runs");
        assertEq(IWebWallet(k).isValidSignature(h, _sig65(BOB_PK, h)), bytes4(0xffffffff), "without a delegation");
    }

    /// A quorum batch calling the account's own `execute` in the default mode is the account under a delegation:
    /// only the lock refuses it. The key's top-level call is the control.
    function test_aBatchCannotReenterTheDefaultMode() public {
        _onboard();
        bytes memory hit = abi.encodePacked(address(target), uint256(0), abi.encodeCall(CallTarget.hit, ()));
        bytes memory inner = abi.encodeCall(IWebWallet.execute, (MODE_SINGLE, hit));
        bytes memory data = _signed(a, _pks(ALICE_PK), _one(_x(a, 0, inner)));
        vm.prank(relayer);
        vm.expectRevert(IWebWallet.Locked.selector);
        IWebWallet(a).execute(AUTHORIZED_MODE, data);
        assertEq(target.calls(), 0, "the default mode ran inside a batch");
        vm.prank(a, a);
        (bool ok,) = a.call(inner);
        assertTrue(ok && target.calls() == 1, "control: the key's default mode");
    }

    function _sig65(uint256 pk, bytes32 h) internal pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, h);
        return abi.encodePacked(r, s, v);
    }

    /// The same signature with `s` mirrored to the upper half and `v` flipped.
    function _highS(bytes memory sig) internal pure returns (bytes memory) {
        (bytes32 r, bytes32 s) = abi.decode(sig, (bytes32, bytes32));
        uint8 v = uint8(sig[64]);
        return abi.encodePacked(r, bytes32(SECP256K1_N - uint256(s)), v == 27 ? uint8(28) : uint8(27));
    }
}
